import { AppError } from '../core/errors.js';
import type { AccountLease, AccountLeaseGate } from '../core/session/account-gate.js';
import type { SessionLease, SessionLeaseGate } from '../core/session/session-manager.js';
import type {
  AutofillContinuationResumeData,
  AutofillContinuationStatusData,
  AwaitAutofillFocusCommand,
  CardFillData,
  CancelHeldFillTargetCommand,
  FillKind,
  FillRole,
  IdentityFillData,
  ResumeHeldFillTargetCommand,
  ResumeKeyboardRepromptCommand,
  TabSuggestionTarget,
} from '../messaging/protocol.js';
import type { AutofillAuthorizationPolicyLease } from './autofill-authorization-policy.js';
import type {
  AutofillKeyboardGrantRegistry,
  KeyboardGrant,
} from './autofill-keyboard-grant-registry.js';
import {
  AutofillContinuationStore,
  autofillContinuationAuthority,
  type AutofillContinuationAction,
  type AutofillContinuationEnvelope,
  type AutofillContinuationSource,
} from './autofill-continuation-store.js';
import type { TabAutofillCoordinator } from './tab-autofill.js';
import type { VaultReleaseGate } from './vault-release-gate.js';
import type { DirectFillCommand, SecretExtensionCommand } from './commands.js';

type Policy = AutofillAuthorizationPolicyLease;
type KeyboardGrantValue = KeyboardGrant<SessionLease, AccountLease, Policy>;

interface BrowserTab {
  readonly id?: number;
  readonly windowId?: number;
  readonly active: boolean;
  readonly url?: string;
}

interface BrowserFrame {
  readonly frameId: number;
  readonly documentId?: string;
  readonly url: string;
}

interface VerifiedKeyboardProof {
  readonly envelope: AutofillContinuationEnvelope;
  readonly runtimeIncarnation: string;
  readonly sessionLease: SessionLease;
  readonly accountLease: AccountLease;
  readonly policyLease: Policy;
  readonly binding: KeyboardGrantValue['binding'];
}

export interface AutofillContinuationBrowserSource {
  readonly tabId: number;
  readonly windowId: number;
  readonly topDocumentId: string;
  readonly topRuntimeIncarnation: string;
  readonly topUrl: string;
  readonly frameId: number;
  readonly frameDocumentId: string;
  readonly frameRuntimeIncarnation: string;
  readonly frameUrl: string;
}

type AutofillContinuationStageSource = Omit<
  AutofillContinuationBrowserSource,
  'topRuntimeIncarnation' | 'frameRuntimeIncarnation'
> & {
  readonly topRuntimeIncarnation: string | null;
  readonly frameRuntimeIncarnation: string | null;
};

interface CurrentSourceUrls {
  readonly topUrl: string;
  readonly frameUrl: string;
}

export interface AutofillContinuationCoordinatorDeps {
  readonly store: AutofillContinuationStore;
  readonly getState: () => Promise<'loggedOut' | 'locked' | 'restricted' | 'unlocked'>;
  readonly sessionGate: Pick<SessionLeaseGate, 'capture' | 'assert'>;
  readonly accountGate: Pick<AccountLeaseGate, 'capture' | 'assert'>;
  readonly capturePolicy: () => Policy;
  readonly assertPolicy: (lease: Policy) => void;
  readonly workerInstanceId: string;
  readonly getStablePolicyDigest: () => Promise<string>;
  readonly verifyMasterPassword: (masterPassword: string) => Promise<boolean>;
  readonly getTab: (tabId: number) => Promise<BrowserTab | undefined>;
  readonly getFrame: (tabId: number, frameId: number) => Promise<BrowserFrame | undefined>;
  readonly isRuntimeCurrent: (
    tabId: number,
    frameId: number,
    documentId: string,
    runtimeIncarnation: string,
  ) => Promise<boolean>;
  readonly getRuntimeIncarnation: (
    tabId: number,
    frameId: number,
    documentId: string,
  ) => Promise<string | undefined>;
  readonly focusSource: (windowId: number, tabId: number) => Promise<void>;
  readonly openPopup: () => Promise<void>;
  readonly openPopupFallback: () => Promise<void>;
  readonly isPopupDocumentOpen: (documentId: string) => Promise<boolean>;
  readonly sendToDocument: (
    tabId: number,
    frameId: number,
    documentId: string,
    command: ResumeHeldFillTargetCommand | ResumeKeyboardRepromptCommand | CancelHeldFillTargetCommand
      | AwaitAutofillFocusCommand,
  ) => Promise<unknown>;
  readonly sendFocusedFill: (tabId: number, commandToken: string) => Promise<unknown>;
  readonly runCommand: (
    command: SecretExtensionCommand,
    tab: { readonly id: number; readonly windowId: number },
    assertCurrent: () => void,
    expectedSource: {
      readonly documentId: string;
      readonly runtimeIncarnation: string;
      readonly url: string;
    },
  ) => Promise<void>;
  readonly keyboardGrants: Pick<
    AutofillKeyboardGrantRegistry<SessionLease, AccountLease, Policy>,
    'issueCommand'
  >;
  readonly tabAutofill: Pick<TabAutofillCoordinator, 'getSuggestions' | 'fill'>;
  readonly getFillData: (
    cipherId: string,
    kind: FillKind,
    roles: readonly FillRole[],
    assertRepromptAuthorized: () => void,
    bindFinalAuthority: (assertCurrent: () => void) => void,
  ) => Promise<CardFillData | IdentityFillData>;
  readonly readLoginCopyValue: (
    cipherId: string,
    field: 'password' | 'totp',
    assertRepromptAuthorized: () => void,
    bindFinalAuthority: (assertCurrent: () => void) => void,
  ) => Promise<string | undefined>;
  readonly clipboard: {
    readonly writeSecretAndScheduleClear: (value: string, assertCurrent: () => void) => Promise<boolean>;
    readonly writeTotpAndScheduleClear: (value: string, assertCurrent: () => void) => Promise<boolean>;
  };
  readonly vaultReleaseGate?: Pick<VaultReleaseGate, 'capture' | 'checkpoint' | 'assertAuthorities' | 'assert'>
    & Partial<Pick<VaultReleaseGate, 'settlePendingAction'>>;
  readonly recordActivity?: () => Promise<void>;
  readonly now?: () => number;
}

export interface RedeemedKeyboardReprompt {
  readonly cipherId: string;
  readonly runtimeIncarnation: string;
  readonly binding: KeyboardGrantValue['binding'];
  readonly source: AutofillContinuationSource;
  readonly sessionLease: SessionLease;
  readonly accountLease: AccountLease;
  readonly policyLease: Policy;
  readonly repromptAuthorization: { readonly assertCurrent: () => void };
}

export class AutofillContinuationCoordinator {
  readonly #deps: AutofillContinuationCoordinatorDeps;
  #stageTail: Promise<void> = Promise.resolve();
  readonly #keyboardProofs = new Map<string, VerifiedKeyboardProof>();
  readonly #pendingKeyboardBindings = new Map<string, {
    readonly binding: KeyboardGrantValue['binding'];
    readonly runtimeIncarnation: string;
    readonly expiresAt: number;
    readonly timer: ReturnType<typeof setTimeout>;
  }>();

  constructor(deps: AutofillContinuationCoordinatorDeps) {
    this.#deps = deps;
  }

  async stageLockedKeyboard(input: {
    readonly tabId: number;
    readonly windowId: number;
    readonly topDocumentId: string;
    readonly topFrameUrl: string;
  }): Promise<void> {
    const source: AutofillContinuationStageSource = {
      tabId: input.tabId,
      windowId: input.windowId,
      topDocumentId: input.topDocumentId,
      topRuntimeIncarnation: null,
      topUrl: input.topFrameUrl,
      frameId: 0,
      frameDocumentId: input.topDocumentId,
      frameRuntimeIncarnation: null,
      frameUrl: input.topFrameUrl,
    };
    await this.#stage(source, { kind: 'locked_keyboard' });
  }

  async stageLockedContext(source: AutofillContinuationBrowserSource): Promise<void> {
    await this.#stage(source, { kind: 'locked_context' });
  }

  async stageLockedCommand(
    command: SecretExtensionCommand,
    source: AutofillContinuationBrowserSource,
  ): Promise<void> {
    await this.#stage(source, { kind: 'locked_command', command });
  }

  async stageContextLoginReprompt(
    source: AutofillContinuationBrowserSource,
    cipherId: string,
    target: TabSuggestionTarget,
  ): Promise<void> {
    await this.#stage(source, { kind: 'context_login_reprompt', cipherId, target });
  }

  async stageCommandFillReprompt(
    source: AutofillContinuationBrowserSource,
    input: {
      readonly command: DirectFillCommand;
      readonly cipherId: string;
      readonly target: TabSuggestionTarget;
    },
  ): Promise<void> {
    await this.#stage(source, { kind: 'command_fill_reprompt', ...input });
  }

  async stageContextCopyReprompt(
    source: AutofillContinuationBrowserSource,
    cipherId: string,
    field: 'password' | 'totp',
  ): Promise<void> {
    await this.#stage(source, { kind: 'context_copy_reprompt', cipherId, field });
  }

  async stageContextStructuredReprompt(
    source: AutofillContinuationBrowserSource,
    input: {
      readonly cipherId: string;
      readonly holdId: string;
      readonly scope: 'form' | 'field';
      readonly fillKind: FillKind;
      readonly roles: readonly FillRole[];
      readonly runtimeIncarnation: string;
    },
  ): Promise<void> {
    await this.#stage(source, { kind: 'context_structured_reprompt', ...input });
  }

  async stageKeyboardReprompt(grant: KeyboardGrantValue, cipherId: string): Promise<string> {
    if (!liveKeyboardBindingMatchesRuntime(grant.binding, grant.runtimeIncarnation)) throw staleContinuation();
    const tab = await this.#deps.getTab(grant.tabId);
    if (!tab || tab.id !== grant.tabId || tab.windowId === undefined) throw staleContinuation();
    const topRuntimeIncarnation = grant.frameId === 0 && grant.documentId === grant.topDocumentId
      ? grant.runtimeIncarnation
      : await this.#currentRuntimeIncarnation(grant.tabId, 0, grant.topDocumentId);
    if (!topRuntimeIncarnation) throw staleContinuation();
    const source: AutofillContinuationBrowserSource = {
      tabId: grant.tabId,
      windowId: tab.windowId,
      topDocumentId: grant.topDocumentId,
      topRuntimeIncarnation,
      topUrl: grant.topFrameUrl,
      frameId: grant.frameId,
      frameDocumentId: grant.documentId,
      frameRuntimeIncarnation: grant.runtimeIncarnation,
      frameUrl: grant.frameUrl,
    };
    const binding = keyboardContinuationBinding(grant.binding, grant.runtimeIncarnation);
    return this.#stage(source, {
      kind: 'keyboard_reprompt',
      cipherId,
      binding,
    }, (envelope) => {
      this.#pruneKeyboardProofs();
      const delay = Math.max(0, envelope.expiresAt - (this.#deps.now?.() ?? Date.now()));
      this.#pendingKeyboardBindings.set(envelope.continuationId, {
        binding: grant.binding,
        runtimeIncarnation: grant.runtimeIncarnation,
        expiresAt: envelope.expiresAt,
        timer: setTimeout(() => this.#deletePendingKeyboardBinding(envelope.continuationId), delay),
      });
    });
  }

  async status(popupDocumentId: string): Promise<AutofillContinuationStatusData> {
    this.#pruneKeyboardProofs();
    const envelope = await this.#deps.store.claimPopup(popupDocumentId);
    if (!envelope) return { status: 'none' };
    if (!await this.#publicEnvelopeCurrent(envelope)) {
      await this.#deps.store.clearExact(envelope.continuationId).catch(() => false);
      return { status: 'none' };
    }
    if (envelope.action.kind === 'keyboard_reprompt'
      && !this.#pendingKeyboardBindings.has(envelope.continuationId)) {
      await this.#deps.store.clearExact(envelope.continuationId).catch(() => false);
      return { status: 'none' };
    }
    const channel = envelope.action.kind.includes('keyboard')
      || envelope.action.kind === 'locked_command'
      || envelope.action.kind === 'command_fill_reprompt'
      ? 'keyboard'
      : 'context';
    if (envelope.action.kind === 'locked_context'
        || envelope.action.kind === 'locked_keyboard'
        || envelope.action.kind === 'locked_command') {
      return {
        status: 'unlock_required',
        continuationId: envelope.continuationId,
        channel,
        expiresAt: envelope.expiresAt,
      };
    }
    return {
      status: 'reprompt_required',
      continuationId: envelope.continuationId,
      channel,
      cipherId: envelope.action.cipherId,
      expiresAt: envelope.expiresAt,
    };
  }

  async resumeUnlock(
    popupDocumentId: string,
    continuationId: string,
  ): Promise<AutofillContinuationResumeData> {
    const envelope = await this.#deps.store.take(popupDocumentId, continuationId);
    if (!envelope || (envelope.action.kind !== 'locked_context'
        && envelope.action.kind !== 'locked_keyboard'
        && envelope.action.kind !== 'locked_command')) {
      return { status: 'stale' };
    }
    if (await this.#deps.getState() !== 'unlocked' || !await this.#publicEnvelopeCurrent(envelope)) {
      return { status: 'stale' };
    }
    if (envelope.action.kind === 'locked_context') {
      const outcome = await this.#deps.tabAutofill.getSuggestions(envelope.source.tabId);
      if (!await this.#publicEnvelopeCurrent(envelope)) return { status: 'stale' };
      return { status: 'show_suggestions', tabId: envelope.source.tabId, outcome };
    }
    if (envelope.action.kind === 'locked_command') {
      void this.#dispatchLockedCommandAfterPopupCloses(
        envelope as AutofillContinuationEnvelope & {
          readonly action: Extract<AutofillContinuationAction, { kind: 'locked_command' }>;
        },
        popupDocumentId,
      ).catch(() => undefined);
      return { status: 'started' };
    }
    void this.#dispatchLockedKeyboardAfterPopupCloses(
      envelope as AutofillContinuationEnvelope & {
        readonly action: Extract<AutofillContinuationAction, { kind: 'locked_keyboard' }>;
      },
      popupDocumentId,
    ).catch(() => undefined);
    return { status: 'started' };
  }

  async authorizeReprompt(
    popupDocumentId: string,
    continuationId: string,
    masterPassword: string,
  ): Promise<{ readonly verified: boolean; readonly result?: AutofillContinuationResumeData }> {
    const envelope = await this.#deps.store.read();
    if (!envelope || envelope.popupDocumentId !== popupDocumentId
        || envelope.continuationId !== continuationId) return { verified: false };
    if (!envelope || envelope.action.kind === 'locked_context'
        || envelope.action.kind === 'locked_keyboard'
        || envelope.action.kind === 'locked_command') {
      return { verified: false };
    }
    if (await this.#deps.getState() !== 'unlocked' || !await this.#publicEnvelopeCurrent(envelope)) {
      return { verified: false, result: { status: 'stale' } };
    }
    const verified = await this.#deps.verifyMasterPassword(masterPassword);
    if (!verified) return { verified: false };
    const consumed = await this.#deps.store.take(popupDocumentId, continuationId);
    if (!consumed) return { verified: true, result: { status: 'stale' } };
    void this.#dispatchRepromptAfterPopupCloses(
      consumed as AutofillContinuationEnvelope & {
        readonly action: Exclude<
          AutofillContinuationAction,
          { kind: 'locked_context' | 'locked_keyboard' | 'locked_command' }
        >;
      },
      popupDocumentId,
    ).catch(() => undefined);
    return { verified: true, result: { status: 'started' } };
  }

  async redeemKeyboardReprompt(
    continuationId: string,
    caller: {
      readonly tabId: number;
      readonly frameId: number;
      readonly documentId: string;
      readonly runtimeIncarnation: string;
      readonly url: string;
    },
  ): Promise<RedeemedKeyboardReprompt | undefined> {
    if (!isCanonicalUuidV4(continuationId)) return undefined;
    const proof = this.#keyboardProofs.get(continuationId);
    if (proof) this.#keyboardProofs.delete(continuationId);
    if (!proof) return undefined;
    let callerRuntimeIncarnation: string;
    try { callerRuntimeIncarnation = canonicalRuntimeIncarnation(caller.runtimeIncarnation); }
    catch { return undefined; }
    const { envelope } = proof;
    if (envelope.action.kind !== 'keyboard_reprompt'
        || envelope.continuationId !== continuationId
        || envelope.source.tabId !== caller.tabId
        || envelope.source.frameId !== caller.frameId
        || envelope.source.frameDocumentId !== caller.documentId
        || envelope.source.frameRuntimeIncarnation !== callerRuntimeIncarnation
        || envelope.action.binding.runtimeIncarnation !== callerRuntimeIncarnation
        || proof.runtimeIncarnation !== callerRuntimeIncarnation
        || !liveKeyboardBindingMatchesRuntime(proof.binding, callerRuntimeIncarnation)
        || !sameKeyboardContinuationBinding(proof.binding, callerRuntimeIncarnation, envelope.action.binding)
        || !await urlMatchesDigest(caller.url, envelope.source.frameUrlDigest)
        || !await this.#sourceCurrent(envelope.source)) return undefined;
    try { this.#assertFreshAuthorities(proof); } catch { return undefined; }
    return Object.freeze({
      cipherId: envelope.action.cipherId,
      runtimeIncarnation: callerRuntimeIncarnation,
      binding: proof.binding,
      source: envelope.source,
      sessionLease: proof.sessionLease,
      accountLease: proof.accountLease,
      policyLease: proof.policyLease,
      repromptAuthorization: Object.freeze({
        assertCurrent: () => this.#assertFreshAuthorities(proof),
      }),
    });
  }

  async cancel(popupDocumentId: string, continuationId: string): Promise<boolean> {
    const envelope = await this.#deps.store.take(popupDocumentId, continuationId);
    if (!envelope) return false;
    this.#keyboardProofs.delete(envelope.continuationId);
    this.#deletePendingKeyboardBinding(envelope.continuationId);
    await this.#cancelHeldTarget(envelope);
    return true;
  }

  async revokeAll(): Promise<void> {
    const envelope = await this.#deps.store.read().catch(() => undefined);
    this.#keyboardProofs.clear();
    for (const id of this.#pendingKeyboardBindings.keys()) this.#deletePendingKeyboardBinding(id);
    await this.#deps.store.clear().catch(() => undefined);
    if (envelope) await this.#cancelHeldTarget(envelope);
  }

  async reconcilePolicy(): Promise<void> {
    const envelope = await this.#deps.store.read().catch(() => undefined);
    if (envelope && !await this.#publicEnvelopeCurrent(envelope)) {
      this.#keyboardProofs.delete(envelope.continuationId);
      this.#deletePendingKeyboardBinding(envelope.continuationId);
      await this.#deps.store.clearExact(envelope.continuationId).catch(() => false);
      await this.#cancelHeldTarget(envelope);
    }
  }

  async revokeTab(tabId: number): Promise<void> {
    const envelope = await this.#deps.store.read().catch(() => undefined);
    if (envelope?.source.tabId === tabId) {
      this.#keyboardProofs.delete(envelope.continuationId);
      this.#deletePendingKeyboardBinding(envelope.continuationId);
      await this.#deps.store.clearExact(envelope.continuationId).catch(() => false);
      await this.#cancelHeldTarget(envelope);
    }
  }

  async #dispatchLockedKeyboardAfterPopupCloses(
    envelope: AutofillContinuationEnvelope & { readonly action: { readonly kind: 'locked_keyboard' } },
    popupDocumentId: string,
  ): Promise<void> {
    if (!await this.#waitForPopupClose(popupDocumentId, envelope.expiresAt)) return;
    if (await this.#deps.getState() !== 'unlocked' || !await this.#publicEnvelopeCurrent(envelope)) {
      return;
    }
    await this.#deps.focusSource(envelope.source.windowId, envelope.source.tabId);
    const source = await this.#sourceCurrent(envelope.source);
    if (!source) return;
    const topRuntimeIncarnation = await this.#currentRuntimeIncarnation(
      envelope.source.tabId,
      0,
      envelope.source.topDocumentId,
    );
    if (!topRuntimeIncarnation) return;
    if (!await this.#awaitSourceFocus(
      envelope.source.tabId,
      0,
      envelope.source.topDocumentId,
      topRuntimeIncarnation,
      source.topUrl,
      envelope.expiresAt,
    )) return;
    if (!await this.#sourceCurrent(envelope.source)
        || !await this.#runtimeBindingCurrent(
          envelope.source.tabId,
          0,
          envelope.source.topDocumentId,
          topRuntimeIncarnation,
        )) return;
    const authorities = this.#captureFreshAuthorities(envelope);
    const commandToken = this.#deps.keyboardGrants.issueCommand({
      tabId: envelope.source.tabId,
      topDocumentId: envelope.source.topDocumentId,
      topFrameUrl: source.topUrl,
      sessionLease: authorities.sessionLease,
    });
    this.#assertFreshAuthorities(authorities);
    await this.#deps.sendFocusedFill(envelope.source.tabId, commandToken);
  }

  async #dispatchLockedCommandAfterPopupCloses(
    envelope: AutofillContinuationEnvelope & {
      readonly action: Extract<AutofillContinuationAction, { kind: 'locked_command' }>;
    },
    popupDocumentId: string,
  ): Promise<void> {
    if (!await this.#waitForPopupClose(popupDocumentId, envelope.expiresAt)) return;
    if (await this.#deps.getState() !== 'unlocked' || !await this.#publicEnvelopeCurrent(envelope)) return;
    await this.#deps.focusSource(envelope.source.windowId, envelope.source.tabId);
    const source = await this.#sourceCurrent(envelope.source);
    if (!source) return;
    const topRuntimeIncarnation = envelope.source.topRuntimeIncarnation;
    if (!topRuntimeIncarnation) return;
    if (!await this.#awaitSourceFocus(
      envelope.source.tabId,
      0,
      envelope.source.topDocumentId,
      topRuntimeIncarnation,
      source.topUrl,
      envelope.expiresAt,
    )) return;
    if (!await this.#sourceCurrent(envelope.source)) return;
    const authorities = this.#captureFreshAuthorities(envelope);
    this.#assertFreshAuthorities(authorities);
    await this.#deps.runCommand(envelope.action.command, {
      id: envelope.source.tabId,
      windowId: envelope.source.windowId,
    }, () => this.#assertFreshAuthorities(authorities), {
      documentId: envelope.source.topDocumentId,
      runtimeIncarnation: topRuntimeIncarnation,
      url: source.topUrl,
    });
  }

  async #dispatchRepromptAfterPopupCloses(
    envelope: AutofillContinuationEnvelope & {
      readonly action: Exclude<
        AutofillContinuationAction,
        { kind: 'locked_context' | 'locked_keyboard' | 'locked_command' }
      >;
    },
    popupDocumentId: string,
  ): Promise<void> {
    const abandon = () => {
      if (envelope.action.kind === 'keyboard_reprompt') {
        this.#deletePendingKeyboardBinding(envelope.continuationId);
      }
    };
    if (!await this.#waitForPopupClose(popupDocumentId, envelope.expiresAt)) { abandon(); return; }
    if (await this.#deps.getState() !== 'unlocked' || !await this.#publicEnvelopeCurrent(envelope)) {
      abandon(); return;
    }
    await this.#deps.focusSource(envelope.source.windowId, envelope.source.tabId);
    const source = await this.#sourceCurrent(envelope.source);
    if (!source) { abandon(); return; }
    const frameRuntimeIncarnation = envelope.source.frameRuntimeIncarnation;
    if (!frameRuntimeIncarnation) { abandon(); return; }
    if (!await this.#awaitSourceFocus(
      envelope.source.tabId,
      envelope.source.frameId,
      envelope.source.frameDocumentId,
      frameRuntimeIncarnation,
      source.frameUrl,
      envelope.expiresAt,
    )) {
      abandon();
      return;
    }
    if (!await this.#sourceCurrent(envelope.source)) {
      abandon();
      return;
    }
    const authorities = this.#captureFreshAuthorities(envelope);

    if (envelope.action.kind === 'context_login_reprompt'
        || envelope.action.kind === 'command_fill_reprompt') {
      try {
        const outcome = await this.#deps.tabAutofill.fill(
          envelope.source.tabId,
          envelope.action.cipherId,
          envelope.action.target,
          () => this.#assertFreshAuthorities(authorities),
          { assertCurrent: () => this.#assertFreshAuthorities(authorities) },
        );
        if (outcome.status === 'filled') await this.#deps.recordActivity?.();
      } finally {
        await this.#deps.vaultReleaseGate?.settlePendingAction?.();
      }
      return;
    }
    if (envelope.action.kind === 'context_copy_reprompt') {
      try {
        const releaseLease = this.#deps.vaultReleaseGate?.capture(authorities.sessionLease);
        let itemAuthority: (() => void) | undefined;
        const assertRepromptAuthorized = () => this.#assertFreshAuthorities(authorities);
        const value = await this.#deps.readLoginCopyValue(
          envelope.action.cipherId,
          envelope.action.field,
          assertRepromptAuthorized,
          (assertCurrent) => { itemAuthority = assertCurrent; },
        );
        if (value === undefined || !itemAuthority || !isBoundedClipboardValue(value)) return;
        const assertFinal = () => {
          this.#assertFreshAuthorities(authorities);
          itemAuthority!();
        };
        const releaseProof = releaseLease && this.#deps.vaultReleaseGate
          ? await this.#deps.vaultReleaseGate.checkpoint(releaseLease)
          : undefined;
        if (releaseProof && this.#deps.vaultReleaseGate) {
          this.#deps.vaultReleaseGate.assertAuthorities(releaseProof, assertFinal);
          this.#deps.vaultReleaseGate.assert(releaseProof);
        }
        assertFinal();
        const copied = envelope.action.field === 'totp'
          ? await this.#deps.clipboard.writeTotpAndScheduleClear(value, assertFinal)
          : await this.#deps.clipboard.writeSecretAndScheduleClear(value, assertFinal);
        if (copied) await this.#deps.recordActivity?.();
      } finally {
        await this.#deps.vaultReleaseGate?.settlePendingAction?.();
      }
      return;
    }
    if (envelope.action.kind === 'context_structured_reprompt') {
      try {
        const result = await this.#resumeStructured(
          envelope as AutofillContinuationEnvelope & {
            readonly action: Extract<AutofillContinuationAction, { kind: 'context_structured_reprompt' }>;
          },
          authorities,
        );
        if (result.status === 'filled' && result.outcome.status === 'filled') {
          await this.#deps.recordActivity?.();
        }
      } finally {
        await this.#deps.vaultReleaseGate?.settlePendingAction?.();
      }
      return;
    }

    const pendingBinding = this.#pendingKeyboardBindings.get(envelope.continuationId);
    this.#deletePendingKeyboardBinding(envelope.continuationId);
    if (!pendingBinding || pendingBinding.expiresAt <= (this.#deps.now?.() ?? Date.now())) return;
    if (pendingBinding.runtimeIncarnation !== frameRuntimeIncarnation
        || envelope.action.binding.runtimeIncarnation !== frameRuntimeIncarnation
        || !liveKeyboardBindingMatchesRuntime(pendingBinding.binding, frameRuntimeIncarnation)
        || !sameKeyboardContinuationBinding(pendingBinding.binding, frameRuntimeIncarnation, envelope.action.binding)) return;
    this.#pruneKeyboardProofs();
    this.#keyboardProofs.set(envelope.continuationId, Object.freeze({
      envelope,
      runtimeIncarnation: frameRuntimeIncarnation,
      binding: pendingBinding.binding,
      ...authorities,
    }));
    try {
      if (!await this.#sourceCurrent(envelope.source)) throw staleContinuation();
      await this.#deps.sendToDocument(
        envelope.source.tabId,
        envelope.source.frameId,
        envelope.source.frameDocumentId,
        {
          type: 'autofill.resumeKeyboardReprompt',
          continuationId: envelope.continuationId,
          expectedFrameUrl: source.frameUrl,
          expectedRuntimeIncarnation: frameRuntimeIncarnation,
        },
      );
      if (!await this.#sourceCurrent(envelope.source)) this.#keyboardProofs.delete(envelope.continuationId);
    } catch {
      this.#keyboardProofs.delete(envelope.continuationId);
    }
  }

  async #waitForPopupClose(documentId: string, expiresAt: number): Promise<boolean> {
    while ((this.#deps.now?.() ?? Date.now()) < expiresAt) {
      let open: boolean;
      try { open = await this.#deps.isPopupDocumentOpen(documentId); }
      catch { return false; }
      if (!open) return true;
      await new Promise<void>((resolve) => setTimeout(resolve, 25));
    }
    return false;
  }

  async #awaitSourceFocus(
    tabId: number,
    frameId: number,
    documentId: string,
    runtimeIncarnation: string,
    frameUrl: string,
    expiresAt: number,
  ): Promise<boolean> {
    try {
      const result = await this.#deps.sendToDocument(tabId, frameId, documentId, {
        type: 'autofill.awaitFocus',
        requestId: crypto.randomUUID(),
        expectedFrameUrl: frameUrl,
        expectedRuntimeIncarnation: runtimeIncarnation,
        expiresAt,
      });
      const focused = isRecord(result)
        && Object.keys(result).length === 1
        && result.status === 'focused';
      return focused && await this.#runtimeBindingCurrent(tabId, frameId, documentId, runtimeIncarnation);
    } catch { return false; }
  }

  #stage(
    browserSource: AutofillContinuationStageSource,
    action: AutofillContinuationAction,
    beforeOpen?: (envelope: AutofillContinuationEnvelope) => void,
  ): Promise<string> {
    const operation = this.#stageTail.then(
      () => this.#stageOperation(browserSource, action, beforeOpen),
      () => this.#stageOperation(browserSource, action, beforeOpen),
    );
    this.#stageTail = operation.then(() => undefined, () => undefined);
    return operation;
  }

  async #stageOperation(
    browserSource: AutofillContinuationStageSource,
    action: AutofillContinuationAction,
    beforeOpen?: (envelope: AutofillContinuationEnvelope) => void,
  ): Promise<string> {
    const expectedState = action.kind === 'locked_context'
      || action.kind === 'locked_keyboard'
      || action.kind === 'locked_command'
      ? 'locked'
      : 'unlocked';
    if (await this.#deps.getState() !== expectedState) throw staleContinuation();
    if (!await this.#browserSourceMatches(browserSource)) throw staleContinuation();
    const accountLease = this.#deps.accountGate.capture();
    const policyLease = this.#deps.capturePolicy();
    const [source, stablePolicyDigest] = await Promise.all([
      durableSource(browserSource),
      this.#deps.getStablePolicyDigest(),
    ]);
    if (await this.#deps.getState() !== expectedState
        || !await this.#browserSourceMatches(browserSource)) throw staleContinuation();
    this.#deps.accountGate.assert(accountLease);
    this.#deps.assertPolicy(policyLease);
    const previous = await this.#deps.store.read().catch(() => undefined);
    if (previous) {
      this.#deletePendingKeyboardBinding(previous.continuationId);
      this.#keyboardProofs.delete(previous.continuationId);
      await this.#cancelHeldTarget(previous);
    }
    const envelope = this.#deps.store.create({
      source,
      authority: autofillContinuationAuthority(
        accountLease,
        policyLease,
        this.#deps.workerInstanceId,
        stablePolicyDigest,
      ),
      action,
    });
    if (await this.#deps.getState() !== expectedState
        || !await this.#browserSourceMatches(browserSource)) throw staleContinuation();
    this.#deps.accountGate.assert(accountLease);
    this.#deps.assertPolicy(policyLease);
    await this.#deps.store.put(envelope);
    const persisted = await this.#deps.store.read().catch(() => undefined);
    if (persisted?.continuationId !== envelope.continuationId
        || await this.#deps.getState() !== expectedState
        || !await this.#browserSourceMatches(browserSource)) {
      await this.#deps.store.clearExact(envelope.continuationId).catch(() => false);
      await this.#cancelHeldTarget(envelope);
      throw staleContinuation();
    }
    beforeOpen?.(envelope);
    try {
      await this.#deps.openPopup();
    } catch {
      try { await this.#deps.openPopupFallback(); }
      catch {
        this.#deletePendingKeyboardBinding(envelope.continuationId);
        await this.#deps.store.clearExact(envelope.continuationId).catch(() => false);
        await this.#cancelHeldTarget(envelope);
        throw new AppError('denied', 'The autofill confirmation could not be opened.');
      }
    }
    return envelope.continuationId;
  }

  async #publicEnvelopeCurrent(envelope: AutofillContinuationEnvelope): Promise<boolean> {
    try {
      const accountLease = this.#deps.accountGate.capture();
      const policyLease = this.#deps.capturePolicy();
      const stablePolicyDigest = await this.#deps.getStablePolicyDigest();
      if (!sameAuthority(
        envelope,
        accountLease,
        policyLease,
        this.#deps.workerInstanceId,
        stablePolicyDigest,
      )) return false;
      if (!await this.#sourceCurrent(envelope.source)) return false;
      this.#deps.accountGate.assert(accountLease);
      this.#deps.assertPolicy(policyLease);
      return true;
    } catch { return false; }
  }

  async #browserSourceMatches(source: AutofillContinuationStageSource): Promise<boolean> {
    const [tab, top, frame, runtimesCurrent] = await Promise.all([
      this.#deps.getTab(source.tabId),
      this.#deps.getFrame(source.tabId, 0),
      source.frameId === 0 ? this.#deps.getFrame(source.tabId, 0) : this.#deps.getFrame(source.tabId, source.frameId),
      this.#runtimeBindingsCurrent(source),
    ]);
    return tab?.id === source.tabId
      && tab.windowId === source.windowId
      && tab.url === source.topUrl
      && top?.frameId === 0
      && top.documentId === source.topDocumentId
      && top.url === source.topUrl
      && frame?.frameId === source.frameId
      && frame.documentId === source.frameDocumentId
      && frame.url === source.frameUrl
      && runtimesCurrent;
  }

  async #sourceCurrent(source: AutofillContinuationSource): Promise<CurrentSourceUrls | undefined> {
    const [tab, top, frame, runtimesCurrent] = await Promise.all([
      this.#deps.getTab(source.tabId),
      this.#deps.getFrame(source.tabId, 0),
      source.frameId === 0 ? this.#deps.getFrame(source.tabId, 0) : this.#deps.getFrame(source.tabId, source.frameId),
      this.#runtimeBindingsCurrent(source),
    ]);
    if (tab?.id !== source.tabId || tab.windowId !== source.windowId || !tab.url
        || top?.frameId !== 0 || top.documentId !== source.topDocumentId
        || frame?.frameId !== source.frameId || frame.documentId !== source.frameDocumentId
        || !sameOrigin(tab.url, source.topOrigin) || !sameOrigin(top.url, source.topOrigin)
        || !sameOrigin(frame.url, source.frameOrigin)
        || !await urlMatchesDigest(tab.url, source.topUrlDigest)
        || !await urlMatchesDigest(top.url, source.topUrlDigest)
        || !await urlMatchesDigest(frame.url, source.frameUrlDigest)
        || !runtimesCurrent) return undefined;
    return Object.freeze({ topUrl: top.url, frameUrl: frame.url });
  }

  async #runtimeBindingsCurrent(source: Pick<
    AutofillContinuationStageSource,
    | 'tabId'
    | 'topDocumentId'
    | 'topRuntimeIncarnation'
    | 'frameId'
    | 'frameDocumentId'
    | 'frameRuntimeIncarnation'
  >): Promise<boolean> {
    if (source.topRuntimeIncarnation === null || source.frameRuntimeIncarnation === null) {
      return source.topRuntimeIncarnation === null && source.frameRuntimeIncarnation === null;
    }
    const topCurrent = this.#runtimeBindingCurrent(
      source.tabId,
      0,
      source.topDocumentId,
      source.topRuntimeIncarnation,
    );
    const sameBinding = source.frameId === 0
      && source.frameDocumentId === source.topDocumentId
      && source.frameRuntimeIncarnation === source.topRuntimeIncarnation;
    const frameCurrent = sameBinding
      ? topCurrent
      : this.#runtimeBindingCurrent(
          source.tabId,
          source.frameId,
          source.frameDocumentId,
          source.frameRuntimeIncarnation,
        );
    const [topMatches, frameMatches] = await Promise.all([topCurrent, frameCurrent]);
    return topMatches && frameMatches;
  }

  async #runtimeBindingCurrent(
    tabId: number,
    frameId: number,
    documentId: string,
    runtimeIncarnation: string,
  ): Promise<boolean> {
    try {
      return await this.#deps.isRuntimeCurrent(
        tabId,
        frameId,
        documentId,
        canonicalRuntimeIncarnation(runtimeIncarnation),
      ) === true;
    } catch { return false; }
  }

  async #currentRuntimeIncarnation(
    tabId: number,
    frameId: number,
    documentId: string,
  ): Promise<string | undefined> {
    try {
      const runtimeIncarnation = canonicalRuntimeIncarnation(
        await this.#deps.getRuntimeIncarnation(tabId, frameId, documentId),
      );
      return await this.#runtimeBindingCurrent(tabId, frameId, documentId, runtimeIncarnation)
        ? runtimeIncarnation
        : undefined;
    } catch { return undefined; }
  }

  #captureFreshAuthorities(envelope: AutofillContinuationEnvelope) {
    const sessionLease = this.#deps.sessionGate.capture();
    const accountLease = this.#deps.accountGate.capture();
    const policyLease = this.#deps.capturePolicy();
    if (!sameRuntimeAuthority(envelope, accountLease, policyLease, this.#deps.workerInstanceId)) {
      throw staleContinuation();
    }
    const result = Object.freeze({ sessionLease, accountLease, policyLease });
    this.#assertFreshAuthorities(result);
    return result;
  }

  #assertFreshAuthorities(authorities: {
    readonly sessionLease: SessionLease;
    readonly accountLease: AccountLease;
    readonly policyLease: Policy;
  }): void {
    this.#deps.accountGate.assert(authorities.accountLease);
    this.#deps.assertPolicy(authorities.policyLease);
    this.#deps.sessionGate.assert(authorities.sessionLease);
  }

  async #resumeStructured(
    envelope: AutofillContinuationEnvelope & {
      readonly action: Extract<AutofillContinuationAction, { kind: 'context_structured_reprompt' }>;
    },
    authorities: { readonly sessionLease: SessionLease; readonly accountLease: AccountLease; readonly policyLease: Policy },
  ): Promise<AutofillContinuationResumeData> {
    let assertItemCurrent: (() => void) | undefined;
    const releaseLease = this.#deps.vaultReleaseGate?.capture(authorities.sessionLease);
    const data = await this.#deps.getFillData(
      envelope.action.cipherId,
      envelope.action.fillKind,
      envelope.action.roles,
      () => this.#assertFreshAuthorities(authorities),
      (assertCurrent) => { assertItemCurrent = assertCurrent; },
    );
    const source = await this.#sourceCurrent(envelope.source);
    if (!source || !assertItemCurrent) return { status: 'stale' };
    const frameRuntimeIncarnation = envelope.source.frameRuntimeIncarnation;
    if (!frameRuntimeIncarnation) return { status: 'stale' };
    this.#assertFreshAuthorities(authorities);
    const releaseProof = releaseLease && this.#deps.vaultReleaseGate
      ? await this.#deps.vaultReleaseGate.checkpoint(releaseLease)
      : undefined;
    if (releaseProof && this.#deps.vaultReleaseGate) {
      this.#deps.vaultReleaseGate.assertAuthorities(releaseProof, () => {
        this.#assertFreshAuthorities(authorities);
        assertItemCurrent!();
      });
      this.#deps.vaultReleaseGate.assert(releaseProof);
    }
    if (!await this.#sourceCurrent(envelope.source)) return { status: 'stale' };
    const raw = await this.#deps.sendToDocument(
      envelope.source.tabId,
      envelope.source.frameId,
      envelope.source.frameDocumentId,
      {
        type: 'autofill.resumeHeldFillTarget',
        holdId: envelope.action.holdId,
        scope: envelope.action.scope,
        kind: envelope.action.fillKind,
        roles: envelope.action.roles,
        expectedFrameUrl: source.frameUrl,
        expectedRuntimeIncarnation: frameRuntimeIncarnation,
        data,
      },
    );
    if (!await this.#sourceCurrent(envelope.source)) return { status: 'stale' };
    const status = isRecord(raw) ? raw.status : undefined;
    if (status !== 'filled') return { status: 'stale' };
    return { status: 'filled', outcome: { status: 'filled' } };
  }

  async #cancelHeldTarget(envelope: AutofillContinuationEnvelope): Promise<void> {
    if (envelope.action.kind !== 'context_structured_reprompt') return;
    const source = await this.#sourceCurrent(envelope.source).catch(() => undefined);
    if (!source) return;
    const frameRuntimeIncarnation = envelope.source.frameRuntimeIncarnation;
    if (!frameRuntimeIncarnation) return;
    await this.#deps.sendToDocument(
      envelope.source.tabId,
      envelope.source.frameId,
      envelope.source.frameDocumentId,
      {
        type: 'autofill.cancelHeldFillTarget',
        holdId: envelope.action.holdId,
        expectedFrameUrl: source.frameUrl,
        expectedRuntimeIncarnation: frameRuntimeIncarnation,
      },
    ).catch(() => undefined);
  }

  #pruneKeyboardProofs(): void {
    const now = this.#deps.now?.() ?? Date.now();
    for (const [id, proof] of this.#keyboardProofs) {
      if (proof.envelope.expiresAt <= now) this.#keyboardProofs.delete(id);
    }
    for (const [id, pending] of this.#pendingKeyboardBindings) {
      if (pending.expiresAt <= now) this.#deletePendingKeyboardBinding(id);
    }
    while (this.#pendingKeyboardBindings.size >= 32) {
      const oldest = this.#pendingKeyboardBindings.keys().next().value as string | undefined;
      if (!oldest) break;
      this.#deletePendingKeyboardBinding(oldest);
    }
    while (this.#keyboardProofs.size >= 32) {
      const oldest = this.#keyboardProofs.keys().next().value as string | undefined;
      if (!oldest) break;
      this.#keyboardProofs.delete(oldest);
    }
  }

  #deletePendingKeyboardBinding(id: string): void {
    const pending = this.#pendingKeyboardBindings.get(id);
    if (pending) clearTimeout(pending.timer);
    this.#pendingKeyboardBindings.delete(id);
  }
}

function sameAuthority(
  envelope: AutofillContinuationEnvelope,
  account: AccountLease,
  policy: Policy,
  workerInstanceId: string,
  stablePolicyDigest: string,
): boolean {
  if (envelope.authority.autofillPolicyDigest !== stablePolicyDigest) return false;
  return sameRuntimeAuthority(envelope, account, policy, workerInstanceId);
}

function sameRuntimeAuthority(
  envelope: AutofillContinuationEnvelope,
  account: AccountLease,
  policy: Policy,
  workerInstanceId: string,
): boolean {
  const expected = envelope.authority;
  const crossesExpectedUnlock = envelope.action.kind === 'locked_context'
    || envelope.action.kind === 'locked_keyboard'
    || envelope.action.kind === 'locked_command';
  return expected.workerInstanceId === workerInstanceId
    && account.serverUrl === expected.serverUrl
    && account.accountIdentity === expected.accountIdentity
    && account.serverGeneration === expected.serverGeneration
    && account.accountGeneration === expected.accountGeneration
    && (crossesExpectedUnlock || policy.autofill.generation === expected.autofillPolicyGeneration)
    && (crossesExpectedUnlock || policy.enterprise.generation === expected.enterprisePolicyGeneration)
    && policy.enterprise.rawGeneration === expected.rawPolicyGeneration;
}

async function durableSource(source: AutofillContinuationStageSource): Promise<AutofillContinuationSource> {
  return Object.freeze({
    tabId: source.tabId,
    windowId: source.windowId,
    topDocumentId: source.topDocumentId,
    topRuntimeIncarnation: source.topRuntimeIncarnation === null
      ? null
      : canonicalRuntimeIncarnation(source.topRuntimeIncarnation),
    topOrigin: new URL(source.topUrl).origin,
    topUrlDigest: await digestUrl(source.topUrl),
    frameId: source.frameId,
    frameDocumentId: source.frameDocumentId,
    frameRuntimeIncarnation: source.frameRuntimeIncarnation === null
      ? null
      : canonicalRuntimeIncarnation(source.frameRuntimeIncarnation),
    frameOrigin: new URL(source.frameUrl).origin,
    frameUrlDigest: await digestUrl(source.frameUrl),
  });
}

async function urlMatchesDigest(url: string, expected: string): Promise<boolean> {
  try { return await digestUrl(url) === expected; }
  catch { return false; }
}

async function digestUrl(value: string): Promise<string> {
  const url = new URL(value);
  if ((url.protocol !== 'https:' && url.protocol !== 'http:') || url.username || url.password) throw staleContinuation();
  const input = new TextEncoder().encode(`miyu.autofill-continuation.url.v1\0${url.href}`);
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', input));
  return Array.from(digest, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

export async function digestAutofillContinuationPolicy(value: unknown): Promise<string> {
  const canonical = canonicalJson(value);
  const input = new TextEncoder().encode(`miyu.autofill-continuation.policy.v1\0${canonical}`);
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', input));
  return Array.from(digest, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

function canonicalJson(value: unknown): string {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') return JSON.stringify(value);
  if (typeof value === 'number' && Number.isFinite(value)) return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (isRecord(value)) {
    return `{${Object.keys(value).sort().map((key) => (
      `${JSON.stringify(key)}:${canonicalJson(value[key])}`
    )).join(',')}}`;
  }
  throw new TypeError('Autofill continuation policy is not serializable');
}

function sameOrigin(url: string, expected: string): boolean {
  try { return new URL(url).origin === expected; }
  catch { return false; }
}

const CANONICAL_UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

function isCanonicalUuidV4(value: unknown): value is string {
  return typeof value === 'string' && CANONICAL_UUID_V4.test(value);
}

function canonicalRuntimeIncarnation(value: unknown): string {
  if (!isCanonicalUuidV4(value)) throw staleContinuation();
  return value;
}

function liveKeyboardBindingMatchesRuntime(
  binding: KeyboardGrantValue['binding'],
  runtimeIncarnation: string,
): boolean {
  return (binding.purpose !== 'card' && binding.purpose !== 'identity')
    || binding.structuredTarget.runtimeIncarnation === runtimeIncarnation;
}

function keyboardContinuationBinding(
  binding: KeyboardGrantValue['binding'],
  runtimeIncarnation: string,
): Extract<AutofillContinuationAction, { kind: 'keyboard_reprompt' }>['binding'] {
  if (binding.purpose === 'login') {
    return { purpose: binding.purpose, runtimeIncarnation, customPlanDigest: binding.customPlanDigest };
  }
  if (binding.purpose === 'totp') return { purpose: binding.purpose, runtimeIncarnation };
  const target = binding.structuredTarget;
  return {
    purpose: binding.purpose,
    runtimeIncarnation,
    formId: target.formId,
    generation: target.generation,
    roles: [...target.roles],
    ...(target.selectedRoles === undefined ? {} : { selectedRoles: [...target.selectedRoles] }),
  };
}

/** The durable confirmation and the live one-time proof must authorize the same field selection. */
function sameKeyboardContinuationBinding(
  binding: KeyboardGrantValue['binding'],
  runtimeIncarnation: string,
  expected: Extract<AutofillContinuationAction, { kind: 'keyboard_reprompt' }>['binding'],
): boolean {
  return canonicalJson(keyboardContinuationBinding(binding, runtimeIncarnation)) === canonicalJson(expected);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function staleContinuation(): AppError {
  return new AppError('denied', 'The autofill continuation is invalid or stale.');
}

function isBoundedClipboardValue(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= 65_536;
}
