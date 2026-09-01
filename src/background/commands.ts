import type {
  FocusedFillCommand,
  TabAutofillSuggestion,
  TabFillOutcome,
  TabSuggestionTarget,
  TabSuggestionsOutcome,
} from '../messaging/protocol.js';
import type { AutofillKeyboardGrantRegistry } from './autofill-keyboard-grant-registry.js';

export const FOCUSED_FILL_COMMAND = 'autofill-focused';

export const EXTENSION_COMMANDS = Object.freeze({
  AutofillFocused: FOCUSED_FILL_COMMAND,
  AutofillLogin: 'autofill-login',
  AutofillCard: 'autofill-card',
  AutofillIdentity: 'autofill-identity',
  GeneratePassword: 'generate-password',
  LockVault: 'lock-vault',
  OpenPopup: 'open-popup',
} as const);

export type ExtensionCommand = (typeof EXTENSION_COMMANDS)[keyof typeof EXTENSION_COMMANDS];
export type DirectFillCommand =
  | typeof EXTENSION_COMMANDS.AutofillLogin
  | typeof EXTENSION_COMMANDS.AutofillCard
  | typeof EXTENSION_COMMANDS.AutofillIdentity;
export type SecretExtensionCommand = DirectFillCommand | typeof EXTENSION_COMMANDS.GeneratePassword;

type DirectFillKind = 'login' | 'card' | 'identity';
const RUNTIME_INCARNATION_UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;

export interface CommandTab {
  readonly id?: number;
  readonly windowId?: number;
}

export interface CommandDocument {
  readonly documentId: string;
  readonly url: string;
  readonly runtimeIncarnation?: string;
}

export interface CommandBrowserSource extends CommandDocument {
  readonly tabId: number;
  readonly windowId: number;
  readonly runtimeIncarnation: string;
}

export type CommandExpectedSource = Pick<
  CommandBrowserSource,
  'documentId' | 'runtimeIncarnation' | 'url'
>;

export interface CommandDeps<SessionLease = unknown> {
  tabs: { sendMessage(tabId: number, message: FocusedFillCommand): Promise<unknown> };
  getTopDocument(tabId: number): Promise<CommandDocument | undefined>;
  getState(): Promise<'loggedOut' | 'locked' | 'restricted' | 'unlocked'>;
  captureSessionLease(): SessionLease;
  assertSessionLease(lease: SessionLease): void;
  beginLocked?(input: {
    readonly tabId: number;
    readonly windowId: number;
    readonly topDocumentId: string;
    readonly topFrameUrl: string;
  }): Promise<void>;
  keyboardGrants: Pick<AutofillKeyboardGrantRegistry<SessionLease, unknown, unknown>, 'issueCommand'>;
}

export interface CommandCoordinatorDeps<
  SessionLease = unknown,
  AccountLease = unknown,
  PolicyLease = unknown,
> extends CommandDeps<SessionLease> {
  captureAccountLease(): AccountLease;
  assertAccountLease(lease: AccountLease): void;
  capturePolicyLease(): PolicyLease;
  assertPolicyLease(lease: PolicyLease): void;
  authorizeFrame(frameUrl: string): Promise<{ assertCurrent(): void }>;
  getTabSuggestions(tabId: number): Promise<TabSuggestionsOutcome>;
  fillTabSuggestion(
    tabId: number,
    cipherId: string,
    target: TabSuggestionTarget,
    assertCurrent: () => void,
  ): Promise<TabFillOutcome>;
  /** Generates through the shared policy engine and commits generator history before returning. */
  generatePasswordAndTrack(
    bindFinalAuthority: (assertCurrent: () => void) => void,
  ): Promise<{ readonly value: string } | undefined>;
  clipboard: {
    /** Worker-only non-TOTP writer. The adapter must bound input and claim owned-clear scheduling. */
    writeSecretAndScheduleClear(value: string, assertCurrent: () => void): Promise<boolean>;
  };
  lockVault(): Promise<void>;
  openPopup(): Promise<void>;
  continuation?: {
    stageLockedCommand(command: SecretExtensionCommand, source: CommandBrowserSource): Promise<void>;
    stageRepromptCommand(input: {
      readonly command: DirectFillCommand;
      readonly source: CommandBrowserSource;
      readonly cipherId: string;
      readonly target: TabSuggestionTarget;
    }): Promise<void>;
  };
  vaultReleaseGate?: {
    capture(sessionLease: SessionLease): object;
    checkpoint(lease: object): Promise<object>;
    assertAuthorities(proof: object, assertCurrent: () => void): void;
    assert(proof: object): void;
    settlePendingAction?(): Promise<void>;
  };
  recordActivity?(): Promise<void>;
}

interface CommandAuthority<SessionLease, AccountLease, PolicyLease> {
  readonly sessionLease: SessionLease;
  readonly accountLease: AccountLease;
  readonly policyLease: PolicyLease;
}

interface CommandCycle {
  readonly documentId: string;
  readonly url: string;
  readonly runtimeIncarnation: string;
  readonly kind: DirectFillKind;
  readonly signature: string;
  readonly cipherId: string;
}

/**
 * Coordinates browser keyboard commands without owning vault, policy, clipboard, or continuation
 * state. Secret-bearing adapters receive a synchronous final-authority assertion and remain the only
 * layers allowed to decrypt or write secrets.
 */
export class CommandCoordinator<
  SessionLease = unknown,
  AccountLease = unknown,
  PolicyLease = unknown,
> {
  static readonly MAX_CYCLE_ENTRIES = 256;
  readonly #cycles = new Map<number, CommandCycle>();

  constructor(private readonly deps: CommandCoordinatorDeps<SessionLease, AccountLease, PolicyLease>) {}

  revokeTab(tabId: number): void {
    if (Number.isInteger(tabId) && tabId >= 0) this.#cycles.delete(tabId);
  }

  revokeAll(): void {
    this.#cycles.clear();
  }

  async handle(
    command: string,
    tab: CommandTab | undefined,
    assertExternalCurrent?: () => void,
    expectedSource?: CommandExpectedSource,
  ): Promise<void> {
    if (command === EXTENSION_COMMANDS.AutofillFocused) {
      await handleFocusedFillCommand(command, tab, this.deps);
      return;
    }
    if (command === EXTENSION_COMMANDS.OpenPopup) {
      await this.deps.openPopup();
      return;
    }
    if (command === EXTENSION_COMMANDS.LockVault) {
      this.revokeAll();
      if (await this.deps.getState() === 'unlocked') await this.deps.lockVault();
      return;
    }
    if (!isSecretCommand(command)) return;

    assertExternalCurrent?.();
    const state = await this.deps.getState();
    assertExternalCurrent?.();
    if (state !== 'locked' && state !== 'unlocked') return;
    if (command === EXTENSION_COMMANDS.GeneratePassword && state === 'unlocked') {
      if (expectedSource) {
        if (typeof tab?.id !== 'number') return;
        const current = await this.deps.getTopDocument(tab.id);
        assertExternalCurrent?.();
        if (!current || !matchesExpectedSource(current, expectedSource)) return;
      }
      try {
        await this.#generate(assertExternalCurrent);
      } finally {
        await this.deps.vaultReleaseGate?.settlePendingAction?.();
      }
      return;
    }
    if (typeof tab?.id !== 'number') return;
    const topDocument = await this.deps.getTopDocument(tab.id);
    assertExternalCurrent?.();
    if (!topDocument) return;
    if (expectedSource && !matchesExpectedSource(topDocument, expectedSource)) return;
    const source = commandSource(tab, topDocument);
    if (!source) return;
    if (state === 'locked') {
      await this.deps.continuation?.stageLockedCommand(command, source);
      return;
    }

    try {
      if (command === EXTENSION_COMMANDS.GeneratePassword) return;
      await this.#fill(command, source, assertExternalCurrent);
    } finally {
      await this.deps.vaultReleaseGate?.settlePendingAction?.();
    }
  }

  async #generate(assertExternalCurrent?: () => void): Promise<void> {
    const authority = this.#captureAuthority();
    const assertCurrent = () => this.#assertAuthority(authority);
    const assertAllCurrent = () => {
      assertCurrent();
      assertExternalCurrent?.();
    };
    const releaseLease = this.deps.vaultReleaseGate?.capture(authority.sessionLease);
    let generatorAuthority: (() => void) | undefined;
    assertAllCurrent();
    const generated = await this.deps.generatePasswordAndTrack((assertGeneratorCurrent) => {
      generatorAuthority = assertGeneratorCurrent;
    });
    assertAllCurrent();
    generatorAuthority?.();
    if (!generated || !isBoundedSecret(generated.value)) return;
    const releaseProof = releaseLease && this.deps.vaultReleaseGate
      ? await this.deps.vaultReleaseGate.checkpoint(releaseLease)
      : undefined;
    const assertFinal = () => {
      assertAllCurrent();
      generatorAuthority?.();
    };
    if (releaseProof && this.deps.vaultReleaseGate) {
      this.deps.vaultReleaseGate.assertAuthorities(releaseProof, assertFinal);
      this.deps.vaultReleaseGate.assert(releaseProof);
    }
    assertFinal();
    const copied = await this.deps.clipboard.writeSecretAndScheduleClear(generated.value, assertFinal);
    if (copied) await this.deps.recordActivity?.();
  }

  async #fill(
    command: DirectFillCommand,
    source: CommandBrowserSource,
    assertExternalCurrent?: () => void,
  ): Promise<void> {
    const kind = directFillKind(command);
    const authority = this.#captureAuthority();
    const authorization = await this.deps.authorizeFrame(source.url);
    if (!await this.#sourceCurrent(source)) return;
    const assertCurrent = () => {
      this.#assertAuthority(authority);
      authorization.assertCurrent();
      assertExternalCurrent?.();
    };
    assertCurrent();
    const outcome = await this.deps.getTabSuggestions(source.tabId);
    if (!await this.#sourceCurrent(source)) return;
    assertCurrent();
    if (outcome.status !== 'ready') return;
    const candidates = outcome.suggestions.filter((candidate) => (
      candidate.kind === kind
      && candidate.target !== undefined
      && targetMatchesSource(candidate.target, source)
    ));
    if (candidates.length === 0) return;
    const selected = this.#select(source, kind, candidates);
    if (!selected.target) return;
    const releaseLease = this.deps.vaultReleaseGate?.capture(authority.sessionLease);
    const releaseProof = releaseLease && this.deps.vaultReleaseGate
      ? await this.deps.vaultReleaseGate.checkpoint(releaseLease)
      : undefined;
    if (!await this.#sourceCurrent(source)) return;
    if (releaseProof && this.deps.vaultReleaseGate) {
      this.deps.vaultReleaseGate.assertAuthorities(releaseProof, assertCurrent);
      this.deps.vaultReleaseGate.assert(releaseProof);
    }
    assertCurrent();
    const fillOutcome = await this.deps.fillTabSuggestion(
      source.tabId,
      selected.id,
      selected.target,
      assertCurrent,
    );
    if (!await this.#sourceCurrent(source)) return;
    assertCurrent();
    if (fillOutcome.status === 'filled') await this.deps.recordActivity?.();
    if (fillOutcome.status === 'reprompt_required') {
      await this.deps.continuation?.stageRepromptCommand({
        command,
        source,
        cipherId: selected.id,
        target: selected.target,
      });
    }
  }

  #select(
    source: CommandBrowserSource,
    kind: DirectFillKind,
    candidates: TabAutofillSuggestion[],
  ): TabAutofillSuggestion {
    const signature = candidates.map((candidate) => `${candidate.id}:${targetKey(candidate.target!)}`).join('|');
    const previous = this.#cycles.get(source.tabId);
    const previousIndex = previous
      && previous.documentId === source.documentId
      && previous.url === source.url
      && previous.runtimeIncarnation === source.runtimeIncarnation
      && previous.kind === kind
      && previous.signature === signature
      ? candidates.findIndex((candidate) => candidate.id === previous.cipherId)
      : -1;
    const selected = candidates[(previousIndex + 1) % candidates.length]!;
    this.#cycles.delete(source.tabId);
    while (this.#cycles.size >= CommandCoordinator.MAX_CYCLE_ENTRIES) {
      const oldest = this.#cycles.keys().next().value as number | undefined;
      if (oldest === undefined) break;
      this.#cycles.delete(oldest);
    }
    this.#cycles.set(source.tabId, Object.freeze({
      documentId: source.documentId,
      url: source.url,
      runtimeIncarnation: source.runtimeIncarnation,
      kind,
      signature,
      cipherId: selected.id,
    }));
    return selected;
  }

  #captureAuthority(): CommandAuthority<SessionLease, AccountLease, PolicyLease> {
    const authority = Object.freeze({
      sessionLease: this.deps.captureSessionLease(),
      accountLease: this.deps.captureAccountLease(),
      policyLease: this.deps.capturePolicyLease(),
    });
    this.#assertAuthority(authority);
    return authority;
  }

  async #sourceCurrent(source: CommandBrowserSource): Promise<boolean> {
    const current = await this.deps.getTopDocument(source.tabId);
    return Boolean(current && matchesExpectedSource(current, source));
  }

  #assertAuthority(authority: CommandAuthority<SessionLease, AccountLease, PolicyLease>): void {
    this.deps.assertAccountLease(authority.accountLease);
    this.deps.assertPolicyLease(authority.policyLease);
    this.deps.assertSessionLease(authority.sessionLease);
  }
}

/**
 * Relay a browser keyboard command to the active tab's content scripts. The message carries no vault
 * data; the focused leaf frame decides what (if anything) to fill.
 */
export async function handleFocusedFillCommand<SessionLease>(
  command: string,
  tab: { id?: number; windowId?: number } | undefined,
  deps: CommandDeps<SessionLease>,
): Promise<void> {
  if (command !== FOCUSED_FILL_COMMAND) return;
  if (typeof tab?.id !== 'number') return;
  const state = await deps.getState();
  if (state !== 'locked' && state !== 'unlocked') return;
  const topDocument = await deps.getTopDocument(tab.id);
  if (!topDocument || !isTopCommandDocument(topDocument)) return;
  if (state === 'locked') {
    if (typeof tab.windowId !== 'number' || !deps.beginLocked) return;
    await deps.beginLocked({
      tabId: tab.id,
      windowId: tab.windowId,
      topDocumentId: topDocument.documentId,
      topFrameUrl: topDocument.url,
    });
    return;
  }
  const sessionLease = deps.captureSessionLease();
  deps.assertSessionLease(sessionLease);
  const commandToken = deps.keyboardGrants.issueCommand({
    tabId: tab.id,
    topDocumentId: topDocument.documentId,
    topFrameUrl: topDocument.url,
    sessionLease,
  });
  deps.assertSessionLease(sessionLease);
  await deps.tabs.sendMessage(tab.id, { type: 'autofill.focusedFill', commandToken });
}

function isSecretCommand(command: string): command is SecretExtensionCommand {
  return command === EXTENSION_COMMANDS.AutofillLogin
    || command === EXTENSION_COMMANDS.AutofillCard
    || command === EXTENSION_COMMANDS.AutofillIdentity
    || command === EXTENSION_COMMANDS.GeneratePassword;
}

function directFillKind(command: DirectFillCommand): DirectFillKind {
  if (command === EXTENSION_COMMANDS.AutofillCard) return 'card';
  if (command === EXTENSION_COMMANDS.AutofillIdentity) return 'identity';
  return 'login';
}

function commandSource(tab: CommandTab, document: CommandDocument): CommandBrowserSource | undefined {
  if (typeof tab.id !== 'number' || typeof tab.windowId !== 'number'
      || !isCommandDocument(document)) return undefined;
  return Object.freeze({
    tabId: tab.id,
    windowId: tab.windowId,
    documentId: document.documentId,
    url: document.url,
    runtimeIncarnation: document.runtimeIncarnation,
  });
}

function targetKey(target: TabSuggestionTarget): string {
  return [
    target.kind,
    target.frameId,
    target.documentId,
    target.runtimeIncarnation,
    target.formId,
    target.generation,
  ].join(':');
}

function targetMatchesSource(target: TabSuggestionTarget, source: CommandBrowserSource): boolean {
  if (!isRuntimeIncarnation(target.runtimeIncarnation)) return false;
  return target.frameId !== 0 || (
    target.documentId === source.documentId
    && target.runtimeIncarnation === source.runtimeIncarnation
  );
}

function isCommandDocument(
  document: CommandDocument,
): document is CommandDocument & { readonly runtimeIncarnation: string } {
  return isTopCommandDocument(document)
    && isRuntimeIncarnation(document.runtimeIncarnation);
}

function matchesExpectedSource(
  document: CommandDocument,
  expected: CommandExpectedSource,
): boolean {
  return document.documentId === expected.documentId
    && document.url === expected.url
    && document.runtimeIncarnation === expected.runtimeIncarnation;
}

function isTopCommandDocument(document: CommandDocument): boolean {
  return Boolean(document.documentId) && isHttpUrl(document.url);
}

function isRuntimeIncarnation(value: unknown): value is string {
  return typeof value === 'string'
    && RUNTIME_INCARNATION_UUID_V4.test(value);
}

function isHttpUrl(value: string): boolean {
  try {
    const url = new URL(value);
    return (url.protocol === 'https:' || url.protocol === 'http:')
      && !url.username && !url.password && url.href === value;
  } catch {
    return false;
  }
}

function isBoundedSecret(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= 65_536;
}
