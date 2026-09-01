import type { SessionState } from '../core/session/session-manager.js';
import {
  type AutofillSettings,
  sanitizeWebsitePasskeySettings,
  type WebsitePasskeySettings,
} from './settings.js';
import type {
  WebsitePasskeyPolicyGate,
  WebsitePasskeyPolicySource,
} from './website-passkey-policy.js';
import type {
  WebsitePasskeyScriptManager,
  WebsitePasskeyScriptState,
} from './website-passkey-script-manager.js';

const STABLE_SOURCE_READ_LIMIT = 3;

export interface WebsitePasskeyLifecycleSettings {
  getWebsitePasskeySettings(): Promise<Readonly<WebsitePasskeySettings>>;
  getAutofillSettings(): Promise<Pick<Readonly<AutofillSettings>, 'blockedDomains'>>;
  getServerUrl(): Promise<string | undefined>;
}

export interface WebsitePasskeyLifecycleDeps {
  readonly settings: WebsitePasskeyLifecycleSettings;
  readonly policy: Pick<WebsitePasskeyPolicyGate, 'publish' | 'invalidate' | 'capture'>;
  readonly scripts: Pick<WebsitePasskeyScriptManager, 'reconcile'>;
}

interface StablePolicySource {
  readonly key: string;
  readonly value: Readonly<WebsitePasskeyPolicySource>;
}

interface AuthoritativePolicySnapshot {
  readonly revision: number;
  readonly identity: string;
  readonly sessionState: SessionState;
  readonly source: StablePolicySource;
}

/** Coordinates revocable website-passkey policy with dynamic script registration. */
export class WebsitePasskeyLifecycle {
  readonly #deps: WebsitePasskeyLifecycleDeps;
  #latestRevision = 0;
  #authoritativeRevision = 0;
  #publicationEpoch = 0;
  #publishedEpoch = -1;
  #publishedRevision = 0;
  #policyAvailable = false;
  #publishedIdentity: string | undefined;
  #authoritativeSnapshot: AuthoritativePolicySnapshot | undefined;
  #requestedSessionState: SessionState | undefined;
  #scriptOperationTail: Promise<void> = Promise.resolve();

  constructor(deps: WebsitePasskeyLifecycleDeps) {
    this.#deps = deps;
  }

  /** Immediately revoke authorization and supersede every in-flight source read. */
  invalidate(): void {
    this.#latestRevision += 1;
    this.#revokePolicy();
  }

  /**
   * Resolve one stable settings/server snapshot. Reads may overlap, but only the newest revision can
   * publish or become the final script state.
   */
  reconcile(sessionState: SessionState): Promise<void> {
    assertSessionState(sessionState);
    if (
      this.#requestedSessionState !== undefined
      && availabilityClass(this.#requestedSessionState) !== availabilityClass(sessionState)
    ) {
      this.#latestRevision += 1;
      this.#revokePolicy();
    }
    this.#requestedSessionState = sessionState;
    const revision = ++this.#latestRevision;
    return this.#reconcileRevision(revision, sessionState);
  }

  invalidateAndReconcile(sessionState: SessionState): Promise<void> {
    this.invalidate();
    return this.reconcile(sessionState);
  }

  async #reconcileRevision(revision: number, sessionState: SessionState): Promise<void> {
    let source: StablePolicySource;
    try {
      source = await this.#readStableSource(revision);
    } catch (error) {
      await this.#handleSourceFailure(revision, sessionState, error);
      return;
    }

    const identity = policyIdentity(source.key, sessionState);
    if (revision < this.#authoritativeRevision) {
      await this.#repairLateAba(revision, identity);
      return;
    }
    if (revision !== this.#latestRevision) {
      await this.#handleStaleObservation(revision, sessionState, identity);
      return;
    }

    const shouldPublish = !this.#policyAvailable
      || this.#publishedEpoch !== this.#publicationEpoch
      || this.#publishedIdentity !== identity;

    if (shouldPublish) {
      try {
        this.#deps.policy.publish(source.value);
      } catch (error) {
        // WebsitePasskeyPolicyGate.publish revokes its old snapshot before validating the new one.
        this.#policyAvailable = false;
        this.#publicationEpoch += 1;
        this.#authoritativeRevision = revision;
        await this.#finishFailedRevision(revision, sessionState, error);
        return;
      }
      this.#policyAvailable = true;
      this.#publishedIdentity = identity;
      this.#publishedEpoch = this.#publicationEpoch;
      this.#publishedRevision = revision;
    }

    this.#authoritativeRevision = revision;
    this.#authoritativeSnapshot = Object.freeze({ revision, identity, sessionState, source });
    const scriptState = this.#scriptState(
      source.value.settings.enabled,
      sessionState,
    );
    try {
      await this.#reconcileScripts(scriptState);
    } catch (error) {
      if (revision === this.#latestRevision) throw error;
    }
  }

  async #handleStaleObservation(
    revision: number,
    sessionState: SessionState,
    identity: string,
  ): Promise<void> {
    if (
      revision <= this.#authoritativeRevision
      || !this.#policyAvailable
      || identity === this.#publishedIdentity
    ) {
      return;
    }

    // A superseded read still proves that an ABA transition happened. Revoke now, but never publish
    // the stale value; the latest revision will publish its own stable snapshot.
    let invalidationError: unknown;
    try {
      this.#revokePolicy();
    } catch (error) {
      invalidationError = error;
    }
    this.#authoritativeRevision = revision;
    const scriptError = await this.#tryReconcileDisabled(sessionState);
    if (revision === this.#latestRevision) {
      throwCombinedErrors(invalidationError, scriptError);
    }
  }

  async #repairLateAba(revision: number, identity: string): Promise<void> {
    const snapshot = this.#authoritativeSnapshot;
    if (
      !this.#policyAvailable
      || revision <= this.#publishedRevision
      || identity === this.#publishedIdentity
      || snapshot === undefined
      || snapshot.revision !== this.#authoritativeRevision
      || snapshot.identity !== this.#publishedIdentity
    ) {
      return;
    }

    // The latest read returned first and matched an older publication, then a middle revision proved
    // that the source had changed in between. Republish only the latest authoritative value.
    try {
      this.#deps.policy.publish(snapshot.source.value);
    } catch (error) {
      this.#policyAvailable = false;
      this.#publicationEpoch += 1;
      await this.#finishFailedRevision(snapshot.revision, snapshot.sessionState, error);
      return;
    }
    this.#publishedEpoch = this.#publicationEpoch;
    this.#publishedRevision = snapshot.revision;
    await this.#reconcileScripts(this.#scriptState(
      snapshot.source.value.settings.enabled,
      snapshot.sessionState,
    ));
  }

  async #handleSourceFailure(
    revision: number,
    sessionState: SessionState,
    sourceError: unknown,
  ): Promise<void> {
    if (revision < this.#authoritativeRevision) return;

    let invalidationError: unknown;
    try {
      this.#revokePolicy();
    } catch (error) {
      invalidationError = error;
    }
    this.#authoritativeRevision = revision;
    const scriptError = await this.#tryReconcileDisabled(sessionState);
    if (revision === this.#latestRevision) {
      throwCombinedErrors(sourceError, invalidationError, scriptError);
    }
  }

  async #finishFailedRevision(
    revision: number,
    sessionState: SessionState,
    sourceError: unknown,
  ): Promise<void> {
    const scriptError = await this.#tryReconcileDisabled(sessionState);
    if (revision === this.#latestRevision) {
      throwCombinedErrors(sourceError, scriptError);
    }
  }

  async #tryReconcileDisabled(sessionState: SessionState): Promise<unknown> {
    try {
      await this.#reconcileScripts(this.#scriptState(false, sessionState));
      return undefined;
    } catch (error) {
      return error;
    }
  }

  #revokePolicy(): void {
    this.#publicationEpoch += 1;
    this.#policyAvailable = false;
    this.#deps.policy.invalidate();
  }

  #reconcileScripts(state: Readonly<WebsitePasskeyScriptState>): Promise<void> {
    const run = this.#scriptOperationTail.then(
      () => this.#deps.scripts.reconcile(state),
      () => this.#deps.scripts.reconcile(state),
    );
    this.#scriptOperationTail = run.then(() => undefined, () => undefined);
    return run;
  }

  #scriptState(enabled: boolean, sessionState: SessionState): Readonly<WebsitePasskeyScriptState> {
    return Object.freeze({
      enabled,
      sessionState,
      policyGeneration: this.#deps.policy.capture().generation,
    });
  }

  async #readStableSource(revision: number): Promise<StablePolicySource> {
    let previous = await this.#readSourceOnce();
    for (let read = 1; read < STABLE_SOURCE_READ_LIMIT; read += 1) {
      const current = await this.#readSourceOnce();
      if (current.key === previous.key) return current;
      if (revision > this.#authoritativeRevision && this.#policyAvailable) {
        // A mismatched pair already proves that the old authorization source is no longer stable.
        // Revoke before another asynchronous retry can yield to ceremony work.
        this.#revokePolicy();
      }
      previous = current;
    }
    throw new Error('Website passkey policy source did not stabilize');
  }

  async #readSourceOnce(): Promise<StablePolicySource> {
    const [rawSettings, autofillSettings, configuredVaultUrl] = await Promise.all([
      this.#deps.settings.getWebsitePasskeySettings(),
      this.#deps.settings.getAutofillSettings(),
      this.#deps.settings.getServerUrl(),
    ]);
    const settings = sanitizeWebsitePasskeySettings(rawSettings);
    if (configuredVaultUrl !== undefined && typeof configuredVaultUrl !== 'string') {
      throw new Error('Invalid website passkey server URL');
    }
    const value: Readonly<WebsitePasskeyPolicySource> = Object.freeze({
      settings,
      blockedDomains: Object.freeze([...autofillSettings.blockedDomains]),
      ...(configuredVaultUrl === undefined ? {} : { configuredVaultUrl }),
    });
    return Object.freeze({
      key: JSON.stringify([
        settings.schemaVersion,
        settings.enabled,
        settings.excludedDomains,
        autofillSettings.blockedDomains,
        configuredVaultUrl ?? null,
      ]),
      value,
    });
  }
}

export function createWebsitePasskeyLifecycle(
  deps: WebsitePasskeyLifecycleDeps,
): WebsitePasskeyLifecycle {
  return new WebsitePasskeyLifecycle(deps);
}

function policyIdentity(sourceKey: string, sessionState: SessionState): string {
  return `${availabilityClass(sessionState)}\u0000${sourceKey}`;
}

function availabilityClass(sessionState: SessionState): 'authenticated' | 'unavailable' {
  return sessionState === 'locked' || sessionState === 'unlocked'
    ? 'authenticated'
    : 'unavailable';
}

function assertSessionState(value: SessionState): void {
  if (
    value !== 'loggedOut'
    && value !== 'locked'
    && value !== 'restricted'
    && value !== 'unlocked'
  ) {
    throw new Error('Invalid website passkey session state');
  }
}

function throwCombinedErrors(...errors: unknown[]): never {
  const failures = errors.filter((error) => error !== undefined);
  if (failures.length === 1) throw failures[0];
  throw new AggregateError(failures, 'Website passkey lifecycle reconciliation failed');
}
