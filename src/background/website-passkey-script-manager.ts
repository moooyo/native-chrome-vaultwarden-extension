import type { SessionState } from '../core/session/session-manager.js';

export const WEBSITE_PASSKEY_MAIN_SCRIPT_ID = 'miyu-website-passkey-main';
export const WEBSITE_PASSKEY_BRIDGE_SCRIPT_ID = 'miyu-website-passkey-bridge';
export const WEBSITE_PASSKEY_SCRIPT_IDS = Object.freeze([
  WEBSITE_PASSKEY_MAIN_SCRIPT_ID,
  WEBSITE_PASSKEY_BRIDGE_SCRIPT_ID,
] as const);

export const WEBSITE_PASSKEY_SCRIPT_MATCHES = Object.freeze([
  'https://*/*',
  'http://localhost/*',
  'http://127.0.0.1/*',
] as const);

export interface WebsitePasskeyRegisteredScript {
  readonly id: string;
  readonly matches?: readonly string[];
  readonly excludeMatches?: readonly string[];
  readonly js?: readonly string[];
  readonly css?: readonly string[];
  readonly runAt?: 'document_start' | 'document_end' | 'document_idle';
  readonly allFrames?: boolean;
  readonly world?: 'ISOLATED' | 'MAIN';
  readonly persistAcrossSessions?: boolean;
  readonly matchOriginAsFallback?: boolean;
}

export interface WebsitePasskeyScriptingAdapter {
  getRegisteredContentScripts(filter: { ids: string[] }): Promise<WebsitePasskeyRegisteredScript[]>;
  registerContentScripts(scripts: WebsitePasskeyRegisteredScript[]): Promise<void>;
  unregisterContentScripts(filter: { ids: string[] }): Promise<void>;
}

export interface WebsitePasskeyScriptManagerDeps {
  readonly scripting: WebsitePasskeyScriptingAdapter;
  /** Re-evaluates already-open frames; the callback owns enumeration and sanitized messages. */
  readonly notifyOpenTopFrames: (
    state: Readonly<WebsitePasskeyScriptState>,
  ) => void | Promise<void>;
}

export interface WebsitePasskeyScriptState {
  readonly enabled: boolean;
  readonly sessionState: SessionState;
  /** Increment for settings, session, and server policy transitions, including ABA changes. */
  readonly policyGeneration: number;
}

/** Owns the MAIN and isolated scripts used by website passkeys. Runtime policy gates authorize each frame. */
export class WebsitePasskeyScriptManager {
  readonly #deps: WebsitePasskeyScriptManagerDeps;
  #operationTail: Promise<void> = Promise.resolve();
  #lastNotifiedKey: string | undefined;

  constructor(deps: WebsitePasskeyScriptManagerDeps) {
    this.#deps = deps;
  }

  reconcile(state: WebsitePasskeyScriptState): Promise<void> {
    const snapshot = validateState(state);
    const run = this.#operationTail.then(
      () => this.#reconcileSnapshot(snapshot),
      () => this.#reconcileSnapshot(snapshot),
    );
    this.#operationTail = run.then(() => undefined, () => undefined);
    return run;
  }

  async #reconcileSnapshot(state: Readonly<WebsitePasskeyScriptState>): Promise<void> {
    const shouldRegister = state.enabled
      && (state.sessionState === 'locked' || state.sessionState === 'unlocked');
    const notificationKey = `${state.policyGeneration}:${state.enabled ? 1 : 0}:${state.sessionState}`;
    const shouldNotify = notificationKey !== this.#lastNotifiedKey;
    let registrationError: unknown;

    try {
      const returned = await this.#deps.scripting.getRegisteredContentScripts({
        ids: [...WEBSITE_PASSKEY_SCRIPT_IDS],
      });
      const owned = returned.filter((script) => isOwnedScriptId(script.id));
      if (!shouldRegister) {
        if (owned.length > 0) {
          await this.#deps.scripting.unregisterContentScripts({
            ids: owned.map((script) => script.id),
          });
        }
      } else if (!registrationsMatch(owned)) {
        if (owned.length > 0) {
          await this.#deps.scripting.unregisterContentScripts({
            ids: owned.map((script) => script.id),
          });
        }
        await this.#deps.scripting.registerContentScripts(createDesiredScripts());
      }
    } catch (error) {
      registrationError = error;
    }

    let notificationError: unknown;
    if (shouldNotify) {
      try {
        await this.#deps.notifyOpenTopFrames(state);
        this.#lastNotifiedKey = notificationKey;
      } catch (error) {
        notificationError = error;
      }
    }

    if (registrationError !== undefined) throw registrationError;
    if (notificationError !== undefined) throw notificationError;
  }
}

export function createDesiredWebsitePasskeyScripts(): readonly WebsitePasskeyRegisteredScript[] {
  return Object.freeze(createDesiredScripts().map((script) => Object.freeze({
    ...script,
    matches: Object.freeze([...(script.matches ?? [])]),
    js: Object.freeze([...(script.js ?? [])]),
  })));
}

function createDesiredScripts(): WebsitePasskeyRegisteredScript[] {
  const shared = {
    matches: [...WEBSITE_PASSKEY_SCRIPT_MATCHES],
    runAt: 'document_start' as const,
    allFrames: true,
    persistAcrossSessions: true,
    matchOriginAsFallback: false,
  };
  return [
    {
      ...shared,
      id: WEBSITE_PASSKEY_MAIN_SCRIPT_ID,
      js: ['content/page-webauthn.js'],
      world: 'MAIN',
    },
    {
      ...shared,
      id: WEBSITE_PASSKEY_BRIDGE_SCRIPT_ID,
      js: ['content/webauthn-bridge.js'],
      world: 'ISOLATED',
    },
  ];
}

function registrationsMatch(actual: readonly WebsitePasskeyRegisteredScript[]): boolean {
  if (actual.length !== WEBSITE_PASSKEY_SCRIPT_IDS.length) return false;
  const byId = new Map(actual.map((script) => [script.id, script]));
  return createDesiredScripts().every((desired) => {
    const current = byId.get(desired.id);
    return current !== undefined && registrationMatches(current, desired);
  });
}

function registrationMatches(
  actual: WebsitePasskeyRegisteredScript,
  desired: WebsitePasskeyRegisteredScript,
): boolean {
  return sameStrings(actual.matches, desired.matches)
    && sameStrings(actual.js, desired.js)
    && (actual.runAt ?? 'document_idle') === desired.runAt
    && actual.allFrames === true
    && (actual.persistAcrossSessions ?? true) === true
    && (actual.matchOriginAsFallback ?? false) === false
    && (actual.world ?? 'ISOLATED') === desired.world
    && (actual.excludeMatches === undefined || actual.excludeMatches.length === 0)
    && (actual.css === undefined || actual.css.length === 0);
}

function sameStrings(left: readonly string[] | undefined, right: readonly string[] | undefined): boolean {
  if (!left || !right || left.length !== right.length) return false;
  return left.every((entry, index) => entry === right[index]);
}

function isOwnedScriptId(id: string): boolean {
  return (WEBSITE_PASSKEY_SCRIPT_IDS as readonly string[]).includes(id);
}

function validateState(state: WebsitePasskeyScriptState): Readonly<WebsitePasskeyScriptState> {
  if (
    typeof state !== 'object'
    || state === null
    || typeof state.enabled !== 'boolean'
    || (state.sessionState !== 'loggedOut'
      && state.sessionState !== 'locked'
      && state.sessionState !== 'restricted'
      && state.sessionState !== 'unlocked')
    || !Number.isSafeInteger(state.policyGeneration)
    || state.policyGeneration < 0
  ) {
    throw new Error('Invalid website passkey script state');
  }
  return Object.freeze({
    enabled: state.enabled,
    sessionState: state.sessionState,
    policyGeneration: state.policyGeneration,
  });
}
