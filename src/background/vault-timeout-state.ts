import type { KeyValueStore } from '../platform/store.js';

const BROWSER_SESSION_KEY = 'vaultTimeoutBrowserSession';
const CLOSE_LOGOUT_KEY = 'vaultTimeoutCloseLogout';
const BROWSER_SESSION_RECOVERY_KEY = 'vaultTimeoutBrowserSessionRecovery';
const ACTIVITY_KEY = 'vaultTimeoutActivity';

interface BrowserSessionRecord { readonly schemaVersion: 1; readonly id: string }
interface BrowserSessionRecoveryRecord { readonly schemaVersion: 1; readonly kind: 'resetAll' }
export type VaultTimeoutCloseLogoutProvenance = 'local' | 'policy' | 'fail_closed' | 'unknown';
export interface VaultTimeoutCloseLogoutOwner {
  readonly accountKey: string;
  readonly email: string;
  readonly actionProvenance: VaultTimeoutCloseLogoutProvenance;
  readonly timeoutProvenance: VaultTimeoutCloseLogoutProvenance;
}
interface CloseLogoutRecord {
  readonly schemaVersion: 3;
  readonly browserSessionId: string;
  readonly owners: Readonly<Record<string, VaultTimeoutCloseLogoutOwner>>;
}
export interface VaultTimeoutActivityRecord {
  readonly schemaVersion: 2;
  readonly accountKey: string;
  readonly email: string;
  readonly sessionBindingId: string;
  readonly lastVaultActivityAt: number;
  readonly lastObservedAt: number;
}
export type VaultTimeoutBrowserSessionStartup =
  | { readonly kind: 'continued' }
  | { readonly kind: 'expired'; readonly owners: readonly VaultTimeoutCloseLogoutOwner[] }
  | { readonly kind: 'corrupt' };

/** Storage boundary for account/session-scoped activity and close/logout intent. */
export class VaultTimeoutStateStore {
  private browserSessionId: string | undefined;
  private mutationTail: Promise<void> = Promise.resolve();
  constructor(private readonly deps: {
    readonly localStore: KeyValueStore;
    readonly sessionStore: KeyValueStore;
    readonly createId?: () => string;
  }) {}

  async initializeBrowserSession(): Promise<VaultTimeoutBrowserSessionStartup> {
    const [rawSession, rawClose, rawRecovery] = await Promise.all([
      this.deps.sessionStore.get<unknown>(BROWSER_SESSION_KEY),
      this.deps.localStore.get<unknown>(CLOSE_LOGOUT_KEY),
      this.deps.localStore.get<unknown>(BROWSER_SESSION_RECOVERY_KEY),
    ]);
    const session = parseBrowserSession(rawSession);
    const close = parseCloseLogout(rawClose);
    const recovery = parseBrowserSessionRecovery(rawRecovery);
    const corrupt = rawRecovery !== undefined
      || (rawSession !== undefined && !session)
      || (rawClose !== undefined && !close);
    if (corrupt && !recovery) {
      await this.deps.localStore.set(BROWSER_SESSION_RECOVERY_KEY, {
        schemaVersion: 1,
        kind: 'resetAll',
      } satisfies BrowserSessionRecoveryRecord);
    }
    if (session) {
      this.browserSessionId = session.id;
      if (corrupt) return { kind: 'corrupt' };
      return !close || close.browserSessionId === session.id
        ? { kind: 'continued' }
        : { kind: 'expired', owners: Object.freeze(Object.values(close.owners)) };
    }
    const id = this.deps.createId?.() ?? crypto.randomUUID();
    if (!bounded(id, 256)) throw new Error('Invalid browser-session identifier');
    await this.deps.sessionStore.set(BROWSER_SESSION_KEY, { schemaVersion: 1, id } satisfies BrowserSessionRecord);
    this.browserSessionId = id;
    if (corrupt) return { kind: 'corrupt' };
    return close
      ? { kind: 'expired', owners: Object.freeze(Object.values(close.owners)) }
      : { kind: 'continued' };
  }

  async completeBrowserSessionRecovery(): Promise<void> {
    await this.mutate(async () => {
      await this.deps.localStore.remove(CLOSE_LOGOUT_KEY);
      await this.deps.localStore.remove(BROWSER_SESSION_RECOVERY_KEY);
    });
  }

  async armResetAllRecovery(): Promise<void> {
    await this.mutate(() => this.deps.localStore.set(BROWSER_SESSION_RECOVERY_KEY, {
      schemaVersion: 1,
      kind: 'resetAll',
    } satisfies BrowserSessionRecoveryRecord));
  }

  async disarmResetAllRecovery(): Promise<void> {
    await this.mutate(() => this.deps.localStore.remove(BROWSER_SESSION_RECOVERY_KEY));
  }

  async armCloseLogout(owner: VaultTimeoutCloseLogoutOwner): Promise<void> {
    const browserSessionId = this.browserSessionId;
    const validated = parseOwner(owner);
    if (!browserSessionId || !validated) throw new Error('Invalid close/logout timeout owner');
    await this.mutate(async () => {
      const raw = await this.deps.localStore.get<unknown>(CLOSE_LOGOUT_KEY);
      const current = parseCloseLogout(raw);
      if (raw !== undefined && !current) throw new Error('Invalid close/logout timeout state');
      const owners = current?.browserSessionId === browserSessionId ? { ...current.owners } : {};
      owners[validated.accountKey] = validated;
      if (Object.keys(owners).length > 32) throw new Error('Too many close/logout timeout owners');
      await this.deps.localStore.set(CLOSE_LOGOUT_KEY, { schemaVersion: 3, browserSessionId, owners } satisfies CloseLogoutRecord);
    });
  }

  async disarmCloseLogout(accountKey: string): Promise<void> {
    await this.mutate(async () => {
      const raw = await this.deps.localStore.get<unknown>(CLOSE_LOGOUT_KEY);
      const current = parseCloseLogout(raw);
      if (raw !== undefined && !current) throw new Error('Invalid close/logout timeout state');
      if (!current?.owners[accountKey]) return;
      const owners = { ...current.owners };
      delete owners[accountKey];
      if (Object.keys(owners).length === 0) await this.deps.localStore.remove(CLOSE_LOGOUT_KEY);
      else await this.deps.localStore.set(CLOSE_LOGOUT_KEY, { ...current, owners });
    });
  }

  async clearCloseLogoutProvenance(options: {
    readonly action?: VaultTimeoutCloseLogoutProvenance;
    readonly timeout?: VaultTimeoutCloseLogoutProvenance;
  }): Promise<void> {
    await this.mutate(async () => {
      const raw = await this.deps.localStore.get<unknown>(CLOSE_LOGOUT_KEY);
      const current = parseCloseLogout(raw);
      if (raw !== undefined && !current) throw new Error('Invalid close/logout timeout state');
      if (!current) return;
      const owners = Object.fromEntries(
        Object.entries(current.owners).filter(([, owner]) => (
          (options.action === undefined || owner.actionProvenance !== options.action)
          && (options.timeout === undefined || owner.timeoutProvenance !== options.timeout)
        )),
      );
      if (Object.keys(owners).length === Object.keys(current.owners).length) return;
      if (Object.keys(owners).length === 0) await this.deps.localStore.remove(CLOSE_LOGOUT_KEY);
      else await this.deps.localStore.set(CLOSE_LOGOUT_KEY, { ...current, owners });
    });
  }

  async reconcileLocalCloseLogoutOwners(options: {
    readonly serverUrl?: string;
    readonly emails: readonly string[];
    readonly enabled: boolean;
  }): Promise<void> {
    const browserSessionId = this.browserSessionId;
    if (!browserSessionId) throw new Error('Browser-session state is unavailable');
    const ownersByAccount = new Map<string, VaultTimeoutCloseLogoutOwner>();
    if (options.serverUrl) {
      for (const candidate of options.emails) {
        const email = candidate.trim().toLowerCase();
        const owner = parseOwner({
          accountKey: `${options.serverUrl}\n${email}`,
          email,
          actionProvenance: 'local',
          timeoutProvenance: 'local',
        });
        if (!owner) throw new Error('Invalid local close/logout account');
        ownersByAccount.set(owner.accountKey, owner);
      }
    }
    if (ownersByAccount.size > 32) throw new Error('Too many close/logout timeout owners');
    await this.mutate(async () => {
      const raw = await this.deps.localStore.get<unknown>(CLOSE_LOGOUT_KEY);
      const current = parseCloseLogout(raw);
      if (raw !== undefined && !current) throw new Error('Invalid close/logout timeout state');
      const owners: Record<string, VaultTimeoutCloseLogoutOwner> = {};
      if (current?.browserSessionId === browserSessionId) {
        for (const [accountKey, owner] of Object.entries(current.owners)) {
          if (!ownersByAccount.has(accountKey)) continue;
          if (!options.enabled
              && (owner.actionProvenance === 'local' || owner.timeoutProvenance === 'local')) continue;
          owners[accountKey] = owner;
        }
      }
      if (options.enabled) {
        for (const [accountKey, owner] of ownersByAccount) owners[accountKey] ??= owner;
      }
      if (Object.keys(owners).length === 0) await this.deps.localStore.remove(CLOSE_LOGOUT_KEY);
      else await this.deps.localStore.set(CLOSE_LOGOUT_KEY, {
        schemaVersion: 3,
        browserSessionId,
        owners,
      } satisfies CloseLogoutRecord);
    });
  }

  async getActivity(): Promise<VaultTimeoutActivityRecord | undefined> {
    const raw = await this.deps.sessionStore.get<unknown>(ACTIVITY_KEY);
    if (raw === undefined) return undefined;
    const parsed = parseActivity(raw);
    if (!parsed) throw new Error('Invalid vault timeout activity state');
    return parsed;
  }

  async setActivity(value: Omit<VaultTimeoutActivityRecord, 'schemaVersion'>): Promise<void> {
    const parsed = parseActivity({ schemaVersion: 2, ...value });
    if (!parsed) throw new Error('Invalid vault timeout activity state');
    await this.deps.sessionStore.set(ACTIVITY_KEY, parsed);
  }

  async clearActivity(): Promise<void> { await this.deps.sessionStore.remove(ACTIVITY_KEY); }
  private mutate<Result>(operation: () => Promise<Result>): Promise<Result> {
    const result = this.mutationTail.then(operation, operation);
    this.mutationTail = result.then(() => undefined, () => undefined);
    return result;
  }
}

export async function recoverVaultTimeoutBrowserSession(
  state: VaultTimeoutStateStore,
  deps: {
    readonly getServerUrl: () => Promise<string | undefined>;
    readonly listAccountEmails: () => Promise<readonly string[]>;
    readonly removeAccount: (email: string) => Promise<void>;
    readonly resetAllAccounts: () => Promise<void>;
    readonly clearDerivedState: () => Promise<void>;
  },
): Promise<boolean> {
  const startup = await state.initializeBrowserSession();
  if (startup.kind === 'continued') return false;
  let changed = false;
  if (startup.kind === 'corrupt') {
    await deps.resetAllAccounts();
    changed = true;
  } else {
    const serverUrl = await deps.getServerUrl();
    const accounts = new Set((await deps.listAccountEmails()).map((email) => email.trim().toLowerCase()));
    for (const owner of startup.owners) {
      const email = owner.email.trim().toLowerCase();
      if (!serverUrl || owner.accountKey !== serverUrl + '\n' + email || !accounts.has(email)) continue;
      await deps.removeAccount(email);
      accounts.delete(email);
      changed = true;
    }
  }
  // Retry cache cleanup even when a prior startup already removed the account but failed later.
  await deps.clearDerivedState();
  await state.completeBrowserSessionRecovery();
  return changed;
}

function parseBrowserSession(value: unknown): BrowserSessionRecord | undefined {
  if (!exact(value, ['schemaVersion', 'id']) || value.schemaVersion !== 1 || !bounded(value.id, 256)) {
    return undefined;
  }
  return Object.freeze({ schemaVersion: 1, id: value.id });
}

function parseBrowserSessionRecovery(value: unknown): BrowserSessionRecoveryRecord | undefined {
  if (!exact(value, ['schemaVersion', 'kind'])
      || value.schemaVersion !== 1
      || value.kind !== 'resetAll') return undefined;
  return Object.freeze({ schemaVersion: 1, kind: 'resetAll' });
}

function parseCloseLogout(value: unknown): CloseLogoutRecord | undefined {
  if (!exact(value, ['schemaVersion', 'browserSessionId', 'owners'])
      || (value.schemaVersion !== 1 && value.schemaVersion !== 2 && value.schemaVersion !== 3)
      || !bounded(value.browserSessionId, 256)
      || !record(value.owners)) return undefined;
  const entries = Object.entries(value.owners);
  if (entries.length > 32) return undefined;
  const owners: Record<string, VaultTimeoutCloseLogoutOwner> = {};
  for (const [key, candidate] of entries) {
    const owner = value.schemaVersion === 3 ? parseOwner(candidate) : parseLegacyOwner(candidate, value.schemaVersion);
    if (!owner || owner.accountKey !== key) return undefined;
    owners[key] = owner;
  }
  return Object.freeze({
    schemaVersion: 3,
    browserSessionId: value.browserSessionId,
    owners: Object.freeze(owners),
  });
}

function parseOwner(value: unknown): VaultTimeoutCloseLogoutOwner | undefined {
  if (!exact(value, ['accountKey', 'email', 'actionProvenance', 'timeoutProvenance'])
      || !bounded(value.accountKey, 4_096)
      || !bounded(value.email, 1_024)
      || !isCloseLogoutProvenance(value.actionProvenance)
      || !isCloseLogoutProvenance(value.timeoutProvenance)) return undefined;
  return Object.freeze({
    accountKey: value.accountKey,
    email: value.email,
    actionProvenance: value.actionProvenance,
    timeoutProvenance: value.timeoutProvenance,
  });
}

function parseLegacyOwner(value: unknown, schemaVersion: 1 | 2): VaultTimeoutCloseLogoutOwner | undefined {
  const expectedKeys = schemaVersion === 1
    ? ['accountKey', 'email']
    : ['accountKey', 'email', 'provenance'];
  if (!exact(value, expectedKeys)
      || !bounded(value.accountKey, 4_096)
      || !bounded(value.email, 1_024)
      || (schemaVersion === 2 && !isCloseLogoutProvenance(value.provenance))) return undefined;
  return Object.freeze({
    accountKey: value.accountKey,
    email: value.email,
    actionProvenance: 'unknown',
    timeoutProvenance: 'unknown',
  });
}

function isCloseLogoutProvenance(value: unknown): value is VaultTimeoutCloseLogoutProvenance {
  return value === 'local' || value === 'policy' || value === 'fail_closed' || value === 'unknown';
}

function parseActivity(value: unknown): VaultTimeoutActivityRecord | undefined {
  const legacy = exact(value, ['schemaVersion', 'accountKey', 'email', 'sessionBindingId', 'lastVaultActivityAt'])
    && value.schemaVersion === 1;
  const current = exact(value, [
    'schemaVersion', 'accountKey', 'email', 'sessionBindingId', 'lastVaultActivityAt', 'lastObservedAt',
  ]) && value.schemaVersion === 2;
  if ((!legacy && !current)
      || !bounded(value.accountKey, 4_096)
      || !bounded(value.email, 1_024)
      || !bounded(value.sessionBindingId, 256)
      || !Number.isSafeInteger(value.lastVaultActivityAt)
      || Number(value.lastVaultActivityAt) < 0) return undefined;
  const lastObservedAt = legacy ? Number(value.lastVaultActivityAt) : Number(value.lastObservedAt);
  if (!Number.isSafeInteger(lastObservedAt)
      || lastObservedAt < Number(value.lastVaultActivityAt)) return undefined;
  return Object.freeze({
    schemaVersion: 2,
    accountKey: value.accountKey,
    email: value.email,
    sessionBindingId: value.sessionBindingId,
    lastVaultActivityAt: Number(value.lastVaultActivityAt),
    lastObservedAt,
  });
}

function exact(value: unknown, keys: readonly string[]): value is Record<string, unknown> {
  return record(value) && Object.keys(value).length === keys.length && keys.every((key) => Object.hasOwn(value, key));
}
function record(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
function bounded(value: unknown, maximum: number): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= maximum && value.trim() === value;
}
