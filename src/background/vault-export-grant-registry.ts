import {
  PERSONAL_VAULT_TRANSFER_EXPORT_TARGET,
  canonicalizeVaultTransferExportTarget,
  sameVaultTransferExportTarget,
  type VaultTransferExportTarget,
} from '../core/vault/vault-transfer-target.js';

export const DEFAULT_VAULT_EXPORT_GRANT_TTL_MS = 30_000;
export const MAX_VAULT_EXPORT_GRANT_TTL_MS = 60_000;
export const DEFAULT_VAULT_EXPORT_GRANT_CAPACITY = 32;
export const MAX_VAULT_EXPORT_GRANT_CAPACITY = 256;

const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

export type VaultExportGrantFormat = 'json' | 'encrypted-json' | 'csv' | 'zip';
export type VaultExportGrantEncryptionType = 'account' | 'file';

export interface VaultExportGrantIssue<SessionLease, AccountLease, PolicyLease> {
  readonly format: VaultExportGrantFormat;
  readonly encryptionType?: VaultExportGrantEncryptionType;
  readonly target?: VaultTransferExportTarget;
  readonly sessionLease: SessionLease;
  readonly accountLease: AccountLease;
  readonly policyLease: PolicyLease;
}

export interface VaultExportGrantReceipt {
  readonly authorizationId: string;
  readonly expiresAt: number;
}

export interface RedeemedVaultExportGrant<SessionLease, AccountLease, PolicyLease> {
  readonly format: VaultExportGrantFormat;
  readonly encryptionType?: VaultExportGrantEncryptionType;
  readonly target: VaultTransferExportTarget;
  readonly sessionLease: SessionLease;
  readonly accountLease: AccountLease;
  readonly policyLease: PolicyLease;
}

export interface VaultExportGrantRegistryOptions<SessionLease, AccountLease, PolicyLease> {
  readonly isSessionLeaseCurrent: (lease: SessionLease) => boolean;
  readonly isAccountLeaseCurrent: (lease: AccountLease) => boolean;
  readonly isPolicyLeaseCurrent: (lease: PolicyLease) => boolean;
  readonly ttlMs?: number;
  readonly maxEntries?: number;
  readonly now?: () => number;
  readonly createToken?: () => string;
}

export type VaultExportGrantRegistryErrorCode =
  | 'capacity'
  | 'invalid_configuration'
  | 'invalid_grant'
  | 'token_collision'
  | 'token_generation';

export class VaultExportGrantRegistryError extends Error {
  constructor(
    readonly code: VaultExportGrantRegistryErrorCode,
    message: string,
  ) {
    super(message);
    this.name = 'VaultExportGrantRegistryError';
  }
}

interface StoredVaultExportGrant<SessionLease, AccountLease, PolicyLease>
  extends RedeemedVaultExportGrant<SessionLease, AccountLease, PolicyLease> {
  readonly expiresAt: number;
}

/**
 * In-memory, one-time authorization for a complete vault export. The registry exposes no lookup or
 * enumeration surface: callers can only issue a grant after verification or consume one for the
 * exact format while its session, account, and enterprise-policy generations remain current.
 */
export class VaultExportGrantRegistry<SessionLease, AccountLease, PolicyLease> {
  readonly #entries = new Map<string, StoredVaultExportGrant<SessionLease, AccountLease, PolicyLease>>();
  readonly #isSessionLeaseCurrent: (lease: SessionLease) => boolean;
  readonly #isAccountLeaseCurrent: (lease: AccountLease) => boolean;
  readonly #isPolicyLeaseCurrent: (lease: PolicyLease) => boolean;
  readonly #ttlMs: number;
  readonly #maxEntries: number;
  readonly #now: () => number;
  readonly #createToken: () => string;

  constructor(options: VaultExportGrantRegistryOptions<SessionLease, AccountLease, PolicyLease>) {
    if (
      typeof options?.isSessionLeaseCurrent !== 'function'
      || typeof options.isAccountLeaseCurrent !== 'function'
      || typeof options.isPolicyLeaseCurrent !== 'function'
    ) {
      throw registryError('invalid_configuration', 'Vault export grant lease validators are required');
    }
    this.#isSessionLeaseCurrent = options.isSessionLeaseCurrent;
    this.#isAccountLeaseCurrent = options.isAccountLeaseCurrent;
    this.#isPolicyLeaseCurrent = options.isPolicyLeaseCurrent;
    this.#ttlMs = boundedPositiveInteger(
      options.ttlMs ?? DEFAULT_VAULT_EXPORT_GRANT_TTL_MS,
      MAX_VAULT_EXPORT_GRANT_TTL_MS,
      'ttlMs',
    );
    this.#maxEntries = boundedPositiveInteger(
      options.maxEntries ?? DEFAULT_VAULT_EXPORT_GRANT_CAPACITY,
      MAX_VAULT_EXPORT_GRANT_CAPACITY,
      'maxEntries',
    );
    this.#now = options.now ?? (() => performance.now());
    this.#createToken = options.createToken ?? (() => globalThis.crypto.randomUUID());
  }

  issue(
    input: VaultExportGrantIssue<SessionLease, AccountLease, PolicyLease>,
  ): VaultExportGrantReceipt {
    const now = this.#currentTime();
    const format = requireFormat(input?.format);
    const encryptionType = requireEncryptionType(format, input?.encryptionType);
    const target = canonicalizeTarget(input?.target);
    if (format === 'zip' && target.kind === 'organization') {
      throw registryError('invalid_grant', 'Organization ZIP export is not supported');
    }
    if (!this.#leasesAreCurrent(input.sessionLease, input.accountLease, input.policyLease)) {
      throw registryError('invalid_grant', 'Vault export grant leases are not current');
    }
    this.#pruneExpired(now);
    if (this.#entries.size >= this.#maxEntries) {
      throw registryError(
        'capacity',
        `Vault export grant capacity (${this.#maxEntries}) was reached`,
      );
    }

    const authorizationId = this.#freshToken();
    const expiresAt = now + this.#ttlMs;
    if (!Number.isFinite(expiresAt) || expiresAt <= now) {
      throw registryError('invalid_configuration', 'Vault export grant expiry is invalid');
    }
    this.#entries.set(authorizationId, Object.freeze({
      format,
      ...(encryptionType ? { encryptionType } : {}),
      target,
      sessionLease: input.sessionLease,
      accountLease: input.accountLease,
      policyLease: input.policyLease,
      expiresAt,
    }));
    return Object.freeze({ authorizationId, expiresAt });
  }

  /** Consume before validation so a mismatch, stale lease, or expired grant can never be retried. */
  redeem(
    authorizationId: string,
    format: VaultExportGrantFormat,
    encryptionType?: VaultExportGrantEncryptionType,
    target?: VaultTransferExportTarget,
  ): RedeemedVaultExportGrant<SessionLease, AccountLease, PolicyLease> | undefined {
    const issued = this.#entries.get(authorizationId);
    if (issued) this.#entries.delete(authorizationId);

    let now: number;
    let canonicalFormat: VaultExportGrantFormat;
    let canonicalEncryptionType: VaultExportGrantEncryptionType | undefined;
    let canonicalTarget: VaultTransferExportTarget;
    try {
      now = this.#currentTime();
      canonicalFormat = requireFormat(format);
      canonicalEncryptionType = requireEncryptionType(canonicalFormat, encryptionType);
      canonicalTarget = canonicalizeTarget(target);
      if (canonicalFormat === 'zip' && canonicalTarget.kind === 'organization') return undefined;
    } catch {
      return undefined;
    }
    this.#pruneExpired(now);
    if (
      !issued
      || !UUID_V4.test(authorizationId)
      || issued.expiresAt <= now
      || issued.format !== canonicalFormat
      || issued.encryptionType !== canonicalEncryptionType
      || !sameVaultTransferExportTarget(issued.target, canonicalTarget)
      || !this.#leasesAreCurrent(
        issued.sessionLease,
        issued.accountLease,
        issued.policyLease,
      )
    ) {
      return undefined;
    }
    return Object.freeze({
      format: issued.format,
      ...(issued.encryptionType ? { encryptionType: issued.encryptionType } : {}),
      target: issued.target,
      sessionLease: issued.sessionLease,
      accountLease: issued.accountLease,
      policyLease: issued.policyLease,
    });
  }

  /** Revoke outstanding grants synchronously at the start of any authentication transition. */
  revokeAll(): void {
    this.#entries.clear();
  }

  #leasesAreCurrent(
    sessionLease: SessionLease,
    accountLease: AccountLease,
    policyLease: PolicyLease,
  ): boolean {
    return safelyCurrent(this.#isSessionLeaseCurrent, sessionLease)
      && safelyCurrent(this.#isAccountLeaseCurrent, accountLease)
      && safelyCurrent(this.#isPolicyLeaseCurrent, policyLease);
  }

  #currentTime(): number {
    const value = this.#now();
    if (!Number.isFinite(value) || value < 0) {
      throw registryError('invalid_configuration', 'Vault export grant clock is invalid');
    }
    return value;
  }

  #pruneExpired(now: number): void {
    for (const [authorizationId, grant] of this.#entries) {
      if (grant.expiresAt <= now) this.#entries.delete(authorizationId);
    }
  }

  #freshToken(): string {
    for (let attempt = 0; attempt < 4; attempt += 1) {
      let token: string;
      try {
        token = this.#createToken();
      } catch {
        throw registryError('token_generation', 'Could not create a vault export grant');
      }
      if (!UUID_V4.test(token)) {
        throw registryError('token_generation', 'Vault export grant must be a canonical UUID v4');
      }
      if (!this.#entries.has(token)) return token;
    }
    throw registryError('token_collision', 'Vault export grant token collision');
  }
}

function canonicalizeTarget(value: unknown): VaultTransferExportTarget {
  try {
    return canonicalizeVaultTransferExportTarget(
      value ?? PERSONAL_VAULT_TRANSFER_EXPORT_TARGET,
    );
  } catch {
    throw registryError('invalid_grant', 'Vault export grant target is invalid');
  }
}

function requireFormat(value: unknown): VaultExportGrantFormat {
  if (value !== 'json' && value !== 'encrypted-json' && value !== 'csv' && value !== 'zip') {
    throw registryError('invalid_grant', 'Vault export grant format is invalid');
  }
  return value;
}

function requireEncryptionType(
  format: VaultExportGrantFormat,
  value: unknown,
): VaultExportGrantEncryptionType | undefined {
  if (format === 'encrypted-json') {
    if (value !== 'account' && value !== 'file') {
      throw registryError('invalid_grant', 'Encrypted JSON grant mode is invalid');
    }
    return value;
  }
  if (value !== undefined) throw registryError('invalid_grant', 'Export grant mode is not allowed');
  return undefined;
}

function safelyCurrent<Lease>(validator: (lease: Lease) => boolean, lease: Lease): boolean {
  try {
    return validator(lease) === true;
  } catch {
    return false;
  }
}

function boundedPositiveInteger(value: number, maximum: number, name: string): number {
  if (!Number.isSafeInteger(value) || value < 1 || value > maximum) {
    throw registryError(
      'invalid_configuration',
      `${name} must be an integer between 1 and ${maximum}`,
    );
  }
  return value;
}

function registryError(
  code: VaultExportGrantRegistryErrorCode,
  message: string,
): VaultExportGrantRegistryError {
  return new VaultExportGrantRegistryError(code, message);
}
