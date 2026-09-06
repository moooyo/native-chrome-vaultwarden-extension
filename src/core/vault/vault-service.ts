import { ATTACHMENT_RESPONSE_MAX_BYTES, ApiHttpError, assertCipherBulkShareRequest, isVaultConflictError, type ApiClient } from '../api/client.js';
import type { AttachmentData, AttachmentUploadSlotReceipt, CipherFieldData, CipherPartialRequest, CipherRequest, CipherResponse, CollectionResponse, Fido2CredentialData, OrganizationResponse, SendRequest, SshKeyCipherData, SshKeyCipherRequestData, SyncProfile, SyncResponse } from '../api/types.js';
import { parseSyncResponse, parseSyncSecurityProfile } from '../api/sync-profile.js';
import { canonicalizeServerCapabilityUrl } from '../api/server-capabilities.js';
import type {
  AuthTokenLease,
  SessionLease,
  SessionLeaseGate,
  SessionManager,
} from '../session/session-manager.js';
import type { AccountLease, AccountLeaseGate } from '../session/account-gate.js';
import type { AuthService } from '../session/auth-service.js';
import type { KeyValueStore } from '../../platform/store.js';
import type { SymmetricKey } from '../crypto/keys.js';
import { CARD_FIELDS, IDENTITY_FIELDS, isActiveCipher, isCipherInactive, isKnownCipherType, type CipherSummary, type CipherInput, type CipherInputPurpose, type CipherCreateTarget, type CollectionSummary, type CompleteDecryptedSshKey, type DecryptedCipher, type DecryptedField, type DecryptedFido2Credential, type FieldName, type FolderSummary, type KnownCipherType, type PasskeyAssertionRequest, type PasskeyLookupRequest, type PasskeyTarget, type PasskeyCandidate, type SshCipherInput, type SshKeyMetadataInput, type SshKeyPublicDetails, type TotpListEntry } from './models.js';
import { decryptCipher, decryptCipherSummary, undecryptableSummary, decryptFolders, decryptCollections, buildSyncProfileOrgKeyMap } from './decrypt.js';
import { encryptCipher, mergeServerManagedFields } from './encrypt.js';
import { getTotp, type TotpResult } from './totp.js';
import { MAX_FIDO2_SIGNATURE_COUNTER, signFido2Assertion, type PasskeyAssertion } from './fido2.js';
import {
  MAX_PASSKEY_CREDENTIAL_DESCRIPTORS,
  buildAttestationObject,
  buildCreateClientDataJSON,
  decidePasskeyCreationRoute,
  encryptFido2Credential,
  generateFido2Keypair,
  normalizePasskeyChallenge,
  normalizePasskeyCredentialSelection,
  normalizePasskeyExcludeCredentialIds,
  normalizePasskeyResidentSelection,
  normalizePasskeyUserHandle,
  type GeneratedFido2Keypair,
  type PasskeyCreateRequest,
  type PasskeyCredentialSelection,
} from './fido2-create.js';
import { decryptToBytes, encryptToText, decryptToText } from '../crypto/encstring.js';
import { unwrapSymmetricKey } from '../crypto/keys.js';
import { base64UrlToBytes, base64ToBytes, bytesToBase64, bytesToBase64Url, bytesToHex, bytesToUtf8, utf8ToBytes } from '../crypto/encoding.js';
import { decryptAttachmentKey, decryptAttachmentFile, encryptAttachmentFile, generateAttachmentKey, wrapAttachmentKey } from './attachments.js';
import { assertLegacyFileMessageBudget, base64EncodedLength } from './file-transfer-limits.js';
import { buildPasswordHealthReport, type PasswordHealthEntry, type PasswordHealthInput } from './password-health.js';
import { pwnedCount } from './pwned.js';
import { buildExportJson, buildEncryptedExportJson, parseImport } from './vault-io.js';
import { buildTextSendRequest, buildFileSendRequest, buildUpdateSendRequest, decryptSend, type SendInput, type SendSummary, type UpdateSendInput } from './sends.js';
import { AppError } from '../errors.js';
import type {
  AutofillCandidate,
  AutofillIntentPurpose,
  AutofillInteractiveLoginData,
  AutofillLoginData,
  AutofillTotpData,
  FillKind,
  FillItemCandidate,
  CardFillData,
  IdentityFillData,
} from '../../messaging/protocol.js';
import { compareMatchResults, isUriMatchStrategySetting, matchLoginUri, UriMatchStrategy, type UriMatchResult, type UriMatchStrategySetting } from './uri-match.js';
import { pageLoadAutofillAllowed } from './autofill-policy.js';
import { buildEquivalentDomainIndex } from './equivalent-domains.js';
import { toContextualOrgPermission } from './org-permissions.js';
import type { OrgPermission } from './org-permissions.js';
import { selectOrganizationMetadata } from './organization-profile.js';
import { getHostAndPort, isRegistrableRpId } from './domain.js';
import {
  VaultCacheRepository,
  type DerivedVaultSnapshot,
  type RawVaultEnvelope,
  type VaultDerivedData,
} from './vault-cache-repository.js';
import {
  VaultCoordinatorError,
  VaultMutationCommitError,
  type VaultMutationCoordinator,
  type VaultSyncPolicy,
} from './vault-mutation-coordinator.js';
import {
  EnterprisePolicyGate,
  EnterprisePolicyType,
  type EffectiveSendControls,
  type PolicyLease,
} from '../policy/effective-enterprise-policy.js';
import { fillDataKeysForRoles, type FillRole } from './fill-roles.js';
import {
  MAX_LOGIN_CUSTOM_ASSIGNMENT_BYTES,
  MAX_LOGIN_CUSTOM_ASSIGNMENT_LENGTH,
  MAX_LOGIN_CUSTOM_HINT_LENGTH,
  MAX_LOGIN_CUSTOM_TARGETS,
  parseLoginCustomTargetPlan,
  type LoginCustomAssignment,
  type LoginCustomTargetPlan,
} from './login-custom-fields.js';
import {
  buildVaultTransferExport,
  type VaultTransferExportAttachment,
} from './vault-transfer-export.js';
import {
  AccountEncryptedVaultTransferError,
  encodeAccountEncryptedVaultExport,
  inspectAccountEncryptedVaultExport,
} from './vault-transfer-account-encrypted.js';
import {
  createStrictVaultTransferExportDecryptors,
  encodeVaultTransferJsonBytes,
} from './vault-transfer-export-crypto.js';
import {
  encodeVaultTransferCsv,
  type EncodeVaultTransferCsvResult,
  type VaultTransferCsvDiagnostic,
} from './vault-transfer-csv.js';
import {
  VAULT_TRANSFER_EXPORT_WARNING_CODES,
  type VaultTransferExportReview,
  type VaultTransferExportWarningCode,
} from './vault-transfer-export-review.js';
import { writeVaultArchive, type VaultArchiveAttachmentInput } from './vault-archive.js';
import {
  CIPHER_INPUT_IMPORT_CAPABILITIES,
  inspectPersonalImportCapabilities,
  toPersonalImportItemWrite,
  type PersonalImportCapabilityPolicy,
} from './vault-transfer-commit.js';
import {
  encryptPersonalImportItemWrite,
  validatePersonalImportItemWrite,
} from './vault-transfer-import-crypto.js';
import {
  inspectVaultTransferSource,
  type InspectVaultTransferSourceOptions,
  type VaultTransferSourceOk,
  type VaultTransferSourceResult,
} from './vault-transfer-source.js';
import {
  generateSshKey,
  importSshPrivateKey,
  SshKeyCodecError,
} from './ssh-key-codec.js';
import {
  parseCompleteDecryptedSshKey,
  parseCompleteSshKeyCipherData,
  parseSshKeyCipherData,
  type SshKeyField,
  validateSshKeyPlaintextField,
} from './ssh-key.js';
import {
  isPasswordProtectedField,
  projectValidatedCipherAccess,
  summaryAllowsCipherAccess,
  type CipherAccessAction,
} from './cipher-access.js';
import { validateRawSyncCipherCompatibility } from './vault-sync-cipher-compat.js';
import { isIsoTimestamp } from './iso-date.js';
import { computeLoginUriChecksum } from './login-uri-checksum.js';
import {
  PERSONAL_VAULT_TRANSFER_EXPORT_TARGET,
  canonicalizeVaultTransferExportTarget,
  canonicalizeVaultTransferOrganizationId,
  type VaultTransferExportTarget,
} from './vault-transfer-target.js';
import { rotateCipher, verifyRotatedCipher, type RotatedCipher } from './rotate.js';
import {
  canCloneOrganizationCipher,
  resolveCollectionCapabilities,
  type CollectionOrganizationAuthority,
} from './collection-permissions.js';
import type { ClientEventAuthorityProjection } from '../events/client-event.js';
import {
  SecurityStampRepository,
  SecurityStampRepositoryError,
  type SecurityStampComparison,
  type SecurityStampRepositoryErrorCode,
} from './security-stamp-repository.js';

const MAX_LOGIN_CUSTOM_FIELDS_SCANNED = 256;
const MAX_PORTABLE_EXPORT_ATTACHMENT_BYTES = 64 * 1024 * 1024;
const MAX_PORTABLE_EXPORT_BYTES = 64 * 1024 * 1024;
const MAX_PORTABLE_EXPORT_PASSWORD_BYTES = 4_096;
const MAX_ARCHIVE_FILE_NAME_CHARS = 160;
const MAX_ATTACHMENT_ENCRYPTION_OVERHEAD_BYTES = 65;
const MAX_ATTACHMENT_PLAINTEXT_BYTES =
  ATTACHMENT_RESPONSE_MAX_BYTES - MAX_ATTACHMENT_ENCRYPTION_OVERHEAD_BYTES;
const MAX_ATTACHMENT_FILE_NAME_BYTES = 255;
const ORGANIZATION_DATA_OWNERSHIP_GRANT_TTL_MS = 30_000;
const MAX_ORGANIZATION_DATA_OWNERSHIP_GRANTS = 64;
const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const CANONICAL_CLIENT_EVENT_UUID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const ORGANIZATION_DATA_OWNERSHIP_RECONCILIATION_PREFIX =
  'organizationDataOwnershipReconciliation:v1:';

export const VAULT_SERVICE_IMPORT_CAPABILITIES: Readonly<PersonalImportCapabilityPolicy> =
  Object.freeze({
    ...CIPHER_INPUT_IMPORT_CAPABILITIES,
    passwordHistory: true,
    passkeys: true,
  });

/** Advertised only when the account and active server generation both authorize archived creates. */
export const VAULT_SERVICE_ARCHIVE_IMPORT_CAPABILITIES: Readonly<PersonalImportCapabilityPolicy> =
  Object.freeze({
    ...VAULT_SERVICE_IMPORT_CAPABILITIES,
    itemDates: true,
  });

/** Advertised only after the active server/client capability generation authorizes type-5 writes. */
export const VAULT_SERVICE_SSH_IMPORT_CAPABILITIES: Readonly<PersonalImportCapabilityPolicy> =
  Object.freeze({
    ...VAULT_SERVICE_IMPORT_CAPABILITIES,
    supportedItemTypes: Object.freeze([1, 2, 3, 4, 5] as const),
  });

/** Advertised only when both dynamic SSH and archive authorizations are currently available. */
export const VAULT_SERVICE_SSH_ARCHIVE_IMPORT_CAPABILITIES: Readonly<PersonalImportCapabilityPolicy> =
  Object.freeze({
    ...VAULT_SERVICE_SSH_IMPORT_CAPABILITIES,
    itemDates: true,
  });

export type PortableVaultExportFormat = 'json' | 'encrypted-json' | 'csv' | 'zip';

export interface BuiltPortableVaultExport {
  readonly bytes: Uint8Array;
  readonly filename: string;
  readonly review?: VaultTransferExportReview;
}

export interface PortableVaultTransferAuthority {
  readonly accountLease: AccountLease;
  readonly sessionLease: SessionLease;
}

export type PortableVaultImportSettlement =
  | { readonly operationId: string; readonly status: 'committed' }
  | {
      readonly operationId: string;
      readonly status: 'rejected' | 'outcome_unknown';
      readonly code: string;
    };

/** Structurally compatible with the background transfer controller's account-scoped journal. */
export interface PortableVaultImportJournal {
  readonly signal: AbortSignal;
  assertCurrent(): Promise<void>;
  markInFlight(
    kind: 'folder' | 'item',
    sourceIndex: number,
  ): Promise<{ readonly operationId: string }>;
  settleInFlight(settlement: PortableVaultImportSettlement): Promise<unknown>;
  recordSkipped(kind: 'folder' | 'item', sourceIndex: number, code: string): Promise<unknown>;
  getAlias(kind: 'folder' | 'item', sourceIndex: number): Promise<string | undefined>;
}

export interface PortableVaultImportInput {
  readonly source: VaultTransferSourceOk;
  readonly capabilities: PersonalImportCapabilityPolicy;
  readonly journal: PortableVaultImportJournal;
}

export interface VaultServiceDeps {
  api: ApiClient;
  auth: Pick<
    AuthService,
    'executeAuthenticatedRequest' | 'refreshIfNeeded' | 'verifyMasterPassword'
  >;
  session: SessionManager;
  localStore: KeyValueStore;
  sessionStore: KeyValueStore;
  getVaultIdentity: () => string | undefined | Promise<string | undefined>;
  sessionGate: SessionLeaseGate;
  accountGate: Pick<AccountLeaseGate, 'capture' | 'assert'>;
  policyGate: EnterprisePolicyGate;
  coordinator: VaultMutationCoordinator<string, AccountLease, VaultListing, string, string>;
  getIdentityEpoch: () => number;
  parseImport?: typeof parseImport;
  now?: () => number;
  onPolicySnapshotPublished?: () => Promise<void>;
  onSyncSuccess?: (identity: string) => void | Promise<void>;
  /** Revoke only the still-current credential after a security stamp mismatch. */
  onSecurityStampMismatch: (authority: VaultSecurityStampMismatchAuthority) => void | Promise<void>;
  onMutationSyncRequired?: (identity: string) => void;
  /** Resolve one account-scoped, revocable authorization for an SSH type-5 write. */
  authorizeSshCipherType5Write?: () => PromiseLike<SshCipherWriteAuthorization>;
  /** Resolve one account-scoped, revocable authorization for creating new archive metadata. */
  authorizeCipherArchive?: () => CipherArchiveAuthorization | PromiseLike<CipherArchiveAuthorization>;
  /** Resolve a revocable backend-kind decision for safe ODO transport selection. */
  authorizeOrganizationDataOwnershipTransport?: () => PromiseLike<
    OrganizationDataOwnershipTransportAuthorization
  >;
  /** Resolve a revocable authorization for Bitwarden's association-preserving name-only update. */
  authorizeCollectionNameOnlyUpdate?: () => PromiseLike<CollectionNameUpdateAuthorization>;
  /** Test seams; production uses the audited in-worker codec. */
  generateSshKey?: typeof generateSshKey;
  importSshPrivateKey?: typeof importSshPrivateKey;
  generateFido2Keypair?: typeof generateFido2Keypair;
  /** Test seam for deterministic cache-transition coverage before HTTP-auth plaintext exists. */
  beforeHttpAuthCredentialDecrypt?: () => Promise<void>;
  /** Test-only observation that an owned manual-autofill per-cipher key was zeroized. */
  onManualAutofillFieldKeyDisposed?: (zeroized: boolean) => void;
}

export interface VaultSecurityStampMismatchAuthority {
  readonly accountLease: AccountLease;
  readonly tokenLease: AuthTokenLease;
  readonly failure:
    | {
        readonly kind: 'mismatch';
        readonly reason: Extract<SecurityStampComparison, { status: 'mismatch' }>['reason'];
      }
    | {
        readonly kind: 'state_unavailable';
        readonly reason: SecurityStampRepositoryErrorCode | 'invalid_sync_profile';
      };
}

export interface SshCipherWriteAuthorization {
  /** Revalidate server/account capability evidence immediately before the network write. */
  assertCurrent(): void;
}

export interface CipherArchiveAuthorization {
  /** Revalidate server/account capability evidence immediately before the network write. */
  assertCurrent(): void;
}

export interface OrganizationDataOwnershipTransportAuthorization {
  readonly serverKind: 'bitwarden' | 'vaultwarden';
  assertCurrent(): void;
}

export interface CollectionNameUpdateAuthorization {
  assertCurrent(): void;
}

interface VaultOperationContext {
  readonly api: ApiClient;
  readonly userKey: SymmetricKey;
  readonly token: string;
  readonly sessionLease: SessionLease;
  readonly accountLease: AccountLease;
  readonly policyLease: PolicyLease;
  readonly accountKey: string;
  readonly identityEpoch: number;
  readonly cacheEpoch: number | undefined;
  readonly cacheEnvelope: RawVaultEnvelope;
  assertBaseCurrent(): void;
  assertLeaseCurrent(): void;
  assertCurrent(): void;
  assertCacheCurrent(): Promise<void>;
  executeAuthenticated<Result>(
    rebuildRequest: (accessToken: string) => Promise<Result>,
  ): Promise<Result>;
  adoptRawSource(source: RawVaultEnvelope, publicationFence: symbol): void;
}

export type VaultFinalAuthorityBinder = (assertCurrent: () => void) => void;

export type ManualAutofillRisk = 'no_match' | 'never' | 'https_downgrade';

export interface ManualAutofillVaultBinding {
  readonly cipherRevision: string;
  readonly uriDigest: string;
  readonly risk: ManualAutofillRisk;
  readonly requiresReprompt: boolean;
}

export interface ManualAutofillVaultAuthority {
  assertCurrent(): void;
}

/** Non-secret identity projected from one fenced raw vault generation for local generator history. */
export interface GeneratorHistoryVaultIdentity {
  readonly serverUrl: string;
  readonly accountIdentity: string;
  readonly userId: string;
}

export interface ManualAutofillVaultPreparation extends ManualAutofillVaultBinding {
  readonly canSave: boolean;
  readonly authority: ManualAutofillVaultAuthority;
}

interface ManualAutofillCipherAccess extends ManualAutofillVaultPreparation {
  readonly cipher: SupportedCipherResponse;
  readonly operation: VaultOperationContext;
}

interface DecryptedCipherAccess {
  readonly cipher: DecryptedCipher;
  readonly raw: SupportedCipherResponse;
  readonly operation: VaultOperationContext;
}

interface SshCipherFieldAccess {
  readonly cipher: SupportedCipherResponse;
  readonly encryptedSshKey: SshKeyCipherData;
  readonly fieldKey: SymmetricKey;
  readonly operation: VaultOperationContext;
}

interface PasskeyCounterState {
  readonly counter: number;
  readonly credentialIndex: number;
  readonly credentials: readonly Fido2CredentialData[];
}

type PasskeySigningOutcome =
  | { readonly ok: true; readonly assertion: PasskeyAssertion }
  | { readonly ok: false; readonly error: unknown };

interface VaultMutationRuntime {
  readonly operation: VaultOperationContext;
  remote<Result>(
    rebuildRequest: (accessToken: string) => Promise<Result>,
    onCommitted?: (value: Result) => void,
  ): Promise<Result>;
  remoteOnce<Result>(
    request: () => Promise<Result>,
    onCommitted?: (value: Result) => void,
  ): Promise<Result>;
  reconcile<Result>(refresh: () => Promise<Result>): Promise<Result>;
}

type PreparedAttachmentUploadResult =
  | { readonly status: 'uploaded'; readonly receipt: AttachmentUploadSlotReceipt }
  | { readonly status: 'rolled_back'; readonly error: unknown };

interface OrganizationCreateContext {
  readonly organizationId: string;
  readonly collectionIds: readonly string[];
  readonly key: SymmetricKey;
}

interface PreparedCipherShare {
  readonly request: CipherRequest;
  readonly attachments: readonly AttachmentData[];
}

type SupportedCipherResponse = CipherResponse & { type: KnownCipherType };

class VaultNotCommittedError extends VaultMutationCommitError {
  constructor(readonly original: unknown) {
    super('not_committed', original instanceof Error ? original.message : String(original));
  }
}

class SecurityStampMismatchError extends Error {
  constructor(
    readonly authority: VaultSecurityStampMismatchAuthority,
  ) {
    super('The active credential security stamp is no longer current');
    this.name = 'SecurityStampMismatchError';
  }
}

class SecurityStampStateUnavailableError extends Error {
  constructor(
    readonly authority: VaultSecurityStampMismatchAuthority,
  ) {
    super('The active credential security stamp state is unavailable');
    this.name = 'SecurityStampStateUnavailableError';
  }
}

class SshWriteAuthorizationChangedError extends AppError {
  constructor() {
    super('denied', 'SSH key write authorization changed during the operation.');
    this.name = 'SshWriteAuthorizationChangedError';
  }
}

class CipherArchiveAuthorizationChangedError extends AppError {
  constructor() {
    super('denied', 'Cipher archive authorization changed during the operation.');
    this.name = 'CipherArchiveAuthorizationChangedError';
  }
}

/** Cap on retained prior passwords (the server may trim further). Keeps the audit trail bounded. */
const MAX_PASSWORD_HISTORY = 5;
const MAX_CREATE_TARGET_COLLECTIONS = 1_000;
const MAX_CREATE_TARGET_ID_LENGTH = 4_096;
const PERSONAL_CIPHER_CREATE_TARGET: CipherCreateTarget = Object.freeze({ kind: 'personal' });

export interface VaultListing {
  items: CipherSummary[];
  folders: FolderSummary[];
  collections: CollectionSummary[];
  orgPermissions: OrgPermission[];
  /** Consumers must require exact `true`; absent legacy snapshots fail closed. */
  personalCreationAllowed?: boolean;
}

export interface OrganizationDataOwnershipGrantReceipt {
  readonly authorizationId: string;
  readonly expiresAt: number;
}

export type OrganizationDataOwnershipStatus =
  | { readonly status: 'not_required' | 'compliant' | 'unavailable' }
  | {
      readonly status: 'reconciliation_required';
      readonly operation: OrganizationDataOwnershipOperation;
      readonly reason: 'outcome_unknown' | 'committed_unsynced';
    }
  | {
      readonly status: 'migration_available';
      readonly organizationId: string;
      readonly collectionId: string;
      readonly personalItemCount: number;
      readonly migrateAuthorization: OrganizationDataOwnershipGrantReceipt;
      readonly leaveAuthorization: OrganizationDataOwnershipGrantReceipt;
    }
  | {
      readonly status: 'blocked';
      readonly organizationId: string;
      readonly personalItemCount: number;
      readonly reason: 'target_unavailable' | 'unsupported_items';
      readonly leaveAuthorization: OrganizationDataOwnershipGrantReceipt;
    };

type OrganizationDataOwnershipOperation = 'migrate' | 'leave';

interface OrganizationDataOwnershipItemRevision {
  readonly cipherId: string;
  readonly revisionDate: string | null;
}

type InternalOrganizationDataOwnershipStatus =
  | { readonly status: 'not_required' | 'compliant' | 'unavailable' }
  | {
      readonly status: 'migration_available';
      readonly organizationId: string;
      readonly collectionId: string;
      readonly personalItemCount: number;
      readonly policyRevisionDate: string | null;
      readonly snapshotDigest: string;
      readonly itemRevisions: readonly OrganizationDataOwnershipItemRevision[];
    }
  | {
      readonly status: 'blocked';
      readonly organizationId: string;
      readonly personalItemCount: number;
      readonly reason: 'target_unavailable' | 'unsupported_items';
      readonly policyRevisionDate: string | null;
      readonly snapshotDigest: string;
      readonly itemRevisions: readonly OrganizationDataOwnershipItemRevision[];
    };

interface StoredOrganizationDataOwnershipGrant {
  readonly popupDocumentId: string;
  readonly operation: OrganizationDataOwnershipOperation;
  readonly organizationId: string;
  readonly collectionId: string | null;
  readonly snapshotDigest: string;
  readonly itemRevisions: readonly OrganizationDataOwnershipItemRevision[];
  readonly sessionLease: SessionLease;
  readonly accountLease: AccountLease;
  readonly policyLease: PolicyLease;
  readonly policyRevisionDate: string | null;
  readonly identityEpoch: number;
  readonly cacheEpoch: number;
  readonly rawGeneration: string;
  readonly expiresAt: number;
}

interface OrganizationDataOwnershipReconciliation {
  readonly accountKey: string;
  readonly operation: OrganizationDataOwnershipOperation;
  readonly reason: 'outcome_unknown' | 'committed_unsynced';
}

type OrganizationDataOwnershipReconciliationState =
  | { readonly status: 'unknown' }
  | { readonly status: 'clear'; readonly accountKey: string }
  | {
      readonly status: 'required';
      readonly reconciliation: OrganizationDataOwnershipReconciliation;
    };

interface StoredOrganizationDataOwnershipReconciliation {
  readonly schemaVersion: 1;
  readonly operation: OrganizationDataOwnershipOperation;
  readonly reason: 'outcome_unknown' | 'committed_unsynced';
}

/** Outcome of an {@link VaultService.importVault} run. Reports how many items were created versus how
 *  many failed so the caller can surface a partial import instead of treating one failure as total. */
export interface ImportResult {
  /** Number of items successfully created on the server. */
  imported: number;
  /** Number of items that failed to import. */
  failed: number;
  /** Per-item failure detail, in input order: the index into the parsed import and the error message. */
  failures: Array<{ index: number; message: string }>;
  /** A post-import cache refresh failure. Remote creates already succeeded and must not be retried. */
  refreshError?: string;
}

/** The save/update decision for a captured form submission. */
export type SaveLoginPrompt =
  | { action: 'none' }
  | { action: 'save'; suggestedName: string }
  | { action: 'update'; cipherId: string; name: string }
  | { action: 'addUri'; cipherId: string; name: string };

export type CapturedLoginCommitDecision = Exclude<SaveLoginPrompt, { action: 'none' }>;

/** The public attestation returned to the page after registering a new passkey. The private key
 *  (keyValue) never leaves the worker — only these public/opaque values cross the boundary. */
export interface Fido2Registration {
  credentialId: string;
  attestationObject: string;
  clientDataJSON: string;
  authData: string;
  publicKeySpki: string;
  publicKeyAlgorithm: -7;
}

/** Internal, non-serializable authorization fence for an externally initiated passkey write. */
export interface PasskeyCreateOptions {
  readonly assertAuthorized?: () => void;
}

export class VaultService {
  private cacheMutationTail: Promise<void> = Promise.resolve();
  private readonly derivedRebuilds = new Map<string, Promise<DerivedVaultSnapshot>>();
  private passkeyAssertionTail: Promise<void> = Promise.resolve();
  private cacheEpoch = 0;
  private policyPublicationFence: symbol | undefined;
  private readonly cache: VaultCacheRepository;
  private readonly securityStamps: SecurityStampRepository;
  private readonly organizationDataOwnershipGrants = new Map<
    string,
    StoredOrganizationDataOwnershipGrant
  >();
  private readonly revokedOrganizationDataOwnershipGrantIds = new Map<string, number>();
  private organizationDataOwnershipReconciliationState: OrganizationDataOwnershipReconciliationState =
    Object.freeze({ status: 'unknown' });

  constructor(private readonly deps: VaultServiceDeps) {
    this.cache = new VaultCacheRepository({
      localStore: deps.localStore,
      sessionStore: deps.sessionStore,
      getIdentity: deps.getVaultIdentity,
      getSessionBindingId: async () => (await deps.session.getActiveAuth())?.sessionBindingId,
    });
    this.securityStamps = new SecurityStampRepository({ store: deps.localStore });
  }

  /** Remove legacy local plaintext cache keys during worker startup. */
  async initializeCache(): Promise<void> {
    await this.cache.initialize();
    this.policyPublicationFence = undefined;
    let accountLease: AccountLease;
    try {
      accountLease = this.deps.accountGate.capture();
    } catch {
      this.deps.policyGate.invalidate();
      return;
    }
    const identityEpoch = this.identityEpoch();
    const assertCurrent = (): void => {
      this.deps.accountGate.assert(accountLease);
      this.assertIdentityEpoch(identityEpoch);
    };
    try {
      await this.readOrganizationDataOwnershipReconciliation(accountKeyFor(accountLease));
      assertCurrent();
    } catch {
      // Unknown reconciliation state forces the next sync to contact the server.
    }
    const source = await this.cache.readRaw();
    assertCurrent();
    if (!source) {
      this.deps.policyGate.invalidate();
      return;
    }
    try {
      await this.assertSyncSecurityStamp(source.response, accountLease, assertCurrent, false);
      assertCurrent();
      const ensured = await this.ensurePolicyForSource(source, accountLease);
      if (ensured.published) await this.enforcePublishedPolicy();
      this.assertPolicyForSource(ensured.policyLease, source, accountLease);
    } catch (error) {
      this.deps.policyGate.invalidate();
      const revocation = securityStampRevocationFrom(error);
      if (revocation) {
        await this.deps.onSecurityStampMismatch(revocation.authority);
        return;
      }
      if (!(error instanceof AppError)) throw error;
    }
  }

  private publishPolicySnapshot(
    source: RawVaultEnvelope,
    accountLease: AccountLease,
    publicationFence?: symbol,
  ): PolicyLease {
    this.deps.accountGate.assert(accountLease);
    if (this.policyPublicationFence !== publicationFence) {
      throw new AppError('sync_required', 'Enterprise policy publication was superseded.');
    }
    if (
      source.identity !== accountKeyFor(accountLease)
      || source.response.profile.email.trim().toLowerCase() !== accountLease.accountIdentity
    ) {
      throw new AppError('sync_required', 'Enterprise policy source belongs to another account.');
    }
    try {
      this.deps.policyGate.replace({
        response: source.response,
        accountLease,
        rawGeneration: source.rawGeneration,
      });
      const lease = this.deps.policyGate.capture();
      if (this.policyPublicationFence !== publicationFence) {
        throw new AppError('sync_required', 'Enterprise policy publication was superseded.');
      }
      this.assertPolicyForSource(lease, source, accountLease);
      this.policyPublicationFence = undefined;
      return lease;
    } catch (error) {
      this.deps.policyGate.invalidate();
      throw error;
    }
  }

  private assertPolicyForSource(
    policyLease: PolicyLease,
    source: RawVaultEnvelope,
    accountLease: AccountLease,
  ): void {
    this.deps.accountGate.assert(accountLease);
    this.deps.policyGate.assert(policyLease);
    if (
      policyLease.serverGeneration !== accountLease.serverGeneration
      || policyLease.accountGeneration !== accountLease.accountGeneration
      || policyLease.serverUrl !== accountLease.serverUrl
      || policyLease.accountIdentity !== accountLease.accountIdentity
      || policyLease.rawGeneration !== source.rawGeneration
      || source.identity !== accountKeyFor(accountLease)
      || source.response.profile.email.trim().toLowerCase() !== accountLease.accountIdentity
    ) {
      throw new AppError('denied', 'Enterprise policy scope changed during the operation.');
    }
  }

  private tryCapturePolicyForSource(
    source: RawVaultEnvelope,
    accountLease: AccountLease,
  ): PolicyLease | undefined {
    try {
      const lease = this.deps.policyGate.capture();
      this.assertPolicyForSource(lease, source, accountLease);
      return lease;
    } catch {
      return undefined;
    }
  }

  /** Restore only from an identity-checked, still-current raw envelope. */
  private async ensurePolicyForSource(
    source: RawVaultEnvelope,
    accountLease: AccountLease,
  ): Promise<{ readonly policyLease: PolicyLease; readonly published: boolean }> {
    if (this.policyPublicationFence !== undefined) {
      throw new AppError('sync_required', 'Enterprise policy state requires a successful sync.');
    }
    const existing = this.tryCapturePolicyForSource(source, accountLease);
    if (existing) return { policyLease: existing, published: false };
    return this.withCacheMutation(async () => {
      this.deps.accountGate.assert(accountLease);
      try {
        await this.cache.assertCurrent(source);
      } catch {
        throw new AppError('sync_required', 'Enterprise policy source is no longer current.');
      }
      const current = this.tryCapturePolicyForSource(source, accountLease);
      if (current) return { policyLease: current, published: false };
      const lease = this.publishPolicySnapshot(source, accountLease);
      try {
        await this.cache.assertCurrent(source);
        this.deps.accountGate.assert(accountLease);
        this.assertPolicyForSource(lease, source, accountLease);
      } catch (error) {
        if (this.deps.policyGate.isCurrent(lease)) this.deps.policyGate.invalidate();
        throw error;
      }
      return { policyLease: lease, published: true };
    });
  }

  private async enforcePublishedPolicy(): Promise<void> {
    try {
      await this.deps.onPolicySnapshotPublished?.();
    } catch (error) {
      this.policyPublicationFence = Symbol('policyEnforcementFailed');
      this.deps.policyGate.invalidate();
      throw error;
    }
  }

  async sync(reason = 'manual', policy: VaultSyncPolicy = 'force'): Promise<VaultListing> {
    const lease = this.deps.accountGate.capture();
    const accountKey = accountKeyFor(lease);
    const effectivePolicy = this.hasKnownClearOrganizationDataOwnershipReconciliation(accountKey)
      ? policy
      : 'force';
    try {
      return await this.deps.coordinator.forAccount(accountKey).requestSync(
        reason,
        effectivePolicy,
        async (context) => {
          const listing = await this.syncInLane(context.lease, context.assertCurrent);
          // This callback only runs for a real remote sync. Keep marker removal inside the lane so a
          // coalesced caller cannot clear reconciliation state without contacting the server.
          await this.clearOrganizationDataOwnershipReconciliation(accountKey);
          return listing;
        },
      );
    } catch (error) {
      const revocation = securityStampRevocationFrom(error);
      if (revocation) return this.revokeSecurityStampAuthority(revocation);
      throw error;
    }
  }

  /**
   * Capture the event-collection authority and cipher ownership from one current raw-cache operation.
   * The projection intentionally excludes provider-only organizations and never trusts caller input.
   */
  async captureClientEventAuthorityProjection(): Promise<ClientEventAuthorityProjection> {
    const operation = await this.beginVaultOperation({
      cache: true,
      allowPendingDataOwnership: true,
    });
    const response = operation.cacheEnvelope.response;
    const profile = requireClientEventAuthorityRecord(response.profile, 'profile');
    const userId = requireClientEventAuthorityId(
      clientEventAuthorityDataValue(profile, 'id'),
      'profile user',
    );
    const organizationsNew = clientEventAuthorityDataValue(profile, 'organizationsNew');
    const directOrganizations = organizationsNew !== undefined && organizationsNew !== null
      ? requireClientEventAuthorityArray(organizationsNew, 'organizationsNew')
      : requireOptionalClientEventAuthorityArray(
          clientEventAuthorityDataValue(profile, 'organizations'),
          'organizations',
        );
    const organizationIds = new Set<string>();
    const organizations: Array<ClientEventAuthorityProjection['organizations'][number]> = [];
    for (const value of directOrganizations) {
      const organization = requireClientEventAuthorityRecord(value, 'organization');
      const id = requireClientEventAuthorityId(
        clientEventAuthorityDataValue(organization, 'id'),
        'organization',
      );
      if (organizationIds.has(id)) throw invalidClientEventAuthority('Duplicate organization id');
      organizationIds.add(id);
      if (clientEventAuthorityDataValue(organization, 'status') !== 2
          || clientEventAuthorityDataValue(organization, 'enabled') !== true) continue;
      organizations.push(Object.freeze({
        id,
        useEvents: clientEventAuthorityDataValue(organization, 'useEvents') === true,
      }));
    }

    const rawCiphers = requireClientEventAuthorityArray(response.ciphers, 'ciphers');
    const cipherIds = new Set<string>();
    const ciphers: Array<ClientEventAuthorityProjection['ciphers'][number]> = [];
    for (const value of rawCiphers) {
      const cipher = requireClientEventAuthorityRecord(value, 'cipher');
      const id = requireClientEventAuthorityId(
        clientEventAuthorityDataValue(cipher, 'id'),
        'cipher',
      );
      if (cipherIds.has(id)) throw invalidClientEventAuthority('Duplicate cipher id');
      cipherIds.add(id);
      const rawOrganizationId = clientEventAuthorityDataValue(cipher, 'organizationId');
      const organizationId = rawOrganizationId === undefined || rawOrganizationId === null
        ? null
        : requireClientEventAuthorityId(rawOrganizationId, 'cipher organization');
      ciphers.push(Object.freeze({ id, organizationId }));
    }

    await operation.assertCacheCurrent();
    operation.assertCurrent();
    return Object.freeze({
      serverUrl: operation.accountLease.serverUrl,
      userId,
      organizations: Object.freeze(organizations),
      ciphers: Object.freeze(ciphers),
    });
  }

  /** Capture only the canonical account/profile identity from one current raw-cache operation. */
  async captureGeneratorHistoryIdentity(): Promise<GeneratorHistoryVaultIdentity> {
    const operation = await this.beginVaultOperation({
      cache: true,
      allowPendingDataOwnership: true,
    });
    try {
      operation.assertCurrent();
      const profile = requireClientEventAuthorityRecord(operation.cacheEnvelope.response.profile, 'profile');
      const userId = requireClientEventAuthorityId(
        clientEventAuthorityDataValue(profile, 'id'),
        'profile user',
      );
      await operation.assertCacheCurrent();
      operation.assertCurrent();
      return Object.freeze({
        serverUrl: operation.accountLease.serverUrl,
        accountIdentity: operation.accountLease.accountIdentity,
        userId,
      });
    } finally {
      operation.userKey.encKey.fill(0);
      operation.userKey.macKey.fill(0);
    }
  }

  private async assertSyncSecurityStamp(
    response: SyncResponse,
    accountLease: AccountLease,
    assertCurrent: () => void,
    initialize: boolean,
  ): Promise<void> {
    assertCurrent();
    const snapshot = await this.deps.session.getActiveAuthSnapshot();
    assertCurrent();
    if (!snapshot
      || snapshot.auth.email !== accountLease.accountIdentity
      || snapshot.tokenLease.email !== accountLease.accountIdentity) {
      throw new AppError('session_expired', 'The active credential changed during sync');
    }
    const tokenLease: AuthTokenLease = Object.freeze({ ...snapshot.tokenLease });
    const assertAuthorityCurrent = async (): Promise<void> => {
      assertCurrent();
      if (!await this.deps.session.isTokenLeaseCurrent(tokenLease)) {
        throw new AppError('session_expired', 'The active credential changed during sync');
      }
      assertCurrent();
    };
    await assertAuthorityCurrent();
    const retainedTokenLeases = await this.deps.session.listAuthTokenLeases();
    await assertAuthorityCurrent();
    if (!retainedTokenLeases.some((lease) => (
      lease.email === tokenLease.email && lease.credentialId === tokenLease.credentialId
    ))) {
      throw new AppError('session_expired', 'The active credential changed during sync');
    }
    let profile: ReturnType<typeof parseSyncSecurityProfile>;
    try {
      profile = parseSyncSecurityProfile(parseSyncResponse(response).profile);
    } catch {
      throw new SecurityStampStateUnavailableError(Object.freeze({
        accountLease,
        tokenLease,
        failure: Object.freeze({
          kind: 'state_unavailable' as const,
          reason: 'invalid_sync_profile' as const,
        }),
      }));
    }
    if (profile.accountIdentity !== accountLease.accountIdentity) {
      throw new AppError('denied', 'The sync response belongs to a different account');
    }
    let comparison: SecurityStampComparison;
    try {
      comparison = await this.securityStamps.compareAndSet({
        serverUrl: canonicalizeServerCapabilityUrl(accountLease.serverUrl),
        profileId: profile.profileId,
        credentialId: tokenLease.credentialId,
      }, profile.securityStamp, {
        initialize,
        retainedCredentialIds: retainedTokenLeases.map((lease) => lease.credentialId),
        assertCurrent: assertAuthorityCurrent,
      });
    } catch (error) {
      await assertAuthorityCurrent();
      if (error instanceof SecurityStampRepositoryError) {
        throw new SecurityStampStateUnavailableError(
          Object.freeze({
            accountLease,
            tokenLease,
            failure: Object.freeze({ kind: 'state_unavailable' as const, reason: error.code }),
          }),
        );
      }
      throw error;
    }
    await assertAuthorityCurrent();
    if (comparison.status === 'uninitialized') {
      throw new AppError('sync_required', 'A fresh sync is required for this credential');
    }
    if (comparison.status === 'mismatch') {
      throw new SecurityStampMismatchError(
        Object.freeze({
          accountLease,
          tokenLease,
          failure: Object.freeze({ kind: 'mismatch' as const, reason: comparison.reason }),
        }),
      );
    }
  }

  private async revokeSecurityStampAuthority(
    error: SecurityStampMismatchError | SecurityStampStateUnavailableError,
  ): Promise<never> {
    await this.deps.onSecurityStampMismatch(error.authority);
    throw new AppError('session_expired', 'The account session was revoked. Sign in again.');
  }

  private async syncInLane(
    accountLease: AccountLease,
    assertCoordinatorCurrent: () => void,
  ): Promise<VaultListing> {
    const identityEpoch = this.identityEpoch();
    const accountKey = accountKeyFor(accountLease);
    const assertCurrent = (): void => {
      assertCoordinatorCurrent();
      this.deps.accountGate.assert(accountLease);
      this.assertIdentityEpoch(identityEpoch);
    };
    const api = this.deps.api
      .forServer(accountLease.serverUrl)
      .withRequestGuard(assertCurrent);
    const response = await this.deps.auth.executeAuthenticatedRequest(
      accountLease,
      (accessToken) => api.sync(accessToken),
    );
    assertCurrent();
    await this.assertSyncSecurityStamp(response, accountLease, assertCurrent, true);
    assertCurrent();
    const published = await this.withCacheMutation(async () => {
      assertCurrent();
      const publicationFence = Symbol('syncPolicyPublication');
      this.policyPublicationFence = publicationFence;
      this.revokeOrganizationDataOwnershipGrants();
      this.deps.policyGate.invalidate();
      this.cacheEpoch++;
      const written = await this.cache.writeRaw(response, accountKey);
      assertCurrent();
      const policyLease = this.publishPolicySnapshot(written, accountLease, publicationFence);
      return { raw: written, policyLease };
    });
    await this.enforcePublishedPolicy();
    assertCurrent();
    this.assertPolicyForSource(published.policyLease, published.raw, accountLease);

    let listing = emptyListing();
    try {
      const sessionLease = this.deps.sessionGate.capture();
      listing = (await this.decryptAndPersist(
        published.raw.response,
        identityEpoch,
        published.raw,
        sessionLease,
        published.policyLease,
        accountLease,
        assertCurrent,
      )).listing;
    } catch (error) {
      if (!(error instanceof AppError && error.code === 'locked')) throw error;
    }
    assertCurrent();
    this.assertPolicyForSource(published.policyLease, published.raw, accountLease);
    await this.deps.onSyncSuccess?.(accountKey);
    assertCurrent();
    this.assertPolicyForSource(published.policyLease, published.raw, accountLease);
    return listing;
  }

  /**
   * Decrypt a sync response and persist every derived cache (summaries, folders, collections, org
   * permissions, equivalence data). Requires an unlocked vault. Shared by sync() and the lock/unlock
   * cache rebuild so the two paths cannot drift.
   */
  private async decryptAndPersist(
    response: SyncResponse,
    identityEpoch: number,
    source: RawVaultEnvelope,
    sessionLease: SessionLease,
    policyLease: PolicyLease,
    accountLease: AccountLease,
    assertAccountCurrent: () => void,
  ): Promise<DerivedVaultSnapshot> {
    const activeAuth = await this.deps.session.getActiveAuth();
    if (!activeAuth?.sessionBindingId) throw new AppError('locked', 'Vault is locked');
    const sessionBindingId = activeAuth.sessionBindingId;
    const assertCurrent = (): void => {
      this.assertIdentityEpoch(identityEpoch);
      this.deps.sessionGate.assert(sessionLease);
      assertAccountCurrent();
      this.assertPolicyForSource(policyLease, source, accountLease);
    };
    assertCurrent();
    const rebuildKey = JSON.stringify([
      source.identity,
      source.rawGeneration,
      identityEpoch,
      sessionBindingId,
      sessionLease.generation,
      accountLease.serverGeneration,
      accountLease.accountGeneration,
      policyLease.generation,
    ]);
    let pending = this.derivedRebuilds.get(rebuildKey);
    if (!pending) {
      pending = this.buildDerivedSnapshot(
        response, identityEpoch, source, sessionLease, policyLease, accountLease,
        assertAccountCurrent, sessionBindingId,
      );
      this.derivedRebuilds.set(rebuildKey, pending);
    }
    try {
      const snapshot = await pending;
      // Each waiter retains its own authorization fence even when the decryption work is shared.
      assertCurrent();
      return snapshot;
    } finally {
      // Keep only in-flight work: quota fallback must not become a second plaintext cache.
      if (this.derivedRebuilds.get(rebuildKey) === pending) this.derivedRebuilds.delete(rebuildKey);
    }
  }

  private async buildDerivedSnapshot(
    response: SyncResponse,
    identityEpoch: number,
    source: RawVaultEnvelope,
    sessionLease: SessionLease,
    policyLease: PolicyLease,
    accountLease: AccountLease,
    assertAccountCurrent: () => void,
    sessionBindingId: string,
  ): Promise<DerivedVaultSnapshot> {
    const userKey = await this.deps.session.loadUserKey();
    if (!userKey) throw new AppError('locked', 'Vault is locked');
    this.deps.sessionGate.assert(sessionLease);
    assertAccountCurrent();
    this.assertPolicyForSource(policyLease, source, accountLease);
    const orgKeys = await this.buildOrgKeys(response.profile);
    const visibleCiphers = response.ciphers.filter((cipher) => !this.deps.policyGate.isItemRestricted(
      policyLease,
      { type: cipher.type, organizationId: cipher.organizationId ?? null },
    ));
    const organizationMetadata = selectOrganizationMetadata(response.profile);
    const organizationAuthorities = new Map(organizationMetadata.entries.map((entry) => [
      entry.organization.id,
      toCollectionOrganizationAuthority(entry.organization, entry.isProviderUser),
    ]));
    const items = await this.decryptSummaries(
      visibleCiphers,
      userKey,
      orgKeys,
      (cipher) => canCloneOrganizationCipher(
        cipher.organizationId ? organizationAuthorities.get(cipher.organizationId) : undefined,
        cipher,
        response.collections,
      ),
    );
    const folders = await decryptFolders(response.folders, userKey);
    const rawCollectionsById = groupCollectionsById(response.collections ?? []);
    let collectionNameUpdateAuthorization: CollectionNameUpdateAuthorization | undefined;
    try {
      collectionNameUpdateAuthorization = await this.authorizeCollectionNameOnlyUpdate();
    } catch {
      // Collection entity management is an optional extension feature. A capability failure hides
      // only rename; sync and item assignment remain available.
    }
    this.deps.sessionGate.assert(sessionLease);
    assertAccountCurrent();
    this.assertPolicyForSource(policyLease, source, accountLease);
    const collections = (await decryptCollections(response.collections, orgKeys)).map((collection) => {
      const rawMatches = rawCollectionsById.get(collection.id) ?? [];
      const authority = organizationAuthorities.get(collection.organizationId);
      const capabilities = rawMatches.length === 1
        ? resolveCollectionCapabilities(authority, rawMatches[0])
        : resolveCollectionCapabilities(undefined, undefined);
      return Object.freeze({
        ...collection,
        canRename: capabilities.canRename && collectionNameUpdateAuthorization !== undefined,
        canDelete: capabilities.canDelete,
        canAssignItems: capabilities.canAssign,
      });
    });
    // Org ciphers whose key could not be unwrapped (e.g. locked private key) are surfaced to the UI.
    const skippedOrgCount = visibleCiphers.filter(
      (cipher) => cipher.organizationId && !orgKeys.has(cipher.organizationId),
    ).length;
    // Domains of global equivalence groups the user has switched off (Domain Rules), so the client
    // stops treating them as equivalent for autofill.
    const excludedDomains = (response.domains?.globalEquivalentDomains ?? [])
      .filter((g) => g.excluded)
      .flatMap((g) => g.domains ?? []);
    const orgPermissions = organizationMetadata.entries.map((entry) => {
      const keyAvailable = orgKeys.has(entry.organization.id);
      const authority = organizationAuthorities.get(entry.organization.id);
      const createCapabilities = resolveCollectionCapabilities(authority);
      const projected = toContextualOrgPermission(entry.organization, {
        isMember: entry.isMember,
        isProviderUser: entry.isProviderUser,
        keyAvailable,
      });
      const canCreateCollections = keyAvailable
        && entry.isMember
        && typeof entry.organization.organizationUserId === 'string'
        && entry.organization.organizationUserId.length > 0
        && createCapabilities.canCreate;
      return Object.freeze({
        ...projected,
        canCreateCollections,
        canManageCollections: canCreateCollections
          || projected.canEditCollections
          || projected.canDeleteCollections,
      });
    });
    const derived: VaultDerivedData = {
      listing: {
        items,
        folders,
        collections,
        orgPermissions,
        personalCreationAllowed: this.deps.policyGate.allows(
          policyLease,
          'createPersonalVaultItem',
        ),
      },
      equivalentDomains: response.domains?.equivalentDomains ?? [],
      excludedDomains,
      skippedOrgCount,
    };
    const snapshot = await this.withCacheMutation(async () => {
      this.assertIdentityEpoch(identityEpoch);
      this.deps.sessionGate.assert(sessionLease);
      assertAccountCurrent();
      this.assertPolicyForSource(policyLease, source, accountLease);
      const written = await this.cache.writeDerived(source, derived, sessionBindingId);
      this.deps.sessionGate.assert(sessionLease);
      assertAccountCurrent();
      this.assertPolicyForSource(policyLease, source, accountLease);
      return written;
    });
    this.assertIdentityEpoch(identityEpoch);
    this.deps.sessionGate.assert(sessionLease);
    this.assertPolicyForSource(policyLease, source, accountLease);
    return snapshot;
  }

  /** Drop the session-scoped decrypted snapshot while retaining raw sync data for an unlocked rebuild. */
  async purgeDecryptedCaches(): Promise<void> {
    await this.withCacheMutation(async () => {
      await this.cache.clearDerived();
    });
  }

  private async requireDerivedSnapshot(): Promise<DerivedVaultSnapshot> {
    const view = await this.requireCacheView();
    this.deps.policyGate.assert(view.policyLease);
    return view.snapshot;
  }

  private async requireCacheView(): Promise<{
    envelope: RawVaultEnvelope;
    snapshot: DerivedVaultSnapshot;
    policyLease: PolicyLease;
  }> {
    const current = await this.rebuildCurrentCache(true);
    if (!current) throw new AppError('sync_required', 'Sync required');
    return current;
  }

  /** Rebuild derived data from the newest raw generation after unlock. */
  async rebuildCache(): Promise<VaultListing> {
    return (await this.requireCacheView()).snapshot.listing;
  }

  private async rebuildCurrentCache(
    required: boolean,
  ): Promise<{
    envelope: RawVaultEnvelope;
    snapshot: DerivedVaultSnapshot;
    policyLease: PolicyLease;
  } | undefined> {
    const accountLease = this.deps.accountGate.capture();
    const sessionLease = this.deps.sessionGate.capture();
    const identityEpoch = this.identityEpoch();
    const assertCurrent = (): void => {
      this.deps.accountGate.assert(accountLease);
      this.deps.sessionGate.assert(sessionLease);
      this.assertIdentityEpoch(identityEpoch);
    };
    for (let attempt = 0; attempt < 3; attempt++) {
      assertCurrent();
      const current = await this.cache.readCurrent();
      assertCurrent();
      if (!current) {
        if (required) throw new AppError('sync_required', 'Sync required');
        return undefined;
      }
      try {
        const ensured = await this.ensurePolicyForSource(current.raw, accountLease);
        const policyLease = ensured.policyLease;
        if (ensured.published) await this.enforcePublishedPolicy();
        assertCurrent();
        this.assertPolicyForSource(policyLease, current.raw, accountLease);
        if (current.derived) {
          return { envelope: current.raw, snapshot: current.derived, policyLease };
        }
        const snapshot = await this.decryptAndPersist(
          current.raw.response,
          identityEpoch,
          current.raw,
          sessionLease,
          policyLease,
          accountLease,
          assertCurrent,
        );
        return { envelope: current.raw, snapshot, policyLease };
      } catch (error) {
        assertCurrent();
        if (!isObsoleteCacheError(error)
          && !(error instanceof AppError && error.code === 'sync_required')) throw error;
      }
    }
    throw new AppError('sync_required', 'Vault cache changed while rebuilding; retry');
  }

  /** Unknown wire types may remain in raw sync storage, but no worker operation may inspect or mutate them. */
  private requireSupportedCipher(
    cipher: CipherResponse,
    allowedTypes?: readonly KnownCipherType[],
  ): SupportedCipherResponse {
    const compatibility = validateRawSyncCipherCompatibility(cipher);
    if (!compatibility.ok) {
      throw new AppError('denied', 'Cipher authorization metadata is invalid or unsupported');
    }
    if (!isKnownCipherType(cipher.type) || (allowedTypes && !allowedTypes.includes(cipher.type))) {
      throw new AppError('denied', 'Unsupported cipher type');
    }
    return cipher as SupportedCipherResponse;
  }

  private assertCipherPolicyAllowed(policyLease: PolicyLease, cipher: CipherResponse): void {
    if (this.deps.policyGate.isItemRestricted(policyLease, {
      type: cipher.type,
      organizationId: cipher.organizationId ?? null,
    })) {
      throw new AppError('denied', 'This item type is restricted by enterprise policy.');
    }
  }

  private bindOperationFinalAuthority(
    operation: VaultOperationContext,
    bindFinalAuthority?: VaultFinalAuthorityBinder,
    assertAdditional?: () => void,
  ): void {
    bindFinalAuthority?.(() => {
      operation.assertCurrent();
      assertAdditional?.();
    });
  }

  private assertCipherTargetPolicyAllowed(
    policyLease: PolicyLease,
    type: number,
    organizationId?: string | null,
  ): void {
    if (this.deps.policyGate.isItemRestricted(policyLease, {
      type,
      organizationId: organizationId ?? null,
    })) {
      throw new AppError('denied', 'This item type is restricted by enterprise policy.');
    }
  }

  private assertPersonalCreationAllowed(policyLease: PolicyLease, type: number): void {
    this.deps.policyGate.assertAllowed(policyLease, 'createPersonalVaultItem');
    this.assertCipherTargetPolicyAllowed(policyLease, type, null);
  }

  private canCreatePersonalCipher(policyLease: PolicyLease, type: number): boolean {
    return this.deps.policyGate.allows(policyLease, 'createPersonalVaultItem')
      && !this.deps.policyGate.isItemRestricted(policyLease, { type, organizationId: null });
  }

  private assertCipherAccessAllowed(
    cipher: SupportedCipherResponse,
    action: CipherAccessAction,
    message: string,
  ): void {
    if (!projectValidatedCipherAccess(cipher)[action]) {
      throw new AppError('denied', message);
    }
  }

  private assertCipherEditAllowed(policyLease: PolicyLease, cipher: SupportedCipherResponse): void {
    this.assertCipherPolicyAllowed(policyLease, cipher);
    this.assertCipherAccessAllowed(cipher, 'edit', 'This item cannot be edited.');
  }

  private assertCipherPasswordViewAllowed(cipher: SupportedCipherResponse): void {
    this.assertCipherAccessAllowed(
      cipher,
      'viewPassword',
      'This item does not allow viewing password-protected values.',
    );
  }

  private assertCipherDeleteAllowed(policyLease: PolicyLease, cipher: SupportedCipherResponse): void {
    this.assertCipherPolicyAllowed(policyLease, cipher);
    this.assertCipherAccessAllowed(cipher, 'delete', 'This item cannot be deleted.');
  }

  private assertCipherRestoreAllowed(policyLease: PolicyLease, cipher: SupportedCipherResponse): void {
    this.assertCipherPolicyAllowed(policyLease, cipher);
    this.assertCipherAccessAllowed(cipher, 'restore', 'This item cannot be restored.');
  }

  private assertCipherAutofillTotpAllowed(cipher: SupportedCipherResponse): void {
    this.assertCipherAccessAllowed(
      cipher,
      'autofillTotp',
      'This item does not allow TOTP autofill.',
    );
  }

  private assertCipherViewTotpAllowed(cipher: SupportedCipherResponse): void {
    this.assertCipherAccessAllowed(cipher, 'viewTotp', 'This item does not allow viewing TOTP codes.');
  }

  private enforceSendWritePolicy(
    policyLease: PolicyLease,
    request: SendRequest,
    hasPassword: boolean,
    now: number,
    mode: 'create' | 'update',
    attemptedDeletionChange = false,
  ): EffectiveSendControls {
    const controls = this.deps.policyGate.getSendControls(policyLease);
    if (!this.deps.policyGate.allowsSend(policyLease, {
      type: request.type,
      hideEmail: request.hideEmail === true,
    })) {
      throw new AppError('denied', 'Creating or editing this Send is restricted by enterprise policy.');
    }
    if (controls.whoCanAccess === 2) {
      throw new AppError(
        'denied',
        'This Send access policy cannot be represented safely by this client.',
      );
    }
    if (controls.whoCanAccess === 1 && !hasPassword) {
      throw new AppError('denied', 'Enterprise policy requires password protection for this Send.');
    }
    if (controls.deletionHours !== null) {
      if (mode === 'create') {
        request.deletionDate = new Date(now + controls.deletionHours * 3_600_000).toISOString();
        if (request.expirationDate
          && Date.parse(request.expirationDate) > Date.parse(request.deletionDate)) {
          throw new AppError(
            'denied',
            'The Send expiration date exceeds the enterprise deletion limit.',
          );
        }
      } else if (attemptedDeletionChange) {
        throw new AppError(
          'denied',
          'Enterprise policy prevents changing this Send deletion date.',
        );
      }
    }
    return controls;
  }

  private identityEpoch(): number {
    return this.deps.getIdentityEpoch();
  }

  private assertIdentityEpoch(expected: number): void {
    if (this.identityEpoch() !== expected) throw new AppError('error', 'Account changed during vault operation');
  }

  private async withCacheMutation<T>(operation: () => Promise<T>): Promise<T> {
    const run = this.cacheMutationTail.then(operation, operation);
    this.cacheMutationTail = run.then(() => undefined, () => undefined);
    return run;
  }

  private runVaultMutation<Result>(
    kind: string,
    task: (runtime: VaultMutationRuntime) => Promise<Result>,
    options?: {
      cache?: boolean;
      bindFinalAuthority?: VaultFinalAuthorityBinder;
      allowPendingDataOwnership?: boolean;
      captured?: { readonly accountLease: AccountLease; readonly sessionLease: SessionLease };
    },
  ): Promise<Result> {
    // Both leases are captured before queue admission. An old queued write can therefore never use
    // keys from a later unlock of the same account.
    const accountLease = options?.captured?.accountLease ?? this.deps.accountGate.capture();
    const sessionLease = options?.captured?.sessionLease ?? this.deps.sessionGate.capture();
    const accountKey = accountKeyFor(accountLease);
    const outcome = this.deps.coordinator.forAccount(accountKey).runMutation(kind, {
      commit: async (coordinatorContext) => {
        let remoteCommitted = false;
        let remoteFailure: unknown;
        let reconciled = false;
        try {
          coordinatorContext.assertCurrent();
          this.deps.accountGate.assert(accountLease);
          this.deps.sessionGate.assert(sessionLease);
          const operation = await this.beginVaultOperation(options, { accountLease, sessionLease });
          const recordRemote = async <Value>(
            request: () => Promise<Value>,
            onCommitted?: (value: Value) => void,
          ): Promise<Value> => {
            operation.assertCurrent();
            coordinatorContext.assertCurrent();
            let thisRequestCommitted = false;
            try {
              const value = await request();
              thisRequestCommitted = true;
              remoteCommitted = true;
              onCommitted?.(value);
              operation.assertCurrent();
              coordinatorContext.assertCurrent();
              return value;
            } catch (error) {
              if (thisRequestCommitted) throw error;
              remoteFailure = error;
              if (error instanceof AppError) {
                throw new VaultNotCommittedError(error);
              }
              throw classifyRemoteMutationError(error);
            }
          };
          const runtime: VaultMutationRuntime = {
            operation,
            remote: <Value>(
              rebuildRequest: (accessToken: string) => Promise<Value>,
              onCommitted?: (value: Value) => void,
            ): Promise<Value> => recordRemote(
              () => operation.executeAuthenticated(rebuildRequest),
              onCommitted,
            ),
            remoteOnce: recordRemote,
            reconcile: async <Value>(refresh: () => Promise<Value>): Promise<Value> => {
              if (!remoteCommitted) throw new Error('Cannot reconcile before a remote commit');
              const value = await refresh();
              reconciled = true;
              return value;
            },
          };
          const value = await task(runtime);
          if (remoteCommitted && !reconciled) {
            await runtime.reconcile(() => this.syncAfterMutation(operation));
          }
          this.bindOperationFinalAuthority(operation, options?.bindFinalAuthority);
          return { value };
        } catch (error) {
          if (remoteCommitted
            && error instanceof AppError
            && error.code === 'outcome_unknown') {
            throw new VaultMutationCommitError('outcome_unknown', error.message);
          }
          if (remoteCommitted) return { error };
          if (remoteFailure !== undefined) throw error;
          if (error instanceof VaultMutationCommitError) throw error;
          throw new VaultNotCommittedError(error);
        }
      },
      reconcile: async (commitResult) => {
        if ('error' in commitResult) throw commitResult.error;
        return commitResult.value;
      },
    });

    return outcome.then(async (result) => {
      if (result.status !== 'committed') {
        const revocation = securityStampRevocationFrom(result.error);
        if (revocation) return this.revokeSecurityStampAuthority(revocation);
      }
      if (result.status === 'committed') return result.value;
      if (result.status === 'not_committed') {
        if (result.error instanceof VaultCoordinatorError && result.error.code === 'reconcile_required') {
          this.deps.onMutationSyncRequired?.(accountKey);
          throw new AppError('committed_unsynced', result.error.message);
        }
        if (result.error instanceof VaultNotCommittedError) throw result.error.original;
        if (result.error instanceof AppError) throw result.error;
        throw result.error;
      }
      this.deps.onMutationSyncRequired?.(accountKey);
      if (result.status === 'conflict') {
        throw new AppError('conflict', 'The vault changed on the server. Sync before retrying.');
      }
      if (result.status === 'outcome_unknown') {
        throw new AppError(
          'outcome_unknown',
          'The server may have committed this change. Sync before taking another action.',
        );
      }
      throw new AppError(
        'committed_unsynced',
        'The change was saved, but the local vault could not be reconciled. Sync before retrying.',
      );
    });
  }

  /** Build the equivalent-domain index from the built-in list plus any cached user-defined groups,
   *  dropping built-in groups the server's Domain Rules have excluded. */
  private loadEquivalentIndex(snapshot: DerivedVaultSnapshot): Map<string, number> {
    return buildEquivalentDomainIndex(snapshot.equivalentDomains, snapshot.excludedDomains);
  }

  /** Unwrap each organization key from the synced profile using the decrypted account private key. */
  private async buildOrgKeys(profile: SyncProfile | undefined): Promise<Map<string, SymmetricKey>> {
    const privateKey = await this.deps.session.loadPrivateKey();
    try {
      return await buildSyncProfileOrgKeyMap(profile, privateKey);
    } finally {
      privateKey?.fill(0);
    }
  }

  async listItems(): Promise<VaultListing> {
    return (await this.requireDerivedSnapshot()).listing;
  }

  async getSkippedOrgCount(): Promise<number> {
    return (await this.requireDerivedSnapshot()).skippedOrgCount;
  }

  async getOrganizationDataOwnershipStatus(
    popupDocumentId: string,
  ): Promise<OrganizationDataOwnershipStatus> {
    const documentId = requireOrganizationDataOwnershipPopupDocumentId(popupDocumentId);
    const operation = await this.beginVaultOperation({
      cache: true,
      allowPendingDataOwnership: true,
    });
    const reconciliation = await this.readOrganizationDataOwnershipReconciliation(
      operation.accountKey,
    );
    if (reconciliation) {
      await operation.assertCacheCurrent();
      operation.assertCurrent();
      return Object.freeze({
        status: 'reconciliation_required',
        operation: reconciliation.operation,
        reason: reconciliation.reason,
      });
    }
    const status = await this.organizationDataOwnershipStatus(operation);
    await operation.assertCacheCurrent();
    operation.assertCurrent();
    if (status.status !== 'migration_available' && status.status !== 'blocked') return status;

    const leaveAuthorization = this.issueOrganizationDataOwnershipGrant(
      documentId,
      'leave',
      status,
      operation,
    );
    if (status.status === 'blocked') {
      return Object.freeze({
        status: status.status,
        organizationId: status.organizationId,
        personalItemCount: status.personalItemCount,
        reason: status.reason,
        leaveAuthorization,
      });
    }
    return Object.freeze({
      status: status.status,
      organizationId: status.organizationId,
      collectionId: status.collectionId,
      personalItemCount: status.personalItemCount,
      migrateAuthorization: this.issueOrganizationDataOwnershipGrant(
        documentId,
        'migrate',
        status,
        operation,
      ),
      leaveAuthorization,
    });
  }

  private async organizationDataOwnershipStatus(
    operation: VaultOperationContext,
  ): Promise<InternalOrganizationDataOwnershipStatus> {
    const snapshot = this.deps.policyGate.assert(operation.policyLease);
    const transferPolicy = snapshot.organizationDataOwnershipTransferPolicy;
    if (!transferPolicy) {
      if (snapshot.malformedPolicyTypes.includes(EnterprisePolicyType.OrganizationDataOwnership)) {
        return Object.freeze({ status: 'unavailable' });
      }
      return Object.freeze({ status: 'not_required' });
    }
    const personal = operation.cacheEnvelope.response.ciphers.filter(
      (cipher) => cipher.organizationId == null,
    );
    if (personal.length === 0) return Object.freeze({ status: 'compliant' });
    const organizationId = transferPolicy.organizationId;
    const metadata = selectOrganizationMetadata(operation.cacheEnvelope.response.profile).entries
      .filter((entry) => entry.organization.id === organizationId);
    const defaultCollections = (operation.cacheEnvelope.response.collections ?? []).filter(
      (collection) => collection.organizationId === organizationId
        && collection.type === 1,
    );
    const itemRevisions = Object.freeze(personal
      .map((cipher) => Object.freeze({
        cipherId: cipher.id,
        revisionDate: isIsoTimestamp(cipher.revisionDate) ? cipher.revisionDate : null,
      }))
      .sort(compareOrganizationDataOwnershipItemRevisions));
    const snapshotDigest = await createDataOwnershipSnapshotDigest({
      organizationId,
      revisionDate: transferPolicy.revisionDate,
      collectionId: defaultCollections.length === 1 ? defaultCollections[0]!.id : null,
      itemRevisions,
    });
    operation.assertCurrent();
    const orgKeys = await this.buildOrgKeys(operation.cacheEnvelope.response.profile);
    if (metadata.length !== 1
        || !metadata[0]!.isMember
        || metadata[0]!.organization.status !== 2
        || metadata[0]!.organization.enabled !== true
        || !orgKeys.has(organizationId)
        || defaultCollections.length !== 1) {
      return Object.freeze({
        status: 'blocked',
        organizationId,
        personalItemCount: personal.length,
        reason: 'target_unavailable',
        policyRevisionDate: transferPolicy.revisionDate,
        snapshotDigest,
        itemRevisions,
      });
    }
    if (new Set(personal.map((cipher) => cipher.id)).size !== personal.length) {
      return Object.freeze({
        status: 'blocked',
        organizationId,
        personalItemCount: personal.length,
        reason: 'unsupported_items',
        policyRevisionDate: transferPolicy.revisionDate,
        snapshotDigest,
        itemRevisions,
      });
    }
    try {
      await this.authorizeOrganizationDataOwnershipTransport();
      operation.assertCurrent();
    } catch {
      return Object.freeze({
        status: 'blocked',
        organizationId,
        personalItemCount: personal.length,
        reason: 'target_unavailable',
        policyRevisionDate: transferPolicy.revisionDate,
        snapshotDigest,
        itemRevisions,
      });
    }
    for (const candidate of personal) {
      try {
        const cipher = this.requireSupportedCipher(candidate);
        if (!isIsoTimestamp(cipher.revisionDate)
            || this.deps.policyGate.isItemRestricted(operation.policyLease, {
              type: cipher.type,
              organizationId,
            })) throw new Error('unsupported');
      } catch {
        return Object.freeze({
          status: 'blocked',
          organizationId,
          personalItemCount: personal.length,
          reason: 'unsupported_items',
          policyRevisionDate: transferPolicy.revisionDate,
          snapshotDigest,
          itemRevisions,
        });
      }
    }
    operation.assertCurrent();
    return Object.freeze({
      status: 'migration_available',
      organizationId,
      collectionId: defaultCollections[0]!.id,
      personalItemCount: personal.length,
      policyRevisionDate: transferPolicy.revisionDate,
      snapshotDigest,
      itemRevisions,
    });
  }

  private issueOrganizationDataOwnershipGrant(
    popupDocumentId: string,
    grantOperation: OrganizationDataOwnershipOperation,
    status: Extract<InternalOrganizationDataOwnershipStatus, {
      readonly status: 'migration_available' | 'blocked';
    }>,
    operation: VaultOperationContext,
  ): OrganizationDataOwnershipGrantReceipt {
    operation.assertCurrent();
    if (operation.cacheEpoch === undefined) {
      throw new AppError('denied', 'Organization data ownership authorization is unavailable.');
    }
    const now = this.organizationDataOwnershipGrantTime();
    this.pruneOrganizationDataOwnershipGrants(now);
    while (this.organizationDataOwnershipGrants.size >= MAX_ORGANIZATION_DATA_OWNERSHIP_GRANTS) {
      const oldest = this.organizationDataOwnershipGrants.entries().next().value as
        | [string, StoredOrganizationDataOwnershipGrant]
        | undefined;
      if (!oldest) break;
      this.organizationDataOwnershipGrants.delete(oldest[0]);
      this.revokedOrganizationDataOwnershipGrantIds.set(oldest[0], oldest[1].expiresAt);
      this.boundRevokedOrganizationDataOwnershipGrants();
    }
    const authorizationId = this.createOrganizationDataOwnershipGrantId();
    const expiresAt = now + ORGANIZATION_DATA_OWNERSHIP_GRANT_TTL_MS;
    const collectionId = grantOperation === 'migrate' && status.status === 'migration_available'
      ? status.collectionId
      : null;
    this.organizationDataOwnershipGrants.set(authorizationId, Object.freeze({
      popupDocumentId,
      operation: grantOperation,
      organizationId: status.organizationId,
      collectionId,
      snapshotDigest: status.snapshotDigest,
      itemRevisions: Object.freeze(status.itemRevisions.map((item) => Object.freeze({ ...item }))),
      sessionLease: operation.sessionLease,
      accountLease: operation.accountLease,
      policyLease: operation.policyLease,
      policyRevisionDate: status.policyRevisionDate,
      identityEpoch: operation.identityEpoch,
      cacheEpoch: operation.cacheEpoch,
      rawGeneration: operation.cacheEnvelope.rawGeneration,
      expiresAt,
    }));
    return Object.freeze({ authorizationId, expiresAt });
  }

  private takeOrganizationDataOwnershipGrant(
    authorizationId: string,
    popupDocumentId: string,
    grantOperation: OrganizationDataOwnershipOperation,
    organizationId: string,
    collectionId: string | null,
  ): StoredOrganizationDataOwnershipGrant | undefined {
    const grant = typeof authorizationId === 'string'
      ? this.organizationDataOwnershipGrants.get(authorizationId)
      : undefined;
    if (grant) this.organizationDataOwnershipGrants.delete(authorizationId);

    let now: number;
    try { now = this.organizationDataOwnershipGrantTime(); } catch { return undefined; }
    this.pruneOrganizationDataOwnershipGrants(now);
    const revokedUntil = typeof authorizationId === 'string'
      ? this.revokedOrganizationDataOwnershipGrantIds.get(authorizationId)
      : undefined;
    if (revokedUntil !== undefined) {
      this.revokedOrganizationDataOwnershipGrantIds.delete(authorizationId);
      if (revokedUntil > now) {
        throw new AppError('conflict', 'The ownership action changed after it was reviewed.');
      }
    }
    if (!grant
        || !UUID_V4.test(authorizationId)
        || grant.expiresAt <= now
        || grant.popupDocumentId !== popupDocumentId
        || grant.operation !== grantOperation
        || grant.organizationId !== organizationId
        || grant.collectionId !== collectionId) return undefined;
    return grant;
  }

  private async resolveOrganizationDataOwnershipGrant(
    grant: StoredOrganizationDataOwnershipGrant,
  ): Promise<{
    readonly operation: VaultOperationContext;
    readonly status: Extract<InternalOrganizationDataOwnershipStatus, {
      readonly status: 'migration_available' | 'blocked';
    }>;
  }> {
    const reconciliation = await this.readOrganizationDataOwnershipReconciliation(
      accountKeyFor(grant.accountLease),
    );
    if (reconciliation) {
      throw new AppError(
        reconciliation.reason,
        'Synchronize the vault before taking another organization data ownership action.',
      );
    }
    try {
      this.deps.sessionGate.assert(grant.sessionLease);
      this.deps.accountGate.assert(grant.accountLease);
      this.deps.policyGate.assert(grant.policyLease);
      this.assertIdentityEpoch(grant.identityEpoch);
    } catch {
      throw new AppError('denied', 'Organization data ownership authorization is no longer current.');
    }
    if (this.cacheEpoch !== grant.cacheEpoch) {
      throw new AppError('conflict', 'The vault changed after organization data ownership was reviewed.');
    }
    const operation = await this.beginVaultOperation(
      { cache: true, allowPendingDataOwnership: true },
      { accountLease: grant.accountLease, sessionLease: grant.sessionLease },
    );
    if (operation.cacheEnvelope.rawGeneration !== grant.rawGeneration) {
      throw new AppError('conflict', 'The vault changed after organization data ownership was reviewed.');
    }
    try {
      this.assertPolicyForSource(grant.policyLease, operation.cacheEnvelope, grant.accountLease);
    } catch {
      throw new AppError('conflict', 'The ownership policy changed after it was reviewed.');
    }
    const status = await this.organizationDataOwnershipStatus(operation);
    await operation.assertCacheCurrent();
    operation.assertCurrent();
    if ((status.status !== 'migration_available' && status.status !== 'blocked')
        || status.organizationId !== grant.organizationId
        || (grant.operation === 'migrate'
          && (status.status !== 'migration_available' || status.collectionId !== grant.collectionId))
        || status.policyRevisionDate !== grant.policyRevisionDate
        || status.snapshotDigest !== grant.snapshotDigest
        || !sameOrganizationDataOwnershipItemRevisions(status.itemRevisions, grant.itemRevisions)) {
      throw new AppError('conflict', 'The ownership migration changed after it was reviewed.');
    }
    return Object.freeze({ operation, status });
  }

  private organizationDataOwnershipGrantTime(): number {
    const now = (this.deps.now ?? Date.now)();
    if (!Number.isFinite(now) || now < 0) {
      throw new AppError('denied', 'Organization data ownership authorization clock is invalid.');
    }
    return now;
  }

  private pruneOrganizationDataOwnershipGrants(now: number): void {
    for (const [authorizationId, grant] of this.organizationDataOwnershipGrants) {
      if (grant.expiresAt <= now) this.organizationDataOwnershipGrants.delete(authorizationId);
    }
    for (const [authorizationId, expiresAt] of this.revokedOrganizationDataOwnershipGrantIds) {
      if (expiresAt <= now) this.revokedOrganizationDataOwnershipGrantIds.delete(authorizationId);
    }
  }

  private createOrganizationDataOwnershipGrantId(): string {
    for (let attempt = 0; attempt < 4; attempt += 1) {
      const authorizationId = globalThis.crypto.randomUUID();
      if (!UUID_V4.test(authorizationId)) break;
      if (!this.organizationDataOwnershipGrants.has(authorizationId)
          && !this.revokedOrganizationDataOwnershipGrantIds.has(authorizationId)) return authorizationId;
    }
    throw new AppError('denied', 'Organization data ownership authorization could not be created.');
  }

  revokeOrganizationDataOwnershipGrants(): void {
    let now: number;
    try {
      now = this.organizationDataOwnershipGrantTime();
    } catch {
      this.organizationDataOwnershipGrants.clear();
      this.revokedOrganizationDataOwnershipGrantIds.clear();
      return;
    }
    this.pruneOrganizationDataOwnershipGrants(now);
    for (const [authorizationId, grant] of this.organizationDataOwnershipGrants) {
      this.revokedOrganizationDataOwnershipGrantIds.set(authorizationId, grant.expiresAt);
    }
    this.organizationDataOwnershipGrants.clear();
    this.boundRevokedOrganizationDataOwnershipGrants();
  }

  private boundRevokedOrganizationDataOwnershipGrants(): void {
    while (this.revokedOrganizationDataOwnershipGrantIds.size > MAX_ORGANIZATION_DATA_OWNERSHIP_GRANTS) {
      const oldest = this.revokedOrganizationDataOwnershipGrantIds.keys().next().value as string | undefined;
      if (oldest === undefined) break;
      this.revokedOrganizationDataOwnershipGrantIds.delete(oldest);
    }
  }

  private async markOrganizationDataOwnershipReconciliation(
    accountKey: string,
    operation: OrganizationDataOwnershipOperation,
    error: unknown,
  ): Promise<void> {
    if (!(error instanceof AppError)
        || (error.code !== 'outcome_unknown' && error.code !== 'committed_unsynced')) return;
    const stored = Object.freeze({
      schemaVersion: 1 as const,
      operation,
      reason: error.code,
    });
    const reconciliation = Object.freeze({
      accountKey,
      ...stored,
    });
    this.organizationDataOwnershipReconciliationState = Object.freeze({
      status: 'required',
      reconciliation,
    });
    this.revokeOrganizationDataOwnershipGrants();
    const key = await organizationDataOwnershipReconciliationKey(accountKey);
    try {
      await this.deps.localStore.set(key, stored);
    } catch {
      let confirmed = false;
      try {
        confirmed = sameOrganizationDataOwnershipReconciliation(
          parseOrganizationDataOwnershipReconciliation(
            await this.deps.localStore.get<unknown>(key),
          ),
          stored,
        );
      } catch {
        // The cache-clear fallback below is the fail-closed terminal state.
      }
      if (confirmed) return;
      try {
        await this.deps.sessionStore.set(key, stored);
      } catch {
        // Clearing the raw cache remains mandatory even if the secondary marker cannot be written.
      }
      await this.clearCache();
      throw new AppError(
        'committed_unsynced',
        'The ownership result is uncertain and its reconciliation marker could not be persisted.',
      );
    }
  }

  private async readOrganizationDataOwnershipReconciliation(
    accountKey: string,
  ): Promise<OrganizationDataOwnershipReconciliation | undefined> {
    const current = this.organizationDataOwnershipReconciliationState;
    if (current.status === 'required' && current.reconciliation.accountKey === accountKey) {
      return current.reconciliation;
    }
    if (current.status === 'clear' && current.accountKey === accountKey) {
      return undefined;
    }
    let value: unknown;
    try {
      const key = await organizationDataOwnershipReconciliationKey(accountKey);
      value = await this.deps.localStore.get<unknown>(key);
      value ??= await this.deps.sessionStore.get<unknown>(key);
    } catch {
      throw new AppError(
        'committed_unsynced',
        'Organization data ownership reconciliation state is unavailable.',
      );
    }
    if (value === undefined) {
      this.organizationDataOwnershipReconciliationState = Object.freeze({ status: 'clear', accountKey });
      return undefined;
    }
    const stored = parseOrganizationDataOwnershipReconciliation(value) ?? {
      schemaVersion: 1 as const,
      operation: 'migrate' as const,
      reason: 'outcome_unknown' as const,
    };
    const reconciliation = Object.freeze({ accountKey, ...stored });
    this.organizationDataOwnershipReconciliationState = Object.freeze({
      status: 'required',
      reconciliation,
    });
    return reconciliation;
  }

  private async clearOrganizationDataOwnershipReconciliation(accountKey: string): Promise<void> {
    const key = await organizationDataOwnershipReconciliationKey(accountKey);
    await Promise.all([
      this.deps.localStore.remove(key),
      this.deps.sessionStore.remove(key),
    ]);
    const current = this.organizationDataOwnershipReconciliationState;
    if (current.status === 'unknown'
        || (current.status === 'clear' && current.accountKey === accountKey)
        || (current.status === 'required' && current.reconciliation.accountKey === accountKey)) {
      this.organizationDataOwnershipReconciliationState = Object.freeze({ status: 'clear', accountKey });
    }
  }

  private hasKnownClearOrganizationDataOwnershipReconciliation(accountKey: string): boolean {
    const current = this.organizationDataOwnershipReconciliationState;
    return current.status === 'clear' && current.accountKey === accountKey;
  }

  private async adoptOrganizationDataOwnershipUpgrade(
    grant: StoredOrganizationDataOwnershipGrant,
    expected: readonly OrganizationDataOwnershipItemRevision[],
    upgradedCipherId: string,
  ): Promise<readonly OrganizationDataOwnershipItemRevision[]> {
    const operation = await this.beginVaultOperation(
      { cache: true, allowPendingDataOwnership: true },
      { accountLease: grant.accountLease, sessionLease: grant.sessionLease },
    );
    const status = await this.organizationDataOwnershipStatus(operation);
    await operation.assertCacheCurrent();
    operation.assertCurrent();
    if (status.status !== 'migration_available'
        || status.organizationId !== grant.organizationId
        || status.collectionId !== grant.collectionId
        || status.policyRevisionDate !== grant.policyRevisionDate
        || !sameOrganizationDataOwnershipItemSet(status.itemRevisions, expected)) {
      throw new AppError('conflict', 'The personal vault changed during migration preparation.');
    }
    for (let index = 0; index < expected.length; index += 1) {
      const before = expected[index]!;
      const after = status.itemRevisions[index]!;
      if (before.cipherId !== upgradedCipherId && before.revisionDate !== after.revisionDate) {
        throw new AppError('conflict', 'Another personal item changed during migration preparation.');
      }
    }
    return status.itemRevisions;
  }

  async migrateOrganizationDataOwnership(
    organizationId: string,
    collectionId: string,
    authorizationId: string,
    popupDocumentId: string,
    masterPassword: string,
  ): Promise<VaultListing> {
    const grant = this.takeOrganizationDataOwnershipGrant(
      authorizationId,
      popupDocumentId,
      'migrate',
      organizationId,
      collectionId,
    );
    if (!grant) {
      throw new AppError('denied', 'Organization data ownership migration is unavailable.');
    }
    try {
    const resolvedGrant = await this.resolveOrganizationDataOwnershipGrant(grant);
    const initialOperation = resolvedGrant.operation;
    const status = resolvedGrant.status;
    if (status.status !== 'migration_available') {
      throw new AppError('conflict', 'The ownership migration changed after it was reviewed.');
    }
    let expectedItemRevisions = grant.itemRevisions;
    initialOperation.assertCurrent();
    if (!masterPassword || !(await this.deps.auth.verifyMasterPassword(masterPassword))) {
      throw new AppError('reprompt_required', 'Master password required to migrate personal items.');
    }
    initialOperation.assertCurrent();
    const legacyAttachments = initialOperation.cacheEnvelope.response.ciphers
      .filter((cipher) => cipher.organizationId == null)
      .flatMap((cipher) => (cipher.attachments ?? [])
        .filter((attachment) => attachment.key == null)
        .map((attachment) => Object.freeze({ cipherId: cipher.id, attachmentId: attachment.id })));
    await initialOperation.assertCacheCurrent();

    for (const attachment of legacyAttachments) {
      await this.upgradeLegacyAttachmentForDataOwnership(
        attachment.cipherId,
        attachment.attachmentId,
        organizationId,
        masterPassword,
        {
          accountLease: initialOperation.accountLease,
          sessionLease: initialOperation.sessionLease,
        },
      );
      initialOperation.assertBaseCurrent();
      expectedItemRevisions = await this.adoptOrganizationDataOwnershipUpgrade(
        grant,
        expectedItemRevisions,
        attachment.cipherId,
      );
    }
    initialOperation.assertBaseCurrent();

    const result = await this.runVaultMutation('cipher.shareManyForDataOwnership', async ({ operation, remote, reconcile }) => {
      const currentStatus = await this.organizationDataOwnershipStatus(operation);
      if (currentStatus.status !== 'migration_available'
          || currentStatus.organizationId !== organizationId
          || currentStatus.collectionId !== collectionId
          || currentStatus.policyRevisionDate !== grant.policyRevisionDate
          || !sameOrganizationDataOwnershipItemRevisions(
            currentStatus.itemRevisions,
            expectedItemRevisions,
          )) {
        throw new AppError('conflict', 'The ownership migration changed after it was reviewed.');
      }
      if (!masterPassword || !(await this.deps.auth.verifyMasterPassword(masterPassword))) {
        throw new AppError('reprompt_required', 'Master password required to migrate personal items.');
      }
      operation.assertCurrent();

      const cache = operation.cacheEnvelope.response;
      const originals = cache.ciphers.filter((cipher) => cipher.organizationId == null)
        .map((cipher) => this.requireSupportedCipher(cipher));
      if (originals.length === 0) {
        return Object.freeze({
          listing: (await this.requireDerivedSnapshot()).listing,
          verified: true,
          remainingPersonalItems: 0,
        });
      }
      const organizationKeys = await this.buildOrgKeys(cache.profile);
      const organizationKey = organizationKeys.get(organizationId);
      if (!organizationKey) throw new AppError('denied', 'The organization key is unavailable.');
      const encryptedFor = requireCreateTargetId(cache.profile.id, 'account');
      const hasSshKey = originals.some((cipher) => cipher.type === 5);
      const sshAuthorization = hasSshKey ? await this.authorizeSshCipherWrite() : undefined;
      const transportAuthorization = await this.authorizeOrganizationDataOwnershipTransport();
      operation.assertCurrent();

      const prepared: Array<{
        readonly original: SupportedCipherResponse;
        readonly share: PreparedCipherShare;
      }> = [];
      for (const original of originals) {
        this.assertCipherTargetPolicyAllowed(operation.policyLease, original.type, organizationId);
        this.assertCipherPasswordViewAllowed(original);
        await this.validatePersonalShareCipher(original, operation.userKey);
        let share: PreparedCipherShare;
        try {
          const rotated = await rotateCipher(original, operation.userKey, organizationKey);
          await verifyRotatedCipher(rotated, organizationKey);
          share = this.prepareCipherShare(rotated, original, organizationId);
        } catch {
          throw new AppError('denied', 'A personal item cannot be moved without losing encrypted data.');
        }
        prepared.push(Object.freeze({ original, share }));
        operation.assertCurrent();
      }
      await operation.assertCacheCurrent();
      let api = sshAuthorization
        ? this.sshWriteApi(operation, sshAuthorization)
        : operation.api;
      api = api.withRequestGuard(() => {
        operation.assertCurrent();
        transportAuthorization.assertCurrent();
      });
      const request = Object.freeze({
        ciphers: Object.freeze(prepared.map(({ original, share }) => Object.freeze({
          ...share.request,
          id: original.id,
          organizationId,
          encryptedFor,
        }))),
        collectionIds: Object.freeze([collectionId]),
        encryptedFor,
      });
      const reconcileAndVerify = async () => {
        const listing = await reconcile(() => this.syncAfterMutation(operation));
        const authoritativeValid = validAuthoritativeBulkShare(
          operation.cacheEnvelope.response.ciphers,
          prepared,
          organizationId,
          [collectionId],
        );
        const remainingPersonalItems = operation.cacheEnvelope.response.ciphers.filter(
          (cipher) => cipher.organizationId == null,
        ).length;
        const ownership = await this.organizationDataOwnershipStatus(operation);
        return Object.freeze({
          listing,
          verified: authoritativeValid
            && remainingPersonalItems === 0
            && ownership.status === 'compliant',
          remainingPersonalItems,
        });
      };

      if (transportAuthorization.serverKind === 'bitwarden') {
        try {
          assertCipherBulkShareRequest(request);
        } catch {
          throw new AppError('denied', 'The personal vault is too large or malformed for one safe migration.');
        }
        const receipts = await remote(async (accessToken) => {
          try {
            return await api.shareCiphers(accessToken, request);
          } catch (error) {
            if (error instanceof AppError
                || (error instanceof ApiHttpError && error.status === 401)) throw error;
            throw new VaultMutationCommitError(
              'outcome_unknown',
              'The organization data ownership request may have partially committed.',
            );
          }
        });
        if (receipts !== undefined && !validBulkShareReceipts(
          receipts,
          prepared,
          organizationId,
        )) {
          throw new AppError('outcome_unknown', 'The server returned an invalid bulk-share receipt.');
        }
        return reconcileAndVerify();
      }

      let completed = 0;
      for (const entry of prepared) {
        try {
          await remote(async (accessToken) => {
            try {
              return await api.shareCipher(accessToken, entry.original.id, {
                cipher: entry.share.request,
                collectionIds: [collectionId],
              });
            } catch (error) {
              if (error instanceof AppError
                  || (error instanceof ApiHttpError && error.status === 401)) throw error;
              throw new VaultMutationCommitError(
                'outcome_unknown',
                'The Vaultwarden share request may have partially committed.',
              );
            }
          });
          completed += 1;
        } catch (error) {
          if (completed === 0) throw error;
          return reconcileAndVerify();
        }
      }
      return reconcileAndVerify();
    }, {
      cache: true,
      allowPendingDataOwnership: true,
      captured: {
        accountLease: initialOperation.accountLease,
        sessionLease: initialOperation.sessionLease,
      },
    });
    if (!result.verified) {
      throw new AppError(
        result.remainingPersonalItems > 0 ? 'conflict' : 'error',
        result.remainingPersonalItems > 0
          ? 'Only part of the personal vault was migrated. Review the remaining items and retry.'
          : 'The migrated items did not match the authoritative vault after sync.',
      );
    }
    return result.listing;
    } catch (error) {
      await this.markOrganizationDataOwnershipReconciliation(
        accountKeyFor(grant.accountLease),
        'migrate',
        error,
      );
      throw error;
    }
  }

  async leaveOrganizationDataOwnership(
    organizationId: string,
    authorizationId: string,
    popupDocumentId: string,
  ): Promise<VaultListing> {
    const grant = this.takeOrganizationDataOwnershipGrant(
      authorizationId,
      popupDocumentId,
      'leave',
      organizationId,
      null,
    );
    if (!grant) {
      throw new AppError('denied', 'Organization data ownership departure is unavailable.');
    }
    try {
    await this.resolveOrganizationDataOwnershipGrant(grant);
    const expectedOrganizationId = requireCreateTargetId(organizationId, 'organization');
    const result = await this.runVaultMutation('organization.revokeSelfForDataOwnership', async ({
      operation,
      remote,
      reconcile,
    }) => {
      const status = await this.organizationDataOwnershipStatus(operation);
      if ((status.status !== 'migration_available' && status.status !== 'blocked')
          || status.organizationId !== expectedOrganizationId
          || status.policyRevisionDate !== grant.policyRevisionDate
          || status.snapshotDigest !== grant.snapshotDigest
          || !sameOrganizationDataOwnershipItemRevisions(
            status.itemRevisions,
            grant.itemRevisions,
          )) {
        throw new AppError('conflict', 'The ownership departure changed after it was reviewed.');
      }
      await operation.assertCacheCurrent();
      let absenceLikeRejection: ApiHttpError | undefined;
      await remote(async (accessToken) => {
        try {
          await operation.api.revokeCurrentOrganizationMembership(
            accessToken,
            expectedOrganizationId,
          );
        } catch (error) {
          if (!(error instanceof ApiHttpError) || (error.status !== 403 && error.status !== 404)) {
            throw error;
          }
          // Another client may already have removed this membership. Treat the response as an
          // uncertain idempotent outcome and prove the postcondition with the authoritative sync.
          absenceLikeRejection = error;
        }
      });
      const listing = await reconcile(() => this.syncAfterMutation(operation));
      const current = await this.organizationDataOwnershipStatus(operation);
      const membershipStillPresent = selectOrganizationMetadata(
        operation.cacheEnvelope.response.profile,
      ).entries.some((entry) => (
        entry.organization.id === expectedOrganizationId && entry.isMember
      ));
      if (membershipStillPresent
          || ((current.status === 'migration_available' || current.status === 'blocked')
            && current.organizationId === expectedOrganizationId)) {
        return Object.freeze({
          listing,
          rejection: absenceLikeRejection
            ? new AppError('denied', 'The server rejected leaving this organization.')
            : new AppError('outcome_unknown', 'The organization departure could not be verified after sync.'),
        });
      }
      return Object.freeze({ listing });
    }, {
      cache: true,
      allowPendingDataOwnership: true,
      captured: {
        accountLease: grant.accountLease,
        sessionLease: grant.sessionLease,
      },
    });
    if ('rejection' in result && result.rejection) throw result.rejection;
    return result.listing;
    } catch (error) {
      await this.markOrganizationDataOwnershipReconciliation(
        accountKeyFor(grant.accountLease),
        'leave',
        error,
      );
      throw error;
    }
  }

  /** Create a folder: encrypt the name under the user key, POST it, then re-sync the listing. */
  async createFolder(name: string): Promise<VaultListing> {
    return this.runVaultMutation('folder.create', async ({ operation, remote, reconcile }) => {
      const encryptedName = await encryptToText(name, operation.userKey);
      await remote((accessToken) => operation.api.createFolder(accessToken, encryptedName));
      return reconcile(() => this.syncAfterMutation(operation));
    });
  }

  /** Rename a folder: encrypt the new name under the user key, PUT it, then re-sync the listing. */
  async renameFolder(id: string, name: string): Promise<VaultListing> {
    return this.runVaultMutation('folder.update', async ({ operation, remote, reconcile }) => {
      const encryptedName = await encryptToText(name, operation.userKey);
      await remote((accessToken) => operation.api.updateFolder(accessToken, id, encryptedName));
      return reconcile(() => this.syncAfterMutation(operation));
    });
  }

  /** Delete a folder, then re-sync the listing (its ciphers fall back to No Folder server-side). */
  async deleteFolder(id: string): Promise<VaultListing> {
    return this.runVaultMutation('folder.delete', async ({ operation, remote, reconcile }) => {
      await remote((accessToken) => operation.api.deleteFolder(accessToken, id));
      return reconcile(() => this.syncAfterMutation(operation));
    });
  }

  /** Resolve an org key from the operation's generation-bound profile, or fail closed. */
  private async requireOrgKey(orgId: string, profile: SyncProfile): Promise<SymmetricKey> {
    const orgKeys = await this.buildOrgKeys(profile);
    const key = orgKeys.get(orgId);
    if (!key) throw new AppError('error', 'Organization key unavailable');
    return key;
  }

  private async requireCollectionOrganizationContext(
    operation: VaultOperationContext,
    organizationId: string,
  ): Promise<{
    readonly authority: CollectionOrganizationAuthority;
    readonly key: SymmetricKey;
    readonly organizationUserId?: string;
  }> {
    const matches = selectOrganizationMetadata(operation.cacheEnvelope.response.profile).entries
      .filter((entry) => entry.organization.id === organizationId);
    if (matches.length !== 1 || (!matches[0]!.isMember && !matches[0]!.isProviderUser)) {
      throw new AppError('denied', 'The organization is not available for collection management.');
    }
    const authority = toCollectionOrganizationAuthority(
      matches[0]!.organization,
      matches[0]!.isProviderUser,
    );
    const provider = matches[0]!.isProviderUser;
    const status = matches[0]!.organization.status;
    const enabled = matches[0]!.organization.enabled;
    if ((!provider && (status !== 2 || enabled !== true))
        || (provider && status !== undefined && status !== null && status !== 2)
        || (provider && enabled !== undefined && enabled !== null && enabled !== true)) {
      throw new AppError('denied', 'The organization is not available for collection management.');
    }
    const key = await this.requireOrgKey(organizationId, operation.cacheEnvelope.response.profile);
    operation.assertCurrent();
    const organizationUserId = matches[0]!.isMember
      && typeof matches[0]!.organization.organizationUserId === 'string'
      && matches[0]!.organization.organizationUserId.length > 0
      ? requireCreateTargetId(matches[0]!.organization.organizationUserId, 'organization user')
      : undefined;
    return Object.freeze({
      authority,
      key,
      ...(organizationUserId ? { organizationUserId } : {}),
    });
  }

  /** Create a collection: encrypt the name under the org key, POST it, then re-sync. */
  async createCollection(orgId: string, name: string): Promise<VaultListing> {
    return this.runVaultMutation('collection.create', async ({ operation, remote, reconcile }) => {
      const context = await this.requireCollectionOrganizationContext(operation, orgId);
      if (!resolveCollectionCapabilities(context.authority).canCreate) {
        throw new AppError('denied', 'This account cannot create collections in the organization.');
      }
      if (!context.organizationUserId) {
        throw new AppError('denied', 'A collection manager could not be bound to this account.');
      }
      const encryptedName = await encryptToText(name, context.key);
      await operation.assertCacheCurrent();
      await remote((accessToken) => operation.api.createCollection(accessToken, orgId, encryptedName, {
        groups: [],
        users: [{
          id: context.organizationUserId!,
          readOnly: false,
          hidePasswords: false,
          manage: true,
        }],
      }));
      return reconcile(() => this.syncAfterMutation(operation));
    }, { cache: true });
  }

  /** Rename through Bitwarden's name-only update without replaying a stale access snapshot. */
  async renameCollection(orgId: string, id: string, name: string): Promise<VaultListing> {
    return this.runVaultMutation('collection.update', async ({ operation, remote, reconcile }) => {
      const cachedCollections = (operation.cacheEnvelope.response.collections ?? [])
        .filter((collection) => collection.id === id);
      if (cachedCollections.length !== 1 || cachedCollections[0]!.organizationId !== orgId) {
        throw new AppError('error', 'Collection is not available');
      }
      const cachedCollection = cachedCollections[0]!;
      const context = await this.requireCollectionOrganizationContext(operation, orgId);
      if (!resolveCollectionCapabilities(context.authority, cachedCollection).canRename) {
        throw new AppError('denied', 'This collection cannot be renamed by this account.');
      }
      const authorization = await this.authorizeCollectionNameOnlyUpdate();
      operation.assertCurrent();
      const externalId = normalizeOptionalExternalId(
        cachedCollection as unknown as Record<string, unknown>,
      );
      if (!externalId.valid) throw new AppError('denied', 'Collection identity is invalid.');
      await operation.assertCacheCurrent();
      const encryptedName = await encryptToText(name, context.key);
      await operation.assertCacheCurrent();
      const api = operation.api.withRequestGuard(() => {
        operation.assertCurrent();
        authorization.assertCurrent();
      });
      const receipt = await remote((accessToken) => api.updateCollectionName(
        accessToken, orgId, id, encryptedName, externalId.value,
      ));
      if (!validCollectionUpdateReceipt(receipt, orgId, id, encryptedName, externalId.value)) {
        throw new AppError('outcome_unknown', 'The server returned an invalid collection update receipt.');
      }
      const listing = await reconcile(() => this.syncAfterMutation(operation));
      const authoritative = (operation.cacheEnvelope.response.collections ?? [])
        .filter((collection) => collection.id === id);
      if (authoritative.length !== 1 || !validCollectionUpdateReceipt(
        authoritative[0]!,
        orgId,
        id,
        encryptedName,
        externalId.value,
      )) {
        throw new AppError('outcome_unknown', 'The renamed collection could not be verified after sync.');
      }
      return listing;
    }, { cache: true });
  }

  /** Delete a collection, then re-sync (member ciphers keep existing, with the collection removed). */
  async deleteCollection(orgId: string, id: string): Promise<VaultListing> {
    return this.runVaultMutation('collection.delete', async ({ operation, remote, reconcile }) => {
      const cachedCollections = (operation.cacheEnvelope.response.collections ?? [])
        .filter((collection) => collection.id === id);
      if (cachedCollections.length !== 1 || cachedCollections[0]!.organizationId !== orgId) {
        throw new AppError('denied', 'Collection is not available.');
      }
      const context = await this.requireCollectionOrganizationContext(operation, orgId);
      if (!resolveCollectionCapabilities(context.authority, cachedCollections[0]).canDelete) {
        throw new AppError('denied', 'This collection cannot be deleted by this account.');
      }
      await operation.assertCacheCurrent();
      await remote((accessToken) => operation.api.deleteCollection(accessToken, orgId, id));
      const listing = await reconcile(() => this.syncAfterMutation(operation));
      if ((operation.cacheEnvelope.response.collections ?? []).some((collection) => (
        collection.id === id
      ))) {
        throw new AppError('outcome_unknown', 'The deleted collection is still present after sync.');
      }
      return listing;
    }, { cache: true });
  }

  /** Assign an organization cipher to collections (all in the cipher's org), then re-sync. */
  async setCipherCollections(id: string, collectionIds: string[]): Promise<VaultListing> {
    const requestedCollectionIds = normalizeCollectionAssignmentIds(collectionIds);
    return this.runVaultMutation('cipher.collections', async ({ operation, remote, reconcile }) => {
    const cache = operation.cacheEnvelope!.response;
    const candidate = cache.ciphers.find((c) => c.id === id);
    if (!candidate) throw new AppError('error', 'Item is not available');
    const cipher = this.requireSupportedCipher(candidate);
    if (cipher.deletedDate != null) {
      throw new AppError('denied', 'Items in the trash cannot be assigned to collections.');
    }
    this.assertCipherEditAllowed(operation.policyLease, cipher);
    const orgId = cipher.organizationId ?? undefined;
    if (!orgId) throw new AppError('error', 'Only organization items can be assigned to collections');
    const context = await this.requireCollectionOrganizationContext(operation, orgId);
    const currentCollectionIds = normalizeCollectionAssignmentIds(cipher.collectionIds ?? []);
    const current = new Set(currentCollectionIds);
    const requested = new Set(requestedCollectionIds);
    const collectionsById = groupCollectionsById(cache.collections ?? []);
    for (const collectionId of requested) {
      const matches = collectionsById.get(collectionId) ?? [];
      if (matches.length === 0 && current.has(collectionId)) continue;
      if (matches.length !== 1 || matches[0]!.organizationId !== orgId) {
        throw new AppError('denied', 'Invalid collection for this item');
      }
    }
    const currentHasDefaultCollection = [...current].some((collectionId) => {
      const matches = collectionsById.get(collectionId) ?? [];
      return matches.length === 1
        && matches[0]!.organizationId === orgId
        && matches[0]!.type === 1;
    });
    const addsDefaultCollection = [...requested].some((collectionId) => {
      if (current.has(collectionId)) return false;
      const matches = collectionsById.get(collectionId) ?? [];
      return matches.length === 1
        && matches[0]!.organizationId === orgId
        && matches[0]!.type === 1;
    });
    if (addsDefaultCollection && current.size > 0 && !currentHasDefaultCollection) {
      throw new AppError(
        'denied',
        'A shared collection item cannot be moved into a default user collection.',
      );
    }
    for (const collectionId of new Set([...current, ...requested])) {
      if (current.has(collectionId) === requested.has(collectionId)) continue;
      const matches = collectionsById.get(collectionId) ?? [];
      if (matches.length !== 1
          || matches[0]!.organizationId !== orgId
          || !resolveCollectionCapabilities(context.authority, matches[0]).canAssign) {
        throw new AppError('denied', 'This collection assignment cannot be changed by this account.');
      }
    }
    await operation.assertCacheCurrent();
    await remote((accessToken) => (
      operation.api.updateCipherCollections(accessToken, id, requestedCollectionIds)
    ));
    const listing = await reconcile(() => this.syncAfterMutation(operation));
    const authoritative = operation.cacheEnvelope.response.ciphers
      .filter((candidate) => candidate.id === id);
    if (authoritative.length !== 1
        || !sameCollectionIds(authoritative[0]!.collectionIds, requestedCollectionIds)) {
      throw new AppError('outcome_unknown', 'The collection assignment could not be verified after sync.');
    }
    return listing;
    }, { cache: true });
  }

  /** Non-diagnostic write availability for extension UI gating. No lease or server detail escapes. */
  async getSshKeyWriteAvailability(): Promise<{ readonly available: boolean }> {
    try {
      const operation = await this.beginVaultOperation({ cache: true });
      if (!this.canCreatePersonalCipher(operation.policyLease, 5)
          && !(await this.hasOrganizationCreateTarget(operation, 5))) {
        return Object.freeze({ available: false });
      }
      await this.authorizeSshCipherWrite();
      await operation.assertCacheCurrent();
      operation.assertCurrent();
      return Object.freeze({ available: true });
    } catch {
      return Object.freeze({ available: false });
    }
  }

  private async hasOrganizationCreateTarget(
    operation: VaultOperationContext,
    cipherType: number,
  ): Promise<boolean> {
    const cache = operation.cacheEnvelope.response;
    const keys = await this.buildOrgKeys(cache.profile);
    for (const metadata of selectOrganizationMetadata(cache.profile).entries) {
      const organization = metadata.organization;
      if ((!metadata.isMember && !metadata.isProviderUser)
          || organization.status !== 2
          || organization.enabled !== true
          || !keys.has(organization.id)
          || this.deps.policyGate.isItemRestricted(operation.policyLease, {
            type: cipherType,
            organizationId: organization.id,
          })) continue;
      if ((cache.collections ?? []).some((collection) => (
        collection.organizationId === organization.id
        && resolveCollectionCapabilities(
          toCollectionOrganizationAuthority(organization, metadata.isProviderUser),
          collection,
        ).canAssign
      ))) return true;
    }
    operation.assertCurrent();
    return false;
  }

  /** Return only public SSH material. The private key is never present on this DTO. */
  async getSshKeyDetails(
    id: string,
    masterPassword?: string,
    bindFinalAuthority?: VaultFinalAuthorityBinder,
  ): Promise<SshKeyPublicDetails | undefined> {
    const operation = await this.beginVaultOperation({ cache: true });
    const access = await this.prepareSshCipherFieldAccess(operation, id, masterPassword);
    if (!access) return undefined;
    const publicKey = access.encryptedSshKey.publicKey
      ? await decryptValidatedSshField(
          access.encryptedSshKey.publicKey,
          access.fieldKey,
          'publicKey',
        )
      : undefined;
    const keyFingerprint = access.encryptedSshKey.keyFingerprint
      ? await decryptValidatedSshField(
          access.encryptedSshKey.keyFingerprint,
          access.fieldKey,
          'keyFingerprint',
        )
      : undefined;
    await operation.assertCacheCurrent();
    operation.assertCurrent();
    this.bindOperationFinalAuthority(operation, bindFinalAuthority, () => {
      this.assertCipherPolicyAllowed(operation.policyLease, access.cipher);
    });
    return Object.freeze({
      ...(publicKey ? { publicKey } : {}),
      ...(keyFingerprint ? { keyFingerprint } : {}),
      hasPrivateKey: true,
    });
  }

  /** Reveal the private key only through an explicit, reprompt-aware request. */
  async revealSshPrivateKey(
    id: string,
    masterPassword?: string,
    bindFinalAuthority?: VaultFinalAuthorityBinder,
  ): Promise<string | undefined> {
    const operation = await this.beginVaultOperation({ cache: true });
    const access = await this.prepareSshCipherFieldAccess(operation, id, masterPassword);
    if (!access) return undefined;
    this.assertCipherPasswordViewAllowed(access.cipher);
    const privateKey = await decryptValidatedSshField(
      access.encryptedSshKey.privateKey,
      access.fieldKey,
      'privateKey',
    );
    await operation.assertCacheCurrent();
    operation.assertCurrent();
    this.bindOperationFinalAuthority(operation, bindFinalAuthority, () => {
      this.assertCipherPolicyAllowed(operation.policyLease, access.cipher);
      this.assertCipherPasswordViewAllowed(access.cipher);
    });
    return privateKey;
  }

  /** Generate an Ed25519 key entirely in the worker and store it in the selected vault. */
  async createGeneratedSshKey(
    metadata: SshKeyMetadataInput,
    target: CipherCreateTarget = PERSONAL_CIPHER_CREATE_TARGET,
  ): Promise<VaultListing> {
    const normalized = parseSshKeyMetadataInput(metadata);
    const createTarget = normalizeCipherCreateTarget(target);
    return this.runVaultMutation('ssh.createGenerated', async ({ operation, remote, reconcile }) => {
      const authorization = await this.authorizeSshCipherWrite();
      operation.assertCurrent();
      const sshKey = this.generateCompleteSshKey();
      await this.createSshCipher(operation, remote, authorization, normalized, sshKey, createTarget);
      return reconcile(() => this.syncAfterMutation(operation));
    }, { cache: true });
  }

  private async createSshCipher(
    operation: VaultOperationContext,
    remote: VaultMutationRuntime['remote'],
    authorization: SshCipherWriteAuthorization,
    metadata: Readonly<SshKeyMetadataInput>,
    sshKey: CompleteDecryptedSshKey,
    target: CipherCreateTarget,
  ): Promise<void> {
    const api = this.sshWriteApi(operation, authorization);
    assertLocalMetadataFolderAvailable(
      operation.cacheEnvelope.response.folders,
      metadata.folderId,
    );
    if (target.kind === 'personal') {
      this.assertPersonalCreationAllowed(operation.policyLease, 5);
      const request = await encryptCipher(toSshCipherInput(metadata, sshKey), operation.userKey);
      await operation.assertCacheCurrent();
      await remote((accessToken) => api.createCipher(accessToken, request));
      return;
    }
    const context = await this.requireOrganizationCreateContext(operation, target, 5);
    const input = toSshCipherInput(metadata, sshKey);
    const request = await encryptCipher(input, context.key);
    request.organizationId = context.organizationId;
    await operation.assertCacheCurrent();
    await remote((accessToken) => api.createOrganizationCipher(
      accessToken,
      request,
      context.collectionIds,
    ));
  }

  /** Import a private key in the worker, deriving the public key and fingerprint from it. */
  async importSshKey(
    metadata: SshKeyMetadataInput,
    privateKey: string,
    target: CipherCreateTarget = PERSONAL_CIPHER_CREATE_TARGET,
  ): Promise<VaultListing> {
    const normalized = parseSshKeyMetadataInput(metadata);
    const createTarget = normalizeCipherCreateTarget(target);
    return this.runVaultMutation('ssh.import', async ({ operation, remote, reconcile }) => {
      const authorization = await this.authorizeSshCipherWrite();
      operation.assertCurrent();
      const sshKey = await this.importCompleteSshKey(privateKey);
      operation.assertCurrent();
      await this.createSshCipher(operation, remote, authorization, normalized, sshKey, createTarget);
      return reconcile(() => this.syncAfterMutation(operation));
    }, { cache: true });
  }

  /** Replace only the SSH key triple, preserving every other encrypted field byte-for-byte. */
  async replaceSshKey(
    id: string,
    privateKey: string,
    masterPassword?: string,
  ): Promise<VaultListing> {
    return this.runVaultMutation('ssh.replace', async ({ operation, remote, reconcile }) => {
      const access = await this.prepareSshCipherFieldAccess(operation, id, masterPassword, true);
      if (!access) throw new AppError('error', 'SSH key item is not available.');
      const authorization = await this.authorizeSshCipherWrite();
      operation.assertCurrent();
      const sshKey = await this.importCompleteSshKey(privateKey);
      operation.assertCurrent();
      const request = this.cipherResponseToRequest(access.cipher, { omitSshKey: true });
      request.sshKey = await encryptCompleteSshKey(sshKey, access.fieldKey);
      await operation.assertCacheCurrent();
      const api = this.sshWriteApi(operation, authorization);
      await remote((accessToken) => api.updateCipher(accessToken, id, request));
      return reconcile(() => this.syncAfterMutation(operation));
    }, { cache: true });
  }

  /** Update common SSH item metadata without decrypting or rewriting its private key. */
  async updateSshKeyMetadata(
    id: string,
    metadata: SshKeyMetadataInput,
    masterPassword?: string,
  ): Promise<VaultListing> {
    const normalized = parseSshKeyMetadataInput(metadata);
    return this.runVaultMutation('ssh.updateMetadata', async ({ operation, remote, reconcile }) => {
      const access = await this.prepareSshCipherFieldAccess(operation, id, masterPassword, true);
      if (!access) throw new AppError('error', 'SSH key item is not available.');
      const authorization = await this.authorizeSshCipherWrite();
      operation.assertCurrent();
      const request = this.cipherResponseToRequest(access.cipher);
      request.name = await encryptToText(normalized.name, access.fieldKey);
      request.notes = normalized.notes
        ? await encryptToText(normalized.notes, access.fieldKey)
        : null;
      request.favorite = normalized.favorite;
      request.reprompt = normalized.reprompt ? 1 : 0;
      request.folderId = normalized.folderId;
      request.fields = await encryptSshMetadataFields(normalized.fields, access.fieldKey);
      await operation.assertCacheCurrent();
      const api = this.sshWriteApi(operation, authorization);
      await remote((accessToken) => api.updateCipher(accessToken, id, request));
      return reconcile(() => this.syncAfterMutation(operation));
    }, { cache: true });
  }

  /**
   * Create a cipher directly in its selected vault. Type-5 remains restricted to the dedicated SSH
   * commands until those commands accept and independently authorize an organization target.
   */
  async createCipher(
    input: CipherInput,
    target: CipherCreateTarget = PERSONAL_CIPHER_CREATE_TARGET,
  ): Promise<VaultListing> {
    if ((input as { readonly type?: unknown }).type === 5) throw genericSshWriteDenied();
    const createTarget = normalizeCipherCreateTarget(target);
    return this.runVaultMutation('cipher.create', async ({ operation, remote, reconcile }) => {
      if (createTarget.kind === 'personal') {
        this.assertPersonalCreationAllowed(operation.policyLease, input.type);
        const request = await encryptCipher(input, operation.userKey);
        await remote((accessToken) => operation.api.createCipher(accessToken, request));
        return reconcile(() => this.syncAfterMutation(operation));
      }

      const context = await this.requireOrganizationCreateContext(
        operation,
        createTarget,
        input.type,
      );
      const request = await encryptCipher(input, context.key);
      request.organizationId = context.organizationId;
      await operation.assertCacheCurrent();
      await remote((accessToken) => operation.api.createOrganizationCipher(
        accessToken,
        request,
        context.collectionIds,
      ));
      return reconcile(() => this.syncAfterMutation(operation));
    }, createTarget.kind === 'organization' ? { cache: true } : undefined);
  }

  /** Update per-user cipher metadata without reading or rewriting encrypted item content. */
  async updateCipherLocalMetadata(
    id: string,
    input: CipherPartialRequest,
  ): Promise<VaultListing> {
    const cipherId = requireLocalMetadataId(id, 'cipher');
    const metadata = normalizeCipherLocalMetadata(input);
    return this.updateCipherLocalMetadataWithCurrent(
      'cipher.updateLocalMetadata',
      cipherId,
      () => metadata,
    );
  }

  /** Set the per-user favorite flag while preserving the current folder from the same cache lease. */
  async setCipherFavorite(id: string, favorite: boolean): Promise<VaultListing> {
    const cipherId = requireLocalMetadataId(id, 'cipher');
    const normalizedFavorite = requireCipherFavorite(favorite);
    return this.updateCipherLocalMetadataWithCurrent(
      'cipher.setFavorite',
      cipherId,
      (cipher) => normalizeCipherLocalMetadata({
        folderId: cipher.folderId ?? null,
        favorite: normalizedFavorite,
      }),
      true,
    );
  }

  private updateCipherLocalMetadataWithCurrent(
    mutation: string,
    cipherId: string,
    metadataForCipher: (cipher: CipherResponse) => CipherPartialRequest,
    requireSupported = false,
  ): Promise<VaultListing> {
    return this.runVaultMutation(mutation, async ({ operation, remote, reconcile }) => {
      const cache = operation.cacheEnvelope.response;
      const cipher = this.requireCipherLifecycleCandidate(cache.ciphers, cipherId);
      if (requireSupported) this.requireSupportedCipher(cipher);
      if (!isActiveCipher(cipher)) {
        throw new AppError('denied', 'Only active items can change local metadata.');
      }
      this.assertCipherPolicyAllowed(operation.policyLease, cipher);
      const metadata = metadataForCipher(cipher);
      assertLocalMetadataFolderAvailable(cache.folders, metadata.folderId);
      await operation.assertCacheCurrent();
      await remote((accessToken) => (
        operation.api.updateCipherPartial(accessToken, cipherId, metadata)
      ));
      return reconcile(() => this.syncAfterMutation(operation, (response) => {
        assertCipherLocalMetadataUpdateCommitted(response, cipherId, metadata);
      }));
    }, { cache: true });
  }

  private async requireOrganizationCreateContext(
    operation: VaultOperationContext,
    target: Extract<CipherCreateTarget, { readonly kind: 'organization' }>,
    cipherType: number,
  ): Promise<OrganizationCreateContext> {
    const cache = operation.cacheEnvelope.response;
    const metadata = selectOrganizationMetadata(cache.profile).entries.find(
      (entry) => entry.organization.id === target.organizationId,
    );
    if (
      !metadata
      || (!metadata.isMember && !metadata.isProviderUser)
      || metadata.organization.status !== 2
      || metadata.organization.enabled !== true
    ) {
      throw new AppError('denied', 'The organization is not available for new items.');
    }
    const authority = toCollectionOrganizationAuthority(
      metadata.organization,
      metadata.isProviderUser,
    );
    this.assertCipherTargetPolicyAllowed(operation.policyLease, cipherType, target.organizationId);

    const collections = new Map<string, CollectionResponse>();
    const duplicateCollectionIds = new Set<string>();
    for (const collection of cache.collections ?? []) {
      if (collections.has(collection.id)) duplicateCollectionIds.add(collection.id);
      else collections.set(collection.id, collection);
    }
    for (const collectionId of target.collectionIds) {
      const collection = collections.get(collectionId);
      if (
        duplicateCollectionIds.has(collectionId)
        || !collection
        || collection.organizationId !== target.organizationId
        || !resolveCollectionCapabilities(authority, collection).canAssign
      ) {
        throw new AppError('denied', 'A selected collection is not writable for this account.');
      }
    }

    const organizationKeys = await this.buildOrgKeys(cache.profile);
    const key = organizationKeys.get(target.organizationId);
    if (!key) throw new AppError('denied', 'The organization key is unavailable.');
    operation.assertCurrent();
    return Object.freeze({
      organizationId: target.organizationId,
      collectionIds: target.collectionIds,
      key,
    });
  }

  async updateCipher(id: string, input: CipherInput): Promise<VaultListing> {
    if ((input as { readonly type?: unknown }).type === 5) throw genericSshWriteDenied();
    return this.runVaultMutation(
      'cipher.update',
      (runtime) => this.updateCipherWithOperation(id, input, runtime),
      { cache: true },
    );
  }

  private async updateCipherWithOperation(
    id: string,
    input: CipherInput,
    runtime: VaultMutationRuntime,
    expectedOriginal?: CipherResponse,
    requestGuard?: () => void,
  ): Promise<VaultListing> {
    const { operation, remote, reconcile } = runtime;
    const cacheEnvelope = operation.cacheEnvelope;
    if (!cacheEnvelope) throw new AppError('sync_required', 'Sync required');
    const cache = cacheEnvelope.response;
    const candidate = expectedOriginal ?? cache.ciphers.find((cipher) => cipher.id === id);
    if (!candidate) throw new AppError('error', 'Item is not available');
    const original = this.requireSupportedCipher(candidate);
    if (original.type === 5) throw genericSshWriteDenied();
    if (original.deletedDate != null) throw new AppError('denied', 'Items in the trash cannot be edited.');
    this.assertCipherEditAllowed(operation.policyLease, original);
    this.assertCipherTargetPolicyAllowed(
      operation.policyLease,
      input.type,
      original.organizationId ?? null,
    );
    // Old plaintext for the password-history diff; only meaningful when the cipher is cached.
    const orgKeys = await this.buildOrgKeys(cache.profile);
    const previous = original ? await decryptCipher(original, operation.userKey, orgKeys) : undefined;
    // Encrypt under the SAME key the cipher already uses — the org key (or its per-cipher key) for an
    // org-owned item, the account key otherwise. Previously this always used the account UserKey, which
    // corrupted org ciphers (re-encrypting their fields under the wrong key while the server kept them
    // org-owned).
    const fieldKey = await this.cipherFieldKey(original, operation.userKey, cache.profile);
    const request = await encryptCipher(input, fieldKey);
    // Carry forward server-managed fields the editor cannot represent (passkeys, the per-cipher key,
    // password history) so the wholesale PUT does not wipe them.
    mergeServerManagedFields(request, original);
    if (original) request.lastKnownRevisionDate = original.revisionDate ?? null;
    // Keep org ownership so the server keeps treating the item as org-owned under the org key.
    if (original?.organizationId) request.organizationId = original.organizationId;
    // Archive changed login and Hidden-field values in one bounded history update.
    await this.appendPasswordHistory(request, original, input, previous, fieldKey);
    await operation.assertCacheCurrent();
    const api = requestGuard ? operation.api.withRequestGuard(requestGuard) : operation.api;
    await remote((accessToken) => api.updateCipher(accessToken, id, request));
    return reconcile(() => this.syncAfterMutation(operation));
  }

  private async prepareSshCipherFieldAccess(
    operation: VaultOperationContext,
    id: string,
    masterPassword?: string,
    forWrite = false,
  ): Promise<SshCipherFieldAccess | undefined> {
    const cache = operation.cacheEnvelope.response;
    const candidate = cache.ciphers.find((cipher) => cipher.id === id);
    if (!candidate) {
      operation.assertCurrent();
      return undefined;
    }
    const cipher = this.requireSupportedCipher(candidate, [5]);
    this.assertCipherPolicyAllowed(operation.policyLease, cipher);
    if (forWrite) {
      this.assertCipherEditAllowed(operation.policyLease, cipher);
      if (cipher.deletedDate != null) throw new AppError('denied', 'SSH key items in the trash cannot be edited.');
    }
    const orgKeys = await this.buildOrgKeys(cache.profile);
    const summary = await decryptCipherSummary(cipher, operation.userKey, orgKeys);
    operation.assertCurrent();
    if (!summary || summary.type !== 5 || summary.undecryptable) {
      throw new AppError('denied', 'SSH key item cannot be safely read.');
    }
    await this.assertRepromptCleared(summary, masterPassword, operation.assertCurrent);
    let encryptedSshKey: SshKeyCipherData;
    try {
      encryptedSshKey = parseSshKeyCipherData(cipher.sshKey);
    } catch {
      throw new AppError('denied', 'SSH key item cannot be safely read.');
    }
    const fieldKey = await this.cipherFieldKey(cipher, operation.userKey, cache.profile);
    await operation.assertCacheCurrent();
    operation.assertCurrent();
    return { cipher, encryptedSshKey, fieldKey, operation };
  }

  private async authorizeSshCipherWrite(): Promise<SshCipherWriteAuthorization> {
    const authorize = this.deps.authorizeSshCipherType5Write;
    if (!authorize) throw new AppError('denied', 'SSH key writes are unavailable.');
    let authorization: SshCipherWriteAuthorization;
    try {
      authorization = await authorize();
      if (!authorization || typeof authorization.assertCurrent !== 'function') {
        throw new AppError('denied', 'SSH key write authorization is invalid.');
      }
      authorization.assertCurrent();
      return authorization;
    } catch (error) {
      if (error instanceof AppError) throw error;
      throw new AppError('denied', 'SSH key writes are unavailable.');
    }
  }

  private sshWriteApi(
    operation: VaultOperationContext,
    authorization: SshCipherWriteAuthorization,
  ): ApiClient {
    return operation.api.withRequestGuard(() => {
      operation.assertCurrent();
      assertSshWriteAuthorizationCurrent(authorization);
    });
  }

  private async authorizeOrganizationDataOwnershipTransport(): Promise<
    OrganizationDataOwnershipTransportAuthorization
  > {
    const authorize = this.deps.authorizeOrganizationDataOwnershipTransport;
    if (!authorize) {
      throw new AppError('denied', 'Organization data ownership transport is unavailable.');
    }
    try {
      const authorization = await authorize();
      if (!authorization
          || (authorization.serverKind !== 'bitwarden'
            && authorization.serverKind !== 'vaultwarden')
          || typeof authorization.assertCurrent !== 'function') {
        throw new AppError('denied', 'Organization data ownership transport is invalid.');
      }
      authorization.assertCurrent();
      return authorization;
    } catch (error) {
      if (error instanceof AppError) throw error;
      throw new AppError('denied', 'Organization data ownership transport is unavailable.');
    }
  }

  private async authorizeCollectionNameOnlyUpdate(): Promise<CollectionNameUpdateAuthorization> {
    const authorize = this.deps.authorizeCollectionNameOnlyUpdate;
    if (!authorize) throw new AppError('denied', 'Safe collection renaming is unavailable.');
    try {
      const authorization = await authorize();
      if (!authorization || typeof authorization.assertCurrent !== 'function') {
        throw new AppError('denied', 'Collection rename authorization is invalid.');
      }
      authorization.assertCurrent();
      return authorization;
    } catch (error) {
      if (error instanceof AppError) throw error;
      throw new AppError('denied', 'Safe collection renaming is unavailable.');
    }
  }

  private async authorizeCipherArchive(): Promise<CipherArchiveAuthorization> {
    const authorize = this.deps.authorizeCipherArchive;
    if (!authorize) throw new AppError('denied', 'Cipher archiving is unavailable.');
    try {
      const authorization = await authorize();
      if (!authorization || typeof authorization.assertCurrent !== 'function') {
        throw new AppError('denied', 'Cipher archive authorization is invalid.');
      }
      assertCipherArchiveAuthorizationCurrent(authorization);
      return authorization;
    } catch (error) {
      if (error instanceof AppError) throw error;
      throw new AppError('denied', 'Cipher archiving is unavailable.');
    }
  }

  private cipherArchiveApi(
    operation: VaultOperationContext,
    authorization: CipherArchiveAuthorization,
  ): ApiClient {
    return operation.api.withRequestGuard(() => {
      operation.assertCurrent();
      assertCipherArchiveAuthorizationCurrent(authorization);
    });
  }

  private generateCompleteSshKey(): CompleteDecryptedSshKey {
    try {
      return parseCompleteDecryptedSshKey((this.deps.generateSshKey ?? generateSshKey)());
    } catch {
      throw new AppError('error', 'SSH key generation failed.');
    }
  }

  private async importCompleteSshKey(privateKey: string): Promise<CompleteDecryptedSshKey> {
    try {
      const imported = await (this.deps.importSshPrivateKey ?? importSshPrivateKey)(privateKey);
      return parseCompleteDecryptedSshKey(imported);
    } catch (error) {
      throw sshKeyImportError(error);
    }
  }

  /** The key a cipher's fields are encrypted under: its per-cipher key when present (unwrapped with the
   *  owning key), otherwise the owning key itself — the org key for org-owned items, else the account key. */
  private async cipherFieldKey(
    original: CipherResponse | undefined,
    userKey: SymmetricKey,
    profile: SyncProfile,
  ): Promise<SymmetricKey> {
    const owningKey = await this.cipherOwningKey(original, userKey, profile);
    return original?.key ? unwrapSymmetricKey(original.key, owningKey) : owningKey;
  }

  /** The owning key for a cipher: the organization key for org-owned items, else the account UserKey. */
  private async cipherOwningKey(
    original: CipherResponse | undefined,
    userKey: SymmetricKey,
    profile: SyncProfile,
  ): Promise<SymmetricKey> {
    if (!original?.organizationId) return userKey;
    const orgKeys = await this.buildOrgKeys(profile);
    const orgKey = orgKeys.get(original.organizationId);
    if (!orgKey) throw new AppError('error', 'Organization key is unavailable; cannot edit this item');
    return orgKey;
  }

  private async validatePersonalShareCipher(
    original: SupportedCipherResponse,
    userKey: SymmetricKey,
  ): Promise<void> {
    const decrypted = await decryptCipher(original, userKey);
    if (!decrypted || decrypted.undecryptable) {
      throw new AppError('denied', 'This item contains invalid encrypted data and cannot be moved.');
    }
    const passkeyCount = original.type === 1
      ? original.login?.fido2Credentials?.length ?? 0
      : 0;
    if ((decrypted.fido2Credentials?.length ?? 0) !== passkeyCount
      || (decrypted.attachments?.length ?? 0) !== (original.attachments?.length ?? 0)) {
      throw new AppError('denied', 'This item contains incomplete encrypted data and cannot be moved.');
    }
    const cipherKey = original.key
      ? await unwrapSymmetricKey(original.key, userKey)
      : userKey;
    const destroyCipherKey = cipherKey !== userKey;
    try {
      await validateKnownCipherEncryptedLeaves(original, cipherKey);
      requireShareAttachmentMetadata(original.attachments, original.attachments);
      for (const attachment of original.attachments ?? []) {
        const attachmentKey = await decryptAttachmentKey(attachment.key!, cipherKey);
        // Unwrapping enforces the exact 64-byte attachment-key shape; the file name was verified above.
        destroySymmetricKey(attachmentKey);
      }
    } catch {
      throw new AppError('denied', 'This item contains invalid encrypted metadata and cannot be moved.');
    } finally {
      if (destroyCipherKey) destroySymmetricKey(cipherKey);
    }
  }

  /** Canonicalize the worker-owned WebAuthn scope and enforce the rpId/origin trust boundary. */
  private normalizePasskeyScope(rpId: string, origin: string): { readonly rpId: string; readonly origin: string } {
    if (
      typeof rpId !== 'string'
      || rpId.length === 0
      || rpId.length > 253
      || rpId !== rpId.trim().toLowerCase()
      || typeof origin !== 'string'
      || origin.length === 0
      || origin.length > 2_048
    ) {
      throw new AppError('denied', 'Invalid passkey origin or relying party');
    }
    let parsed: URL;
    try {
      parsed = new URL(origin);
    } catch {
      throw new AppError('denied', 'Invalid passkey origin');
    }
    const canonicalOrigin = parsed.origin;
    const secureScheme = parsed.protocol === 'https:';
    const loopbackDevelopment = parsed.protocol === 'http:'
      && (parsed.hostname === 'localhost' || parsed.hostname === '127.0.0.1');
    if (
      canonicalOrigin === 'null'
      || origin !== canonicalOrigin
      || (!secureScheme && !loopbackDevelopment)
      || !isRegistrableRpId(rpId, parsed.hostname)
    ) {
      throw new AppError('denied', 'rpId is not valid for this origin');
    }
    return Object.freeze({ rpId, origin: canonicalOrigin });
  }

  private normalizePasskeySelection(
    allowedCredentialIds: readonly string[] | undefined,
  ): PasskeyCredentialSelection {
    try {
      return normalizePasskeyCredentialSelection(allowedCredentialIds);
    } catch {
      throw new AppError('denied', 'Invalid passkey credential descriptor list');
    }
  }

  /** Check the freshest account-bound raw generation. A credential in trash or behind reprompt still
   * participates: excludeCredentials prevents duplicates, it does not authorize an assertion. */
  private async assertNoExcludedPasskey(
    operation: VaultOperationContext,
    rpId: string,
    excludeCredentialIds: readonly string[],
  ): Promise<string> {
    operation.assertBaseCurrent();
    const source = await this.cache.readRaw();
    operation.assertBaseCurrent();
    if (!source) throw new AppError('sync_required', 'Sync required');
    if (excludeCredentialIds.length > 0) {
      const excluded = new Set(excludeCredentialIds);
      const orgKeys = await this.buildOrgKeys(source.response.profile);
      for (const cipher of source.response.ciphers) {
        const storedCredentials = cipher.login?.fido2Credentials;
        if (cipher.type !== 1 || !storedCredentials?.length) continue;
        if (storedCredentials.length !== 1) {
          throw new AppError('denied', 'Stored passkey metadata cannot be safely checked');
        }
        const decrypted = await decryptCipher(cipher, operation.userKey, orgKeys);
        if (!decrypted || decrypted.undecryptable || decrypted.fido2Credentials?.length !== 1) {
          throw new AppError('denied', 'Stored passkey metadata cannot be safely checked');
        }
        const credential = decrypted.fido2Credentials[0]!;
        if (credential.rpId === rpId && excluded.has(credential.credentialId)) {
          throw duplicatePasskeyError();
        }
      }
    }
    await operation.assertCacheCurrent();
    operation.assertCurrent();
    return source.rawGeneration;
  }

  /** Preserve changed login and Hidden-field values using Bitwarden's password-history rules. */
  private async appendPasswordHistory(
    request: CipherRequest,
    original: CipherResponse | undefined,
    input: CipherInput,
    previous: DecryptedCipher | undefined,
    fieldKey: SymmetricKey,
  ): Promise<void> {
    const oldPassword = previous?.password;
    const newPassword = input.login?.password ?? '';
    const passwordChanged = request.type === 1
      && original?.type === 1
      && Boolean(original.login?.password)
      && Boolean(oldPassword)
      && oldPassword !== newPassword;

    const currentHiddenFields = input.fields?.filter((field) => field.type === 1) ?? [];
    const changedHiddenValues: string[] = [];
    const seenHiddenValues = new Set<string>();
    for (const field of previous?.fields ?? []) {
      if (field.type !== 1 || !field.name || !field.value) continue;
      const current = currentHiddenFields.find((candidate) => candidate.name === field.name);
      if (current?.value === field.value) continue;
      const historyValue = `${field.name}: ${field.value}`;
      if (seenHiddenValues.has(historyValue)) continue;
      seenHiddenValues.add(historyValue);
      changedHiddenValues.push(historyValue);
    }
    if (!passwordChanged && changedHiddenValues.length === 0) return;

    const now = new Date((this.deps.now ?? Date.now)()).toISOString();
    const additions = [] as NonNullable<CipherRequest['passwordHistory']>;
    for (const value of changedHiddenValues.reverse().slice(0, MAX_PASSWORD_HISTORY)) {
      additions.push({ password: await encryptToText(value, fieldKey), lastUsedDate: now });
    }
    if (passwordChanged) {
      additions.push({ password: original!.login!.password!, lastUsedDate: now });
      request.login = { ...(request.login ?? {}), passwordRevisionDate: now };
    }
    request.passwordHistory = [
      ...additions,
      ...(request.passwordHistory ?? []),
    ].slice(0, MAX_PASSWORD_HISTORY);
  }

  /** Move a complete personal cipher into an organization without rebuilding it from editor data. */
  async shareCipher(id: string, organizationId: string, collectionIds: string[], masterPassword?: string): Promise<VaultListing> {
    const target = normalizeCipherCreateTarget({
      kind: 'organization',
      organizationId,
      collectionIds,
    });
    if (target.kind !== 'organization') throw new AppError('denied', 'Invalid share target.');
    await this.upgradeLegacyAttachmentsBeforeShare(id, target, masterPassword);
    return this.runVaultMutation('cipher.share', async ({ operation, remote, reconcile }) => {
      const cache = operation.cacheEnvelope.response;
      const matches = cache.ciphers.filter((cipher) => cipher.id === id);
      if (matches.length !== 1) throw new AppError('denied', 'Item is not available.');
      const original = this.requireSupportedCipher(matches[0]!);
      this.assertCipherEditAllowed(operation.policyLease, original);
      this.assertCipherPasswordViewAllowed(original);
      if (original.organizationId) {
        throw new AppError('denied', 'This item already belongs to an organization.');
      }
      if (isCipherInactive(original)) {
        throw new AppError('denied', 'Inactive items cannot be moved to an organization.');
      }
      const context = await this.requireOrganizationCreateContext(operation, target, original.type);
      await this.assertRepromptCleared(
        { reprompt: original.reprompt === 1 },
        masterPassword,
        operation.assertCurrent,
      );
      await this.validatePersonalShareCipher(original, operation.userKey);
      operation.assertCurrent();
      const sshAuthorization = original.type === 5
        ? await this.authorizeSshCipherWrite()
        : undefined;
      operation.assertCurrent();

      let prepared: PreparedCipherShare;
      try {
        const rotated = await rotateCipher(original, operation.userKey, context.key);
        await verifyRotatedCipher(rotated, context.key);
        prepared = this.prepareCipherShare(rotated, original, context.organizationId);
      } catch {
        throw new AppError('denied', 'This item cannot be moved without losing encrypted data.');
      }
      operation.assertCurrent();
      await operation.assertCacheCurrent();
      const api = sshAuthorization
        ? this.sshWriteApi(operation, sshAuthorization)
        : operation.api;
      const receipt = await remote((accessToken) => api.shareCipher(accessToken, id, {
        cipher: prepared.request,
        collectionIds: [...context.collectionIds],
      }));
      if (!validSharedCipherReceipt(
        receipt,
        id,
        context.organizationId,
        prepared.request,
        prepared.attachments,
      )) {
        throw new AppError('outcome_unknown', 'The server returned an invalid share receipt.');
      }

      const listing = await reconcile(() => this.syncAfterMutation(operation));
      const authoritative = operation.cacheEnvelope.response.ciphers
        .filter((cipher) => cipher.id === id);
      if (authoritative.length !== 1 || !validAuthoritativeSharedCipher(
        authoritative[0]!,
        id,
        context.organizationId,
        context.collectionIds,
        prepared.request,
        prepared.attachments,
      )) {
        throw new AppError('outcome_unknown', 'The shared item could not be verified after sync.');
      }
      return listing;
    }, { cache: true });
  }

  private async upgradeLegacyAttachmentsBeforeShare(
    cipherId: string,
    target: Extract<CipherCreateTarget, { readonly kind: 'organization' }>,
    masterPassword?: string,
  ): Promise<void> {
    const operation = await this.beginVaultOperation({ cache: true });
    const matches = operation.cacheEnvelope.response.ciphers.filter(
      (cipher) => cipher.id === cipherId,
    );
    if (matches.length !== 1) throw new AppError('denied', 'Item is not available.');
    const cipher = this.requireSupportedCipher(matches[0]!);
    const legacyAttachmentIds = cipher.attachments
      ?.filter((attachment) => attachment.key == null)
      .map((attachment) => attachment.id) ?? [];
    if (legacyAttachmentIds.length === 0) return;

    this.assertCipherEditAllowed(operation.policyLease, cipher);
    this.assertCipherPasswordViewAllowed(cipher);
    if (cipher.organizationId || isCipherInactive(cipher)) {
      throw new AppError('denied', 'Inactive or organization items cannot be moved.');
    }
    await this.requireOrganizationCreateContext(operation, target, cipher.type);
    await this.assertRepromptCleared(
      { reprompt: cipher.reprompt === 1 },
      masterPassword,
      operation.assertCurrent,
    );
    if (cipher.type === 5) await this.authorizeSshCipherWrite();
    await operation.assertCacheCurrent();

    for (const attachmentId of legacyAttachmentIds) {
      await this.upgradeLegacyAttachment(cipherId, attachmentId, masterPassword);
    }
  }

  /** List the account's Sends, decrypted for display (name/text + the shareable access URL). */
  async listSends(
    serverUrl: string,
    bindFinalAuthority?: VaultFinalAuthorityBinder,
  ): Promise<SendSummary[]> {
    const operation = await this.beginVaultOperation();
    operation.assertCurrent();
    const sends = await operation.executeAuthenticated(
      (accessToken) => operation.api.listSends(accessToken),
    );
    const out: SendSummary[] = [];
    for (const send of sends) {
      try {
        out.push(await decryptSend(send, operation.userKey, serverUrl));
      } catch {
        // Skip a send we cannot decrypt rather than failing the whole list.
      }
    }
    operation.assertCurrent();
    this.bindOperationFinalAuthority(operation, bindFinalAuthority);
    return out;
  }

  /** Create a text Send and return it decrypted (with its access URL) for immediate sharing. */
  async createTextSend(
    input: SendInput,
    serverUrl: string,
    bindFinalAuthority?: VaultFinalAuthorityBinder,
  ): Promise<SendSummary> {
    return this.runVaultMutation('send.createText', async ({ operation, remote, reconcile }) => {
    const now = (this.deps.now ?? Date.now)();
    const { request } = await buildTextSendRequest(input, operation.userKey, { now: () => now });
    this.enforceSendWritePolicy(
      operation.policyLease,
      request,
      isNonBlank(input.password),
      now,
      'create',
    );
    const created = await remote((accessToken) => operation.api.createSend(accessToken, request));
    const decrypted = await decryptSend(created, operation.userKey, serverUrl);
    await reconcile(() => this.syncAfterMutation(operation));
    return decrypted;
    }, { cache: true, ...(bindFinalAuthority ? { bindFinalAuthority } : {}) });
  }

  /** Compatibility adapter for small legacy messages. New UI transfers use bounded Port chunks. */
  async createFileSend(
    input: SendInput,
    dataB64: string,
    fileName: string,
    serverUrl: string,
    bindFinalAuthority?: VaultFinalAuthorityBinder,
  ): Promise<SendSummary> {
    assertLegacyFileMessageBudget({ type: 'sends.createFile', input, dataB64: '', fileName }, dataB64.length);
    const fileBytes = base64ToBytes(dataB64);
    try {
      return await this.createFileSendBytes(input, fileBytes, fileName, serverUrl, bindFinalAuthority);
    } finally {
      fileBytes.fill(0);
    }
  }

  /** Encrypt a borrowed file buffer in the worker and upload it through the existing mutation gate. */
  async createFileSendBytes(
    input: SendInput,
    fileBytes: Uint8Array,
    fileName: string,
    serverUrl: string,
    bindFinalAuthority?: VaultFinalAuthorityBinder,
    assertTransferCurrent: () => void = () => undefined,
  ): Promise<SendSummary> {
    assertTransferCurrent();
    if (!(fileBytes instanceof Uint8Array) || fileBytes.byteLength > 100 * 1024 * 1024) {
      throw new AppError('error', 'Send file exceeds this client\'s size limit.');
    }
    return this.runVaultMutation('send.createFile', async ({
      operation, remote, remoteOnce, reconcile,
    }) => {
    assertTransferCurrent();
    const now = (this.deps.now ?? Date.now)();
    const { request, sendKey, encryptedFile, encryptedFileName } = await buildFileSendRequest(
      input, fileName, fileBytes, operation.userKey, { now: () => now },
    );
    try {
    assertTransferCurrent();
    this.enforceSendWritePolicy(
      operation.policyLease,
      request,
      isNonBlank(input.password),
      now,
      'create',
    );
    let created: Awaited<ReturnType<ApiClient['createSendFile']>> | undefined;
    try {
      const { url } = await remote(
        (accessToken) => {
          assertTransferCurrent();
          return operation.api.createSendFile(accessToken, request);
        },
        (value) => { created = value; },
      );
      const upload = (accessToken: string) => {
        assertTransferCurrent();
        return operation.api.uploadSendFileData(accessToken, url, encryptedFile, encryptedFileName);
      };
      // Absolute upload URLs may target a CDN without a bearer token. Keep that external response on
      // the single-attempt path; relative API uploads are rebuildable authenticated requests.
      if (/^https?:\/\//iu.test(url)) await remoteOnce(() => upload(operation.token));
      else await remote(upload);
      assertTransferCurrent();
    } catch (err) {
      // The Send record exists but holds no blob — delete the orphan, then surface the original error.
      try {
        // Bounded compensation exception: this exact id was created by this operation. The captured
        // token can only remove that orphan from its original account; it cannot affect the new one.
        if (created) {
          const compensationApi = this.deps.api.forServer(operation.accountLease.serverUrl);
          await compensationApi.deleteSend(operation.token, created.sendResponse.id);
        }
      } catch {
        // Best effort only. The original upload/session failure remains the caller-visible error.
      }
      throw err;
    }
    if (!created) throw new AppError('outcome_unknown', 'The Send create result is unavailable.');
    const decrypted = await decryptSend(created.sendResponse, operation.userKey, serverUrl);
    await reconcile(() => this.syncAfterMutation(operation));
    return decrypted;
    } finally {
      sendKey.fill(0);
      encryptedFile.fill(0);
    }
    }, { cache: true, ...(bindFinalAuthority ? { bindFinalAuthority } : {}) });
  }

  /** Edit an existing Send's metadata: re-encrypt under its existing send key and PUT. Password removal
   *  uses the dedicated endpoint. Returns the updated, decrypted summary. */
  async updateSend(
    id: string,
    input: UpdateSendInput,
    serverUrl: string,
    bindFinalAuthority?: VaultFinalAuthorityBinder,
  ): Promise<SendSummary> {
    return this.runVaultMutation('send.update', async ({ operation, remote, reconcile }) => {
    // The pre-PUT read is required — there is no single-send GET, and buildUpdateSendRequest needs the
    // existing send key / dates / file. The PUT response is the authoritative post-update record, so we
    // reuse it directly instead of re-listing every send.
    const existing = (await operation.executeAuthenticated(
      (accessToken) => operation.api.listSends(accessToken),
    )).find((s) => s.id === id);
    operation.assertCurrent();
    if (!existing) throw new AppError('error', 'Send not found');
    if (
      existing.authType === 0
      || (existing.emails?.length ?? 0) > 0
      || (existing.authType !== null
        && existing.authType !== undefined
        && existing.authType !== 1
        && existing.authType !== 2)
    ) {
      throw new AppError(
        'denied',
        'This Send authentication mode cannot be edited safely by this client.',
      );
    }
    const now = (this.deps.now ?? Date.now)();
    const request = await buildUpdateSendRequest(existing, input, operation.userKey, { now: () => now });
    const hasPassword = input.passwordMode === 'set'
      ? isNonBlank(input.newPassword)
      : input.passwordMode === 'remove'
        ? false
        : Boolean(existing.password);
    this.enforceSendWritePolicy(
      operation.policyLease,
      request,
      hasPassword,
      now,
      'update',
      input.deletionHours !== undefined || input.deletionDays !== undefined,
    );
    const updated = await remote((accessToken) => operation.api.updateSend(accessToken, id, request));
    if (input.passwordMode === 'remove') {
      await remote((accessToken) => operation.api.removeSendPassword(accessToken, id));
      // The PUT response still carries the pre-removal password hash; clear it so the summary reports
      // passwordProtected: false to match the just-removed state.
      const decrypted = await decryptSend({ ...updated, password: null }, operation.userKey, serverUrl);
      await reconcile(() => this.syncAfterMutation(operation));
      return decrypted;
    }
    const decrypted = await decryptSend(updated, operation.userKey, serverUrl);
    await reconcile(() => this.syncAfterMutation(operation));
    return decrypted;
    }, { cache: true, ...(bindFinalAuthority ? { bindFinalAuthority } : {}) });
  }

  /** Delete a Send. */
  async deleteSend(id: string): Promise<void> {
    return this.runVaultMutation('send.delete', async ({ operation, remote, reconcile }) => {
      await remote((accessToken) => operation.api.deleteSend(accessToken, id));
      await reconcile(() => this.syncAfterMutation(operation));
    });
  }

  /** Archive an active cipher as per-user metadata. This does not require organization edit access. */
  async archiveCipher(id: string, masterPassword?: string): Promise<VaultListing> {
    return this.runVaultMutation('cipher.archive', async ({ operation, remote, reconcile }) => {
      const cache = operation.cacheEnvelope.response;
      const cipher = this.requireCipherLifecycleCandidate(cache.ciphers, id);
      this.assertCipherPolicyAllowed(operation.policyLease, cipher);
      if (cipher.deletedDate != null || cipher.archivedDate != null) {
        throw new AppError('denied', 'Only active items can be archived.');
      }
      if (!hasArchiveEntitlement(cache.profile)) {
        throw new AppError('denied', 'Premium access is required to archive items.');
      }
      await this.assertRepromptCleared(
        { reprompt: cipher.reprompt === 1 },
        masterPassword,
        operation.assertCurrent,
      );
      const authorization = await this.authorizeCipherArchive();
      operation.assertCurrent();
      await operation.assertCacheCurrent();
      const api = this.cipherArchiveApi(operation, authorization);
      await remote((accessToken) => api.archiveCiphers(accessToken, [id]));
      return reconcile(() => this.syncAfterMutation(operation));
    }, { cache: true });
  }

  /** Unarchive existing per-user metadata regardless of current premium or archive capability. */
  async unarchiveCipher(id: string, masterPassword?: string): Promise<VaultListing> {
    return this.runVaultMutation('cipher.unarchive', async ({ operation, remote, reconcile }) => {
      const cache = operation.cacheEnvelope.response;
      const cipher = this.requireCipherLifecycleCandidate(cache.ciphers, id);
      this.assertCipherPolicyAllowed(operation.policyLease, cipher);
      if (cipher.deletedDate != null || cipher.archivedDate == null) {
        throw new AppError('denied', 'Only archived items outside the trash can be unarchived.');
      }
      await this.assertRepromptCleared(
        { reprompt: cipher.reprompt === 1 },
        masterPassword,
        operation.assertCurrent,
      );
      await operation.assertCacheCurrent();
      await remote((accessToken) => operation.api.unarchiveCiphers(accessToken, [id]));
      return reconcile(() => this.syncAfterMutation(operation));
    }, { cache: true });
  }

  private requireCipherLifecycleCandidate(
    ciphers: readonly CipherResponse[],
    id: string,
  ): CipherResponse {
    const matches = ciphers.filter((cipher) => cipher.id === id);
    if (matches.length !== 1) throw new AppError('denied', 'Item is not available.');
    const cipher = matches[0]!;
    if (
      !Number.isSafeInteger(cipher.type)
      || cipher.type <= 0
      || (cipher.reprompt !== undefined
        && cipher.reprompt !== null
        && cipher.reprompt !== 0
        && cipher.reprompt !== 1)
      || !isOptionalLifecycleDate(cipher.deletedDate)
      || !isOptionalLifecycleDate(cipher.archivedDate)
    ) {
      throw new AppError('denied', 'Item lifecycle metadata is invalid.');
    }
    return cipher;
  }

  /** Permanently delete a cipher (no recovery), then re-sync. Used for "delete forever" from the trash. */
  async deleteCipher(id: string): Promise<VaultListing> {
    return this.runVaultMutation('cipher.delete', async ({ operation, remote, reconcile }) => {
      const candidate = this.requireCipherLifecycleCandidate(
        operation.cacheEnvelope!.response.ciphers,
        id,
      );
      const cipher = this.requireSupportedCipher(candidate);
      if (candidate.deletedDate == null) {
        throw new AppError('denied', 'Only items in the trash can be permanently deleted.');
      }
      this.assertCipherDeleteAllowed(operation.policyLease, cipher);
      await remote((accessToken) => operation.api.deleteCipher(accessToken, id));
      return reconcile(() => this.syncAfterMutation(operation));
    }, { cache: true });
  }

  /** Soft-delete a cipher: move it to the trash (recoverable), then re-sync. */
  async softDeleteCipher(id: string): Promise<VaultListing> {
    return this.runVaultMutation('cipher.softDelete', async ({ operation, remote, reconcile }) => {
      const candidate = this.requireCipherLifecycleCandidate(
        operation.cacheEnvelope!.response.ciphers,
        id,
      );
      const cipher = this.requireSupportedCipher(candidate);
      if (candidate.deletedDate != null) {
        throw new AppError('denied', 'Only items outside the trash can be moved to the trash.');
      }
      this.assertCipherDeleteAllowed(operation.policyLease, cipher);
      await remote((accessToken) => operation.api.softDeleteCipher(accessToken, id));
      return reconcile(() => this.syncAfterMutation(operation));
    }, { cache: true });
  }

  /** Restore a cipher from the trash, then re-sync. */
  async restoreCipher(id: string): Promise<VaultListing> {
    return this.runVaultMutation('cipher.restore', async ({ operation, remote, reconcile }) => {
      const candidate = this.requireCipherLifecycleCandidate(
        operation.cacheEnvelope!.response.ciphers,
        id,
      );
      const cipher = this.requireSupportedCipher(candidate);
      if (candidate.deletedDate == null) {
        throw new AppError('denied', 'Only items in the trash can be restored.');
      }
      this.assertCipherRestoreAllowed(operation.policyLease, cipher);
      await remote((accessToken) => operation.api.restoreCipher(accessToken, id));
      return reconcile(() => this.syncAfterMutation(operation));
    }, { cache: true });
  }

  /**
   * Decrypt a cipher into editable plaintext for the editor. Unlike getCipherDetail this DOES include
   * secrets (password/totp/card number/etc.) because the editor must round-trip them.
   */
  async getCipherInput(
    id: string,
    masterPassword?: string,
    purpose: CipherInputPurpose = 'edit',
    bindFinalAuthority?: VaultFinalAuthorityBinder,
  ): Promise<CipherInput | undefined> {
    if (purpose !== 'edit' && purpose !== 'clone') {
      throw new AppError('denied', 'Cipher input purpose is invalid.');
    }
    const cloneAuthority = purpose === 'clone'
      ? (operation: VaultOperationContext, cipher: SupportedCipherResponse) => {
          this.assertCipherCloneAllowed(operation, cipher);
        }
      : undefined;
    const access = await this.decryptCipherById(id, cloneAuthority);
    if (!access || access.cipher.undecryptable || access.cipher.type === 5) return undefined;
    if (access.raw.deletedDate != null) {
      throw new AppError('denied', 'Items in the trash cannot be edited.');
    }
    this.assertCipherEditAllowed(access.operation.policyLease, access.raw);
    if (access.raw.type === 1 || access.raw.fields?.some((field) => field.type === 1)) {
      this.assertCipherPasswordViewAllowed(access.raw);
    }
    if (access.raw.type === 1 && access.raw.login?.totp) {
      this.assertCipherViewTotpAllowed(access.raw);
    }
    await this.assertRepromptCleared(access.cipher, masterPassword, access.operation.assertCurrent);
    const input = this.toCipherInput(access.cipher);
    await access.operation.assertCacheCurrent();
    access.operation.assertCurrent();
    cloneAuthority?.(access.operation, access.raw);
    this.bindOperationFinalAuthority(access.operation, bindFinalAuthority, () => {
      this.assertCipherEditAllowed(access.operation.policyLease, access.raw);
      if (access.raw.type === 1 || access.raw.fields?.some((field) => field.type === 1)) {
        this.assertCipherPasswordViewAllowed(access.raw);
      }
      if (access.raw.type === 1 && access.raw.login?.totp) this.assertCipherViewTotpAllowed(access.raw);
      cloneAuthority?.(access.operation, access.raw);
    });
    return input;
  }

  private toCipherInput(decrypted: DecryptedCipher): CipherInput {
    if (decrypted.type === 5) throw new AppError('error', 'Unsupported cipher type');
    const input: CipherInput = { type: decrypted.type, name: decrypted.name, favorite: decrypted.favorite };
    if (decrypted.reprompt) input.reprompt = true;
    if (decrypted.notes) input.notes = decrypted.notes;
    if (decrypted.folderId) input.folderId = decrypted.folderId;
    if (decrypted.type === 1) {
      const login: NonNullable<CipherInput['login']> = {};
      if (decrypted.username) login.username = decrypted.username;
      if (decrypted.password) login.password = decrypted.password;
      if (decrypted.totp) login.totp = decrypted.totp;
      if (decrypted.loginUris.length) login.uris = decrypted.loginUris;
      if (decrypted.autofillOnPageLoad !== undefined) {
        login.autofillOnPageLoad = decrypted.autofillOnPageLoad;
      }
      input.login = login;
    } else if (decrypted.type === 3 && decrypted.card) {
      input.card = decrypted.card;
    } else if (decrypted.type === 4 && decrypted.identity) {
      input.identity = decrypted.identity;
    }
    if (decrypted.fields?.length) input.fields = decrypted.fields;
    return input;
  }

  /**
   * Capture all account-scoped mutation material under one lease. Refresh happens before reading the
   * key/token pair; a transition at any await invalidates the lease or epoch before a write can start.
   */
  private async beginVaultOperation(
    options?: { cache?: boolean; allowPendingDataOwnership?: boolean },
    captured?: { accountLease: AccountLease; sessionLease: SessionLease },
  ): Promise<VaultOperationContext> {
    const accountLease = captured?.accountLease ?? this.deps.accountGate.capture();
    const sessionLease = captured?.sessionLease ?? this.deps.sessionGate.capture();
    const accountKey = accountKeyFor(accountLease);
    const identityEpoch = this.identityEpoch();
    const assertBaseCurrent = (): void => {
      this.deps.sessionGate.assert(sessionLease);
      this.deps.accountGate.assert(accountLease);
      this.assertIdentityEpoch(identityEpoch);
    };

    await this.deps.auth.refreshIfNeeded();
    assertBaseCurrent();
    const [userKey, auth, identity] = await Promise.all([
      this.deps.session.loadUserKey(),
      this.deps.session.getActiveAuth(),
      this.deps.getVaultIdentity(),
    ]);
    assertBaseCurrent();
    if (!userKey) throw new AppError('locked', 'Vault is locked');
    if (!auth || auth.email.trim().toLowerCase() !== accountLease.accountIdentity) {
      throw new AppError('session_expired', 'The active account changed during vault operation');
    }
    if (identity !== accountKey) {
      throw new AppError('session_expired', 'The vault identity changed during operation');
    }

    const initialSource = await this.cache.readRaw();
    assertBaseCurrent();
    if (!initialSource) throw new AppError('sync_required', 'Sync required');
    let cacheEnvelope = initialSource;
    const ensuredPolicy = await this.ensurePolicyForSource(cacheEnvelope, accountLease);
    let policyLease = ensuredPolicy.policyLease;
    if (ensuredPolicy.published) await this.enforcePublishedPolicy();
    if (!options?.allowPendingDataOwnership) {
      const policy = this.deps.policyGate.assert(policyLease);
      const pending = cacheEnvelope.response.ciphers.some((cipher) => cipher.organizationId == null)
        && (policy.organizationDataOwnershipTransferPolicy !== null
          || policy.malformedPolicyTypes.includes(EnterprisePolicyType.OrganizationDataOwnership));
      if (pending) {
        throw new AppError(
          'denied',
          'Resolve the organization data ownership requirement before using vault data.',
        );
      }
    }
    let cacheEpoch = options?.cache ? this.cacheEpoch : undefined;

    const assertLeaseCurrent = (): void => {
      assertBaseCurrent();
      this.assertPolicyForSource(policyLease, cacheEnvelope, accountLease);
    };
    const assertCurrent = (): void => {
      assertLeaseCurrent();
      if (cacheEpoch !== undefined && this.cacheEpoch !== cacheEpoch) {
        throw new AppError('error', 'Vault changed during operation');
      }
    };
    const assertCacheCurrent = async (): Promise<void> => {
      assertCurrent();
      try {
        await this.cache.assertCurrent(cacheEnvelope);
      } catch {
        throw new AppError('error', 'Vault changed during operation');
      }
      assertCurrent();
    };
    const adoptRawSource = (source: RawVaultEnvelope, publicationFence: symbol): void => {
      assertBaseCurrent();
      policyLease = this.publishPolicySnapshot(source, accountLease, publicationFence);
      cacheEnvelope = source;
      if (cacheEpoch !== undefined) cacheEpoch = this.cacheEpoch;
      assertCurrent();
    };
    assertCurrent();

    let token = auth.accessToken;
    const executeAuthenticated = async <Result>(
      rebuildRequest: (accessToken: string) => Promise<Result>,
    ): Promise<Result> => {
      assertCurrent();
      const result = await this.deps.auth.executeAuthenticatedRequest(
        accountLease,
        async (currentAccessToken) => {
          assertCurrent();
          token = currentAccessToken;
          return rebuildRequest(currentAccessToken);
        },
      );
      return result;
    };

    return Object.freeze({
      api: this.deps.api.forServer(accountLease.serverUrl).withRequestGuard(assertCurrent),
      userKey,
      get token() { return token; },
      sessionLease,
      accountLease,
      get policyLease() { return policyLease; },
      accountKey,
      identityEpoch,
      get cacheEpoch() { return cacheEpoch; },
      get cacheEnvelope() { return cacheEnvelope; },
      assertBaseCurrent,
      assertLeaseCurrent,
      assertCurrent,
      assertCacheCurrent,
      executeAuthenticated,
      adoptRawSource,
    });
  }

  private async syncAfterMutation(
    operation: VaultOperationContext,
    verify?: (response: SyncResponse) => void,
  ): Promise<VaultListing> {
    operation.assertCurrent();
    const response = await operation.executeAuthenticated(
      (accessToken) => operation.api.sync(accessToken),
    );
    operation.assertCurrent();
    await this.assertSyncSecurityStamp(
      response,
      operation.accountLease,
      operation.assertCurrent,
      true,
    );
    operation.assertCurrent();
    verify?.(response);
    operation.assertCurrent();
    const source = await this.withCacheMutation(async () => {
      operation.assertCurrent();
      const publicationFence = Symbol('mutationSyncPolicyPublication');
      this.policyPublicationFence = publicationFence;
      this.revokeOrganizationDataOwnershipGrants();
      this.deps.policyGate.invalidate();
      this.cacheEpoch++;
      const written = await this.cache.writeRaw(response, operation.accountKey);
      operation.assertBaseCurrent();
      operation.adoptRawSource(written, publicationFence);
      return written;
    });
    await this.enforcePublishedPolicy();
    operation.assertCurrent();
    const snapshot = await this.decryptAndPersist(
      response,
      operation.identityEpoch,
      source,
      operation.sessionLease,
      operation.policyLease,
      operation.accountLease,
      operation.assertLeaseCurrent,
    );
    await this.deps.onSyncSuccess?.(operation.accountKey);
    operation.assertLeaseCurrent();
    return snapshot.listing;
  }

  /**
   * Enforce master-password reprompt at the worker boundary: a reprompt-flagged cipher releases its
   * secrets only after the master password is re-verified. Throws 'reprompt_required' when the proof
   * is missing or wrong. This is the real security gate — UI prompts are convenience on top of it.
   */
  private async assertRepromptCleared(
    cipher: Pick<DecryptedCipher, 'reprompt'>,
    masterPassword?: string,
    assertCurrent: () => void = () => {},
    assertRepromptAuthorized?: () => void,
  ): Promise<void> {
    assertCurrent();
    if (!cipher.reprompt) return;
    if (assertRepromptAuthorized) {
      assertRepromptAuthorized();
      assertCurrent();
      return;
    }
    if (!masterPassword || !(await this.deps.auth.verifyMasterPassword(masterPassword))) {
      throw new AppError('reprompt_required', 'Master password required to access this item');
    }
    assertCurrent();
  }

  async getField(
    id: string,
    field: FieldName,
    masterPassword?: string,
    bindFinalAuthority?: VaultFinalAuthorityBinder,
    assertRepromptAuthorized?: () => void,
  ): Promise<string | undefined> {
    const access = await this.decryptCipherById(id);
    if (!access) return undefined;
    const decrypted = access.cipher;
    if (field === 'totp') {
      throw new AppError('denied', 'TOTP seeds cannot be revealed directly.');
    }
    if (isPasswordProtectedField(field)) this.assertCipherPasswordViewAllowed(access.raw);
    await this.assertRepromptCleared(
      decrypted,
      masterPassword,
      access.operation.assertCurrent,
      assertRepromptAuthorized,
    );
    let value: string | undefined;
    if (field === 'card.number') value = decrypted.card?.number;
    else if (field === 'card.code') value = decrypted.card?.code;
    else if (field === 'identity.ssn') value = decrypted.identity?.ssn;
    else if (field === 'identity.passportNumber') value = decrypted.identity?.passportNumber;
    else if (field === 'identity.licenseNumber') value = decrypted.identity?.licenseNumber;
    else value = decrypted[field];
    access.operation.assertCurrent();
    this.bindOperationFinalAuthority(access.operation, bindFinalAuthority, () => {
      assertRepromptAuthorized?.();
      this.assertCipherPolicyAllowed(access.operation.policyLease, access.raw);
      if (isPasswordProtectedField(field)) this.assertCipherPasswordViewAllowed(access.raw);
    });
    return value;
  }

  /** Copy-only username projection. Item reprompt protects secret fields, while the login username
   * remains visible in vault summaries and may be copied without manufacturing a master-password
   * proof. The operation is still bound to the item, account, cache, and enterprise-policy fences. */
  async getLoginUsernameForCopy(
    id: string,
    bindFinalAuthority?: VaultFinalAuthorityBinder,
  ): Promise<string | undefined> {
    const access = await this.decryptCipherById(id);
    if (!access || access.cipher.type !== 1 || isCipherInactive(access.raw)) return undefined;
    const value = access.cipher.username;
    access.operation.assertCurrent();
    this.bindOperationFinalAuthority(access.operation, bindFinalAuthority, () => {
      this.assertCipherPolicyAllowed(access.operation.policyLease, access.raw);
    });
    return value;
  }

  /** Decrypt one cipher for the detail view, with the sensitive secrets stripped out. */
  async getCipherDetail(
    id: string,
    masterPassword?: string,
    bindFinalAuthority?: VaultFinalAuthorityBinder,
  ): Promise<DecryptedCipher | undefined> {
    const access = await this.decryptCipherById(id);
    if (!access) return undefined;
    const decrypted = access.cipher;
    await this.assertRepromptCleared(decrypted, masterPassword, access.operation.assertCurrent);
    const safe: DecryptedCipher = { ...decrypted };
    delete safe.password;
    delete safe.totp;
    if (safe.card) {
      safe.card = { ...safe.card };
      delete safe.card.number;
      delete safe.card.code;
    }
    if (safe.identity) {
      safe.identity = { ...safe.identity };
      delete safe.identity.ssn;
      delete safe.identity.passportNumber;
      delete safe.identity.licenseNumber;
    }
    // SSH material is not part of the detail DTO until a dedicated, reprompt-aware UI/API exists.
    // Drop the whole payload so the private key cannot cross the worker boundary accidentally.
    delete safe.sshKey;
    // Passkeys may ride along for display, but the private key (keyValue) must never cross the boundary.
    if (safe.fido2Credentials) {
      safe.fido2Credentials = safe.fido2Credentials.map((c) => ({ ...c, keyValue: '' }));
    }
    // Hidden custom-field values are secrets: mask them in the detail view (revealed on demand via
    // getCustomField). Text/Boolean/Linked fields are non-secret and ride along for display.
    if (safe.fields) {
      safe.fields = safe.fields.map((f) => {
        if (f.type !== 1) return f;
        const { value: _hidden, ...masked } = f; // drop the Hidden value entirely (not even undefined)
        void _hidden;
        return masked;
      });
    }
    access.operation.assertCurrent();
    this.bindOperationFinalAuthority(access.operation, bindFinalAuthority, () => {
      this.assertCipherPolicyAllowed(access.operation.policyLease, access.raw);
    });
    return safe;
  }

  /** Reveal one Hidden custom field's value on demand (reprompt-gated like other secret fields). */
  async getCustomField(
    id: string,
    index: number,
    masterPassword?: string,
    bindFinalAuthority?: VaultFinalAuthorityBinder,
  ): Promise<string | undefined> {
    const access = await this.decryptCipherById(id);
    if (!access) return undefined;
    const field = access.cipher.fields?.[index];
    if (field?.type === 1) this.assertCipherPasswordViewAllowed(access.raw);
    await this.assertRepromptCleared(access.cipher, masterPassword, access.operation.assertCurrent);
    const value = field?.value;
    access.operation.assertCurrent();
    this.bindOperationFinalAuthority(access.operation, bindFinalAuthority, () => {
      this.assertCipherPolicyAllowed(access.operation.policyLease, access.raw);
      if (field?.type === 1) this.assertCipherPasswordViewAllowed(access.raw);
    });
    return value;
  }

  /**
   * Download and decrypt one attachment inside the worker, returning the plaintext bytes (base64) and
   * file name for the popup to save. Reprompt-gated; the attachment key never crosses the boundary.
   */
  async getAttachment(
    cipherId: string,
    attachmentId: string,
    masterPassword?: string,
    bindFinalAuthority?: VaultFinalAuthorityBinder,
  ): Promise<{ fileName: string; dataB64: string }> {
    const result = await this.getAttachmentBytes(cipherId, attachmentId, masterPassword, bindFinalAuthority);
    try {
      assertLegacyFileMessageBudget({ ok: true, data: { fileName: result.fileName, dataB64: '' } }, base64EncodedLength(result.bytes.byteLength));
      return { fileName: result.fileName, dataB64: bytesToBase64(result.bytes) };
    } finally {
      result.bytes.fill(0);
    }
  }

  /** Return caller-owned plaintext bytes for a bounded, release-gated Port download. */
  async getAttachmentBytes(
    cipherId: string,
    attachmentId: string,
    masterPassword?: string,
    bindFinalAuthority?: VaultFinalAuthorityBinder,
    assertTransferCurrent: () => void = () => undefined,
  ): Promise<{ fileName: string; bytes: Uint8Array }> {
    assertTransferCurrent();
    const operation = await this.beginVaultOperation({ cache: true });
    const cache = operation.cacheEnvelope!.response;
    const candidate = cache.ciphers.find((c) => c.id === cipherId);
    if (!candidate) throw new AppError('error', 'Attachment is unavailable');
    const cipher = this.requireSupportedCipher(candidate);
    this.assertCipherPolicyAllowed(operation.policyLease, cipher);
    const att = cipher?.attachments?.find((a) => a.id === attachmentId);
    if (!att) throw new AppError('error', 'Attachment is unavailable');
    const orgKeys = await this.buildOrgKeys(cache.profile);
    const decrypted = await decryptCipher(cipher, operation.userKey, orgKeys);
    if (!decrypted || decrypted.undecryptable) throw new AppError('denied', 'Item cannot be decrypted');
    await this.assertRepromptCleared(decrypted, masterPassword, operation.assertCurrent);
    let attachmentKey: SymmetricKey | undefined;
    let destroyAttachmentKey = false;
    let encrypted: Uint8Array | undefined;
    let plaintext: Uint8Array | undefined;
    try {
      if (att.key) {
        const cipherKey = await this.cipherFieldKey(cipher, operation.userKey, cache.profile);
        try {
          attachmentKey = await decryptAttachmentKey(att.key, cipherKey);
          destroyAttachmentKey = true;
        } finally {
          if (cipher.key) destroySymmetricKey(cipherKey);
        }
      } else {
        // Legacy attachments predate per-attachment and per-cipher keys. Their file content is
        // encrypted directly with the owning UserKey or OrgKey, even if the cipher was later keyed.
        attachmentKey = await this.cipherOwningKey(cipher, operation.userKey, cache.profile);
      }
      await operation.assertCacheCurrent();
      operation.assertCurrent();
      const downloadUrl = await this.resolveAttachmentDownloadUrl(
        operation,
        cipherId,
        attachmentId,
        att.url,
      );
      await operation.assertCacheCurrent();
      operation.assertCurrent();
      assertTransferCurrent();
      encrypted = await operation.api.downloadAttachment(downloadUrl, operation.token);
      assertTransferCurrent();
      plaintext = await decryptAttachmentFile(encrypted, attachmentKey);
      const fileName = decrypted.attachments?.find((a) => a.id === attachmentId)?.fileName ?? 'attachment';
      await operation.assertCacheCurrent();
      operation.assertCurrent();
      assertTransferCurrent();
      this.bindOperationFinalAuthority(operation, bindFinalAuthority, () => {
        this.assertCipherPolicyAllowed(operation.policyLease, cipher);
      });
      const bytes = plaintext;
      plaintext = undefined;
      return { fileName, bytes };
    } finally {
      encrypted?.fill(0);
      plaintext?.fill(0);
      if (destroyAttachmentKey) destroySymmetricKey(attachmentKey);
    }
  }

  private async resolveAttachmentDownloadUrl(
    operation: VaultOperationContext,
    cipherId: string,
    attachmentId: string,
    cachedUrl: string | null | undefined,
  ): Promise<string> {
    let url: string;
    try {
      url = await operation.executeAuthenticated((accessToken) => (
        operation.api.getAttachmentDownloadUrl(accessToken, cipherId, attachmentId)
      ));
    } catch (error) {
      if (!(error instanceof ApiHttpError) || error.status !== 404 || !cachedUrl) throw error;
      url = cachedUrl;
    }
    await operation.assertCacheCurrent();
    operation.assertCurrent();
    return url;
  }

  /** Encrypt a file under a fresh attachment key, upload it through v2, and verify the synced receipt. */
  async addAttachment(
    cipherId: string,
    fileName: string,
    dataB64: string,
    masterPassword?: string,
  ): Promise<VaultListing> {
    assertLegacyFileMessageBudget({ type: 'vault.addAttachment', cipherId, fileName, dataB64: '', ...(masterPassword === undefined ? {} : { masterPassword }) }, dataB64.length);
    const plaintext = parseAttachmentInput(fileName, dataB64);
    try {
      return await this.addAttachmentBytes(cipherId, fileName, plaintext, masterPassword);
    } finally {
      plaintext.fill(0);
    }
  }

  /** Borrow a staged file buffer while preserving attachment authorization and compensation. */
  async addAttachmentBytes(
    cipherId: string,
    fileName: string,
    fileBytes: Uint8Array,
    masterPassword?: string,
    bindFinalAuthority?: VaultFinalAuthorityBinder,
    assertTransferCurrent: () => void = () => undefined,
  ): Promise<VaultListing> {
    assertTransferCurrent();
    assertAttachmentFileName(fileName);
    if (!(fileBytes instanceof Uint8Array) || fileBytes.byteLength > MAX_ATTACHMENT_PLAINTEXT_BYTES) {
      throw new AppError('error', 'Attachment exceeds this client\'s size limit.');
    }
    const result = await this.runVaultMutation(
      'attachment.create',
      async (runtime): Promise<
        | { readonly status: 'committed'; readonly listing: VaultListing }
        | { readonly status: 'rolled_back'; readonly error: unknown }
      > => {
        assertTransferCurrent();
        const { operation, reconcile } = runtime;
        const cache = operation.cacheEnvelope!.response;
        const candidate = cache.ciphers.find((cipher) => cipher.id === cipherId);
        if (!candidate) throw new AppError('error', 'Item is not available');
        const cipher = this.requireSupportedCipher(candidate);
        if (cipher.deletedDate != null) {
          throw new AppError('denied', 'Attachments on items in the trash cannot be changed.');
        }
        this.assertCipherEditAllowed(operation.policyLease, cipher);
        const decrypted = await decryptCipher(
          cipher,
          operation.userKey,
          await this.buildOrgKeys(cache.profile),
        );
        if (!decrypted || decrypted.undecryptable) {
          throw new AppError('denied', 'Item cannot be decrypted');
        }
        await this.assertRepromptCleared(decrypted, masterPassword, operation.assertCurrent);
        assertAttachmentFileNameAvailable(decrypted.attachments, fileName);

        let encrypted: Uint8Array | undefined;
        let cipherKey: SymmetricKey | undefined;
        let attachmentKey: SymmetricKey | undefined;
        try {
          assertTransferCurrent();
          cipherKey = await this.cipherFieldKey(cipher, operation.userKey, cache.profile);
          attachmentKey = generateAttachmentKey();
          const wrappedKey = await wrapAttachmentKey(attachmentKey, cipherKey);
          encrypted = await encryptAttachmentFile(fileBytes, attachmentKey);
          const encryptedFileName = await encryptToText(fileName, cipherKey);
          await operation.assertCacheCurrent();
          assertAttachmentFileNameAvailable(decrypted.attachments, fileName);
          operation.assertLeaseCurrent();
          assertTransferCurrent();

          const upload = await this.uploadPreparedAttachment(runtime, cipher, {
            wrappedKey,
            encryptedFileName,
            encrypted,
          }, assertTransferCurrent);
          if (upload.status === 'rolled_back') return upload;
          const listing = await reconcile(() => this.syncAfterMutation(operation, (response) => {
            assertAttachmentUploadCommitted(
              response,
              cipherId,
              upload.receipt.attachmentId,
              wrappedKey,
              encryptedFileName,
              encrypted!.byteLength,
            );
          }));
          return { status: 'committed', listing };
        } finally {
          encrypted?.fill(0);
          destroySymmetricKey(attachmentKey);
          if (cipher.key) destroySymmetricKey(cipherKey);
        }
      },
      { cache: true, ...(bindFinalAuthority ? { bindFinalAuthority } : {}) },
    );
    if (result.status === 'rolled_back') throw attachmentUploadFailure(result.error);
    return result.listing;
  }

  private async uploadPreparedAttachment(
    runtime: VaultMutationRuntime,
    cipher: SupportedCipherResponse,
    prepared: {
      readonly wrappedKey: string;
      readonly encryptedFileName: string;
      readonly encrypted: Uint8Array;
    },
    assertTransferCurrent: () => void = () => undefined,
  ): Promise<PreparedAttachmentUploadResult> {
    const { operation, remote, remoteOnce, reconcile } = runtime;
    let receipt: AttachmentUploadSlotReceipt | undefined;
    try {
      receipt = await remote(
        (accessToken) => {
          assertTransferCurrent();
          return operation.api.createAttachmentUploadSlot(accessToken, cipher.id, {
          key: prepared.wrappedKey,
          fileName: prepared.encryptedFileName,
          fileSize: prepared.encrypted.byteLength,
          adminRequest: false,
          lastKnownRevisionDate: cipher.revisionDate ?? null,
          });
        },
        (value) => { receipt = value; },
      );
      const upload = (accessToken: string) => {
        assertTransferCurrent();
        return operation.api.uploadAttachmentSlotData(accessToken, cipher.id, receipt!, prepared.encryptedFileName, prepared.encrypted);
      };
      if (receipt.fileUploadType === 0) await remote(upload);
      // Type 1 is an Azure signed PUT. Its HTTP status does not describe the account bearer token.
      else await remoteOnce(() => upload(operation.token));
      assertTransferCurrent();
      return { status: 'uploaded', receipt };
    } catch (error) {
      if (!receipt) throw error;
      const compensationApi = this.deps.api.forServer(operation.accountLease.serverUrl);
      try {
        await compensationApi.deleteAttachment(
          operation.token,
          cipher.id,
          receipt.attachmentId,
        );
      } catch (rollbackError) {
        if (!(rollbackError instanceof ApiHttpError) || rollbackError.status !== 404) {
          throw new AppError(
            'committed_unsynced',
            'The attachment upload failed and its allocated slot could not be rolled back.',
          );
        }
      }
      await reconcile(() => this.syncAfterMutation(operation, (response) => {
        assertAttachmentUploadRolledBack(response, receipt!.attachmentId);
      }));
      return { status: 'rolled_back', error };
    }
  }

  /** Re-encrypt one keyless legacy attachment under a new independent attachment key. */
  async upgradeLegacyAttachment(
    cipherId: string,
    attachmentId: string,
    masterPassword?: string,
  ): Promise<VaultListing> {
    return this.upgradeLegacyAttachmentInternal(cipherId, attachmentId, masterPassword);
  }

  private async upgradeLegacyAttachmentForDataOwnership(
    cipherId: string,
    attachmentId: string,
    organizationId: string,
    masterPassword: string,
    captured: { readonly accountLease: AccountLease; readonly sessionLease: SessionLease },
  ): Promise<VaultListing> {
    return this.upgradeLegacyAttachmentInternal(
      cipherId,
      attachmentId,
      masterPassword,
      organizationId,
      captured,
    );
  }

  private async upgradeLegacyAttachmentInternal(
    cipherId: string,
    attachmentId: string,
    masterPassword?: string,
    ownershipOrganizationId?: string,
    captured?: { readonly accountLease: AccountLease; readonly sessionLease: SessionLease },
  ): Promise<VaultListing> {
    const result = await this.runVaultMutation(
      'attachment.upgradeLegacy',
      async (runtime): Promise<
        | { readonly status: 'committed'; readonly listing: VaultListing }
        | { readonly status: 'rolled_back'; readonly error: unknown }
      > => {
        const { operation, reconcile } = runtime;
        const cache = operation.cacheEnvelope!.response;
        const candidate = cache.ciphers.find((cipher) => cipher.id === cipherId);
        if (!candidate) throw new AppError('error', 'Item is not available');
        const cipher = this.requireSupportedCipher(candidate);
        if (ownershipOrganizationId !== undefined) {
          const ownership = await this.organizationDataOwnershipStatus(operation);
          if (ownership.status !== 'migration_available'
              || ownership.organizationId !== ownershipOrganizationId
              || cipher.organizationId != null) {
            throw new AppError('denied', 'Organization data ownership migration is unavailable.');
          }
          this.assertCipherTargetPolicyAllowed(
            operation.policyLease,
            cipher.type,
            ownershipOrganizationId,
          );
        } else {
          this.assertCipherEditAllowed(operation.policyLease, cipher);
        }
        if (cipher.deletedDate != null && ownershipOrganizationId === undefined) {
          throw new AppError('denied', 'Attachments on items in the trash cannot be changed.');
        }
        const attachment = cipher.attachments?.find((entry) => entry.id === attachmentId);
        if (!attachment || attachment.key != null || !attachment.fileName) {
          throw new AppError('conflict', 'The legacy attachment is no longer available to upgrade.');
        }
        const decrypted = await decryptCipher(
          cipher,
          operation.userKey,
          await this.buildOrgKeys(cache.profile),
        );
        if (!decrypted || decrypted.undecryptable) {
          throw new AppError('denied', 'Item cannot be decrypted');
        }
        await this.assertRepromptCleared(decrypted, masterPassword, operation.assertCurrent);

        let legacyEncrypted: Uint8Array | undefined;
        let plaintext: Uint8Array | undefined;
        let encrypted: Uint8Array | undefined;
        let cipherKey: SymmetricKey | undefined;
        let attachmentKey: SymmetricKey | undefined;
        try {
          cipherKey = await this.cipherFieldKey(cipher, operation.userKey, cache.profile);
          let fileName: string;
          try {
            fileName = await decryptToText(attachment.fileName, cipherKey);
          } catch {
            throw new AppError('denied', 'Attachment name cannot be decrypted.');
          }
          assertAttachmentFileName(fileName);
          const owningKey = await this.cipherOwningKey(cipher, operation.userKey, cache.profile);
          await operation.assertCacheCurrent();
          const downloadUrl = await this.resolveAttachmentDownloadUrl(
            operation,
            cipherId,
            attachmentId,
            attachment.url,
          );
          await operation.assertCacheCurrent();
          legacyEncrypted = await operation.api.downloadAttachment(downloadUrl, operation.token);
          plaintext = await decryptAttachmentFile(legacyEncrypted, owningKey);
          if (plaintext.byteLength > MAX_ATTACHMENT_PLAINTEXT_BYTES) {
            throw new AppError('error', 'Attachment exceeds this client\'s size limit.');
          }

          attachmentKey = generateAttachmentKey();
          const wrappedKey = await wrapAttachmentKey(attachmentKey, cipherKey);
          encrypted = await encryptAttachmentFile(plaintext, attachmentKey);
          const encryptedFileName = await encryptToText(fileName, cipherKey);
          await operation.assertCacheCurrent();
          const upload = await this.uploadPreparedAttachment(runtime, cipher, {
            wrappedKey,
            encryptedFileName,
            encrypted,
          });
          if (upload.status === 'rolled_back') return upload;

          try {
            await operation.executeAuthenticated((accessToken) => (
              operation.api.deleteAttachment(accessToken, cipherId, attachmentId)
            ));
          } catch (error) {
            if (!(error instanceof ApiHttpError) || error.status !== 404) throw error;
          }
          operation.assertCurrent();
          const listing = await reconcile(() => this.syncAfterMutation(operation, (response) => {
            assertAttachmentUploadCommitted(
              response,
              cipherId,
              upload.receipt.attachmentId,
              wrappedKey,
              encryptedFileName,
              encrypted!.byteLength,
            );
            assertAttachmentUploadRolledBack(response, attachmentId);
          }));
          return { status: 'committed', listing };
        } finally {
          legacyEncrypted?.fill(0);
          plaintext?.fill(0);
          encrypted?.fill(0);
          destroySymmetricKey(attachmentKey);
          if (cipher.key) destroySymmetricKey(cipherKey);
        }
      },
      {
        cache: true,
        allowPendingDataOwnership: ownershipOrganizationId !== undefined,
        ...(captured ? { captured } : {}),
      },
    );
    if (result.status === 'rolled_back') throw attachmentUploadFailure(result.error);
    return result.listing;
  }

  /** Delete one attachment from a cipher, then re-sync. */
  async deleteAttachment(cipherId: string, attachmentId: string): Promise<VaultListing> {
    return this.runVaultMutation('attachment.delete', async ({ operation, remote, reconcile }) => {
      const candidate = operation.cacheEnvelope!.response.ciphers.find((cipher) => cipher.id === cipherId);
      if (!candidate) throw new AppError('error', 'Item is not available');
      const cipher = this.requireSupportedCipher(candidate);
      if (cipher.deletedDate != null) {
        throw new AppError('denied', 'Attachments on items in the trash cannot be changed.');
      }
      this.assertCipherEditAllowed(operation.policyLease, cipher);
      await remote((accessToken) => (
        operation.api.deleteAttachment(accessToken, cipherId, attachmentId)
      ));
      return reconcile(() => this.syncAfterMutation(operation));
    }, { cache: true });
  }

  /** Decrypt a login's retained previous passwords (most-recent first), reprompt-gated. The decrypted
   *  values cross the boundary only on this explicit, user-initiated request. */
  async getPasswordHistory(
    id: string,
    masterPassword?: string,
    bindFinalAuthority?: VaultFinalAuthorityBinder,
  ): Promise<Array<{ password: string; lastUsedDate?: string }>> {
    const operation = await this.beginVaultOperation({ cache: true });
    const cache = operation.cacheEnvelope.response;
    const candidate = cache.ciphers.find((c) => c.id === id);
    if (!candidate) {
      operation.assertCurrent();
      return [];
    }
    const cipher = this.requireSupportedCipher(candidate);
    this.assertCipherPolicyAllowed(operation.policyLease, cipher);
    this.assertCipherPasswordViewAllowed(cipher);
    if (!cipher.passwordHistory?.length) {
      operation.assertCurrent();
      return [];
    }
    const orgKeys = await this.buildOrgKeys(cache.profile);
    const decrypted = await decryptCipher(cipher, operation.userKey, orgKeys);
    if (!decrypted || decrypted.undecryptable) throw new AppError('denied', 'Item cannot be decrypted');
    await this.assertRepromptCleared(decrypted, masterPassword, operation.assertCurrent);
    const baseKey = cipher.organizationId ? orgKeys.get(cipher.organizationId) : operation.userKey;
    if (!baseKey) {
      operation.assertCurrent();
      return [];
    }
    const key = cipher.key ? await unwrapSymmetricKey(cipher.key, baseKey) : baseKey;
    const out: Array<{ password: string; lastUsedDate?: string }> = [];
    for (const entry of cipher.passwordHistory) {
      if (!entry.password) continue;
      try {
        const password = await decryptToText(entry.password, key);
        out.push(entry.lastUsedDate ? { password, lastUsedDate: entry.lastUsedDate } : { password });
      } catch {
        // Skip an entry we cannot decrypt rather than failing the whole history.
      }
    }
    await operation.assertCacheCurrent();
    operation.assertCurrent();
    this.bindOperationFinalAuthority(operation, bindFinalAuthority, () => {
      this.assertCipherPolicyAllowed(operation.policyLease, cipher);
      this.assertCipherPasswordViewAllowed(cipher);
    });
    return out;
  }

  /** Generate the current TOTP code for a login, decrypting the secret only inside the worker. */
  async getTotpCode(
    id: string,
    masterPassword?: string,
    bindFinalAuthority?: VaultFinalAuthorityBinder,
    assertRepromptAuthorized?: () => void,
  ): Promise<TotpResult | undefined> {
    const access = await this.decryptCipherById(id);
    if (!access?.cipher.totp || isCipherInactive(access.raw)) return undefined;
    this.assertCipherViewTotpAllowed(access.raw);
    await this.assertRepromptCleared(
      access.cipher,
      masterPassword,
      access.operation.assertCurrent,
      assertRepromptAuthorized,
    );
    const result = await getTotp(access.cipher.totp, (this.deps.now ?? Date.now)());
    access.operation.assertCurrent();
    this.bindOperationFinalAuthority(access.operation, bindFinalAuthority, () => {
      assertRepromptAuthorized?.();
      this.assertCipherPolicyAllowed(access.operation.policyLease, access.raw);
      this.assertCipherViewTotpAllowed(access.raw);
    });
    return result;
  }

  /** Live one-time codes for every non-trashed login carrying a TOTP secret, for the 2FA view. The
   *  secret is decrypted only in the worker; only the short code + timing + display name/username
   *  cross the boundary. Master-password-reprompt items are omitted — their code must be revealed
   *  explicitly through the item detail, not shown at a glance. */
  async listTotpCodes(bindFinalAuthority?: VaultFinalAuthorityBinder): Promise<TotpListEntry[]> {
    const operation = await this.beginVaultOperation({ cache: true });
    const cache = operation.cacheEnvelope.response;
    const orgKeys = await this.buildOrgKeys(cache.profile);
    const now = (this.deps.now ?? Date.now)();
    const out: TotpListEntry[] = [];
    for (const candidate of cache.ciphers) {
      if (candidate.type !== 1 || isCipherInactive(candidate) || candidate.reprompt) continue;
      let cipher: SupportedCipherResponse;
      try {
        cipher = this.requireSupportedCipher(candidate, [1]);
        this.assertCipherViewTotpAllowed(cipher);
      } catch {
        continue;
      }
      if (this.deps.policyGate.isItemRestricted(operation.policyLease, {
        type: cipher.type,
        organizationId: cipher.organizationId ?? null,
      })) continue;
      let decrypted;
      try {
        decrypted = await decryptCipher(cipher, operation.userKey, orgKeys);
      } catch {
        continue; // a single undecryptable cipher must not drop every other code
      }
      if (!decrypted?.totp) continue;
      const totp = await getTotp(decrypted.totp, now);
      if (!totp) continue; // unparseable secret → skip rather than surface a broken row
      out.push(decrypted.username
        ? { id: decrypted.id, name: decrypted.name, username: decrypted.username, code: totp.code, period: totp.period, remaining: totp.remaining }
        : { id: decrypted.id, name: decrypted.name, code: totp.code, period: totp.period, remaining: totp.remaining });
    }
    await operation.assertCacheCurrent();
    operation.assertCurrent();
    this.bindOperationFinalAuthority(operation, bindFinalAuthority);
    return out;
  }

  /**
   * Sign a WebAuthn assertion for a stored passkey matching the request. Searches all logins for a
   * fido2Credential with the requested rpId (and allowed credentialId, if any), signs in the worker
   * with the credential's private key, and returns the assertion. The private key never leaves the worker.
   */
  async getPasskeyAssertion(params: PasskeyAssertionRequest): Promise<PasskeyAssertion | undefined> {
    // Capture before queueing so an assertion requested by one account can never bind to a later
    // active account. The dedicated queue also keeps advisory counter reads from racing the policy
    // publication performed by another assertion's authoritative refresh.
    const captured = {
      accountLease: this.deps.accountGate.capture(),
      sessionLease: this.deps.sessionGate.capture(),
    };
    const result = this.passkeyAssertionTail.then(() => (
      this.getPasskeyAssertionSerialized(params, captured)
    ));
    this.passkeyAssertionTail = result.then(() => undefined, () => undefined);
    return result;
  }

  private async getPasskeyAssertionSerialized(
    params: PasskeyAssertionRequest,
    captured: { readonly accountLease: AccountLease; readonly sessionLease: SessionLease },
  ): Promise<PasskeyAssertion | undefined> {
    const scope = this.normalizePasskeyScope(params.rpId, params.origin);
    if (params.crossOrigin !== undefined && typeof params.crossOrigin !== 'boolean') {
      throw new AppError('denied', 'Invalid passkey ancestor context');
    }
    const signingScope = Object.freeze({ ...scope, crossOrigin: params.crossOrigin === true });
    const selection = this.normalizePasskeySelection(params.allowedCredentialIds);
    let challenge: string;
    try {
      challenge = normalizePasskeyChallenge(params.challenge);
    } catch {
      throw new AppError('denied', 'Invalid passkey challenge');
    }
    const match = await this.findPasskeyCredential(
      scope.rpId,
      selection,
      false,
      captured,
    );
    if (!match) return undefined;
    const cred = match.credential;
    const counter = await this.withPasskeyCounterState(
      match.operation,
      match.cipher,
      cred.credentialId,
      (state) => state.counter,
    );
    if (counter > 0) {
      if (counter >= MAX_FIDO2_SIGNATURE_COUNTER) throw invalidPasskeyCounter();
      return this.incrementPasskeyCounterAndGetAssertion(
        signingScope,
        challenge,
        match.cipher.id,
        cred.credentialId,
        match.operation.accountLease,
        match.operation.sessionLease,
      );
    }
    return this.signPasskeyCredential(match.operation, cred, signingScope, challenge, 0);
  }

  private async incrementPasskeyCounterAndGetAssertion(
    scope: { readonly rpId: string; readonly origin: string; readonly crossOrigin: boolean },
    challenge: string,
    cipherId: string,
    credentialId: string,
    accountLease: AccountLease,
    sessionLease: SessionLease,
  ): Promise<PasskeyAssertion> {
    const selection = normalizePasskeyCredentialSelection([credentialId]);
    const outcome = await this.runVaultMutation<PasskeySigningOutcome>('passkey.incrementCounter', async ({ operation, remote, reconcile }) => {
      // A non-zero signature counter is shared mutable state. Refresh inside the account mutation
      // lane before selecting it so OCC starts from the latest authoritative server revision.
      await this.syncAfterMutation(operation);
      const fresh = await this.findPasskeyCredentialInOperation(
        operation,
        scope.rpId,
        selection,
        false,
        cipherId,
        true,
      );
      if (!fresh || fresh.credential.credentialId !== credentialId) {
        throw unavailablePasskeyCredential();
      }
      this.assertCipherPolicyAllowed(operation.policyLease, fresh.cipher);
      this.assertCipherEditAllowed(operation.policyLease, fresh.cipher);
      const revisionDate = fresh.cipher.revisionDate;
      if (!isIsoTimestamp(revisionDate)) {
        throw new AppError('denied', 'Passkey counter revision is unavailable.');
      }

      const prepared = await this.withPasskeyCounterState(
        operation,
        fresh.cipher,
        credentialId,
        async (state, fieldKey) => {
          if (state.counter <= 0 || state.counter >= MAX_FIDO2_SIGNATURE_COUNTER) {
            throw invalidPasskeyCounter();
          }
          const nextCounter = state.counter + 1;
          const encryptedCounter = await encryptToText(String(nextCounter), fieldKey);
          const credentials = state.credentials.map((credential, index) => (
            index === state.credentialIndex
              ? { ...credential, counter: encryptedCounter }
              : credential
          ));
          const request = this.cipherResponseToRequest(fresh.cipher);
          request.login = { ...(request.login ?? {}), fido2Credentials: credentials };
          request.lastKnownRevisionDate = revisionDate;
          return { credentials, nextCounter, request };
        },
      );

      await operation.assertCacheCurrent();
      await remote((accessToken) => (
        operation.api.updateCipher(accessToken, cipherId, prepared.request)
      ));
      await reconcile(() => this.syncAfterMutation(operation, (response) => {
        assertPasskeyCounterUpdateCommitted(response, cipherId, prepared.credentials);
      }));
      try {
        const committed = await this.findPasskeyCredentialInOperation(
          operation,
          scope.rpId,
          selection,
          false,
          cipherId,
          true,
        );
        if (!committed || committed.credential.credentialId !== credentialId) {
          throw unavailablePasskeyCredential();
        }
        this.assertCipherPolicyAllowed(operation.policyLease, committed.cipher);
        this.assertCipherEditAllowed(operation.policyLease, committed.cipher);
        const committedCounter = await this.withPasskeyCounterState(
          operation,
          committed.cipher,
          credentialId,
          (state) => state.counter,
        );
        if (committedCounter !== prepared.nextCounter) {
          throw new AppError(
            'denied',
            'The passkey signature counter changed after synchronization.',
          );
        }
        const assertion = await this.signPasskeyCredential(
          operation,
          committed.credential,
          scope,
          challenge,
          committedCounter,
        );
        return { ok: true, assertion } as const;
      } catch (error) {
        // The counter mutation is already authoritatively reconciled. Surface a local signing
        // failure without leaving the account dirty or releasing a stale assertion.
        return { ok: false, error } as const;
      }
    }, {
      cache: true,
      captured: { accountLease, sessionLease },
    });
    if (!outcome.ok) throw outcome.error;
    return outcome.assertion;
  }

  private async signPasskeyCredential(
    operation: VaultOperationContext,
    credential: DecryptedFido2Credential,
    scope: { readonly rpId: string; readonly origin: string; readonly crossOrigin: boolean },
    challenge: string,
    counter: number,
  ): Promise<PasskeyAssertion> {
    if (!isUint32(counter)) throw invalidPasskeyCounter();
    await operation.assertCacheCurrent();
    let privateKeyBytes: Uint8Array | undefined;
    try {
      privateKeyBytes = base64UrlToBytes(credential.keyValue);
      const assertion = await signFido2Assertion(privateKeyBytes, {
        rpId: scope.rpId,
        origin: scope.origin,
        challenge,
        counter,
        crossOrigin: scope.crossOrigin,
        // Consent is user presence, not user verification. A real verifier must be added before UV.
        userVerified: false,
      });
      await operation.assertCacheCurrent();
      operation.assertCurrent();
      const result: PasskeyAssertion = { credentialId: credential.credentialId, ...assertion };
      if (credential.userHandle) result.userHandle = credential.userHandle;
      return result;
    } finally {
      privateKeyBytes?.fill(0);
    }
  }

  private async withPasskeyCounterState<Result>(
    operation: VaultOperationContext,
    cipher: SupportedCipherResponse,
    credentialId: string,
    use: (
      state: PasskeyCounterState,
      fieldKey: SymmetricKey,
    ) => Result | PromiseLike<Result>,
  ): Promise<Result> {
    const credentials = cipher.login?.fido2Credentials;
    if (!Array.isArray(credentials) || credentials.length !== 1) {
      throw unavailablePasskeyCredential();
    }
    const fieldKey = await this.cipherFieldKey(
      cipher,
      operation.userKey,
      operation.cacheEnvelope.response.profile,
    );
    try {
      operation.assertCurrent();

      const encryptedId = credentials[0]?.credentialId;
      if (typeof encryptedId !== 'string' || encryptedId.length === 0) {
        throw unavailablePasskeyCredential();
      }
      let currentId: string;
      try {
        currentId = await decryptToText(encryptedId, fieldKey);
      } catch {
        throw unavailablePasskeyCredential();
      }
      operation.assertCurrent();
      if (currentId !== credentialId) throw unavailablePasskeyCredential();

      const encryptedCounter = credentials[0]!.counter;
      if (typeof encryptedCounter !== 'string' || encryptedCounter.length === 0) {
        throw invalidPasskeyCounter();
      }
      let plaintext: string;
      try {
        plaintext = await decryptToText(encryptedCounter, fieldKey);
      } catch {
        throw invalidPasskeyCounter();
      }
      const counter = parsePasskeyCounter(plaintext);
      await operation.assertCacheCurrent();
      const result = await use({ counter, credentialIndex: 0, credentials }, fieldKey);
      await operation.assertCacheCurrent();
      return result;
    } finally {
      if (cipher.key != null) destroySymmetricKey(fieldKey);
    }
  }

  /** True when an unexpired stored passkey matches the rpId (and allowedCredentialIds, if given).
   *  Lets the page decide whether to prompt for consent without signing or revealing key material. */
  async hasMatchingPasskey(params: PasskeyLookupRequest): Promise<boolean> {
    const scope = this.normalizePasskeyScope(params.rpId, params.origin);
    const selection = this.normalizePasskeySelection(params.allowedCredentialIds);
    // First-phase metadata may include a reprompt item; signing still excludes it below.
    return (await this.findPasskeyCredential(scope.rpId, selection, true)) !== undefined;
  }

  /** Every stored passkey matching the rpId (and allowedCredentialIds, if given), for the get() account
   *  picker when a site has more than one. Display-only: the public credentialId plus the login's
   *  name/username (or the passkey's stored userName) — never the private keyValue. */
  async listPasskeyCandidates(params: PasskeyLookupRequest): Promise<PasskeyCandidate[]> {
    const scope = this.normalizePasskeyScope(params.rpId, params.origin);
    const selection = this.normalizePasskeySelection(params.allowedCredentialIds);
    const operation = await this.beginVaultOperation({ cache: true });
    const cache = operation.cacheEnvelope.response;
    const orgKeys = await this.buildOrgKeys(cache.profile);
    const out: PasskeyCandidate[] = [];
    const seenCredentialIds = new Set<string>();
    for (const cipher of cache.ciphers) {
      if (cipher.type !== 1
        || cipher.login?.fido2Credentials?.length !== 1
        || isCipherInactive(cipher)) continue;
      if (this.deps.policyGate.isItemRestricted(operation.policyLease, {
        type: cipher.type,
        organizationId: cipher.organizationId ?? null,
      })) continue;
      let decrypted;
      try {
        decrypted = await decryptCipher(cipher, operation.userKey, orgKeys);
      } catch {
        continue; // a single undecryptable cipher must not poison the picker for all rpIds
      }
      if (decrypted?.fido2Credentials?.length !== 1) continue;
      const cred = decrypted.fido2Credentials[0]!;
      if (cred.rpId !== scope.rpId || !passkeySelectionMatches(cred, selection)) continue;
      if (seenCredentialIds.has(cred.credentialId)) continue;
      seenCredentialIds.add(cred.credentialId);
      const username = decrypted.username || cred.userName;
      const candidate: PasskeyCandidate = {
        credentialId: cred.credentialId,
        name: decrypted.name,
        ...(username ? { username } : {}),
        ...(cipher.reprompt ? { requiresReprompt: true } : {}),
      };
      out.push(candidate);
      if (out.length >= MAX_PASSKEY_CREDENTIAL_DESCRIPTORS) break;
    }
    await operation.assertCacheCurrent();
    operation.assertCurrent();
    return out;
  }

  /** Same-domain writable login items a new passkey could be saved into (for the create picker).
   *  Reads the decrypted summary cache — carries only id/name/username, never secrets. */
  async getPasskeyTargets(params: { rpId: string; origin: string }): Promise<PasskeyTarget[]> {
    const scope = this.normalizePasskeyScope(params.rpId, params.origin);
    const operation = await this.beginVaultOperation({ cache: true });
    const view = await this.requireCacheView();
    operation.assertCurrent();
    if (view.envelope.rawGeneration !== operation.cacheEnvelope.rawGeneration) {
      throw new AppError('denied', 'Passkey target discovery is no longer current.');
    }
    const summaries = view.snapshot.listing.items;
    const rawCiphers = new Map(operation.cacheEnvelope.response.ciphers.map((cipher) => [cipher.id, cipher]));
    const out: PasskeyTarget[] = [];
    for (const s of summaries) {
      const rawCipher = rawCiphers.get(s.id);
      if (s.type !== 1
          || isCipherInactive(s)
          || s.undecryptable
          || !rawCipher
          || !hasNoStoredPasskey(rawCipher)
          || !summaryAllowsCipherAccess(s, 'edit')
          || !summaryAllowsCipherAccess(s, 'viewPassword')) continue;
      const matches = s.loginUris.some((u) => {
        const host = getHostAndPort(u.uri)?.host;
        return host ? isRegistrableRpId(scope.rpId, host) : false;
      });
      if (!matches) continue;
      out.push({
        id: s.id,
        name: s.name,
        ...(s.username ? { username: s.username } : {}),
        ...(s.reprompt ? { requiresReprompt: true } : {}),
      });
    }
    operation.assertCurrent();
    return out;
  }

  /** Generate an ES256 passkey, build its attestation, and store it as the sole credential on either
   *  a new personal login or an empty same-domain writable login offered by the picker. Then
   *  authoritatively verify the single-credential result before clearing the mutation marker and
   *  return the attestation. The private key never leaves the worker. */
  async createPasskey(
    params: PasskeyCreateRequest,
    options: PasskeyCreateOptions = {},
  ): Promise<Fido2Registration> {
    const assertAuthorized = options.assertAuthorized;
    if (assertAuthorized !== undefined && typeof assertAuthorized !== 'function') {
      throw new AppError('denied', 'Passkey creation authorization is invalid');
    }
    assertAuthorized?.();
    const scope = this.normalizePasskeyScope(params.rpId, params.origin);
    let challenge: string;
    let userHandle: string | undefined;
    let excludeCredentialIds: readonly string[];
    let discoverable: boolean;
    let crossOrigin: boolean;
    try {
      challenge = normalizePasskeyChallenge(params.challenge);
      userHandle = normalizePasskeyUserHandle(params.userHandle);
      excludeCredentialIds = normalizePasskeyExcludeCredentialIds(params.excludeCredentialIds);
      if (params.crossOrigin !== undefined && typeof params.crossOrigin !== 'boolean') {
        throw new TypeError('Invalid crossOrigin value');
      }
      crossOrigin = params.crossOrigin === true;
      discoverable = normalizePasskeyResidentSelection(
        params.residentKey,
        params.requireResidentKey,
      ).discoverable;
      const route = decidePasskeyCreationRoute(params.authenticatorAttachment);
      if (route.kind === 'native-fallback') {
        throw new AppError('no_match', 'A cross-platform authenticator was requested');
      }
    } catch (error) {
      if (error instanceof AppError) throw error;
      throw new AppError('denied', 'Invalid passkey creation request');
    }
    const rpName = optionalBoundedPasskeyText(params.rpName, 256, 'rpName');
    const userName = optionalBoundedPasskeyText(params.userName, 256, 'userName');
    const userDisplayName = optionalBoundedPasskeyText(
      params.userDisplayName,
      256,
      'userDisplayName',
    );
    const targetCipherId = optionalBoundedPasskeyText(
      params.targetCipherId,
      256,
      'targetCipherId',
    );
    let registration: Fido2Registration | undefined;
    let keypair: GeneratedFido2Keypair | undefined;
    try {
      return await this.runVaultMutation('passkey.create', async ({ operation, remote, reconcile }) => {
    assertAuthorized?.();
    let targetOriginal: SupportedCipherResponse | undefined;
    const targetSource = operation.cacheEnvelope;
    if (targetCipherId) {
      const candidate = targetSource.response.ciphers.find((cipher) => cipher.id === targetCipherId);
      if (!candidate) throw new AppError('error', 'Target is not a valid target for this passkey');
      targetOriginal = this.requireSupportedCipher(candidate, [1]);
      this.assertCipherEditAllowed(operation.policyLease, targetOriginal);
      this.assertCipherPasswordViewAllowed(targetOriginal);
      if (isCipherInactive(targetOriginal) || targetOriginal.reprompt) {
        throw new AppError('error', 'Target is not a valid target for this passkey');
      }
      // The current picker cannot communicate an overwrite. Existing, malformed, and multi-credential
      // targets are therefore excluded during discovery and rejected again at the mutation boundary.
      if (!hasNoStoredPasskey(targetOriginal)) {
        throw new AppError('error', 'Target already contains a passkey');
      }
    } else {
      this.assertPersonalCreationAllowed(operation.policyLease, 1);
    }

    assertAuthorized?.();
    await this.assertNoExcludedPasskey(operation, scope.rpId, excludeCredentialIds);
    assertAuthorized?.();
    keypair = await (this.deps.generateFido2Keypair ?? generateFido2Keypair)();
    assertAuthorized?.();
    const credentialIdB64 = bytesToBase64Url(keypair.credentialId);
    const { attestationObject, authData } = await buildAttestationObject({
      rpId: scope.rpId, coseKey: keypair.coseKey, credentialId: keypair.credentialId,
      userVerified: false,
    });
    const clientDataJSON = buildCreateClientDataJSON(challenge, scope.origin, crossOrigin);
    const creationDate = new Date((this.deps.now ?? Date.now)()).toISOString();
    const newCredPlain = {
      credentialId: credentialIdB64,
      keyValue: bytesToBase64Url(keypair.pkcs8),
      rpId: scope.rpId,
      counter: 0,
      discoverable,
      creationDate,
      ...(userHandle ? { userHandle } : {}),
      ...(userName ? { userName } : {}),
      ...(rpName ? { rpName } : {}),
      ...(userDisplayName ? { userDisplayName } : {}),
    };

    registration = {
      credentialId: credentialIdB64,
      attestationObject: bytesToBase64Url(attestationObject),
      clientDataJSON: bytesToBase64Url(new TextEncoder().encode(clientDataJSON)),
      authData: bytesToBase64Url(authData),
      publicKeySpki: bytesToBase64Url(keypair.publicKeySpki),
      publicKeyAlgorithm: -7,
    };

    let request: CipherRequest;
    let updateTargetId: string | undefined;
    if (targetCipherId && targetOriginal) {
      const original = targetOriginal;
      const target = await decryptCipher(
        original,
        operation.userKey,
        await this.buildOrgKeys(targetSource.response.profile),
      );
      const matchesRp = target?.loginUris.some((uri) => {
        const host = getHostAndPort(uri.uri)?.host;
        return host ? isRegistrableRpId(scope.rpId, host) : false;
      });
      if (!target || target.undecryptable || !matchesRp) throw new AppError('error', 'Target is not a valid target for this passkey');
      // Encrypt under the TARGET cipher's own field key (its per-cipher key, or the org/account key that
      // owns it) — NEVER the account UserKey. Encrypting under the wrong key would make an org or
      // per-cipher-keyed item's passkey (and everything else read with that field key) undecryptable.
      const fieldKey = await this.cipherFieldKey(original, operation.userKey, targetSource.response.profile);
      const newCred = await encryptFido2Credential(newCredPlain, fieldKey);
      // Build the PUT body verbatim from the original CipherResponse (bypassing encryptCipher and
      // mergeServerManagedFields) so every non-passkey encrypted field survives byte-for-byte.
      request = this.cipherResponseToRequest(original);
      request.login = { ...(request.login ?? {}), fido2Credentials: [newCred] };
      request.lastKnownRevisionDate = original.revisionDate ?? null;
      updateTargetId = targetCipherId;
    } else {
      const newCred = await encryptFido2Credential(newCredPlain, operation.userKey);
      request = await encryptCipher({
        type: 1, name: rpName || scope.rpId,
        login: { ...(userName ? { username: userName } : {}), uris: [{ uri: scope.origin }] },
      }, operation.userKey);
      request.login = { ...(request.login ?? {}), fido2Credentials: [newCred] };
    }

    assertAuthorized?.();
    const checkedRawGeneration = await this.assertNoExcludedPasskey(
      operation,
      scope.rpId,
      excludeCredentialIds,
    );
    assertAuthorized?.();
    const api = operation.api.withRequestGuard(() => {
      operation.assertCurrent();
      assertAuthorized?.();
      if (operation.cacheEnvelope.rawGeneration !== checkedRawGeneration) {
        throw new AppError('conflict', 'Passkey exclusion state changed during creation');
      }
    });
    let committedCipherId: string;
    if (updateTargetId) {
      await remote((accessToken) => api.updateCipher(accessToken, updateTargetId, request));
      committedCipherId = updateTargetId;
    } else {
      const created = await remote((accessToken) => api.createCipher(accessToken, request));
      if (typeof created.id !== 'string' || created.id.length === 0) {
        throw new AppError('committed_unsynced', 'The created passkey item could not be identified.');
      }
      committedCipherId = created.id;
    }

    // Reconcile authoritatively before clearing dirty. If this sync fails, the stored credential is
    // still returned to the RP so a committed registration is never reported as a WebAuthn failure.
    await reconcile(() => this.syncAfterMutation(operation, (response) => {
      assertPasskeyCreationCommitted(
        response,
        committedCipherId,
        request.login!.fido2Credentials![0]!,
      );
    }));
    return registration;
      }, { cache: true });
    } catch (error) {
      if (registration && error instanceof AppError && error.code === 'committed_unsynced') {
        return registration;
      }
      throw error;
    } finally {
      keypair?.pkcs8.fill(0);
    }
  }

  /** Remove exactly one stored passkey by its public credential ID without re-encrypting the item. */
  async deletePasskey(
    cipherId: string,
    credentialId: string,
    masterPassword?: string,
  ): Promise<VaultListing> {
    const requestedCredentialId = requirePasskeyCredentialId(credentialId);
    return this.runVaultMutation('passkey.delete', async ({ operation, remote, reconcile }) => {
      const cache = operation.cacheEnvelope.response;
      const candidate = cache.ciphers.find((cipher) => cipher.id === cipherId);
      if (!candidate) throw new AppError('error', 'Item is not available');
      const cipher = this.requireSupportedCipher(candidate, [1]);
      if (cipher.deletedDate != null) throw new AppError('denied', 'Items in the trash cannot be edited.');
      this.assertCipherEditAllowed(operation.policyLease, cipher);
      this.assertCipherPasswordViewAllowed(cipher);
      await this.assertRepromptCleared(
        { reprompt: Boolean(cipher.reprompt) },
        masterPassword,
        operation.assertCurrent,
      );

      const credentials = cipher.login?.fido2Credentials;
      if (!credentials?.length) throw unavailablePasskeyCredential();
      const fieldKey = await this.cipherFieldKey(cipher, operation.userKey, cache.profile);
      const seenCredentialIds = new Set<string>();
      let matchingIndex = -1;
      for (const [index, credential] of credentials.entries()) {
        operation.assertCurrent();
        if (!credential.credentialId) throw unavailablePasskeyCredential();
        let decryptedCredentialId: string;
        try {
          decryptedCredentialId = requirePasskeyCredentialId(
            await decryptToText(credential.credentialId, fieldKey),
          );
        } catch {
          throw unavailablePasskeyCredential();
        }
        operation.assertCurrent();
        if (seenCredentialIds.has(decryptedCredentialId)) throw unavailablePasskeyCredential();
        seenCredentialIds.add(decryptedCredentialId);
        if (decryptedCredentialId === requestedCredentialId) matchingIndex = index;
      }
      if (matchingIndex < 0) throw unavailablePasskeyCredential();

      const remaining = credentials.filter((_, index) => index !== matchingIndex);
      const request = this.cipherResponseToRequest(cipher);
      request.login = {
        ...(request.login ?? {}),
        fido2Credentials: remaining,
      };
      request.lastKnownRevisionDate = cipher.revisionDate ?? null;
      await operation.assertCacheCurrent();
      await remote((accessToken) => operation.api.updateCipher(accessToken, cipherId, request));
      return reconcile(() => this.syncAfterMutation(operation));
    }, { cache: true });
  }

  /** Build a wholesale CipherRequest from an existing CipherResponse, carrying every field verbatim
   *  (all already EncStrings). Used by passkey updates to avoid re-encrypting or dropping fields. */
  private cipherResponseToRequest(
    c: CipherResponse,
    options: { readonly omitSshKey?: boolean } = {},
  ): CipherRequest {
    const cipher = this.requireSupportedCipher(c);
    const req: CipherRequest = { type: cipher.type, name: cipher.name ?? '' };
    if (c.notes != null) req.notes = c.notes;
    if (c.favorite != null) req.favorite = c.favorite;
    if (c.folderId != null) req.folderId = c.folderId;
    if (c.organizationId != null) req.organizationId = c.organizationId;
    if (c.login != null) req.login = { ...c.login };
    if (c.card != null) req.card = c.card;
    if (c.identity != null) req.identity = c.identity;
    if (cipher.type === 5 && !options.omitSshKey) {
      try {
        req.sshKey = parseCompleteSshKeyCipherData(c.sshKey);
      } catch {
        throw new AppError('denied', 'SSH key item cannot be safely updated.');
      }
    }
    if (c.key != null) req.key = c.key;
    if (c.fields != null) req.fields = c.fields;
    if (c.passwordHistory != null) req.passwordHistory = c.passwordHistory;
    if (c.reprompt != null) req.reprompt = c.reprompt;
    if (c.archivedDate != null) req.archivedDate = c.archivedDate;
    if (c.revisionDate != null) req.lastKnownRevisionDate = c.revisionDate;
    return req;
  }

  private prepareCipherShare(
    rotated: RotatedCipher,
    original: SupportedCipherResponse,
    organizationId: string,
  ): PreparedCipherShare {
    const record = rotated as Record<string, unknown>;
    const attachments = requireShareAttachmentMetadata(record.attachments, original.attachments);
    const responseProjection = { ...record };
    delete responseProjection.attachments2;
    const request = this.cipherResponseToRequest(responseProjection as unknown as CipherResponse);
    if (request.type === 2) request.secureNote = { type: 0 };
    request.organizationId = organizationId;
    request.lastKnownRevisionDate = original.revisionDate ?? null;
    if (attachments.length > 0) {
      request.attachments2 = Object.fromEntries(attachments.map((attachment) => [
        attachment.id,
        { key: attachment.key!, fileName: attachment.fileName! },
      ]));
    }
    return Object.freeze({ request, attachments });
  }

  /** Find a stored passkey for the rpId. Returns the decrypted credential (incl. private key, which
   *  stays inside the worker) or undefined. Trashed ciphers never authenticate. */
  private async findPasskeyCredential(
    rpId: string,
    selection: PasskeyCredentialSelection,
    includeReprompt: boolean,
    captured?: { readonly accountLease: AccountLease; readonly sessionLease: SessionLease },
  ) {
    const operation = await this.beginVaultOperation({ cache: true }, captured);
    return this.findPasskeyCredentialInOperation(
      operation,
      rpId,
      selection,
      includeReprompt,
    );
  }

  private async findPasskeyCredentialInOperation(
    operation: VaultOperationContext,
    rpId: string,
    selection: PasskeyCredentialSelection,
    includeReprompt: boolean,
    expectedCipherId?: string,
    requireUnique = false,
  ) {
    const cache = operation.cacheEnvelope.response;
    const orgKeys = await this.buildOrgKeys(cache.profile);
    let match: {
      readonly credential: DecryptedFido2Credential;
      readonly cipher: SupportedCipherResponse;
      readonly operation: VaultOperationContext;
    } | undefined;
    for (const cipher of cache.ciphers) {
      if (
        cipher.type !== 1
        || cipher.login?.fido2Credentials?.length !== 1
        || (cipher.reprompt && !includeReprompt)
      ) continue;
      if (isCipherInactive(cipher)) continue; // trashed or archived passkeys must not authenticate
      if (this.deps.policyGate.isItemRestricted(operation.policyLease, {
        type: cipher.type,
        organizationId: cipher.organizationId ?? null,
      })) continue;
      let decrypted;
      try {
        decrypted = await decryptCipher(cipher, operation.userKey, orgKeys);
      } catch {
        continue; // a single undecryptable cipher must not poison passkey lookup for all rpIds
      }
      if (decrypted?.fido2Credentials?.length !== 1) continue;
      const cred = decrypted.fido2Credentials[0]!;
      if (cred.rpId !== rpId || !passkeySelectionMatches(cred, selection)) continue;
      if (expectedCipherId !== undefined && cipher.id !== expectedCipherId) {
        if (requireUnique) throw unavailablePasskeyCredential();
        continue;
      }
      if (match && requireUnique) throw unavailablePasskeyCredential();
      match ??= {
        credential: cred,
        cipher: this.requireSupportedCipher(cipher, [1]),
        operation,
      };
    }
    await operation.assertCacheCurrent();
    operation.assertCurrent();
    return match;
  }

  /**
   * Decrypt every active personal-vault login password in the worker and return non-secret health
   * metadata for each one.
   * The complete id set lets the UI merge an explicit HIBP result without exposing passwords across
   * the messaging boundary.
   */
  async getPasswordHealth(): Promise<PasswordHealthEntry[]> {
    const operation = await this.beginVaultOperation({ cache: true });
    const cache = operation.cacheEnvelope.response;
    const orgKeys = await this.buildOrgKeys(cache.profile);
    const inputs: PasswordHealthInput[] = [];
    for (const candidate of cache.ciphers) {
      if (candidate.type !== 1 || candidate.organizationId != null) continue;
      if (isCipherInactive(candidate)) continue; // exclude trashed and archived logins from the health report
      let cipher: SupportedCipherResponse;
      try {
        cipher = this.requireSupportedCipher(candidate, [1]);
        this.assertCipherPasswordViewAllowed(cipher);
      } catch {
        continue;
      }
      if (this.deps.policyGate.isItemRestricted(operation.policyLease, {
        type: cipher.type,
        organizationId: cipher.organizationId ?? null,
      })) continue;
      const decrypted = await decryptCipher(cipher, operation.userKey, orgKeys);
      if (decrypted && !decrypted.undecryptable && decrypted.password) {
        inputs.push({
          id: decrypted.id,
          name: decrypted.name,
          password: decrypted.password,
          ...(decrypted.username ? { username: decrypted.username } : {}),
        });
      }
    }
    const report = buildPasswordHealthReport(inputs);
    await operation.assertCacheCurrent();
    operation.assertCurrent();
    return report;
  }

  /** Check each active personal-vault login password against HIBP (k-anonymity). Decrypts in the
   *  worker, dedupes by password, looks up unique passwords (concurrency-limited), and returns only
   *  per-id breach counts. */
  async getPwnedReport(): Promise<Array<{ id: string; pwnedCount: number }>> {
    const operation = await this.beginVaultOperation({ cache: true });
    const cache = operation.cacheEnvelope.response;
    const orgKeys = await this.buildOrgKeys(cache.profile);
    const logins: Array<{ id: string; password: string }> = [];
    for (const candidate of cache.ciphers) {
      if (candidate.type !== 1 || candidate.organizationId != null || isCipherInactive(candidate)) continue;
      let cipher: SupportedCipherResponse;
      try {
        cipher = this.requireSupportedCipher(candidate, [1]);
        this.assertCipherPasswordViewAllowed(cipher);
      } catch {
        continue;
      }
      if (this.deps.policyGate.isItemRestricted(operation.policyLease, {
        type: cipher.type,
        organizationId: cipher.organizationId ?? null,
      })) continue;
      const decrypted = await decryptCipher(cipher, operation.userKey, orgKeys);
      if (decrypted && !decrypted.undecryptable && decrypted.password) logins.push({ id: decrypted.id, password: decrypted.password });
    }
    const unique = [...new Set(logins.map((l) => l.password))];
    const byPassword = new Map<string, number>();
    const LIMIT = 6;
    // Look up each unique password independently: one failed HIBP request must not abort the whole
    // report. Failed passwords are simply left out of byPassword (their ids get pwnedCount undefined,
    // never a misleading 0). Only a total failure — no lookup succeeded — surfaces as an error.
    for (let i = 0; i < unique.length; i += LIMIT) {
      const batch = unique.slice(i, i + LIMIT);
      const results = await Promise.allSettled(batch.map((pw) => pwnedCount(pw)));
      results.forEach((r, j) => {
        if (r.status === 'fulfilled') byPassword.set(batch[j]!, r.value);
      });
    }
    if (unique.length > 0 && byPassword.size === 0) {
      throw new AppError('error', 'Could not reach the breach service');
    }
    // Omit ids whose lookup failed so the UI shows them as unknown (undefined) rather than "0 breaches".
    const report = logins.flatMap((l) => {
      const count = byPassword.get(l.password);
      return count === undefined ? [] : [{ id: l.id, pwnedCount: count }];
    });
    await operation.assertCacheCurrent();
    operation.assertCurrent();
    return report;
  }

  /** Build a complete personal or managed-organization export under one fenced vault authority. */
  async buildPortableVaultExport(
    format: PortableVaultExportFormat,
    password?: string,
    authority?: PortableVaultTransferAuthority,
    target: VaultTransferExportTarget = PERSONAL_VAULT_TRANSFER_EXPORT_TARGET,
  ): Promise<BuiltPortableVaultExport> {
    const exportTarget = requirePortableExportTarget(target);
    validatePortableExportRequest(format, password, exportTarget);
    if (exportTarget.kind === 'organization') {
      return this.buildPortableOrganizationVaultExport(
        format,
        password,
        authority,
        exportTarget.organizationId,
      );
    }
    const operation = await this.beginVaultOperation({ cache: true }, authority);
    this.deps.policyGate.assertAllowed(operation.policyLease, 'exportPersonalVault');

    const response = operation.cacheEnvelope.response;
    for (const cipher of response.ciphers ?? []) {
      if (cipher.organizationId == null && cipher.deletedDate == null) {
        this.assertCipherPolicyAllowed(operation.policyLease, cipher);
      }
    }

    // Data-only exports deliberately exclude attachment metadata and content. Build from a detached
    // response projection so corrupt or legacy attachment records cannot block an otherwise valid
    // JSON export, while ZIP keeps the complete strict attachment audit and download plan.
    const exportResponse: SyncResponse = format === 'zip' || format === 'csv'
      ? response
      : {
          ...response,
          ciphers: response.ciphers.map(({ attachments: _attachments, ...cipher }) => cipher),
        };
    const strict = createStrictVaultTransferExportDecryptors({
      scope: { kind: 'personal' },
      userKey: operation.userKey,
    });
    const built = await buildVaultTransferExport(exportResponse, {
      scope: { kind: 'personal' },
      limits: { maxTotalDeclaredAttachmentBytes: MAX_PORTABLE_EXPORT_ATTACHMENT_BYTES },
    }, {
      decryptFolder: async (folder, sourceIndex) => {
        operation.assertCurrent();
        const result = await strict.decryptFolder(folder, sourceIndex);
        operation.assertCurrent();
        return result;
      },
      decryptCollection: async (collection, sourceIndex) => {
        operation.assertCurrent();
        const result = await strict.decryptCollection(collection, sourceIndex);
        operation.assertCurrent();
        return result;
      },
      decryptCipher: async (cipher, sourceIndex) => {
        operation.assertCurrent();
        const result = await strict.decryptCipher(cipher, sourceIndex);
        operation.assertCurrent();
        return result;
      },
    });
    await operation.assertCacheCurrent();
    if (!built.ok || !built.ir) {
      throw new AppError('denied', 'The vault cannot be exported without losing or exposing data.');
    }
    if (format === 'encrypted-json' && password === undefined) {
      let bytes: Uint8Array | undefined;
      try {
        bytes = await encodeAccountEncryptedVaultExport(response, built.ir, operation.userKey, {
          maxOutputBytes: MAX_PORTABLE_EXPORT_BYTES,
        });
        await operation.assertCacheCurrent();
        operation.assertCurrent();
        const owned = bytes;
        bytes = undefined;
        return { bytes: owned, filename: 'miyu-vault-account-encrypted.json' };
      } finally {
        bytes?.fill(0);
      }
    }
    if (format === 'csv') {
      const encoded = encodeVaultTransferCsv(built.ir);
      if (!encoded.ok || encoded.csv === null
        || encoded.diagnostics.some((diagnostic) => diagnostic.severity === 'error')) {
        throw new AppError('denied', 'The CSV export exceeds capacity or contains invalid data.');
      }
      const bytes = new TextEncoder().encode(encoded.csv);
      if (bytes.byteLength > MAX_PORTABLE_EXPORT_BYTES) {
        bytes.fill(0);
        throw new AppError('denied', 'The CSV export exceeds the transfer size limit.');
      }
      const review = buildPortableCsvExportReview(encoded, built.attachments.length);
      await operation.assertCacheCurrent();
      operation.assertCurrent();
      return { bytes, filename: 'miyu-vault.csv', review };
    }
    const encoded = encodeVaultTransferJsonBytes(built.ir);
    if (!encoded.ok || !encoded.bytes) {
      throw new AppError('denied', 'The vault cannot be encoded without losing data.');
    }
    let dataJson: Uint8Array | undefined = encoded.bytes;
    try {
      if (format === 'json') {
        await operation.assertCacheCurrent();
        operation.assertCurrent();
        const bytes = dataJson;
        dataJson = undefined;
        return { bytes, filename: 'miyu-vault.json' };
      }
      if (format === 'encrypted-json') {
        const auth = await this.deps.session.getPersistedAuth();
        operation.assertCurrent();
        const encrypted = await buildEncryptedExportJson(
          bytesToUtf8(dataJson),
          password!,
          auth ?? { kdf: 0, kdfIterations: 600_000 },
        );
        const bytes = new TextEncoder().encode(encrypted);
        if (bytes.byteLength > MAX_PORTABLE_EXPORT_BYTES) {
          bytes.fill(0);
          throw new AppError('denied', 'The encrypted export exceeds the transfer size limit.');
        }
        await operation.assertCacheCurrent();
        operation.assertCurrent();
        return { bytes, filename: 'miyu-vault-encrypted.json' };
      }

      const archive = await this.buildPortableVaultArchive(operation, dataJson, built.attachments);
      dataJson.fill(0);
      dataJson = undefined;
      return { bytes: archive, filename: 'miyu-vault.zip' };
    } finally {
      dataJson?.fill(0);
    }
  }

  /** Build the Password Manager managed-collection organization export under one fenced cache view. */
  private async buildPortableOrganizationVaultExport(
    format: PortableVaultExportFormat,
    password: string | undefined,
    authority: PortableVaultTransferAuthority | undefined,
    organizationId: string,
  ): Promise<BuiltPortableVaultExport> {
    if (format === 'zip') throw new AppError('denied', 'ZIP export is not supported for organizations.');
    const operation = await this.beginVaultOperation({ cache: true }, authority);
    const response = operation.cacheEnvelope.response;
    const matchingMetadata = selectOrganizationMetadata(response.profile).entries.filter((entry) => (
      canonicalOrganizationIdOrUndefined(entry.organization.id) === organizationId
      && entry.isMember
    ));
    const metadata = matchingMetadata.length === 1 ? matchingMetadata[0] : undefined;
    if (!metadata
      || metadata.organization.status !== 2
      || metadata.organization.enabled !== true
      || metadata.organization.usePasswordManager === false) {
      throw new AppError('denied', 'The organization is not available for managed export.');
    }

    const organizationKeys = await this.buildOrgKeys(response.profile);
    try {
      const organizationKey = organizationKeys.get(metadata.organization.id)
        ?? organizationKeys.get(organizationId);
      if (!organizationKey) {
        throw new AppError('denied', 'The organization key is unavailable.');
      }

      const selectedCollections: CollectionResponse[] = [];
      const managedCollectionIds = new Set<string>();
      for (const collection of response.collections ?? []) {
        if (canonicalOrganizationIdOrUndefined(collection.organizationId) !== organizationId
          || collection.manage !== true) continue;
        if (typeof collection.id !== 'string' || collection.id.length === 0
          || managedCollectionIds.has(collection.id)) {
          throw new AppError('denied', 'Managed organization collections are ambiguous.');
        }
        managedCollectionIds.add(collection.id);
        selectedCollections.push({ ...collection, organizationId });
      }
      if (selectedCollections.length === 0) {
        throw new AppError('denied', 'No managed organization collections are available for export.');
      }

      const selectedCiphers: CipherResponse[] = [];
      for (const cipher of response.ciphers ?? []) {
        if (canonicalOrganizationIdOrUndefined(cipher.organizationId) !== organizationId
          || cipher.deletedDate != null
          || !Array.isArray(cipher.collectionIds)) continue;
        const selectedIds = cipher.collectionIds.filter((id): id is string => (
          typeof id === 'string' && managedCollectionIds.has(id)
        ));
        if (selectedIds.length === 0) continue;
        if (cipher.collectionIds.some((id) => typeof id !== 'string')
          || new Set(selectedIds).size !== selectedIds.length) {
          throw new AppError('denied', 'Organization item collection metadata is invalid.');
        }
        this.assertCipherPolicyAllowed(operation.policyLease, cipher);
        selectedCiphers.push({ ...cipher, organizationId, collectionIds: selectedIds });
      }

      const selected: SyncResponse = {
        ...response,
        profile: {
          ...response.profile,
          organizations: [{ ...metadata.organization, id: organizationId }],
        },
        folders: [],
        collections: selectedCollections,
        ciphers: selectedCiphers,
      };
      const exportResponse: SyncResponse = format === 'csv'
        ? selected
        : {
            ...selected,
            ciphers: selected.ciphers.map(({ attachments: _attachments, ...cipher }) => cipher),
          };
      const scope = { kind: 'organization', organizationId } as const;
      const strict = createStrictVaultTransferExportDecryptors({
        scope,
        userKey: operation.userKey,
        organizationKeys: new Map([[organizationId, organizationKey]]),
      });
      const built = await buildVaultTransferExport(exportResponse, {
        scope,
        limits: { maxTotalDeclaredAttachmentBytes: MAX_PORTABLE_EXPORT_ATTACHMENT_BYTES },
      }, {
        decryptFolder: async (folder, sourceIndex) => {
          operation.assertCurrent();
          const result = await strict.decryptFolder(folder, sourceIndex);
          operation.assertCurrent();
          return result;
        },
        decryptCollection: async (collection, sourceIndex) => {
          operation.assertCurrent();
          const result = await strict.decryptCollection(collection, sourceIndex);
          operation.assertCurrent();
          return result;
        },
        decryptCipher: async (cipher, sourceIndex) => {
          operation.assertCurrent();
          const result = await strict.decryptCipher(cipher, sourceIndex);
          operation.assertCurrent();
          return result;
        },
      });
      await operation.assertCacheCurrent();
      if (!built.ok || !built.ir || built.ir.scope !== 'organization') {
        throw new AppError('denied', 'The organization cannot be exported without losing or exposing data.');
      }

      if (format === 'encrypted-json' && password === undefined) {
        let bytes: Uint8Array | undefined;
        try {
          bytes = await encodeAccountEncryptedVaultExport(
            exportResponse,
            built.ir,
            operation.userKey,
            {
              maxOutputBytes: MAX_PORTABLE_EXPORT_BYTES,
              organization: { organizationId, key: organizationKey },
            },
          );
          await operation.assertCacheCurrent();
          operation.assertCurrent();
          const owned = bytes;
          bytes = undefined;
          return { bytes: owned, filename: 'miyu-organization-vault-account-encrypted.json' };
        } finally {
          bytes?.fill(0);
        }
      }

      if (format === 'csv') {
        const encoded = encodeVaultTransferCsv(built.ir);
        if (!encoded.ok || encoded.csv === null
          || encoded.diagnostics.some((diagnostic) => diagnostic.severity === 'error')) {
          throw new AppError('denied', 'The organization CSV export contains invalid data.');
        }
        let bytes: Uint8Array | undefined = new TextEncoder().encode(encoded.csv);
        try {
          if (bytes.byteLength > MAX_PORTABLE_EXPORT_BYTES) {
            throw new AppError('denied', 'The organization CSV export exceeds the transfer size limit.');
          }
          const review = buildPortableCsvExportReview(encoded, built.attachments.length);
          await operation.assertCacheCurrent();
          operation.assertCurrent();
          const owned = bytes;
          bytes = undefined;
          return { bytes: owned, filename: 'miyu-organization-vault.csv', review };
        } finally {
          bytes?.fill(0);
        }
      }

      const encoded = encodeVaultTransferJsonBytes(built.ir, {
        organization: { mode: 'export' },
      });
      if (!encoded.ok || !encoded.bytes) {
        throw new AppError('denied', 'The organization cannot be encoded without losing data.');
      }
      let dataJson: Uint8Array | undefined = encoded.bytes;
      try {
        if (format === 'json') {
          await operation.assertCacheCurrent();
          operation.assertCurrent();
          const bytes = dataJson;
          dataJson = undefined;
          return { bytes, filename: 'miyu-organization-vault.json' };
        }

        const auth = await this.deps.session.getPersistedAuth();
        operation.assertCurrent();
        const encrypted = await buildEncryptedExportJson(
          bytesToUtf8(dataJson),
          password!,
          auth ?? { kdf: 0, kdfIterations: 600_000 },
        );
        let bytes: Uint8Array | undefined = new TextEncoder().encode(encrypted);
        try {
          if (bytes.byteLength > MAX_PORTABLE_EXPORT_BYTES) {
            throw new AppError('denied', 'The encrypted organization export exceeds the transfer size limit.');
          }
          await operation.assertCacheCurrent();
          operation.assertCurrent();
          const owned = bytes;
          bytes = undefined;
          return { bytes: owned, filename: 'miyu-organization-vault-encrypted.json' };
        } finally {
          bytes?.fill(0);
        }
      } finally {
        dataJson?.fill(0);
      }
    } finally {
      for (const key of organizationKeys.values()) destroySymmetricKey(key);
    }
  }

  private async buildPortableVaultArchive(
    operation: VaultOperationContext,
    dataJson: Uint8Array,
    plan: readonly VaultTransferExportAttachment[],
  ): Promise<Uint8Array> {
    const response = operation.cacheEnvelope.response;
    const attachments: VaultArchiveAttachmentInput[] = [];
    let totalBytes = 0;
    let totalDeclaredBytes = 0;
    try {
      for (const planned of plan) {
        await operation.assertCacheCurrent();
        const cipher = response.ciphers?.[planned.itemSourceIndex];
        if (!cipher || cipher.id !== planned.itemToken || cipher.organizationId != null || cipher.deletedDate != null) {
          throw new AppError('denied', 'Attachment export plan no longer matches the vault.');
        }
        this.assertCipherPolicyAllowed(operation.policyLease, cipher);
        const rawAttachment = cipher.attachments?.[planned.sourceIndex];
        if (!rawAttachment
          || rawAttachment.id !== planned.attachmentId
          || !rawAttachment.key
          || !rawAttachment.fileName
          || optionalText(rawAttachment.size) !== optionalText(planned.size)
          || optionalText(rawAttachment.sizeName) !== optionalText(planned.sizeName)) {
          throw new AppError('denied', 'Attachment export plan no longer matches the vault.');
        }

        let cipherKey = operation.userKey;
        const destroyCipherKey = cipher.key != null;
        let attachmentKey: SymmetricKey | undefined;
        let encrypted: Uint8Array | undefined;
        let plaintext: Uint8Array | undefined;
        try {
          if (cipher.key != null) cipherKey = await unwrapSymmetricKey(cipher.key, operation.userKey);
          operation.assertCurrent();
          const fileName = await decryptToText(rawAttachment.fileName, cipherKey);
          if (fileName !== planned.fileName) {
            throw new AppError('denied', 'Attachment file name changed during export.');
          }
          const declaredSize = parsePortableAttachmentSize(planned.size);
          if (declaredSize !== undefined
            && declaredSize > MAX_PORTABLE_EXPORT_ATTACHMENT_BYTES - totalDeclaredBytes) {
            throw new AppError('denied', 'Attachments exceed the export size limit.');
          }
          if (declaredSize !== undefined) totalDeclaredBytes += declaredSize;
          attachmentKey = await decryptAttachmentKey(rawAttachment.key, cipherKey);
          await operation.assertCacheCurrent();
          const downloadUrl = await this.resolveAttachmentDownloadUrl(
            operation,
            cipher.id,
            rawAttachment.id,
            rawAttachment.url,
          );
          const remaining = MAX_PORTABLE_EXPORT_ATTACHMENT_BYTES - totalBytes;
          const encryptedLimit = declaredSize ?? remaining + 65;
          encrypted = await operation.api.downloadAttachment(
            downloadUrl,
            operation.token,
            encryptedLimit,
          );
          await operation.assertCacheCurrent();
          if (declaredSize !== undefined && encrypted.byteLength !== declaredSize) {
            throw new AppError('denied', 'Attachment download size does not match the export plan.');
          }
          plaintext = await decryptAttachmentFile(encrypted, attachmentKey);
          operation.assertCurrent();
          if (plaintext.byteLength > remaining) {
            throw new AppError('denied', 'Attachment size does not match the export plan.');
          }
          totalBytes += plaintext.byteLength;
          attachments.push({
            path: portableAttachmentPath(planned),
            data: plaintext,
            itemToken: planned.itemToken,
            attachmentId: planned.attachmentId,
          });
          plaintext = undefined;
        } finally {
          encrypted?.fill(0);
          plaintext?.fill(0);
          destroySymmetricKey(attachmentKey);
          if (destroyCipherKey) destroySymmetricKey(cipherKey);
        }
      }

      await operation.assertCacheCurrent();
      const written = writeVaultArchive({ dataJson, attachments, includeManifest: true }, {
        // The archive contains locally authenticated plaintext, so STORE avoids rejecting legitimate
        // highly-compressible files as zip bombs and keeps the final 64 MiB bound predictable.
        compressionLevel: 0,
        limits: {
          maxArchiveBytes: MAX_PORTABLE_EXPORT_BYTES,
          maxTotalCompressedBytes: MAX_PORTABLE_EXPORT_BYTES,
          maxEntryCompressedBytes: MAX_PORTABLE_EXPORT_BYTES,
          maxEntryUncompressedBytes: MAX_PORTABLE_EXPORT_ATTACHMENT_BYTES,
        },
      });
      if (!written.ok || !written.archive) {
        throw new AppError('denied', 'The vault archive could not be created safely.');
      }
      await operation.assertCacheCurrent();
      operation.assertCurrent();
      return written.archive;
    } finally {
      for (const attachment of attachments) attachment.data.fill(0);
    }
  }

  /** Resolve the exact personal-import feature set available to the active account generation. */
  async getPortableVaultImportCapabilities(): Promise<Readonly<PersonalImportCapabilityPolicy>> {
    const view = await this.requireCacheView();
    const archiveEligible = hasArchiveEntitlement(view.envelope.response.profile);
    const [sshAvailable, archiveAvailable] = await Promise.all([
      this.authorizeSshCipherWrite().then(() => true, () => false),
      archiveEligible
        ? this.authorizeCipherArchive().then(() => true, () => false)
        : Promise.resolve(false),
    ]);
    if (sshAvailable && archiveAvailable) return VAULT_SERVICE_SSH_ARCHIVE_IMPORT_CAPABILITIES;
    if (sshAvailable) return VAULT_SERVICE_SSH_IMPORT_CAPABILITIES;
    if (archiveAvailable) return VAULT_SERVICE_ARCHIVE_IMPORT_CAPABILITIES;
    return VAULT_SERVICE_IMPORT_CAPABILITIES;
  }

  /** Inspect account-encrypted inputs under the exact account/session/cache authority held by transfer. */
  async inspectPortableVaultTransferSource(
    source: Uint8Array,
    options: Omit<InspectVaultTransferSourceOptions, 'inspectAccountEncrypted'>,
    authority: PortableVaultTransferAuthority,
  ): Promise<VaultTransferSourceResult> {
    const operation = await this.beginVaultOperation({ cache: true }, authority);
    let organizationKeys: Map<string, SymmetricKey> | undefined;
    try {
      const result = await inspectVaultTransferSource(source, {
        ...options,
        inspectAccountEncrypted: async (content, limits) => {
          try {
            return await inspectAccountEncryptedVaultExport(content, {
              userKey: operation.userKey,
              loadOrganizationKeys: async () => {
                organizationKeys ??= await this.buildOrgKeys(operation.cacheEnvelope.response.profile);
                return organizationKeys;
              },
              limits,
              assertCurrent: () => operation.assertCurrent(),
            });
          } catch (error) {
            if (error instanceof AccountEncryptedVaultTransferError) return null;
            throw error;
          }
        },
      });
      await operation.assertCacheCurrent();
      operation.assertCurrent();
      return result;
    } finally {
      for (const key of organizationKeys?.values() ?? []) destroySymmetricKey(key);
    }
  }

  /** Validate advanced plaintext fields inside the worker before the UI is allowed to confirm. */
  async validatePortableVaultImportSource(
    source: VaultTransferSourceOk,
    capabilities: PersonalImportCapabilityPolicy,
  ): Promise<boolean> {
    try {
      if (!isSupportedPortableImportCapabilities(capabilities)
        || source.attachmentCount !== 0
        || source.attachments.length !== 0
        || source.skippedAttachmentCount !== 0
        || source.inspection.canCommit !== true
        || source.inspection.ir?.scope !== 'personal'
        || inspectPersonalImportCapabilities(source.inspection, capabilities).length > 0) {
        return false;
      }
      for (const item of source.inspection.ir.items) {
        const write = toPersonalImportItemWrite(item, undefined);
        if (!write) return false;
        await validatePersonalImportItemWrite(write);
      }
      return true;
    } catch {
      return false;
    }
  }

  /** Commit a preflighted personal import using the controller-owned durable journal. */
  async commitPortableVaultImport(input: PortableVaultImportInput): Promise<void> {
    validatePortableImportInput(input);
    await this.runVaultMutation('vault.import.v2', async ({ operation, remote, reconcile }) => {
      await assertPortableImportBoundary(operation, input.journal);
      validatePortableImportInput(input);
      this.deps.policyGate.assertAllowed(operation.policyLease, 'createPersonalVaultItem');
      const capabilityErrors = inspectPersonalImportCapabilities(
        input.source.inspection,
        input.capabilities,
      );
      if (capabilityErrors.length > 0 || !input.source.inspection.ir) {
        throw new AppError('denied', 'This transfer cannot be imported without losing data.');
      }
      const ir = input.source.inspection.ir;
      for (const item of ir.items) {
        this.assertCipherTargetPolicyAllowed(operation.policyLease, item.rawType, null);
        this.assertPersonalCreationAllowed(operation.policyLease, item.rawType);
      }
      const sshAuthorization = ir.items.some((item) => item.rawType === 5)
        ? await this.authorizeSshCipherWrite()
        : undefined;
      const hasArchivedItems = ir.items.some((item) => item.archivedDate != null);
      if (hasArchivedItems && !hasArchiveEntitlement(operation.cacheEnvelope.response.profile)) {
        throw new AppError('denied', 'Premium access is required to import archived items.');
      }
      const archiveAuthorization = hasArchivedItems
        ? await this.authorizeCipherArchive()
        : undefined;
      await assertPortableImportBoundary(operation, input.journal);

      const encryptedFolders = new Map<number, string>();
      for (const folder of ir.folders) {
        await assertPortableImportBoundary(operation, input.journal);
        encryptedFolders.set(folder.sourceIndex, await encryptToText(folder.name, operation.userKey));
      }

      const preparedItems = new Map<number, CipherRequest>();
      try {
        for (const item of ir.items) {
          await assertPortableImportBoundary(operation, input.journal);
          if (item.rawType === 5) {
            if (!sshAuthorization) throw new AppError('denied', 'SSH key writes are unavailable.');
            assertSshWriteAuthorizationCurrent(sshAuthorization);
          }
          if (item.archivedDate != null) {
            if (!archiveAuthorization) throw new AppError('denied', 'Cipher archiving is unavailable.');
            assertCipherArchiveAuthorizationCurrent(archiveAuthorization);
          }
          const write = toPersonalImportItemWrite(item, undefined);
          if (!write) {
            throw new AppError('denied', 'This transfer contains an unsupported item.');
          }
          preparedItems.set(
            item.sourceIndex,
            await encryptPersonalImportItemWrite(write, operation.userKey),
          );
        }
      } catch (error) {
        if (error instanceof AppError) throw error;
        throw new AppError(
          'denied',
          'This transfer contains invalid or unsupported advanced item data.',
        );
      }
      await assertPortableImportBoundary(operation, input.journal);
      const guardedApi = sshAuthorization || archiveAuthorization
        ? operation.api.withRequestGuard(() => {
            operation.assertCurrent();
            if (sshAuthorization) assertSshWriteAuthorizationCurrent(sshAuthorization);
            if (archiveAuthorization) {
              assertCipherArchiveAuthorizationCurrent(archiveAuthorization);
            }
          })
        : operation.api;

      const mappedFolders = new Map<string, string>();
      const rejectedFolders = new Set<string>();
      let committed = 0;

      for (const folder of ir.folders) {
        await assertPortableImportBoundary(operation, input.journal);
        if (sshAuthorization) assertSshWriteAuthorizationCurrent(sshAuthorization);
        if (archiveAuthorization) assertCipherArchiveAuthorizationCurrent(archiveAuthorization);
        const encryptedName = encryptedFolders.get(folder.sourceIndex);
        if (!encryptedName) throw new AppError('denied', 'The prepared import folder is unavailable.');
        const result = await commitPortableRemote(
          operation,
          input.journal,
          remote,
          'folder',
          folder.sourceIndex,
          (accessToken) => guardedApi.createFolder(accessToken, encryptedName),
          (value) => typeof value.id === 'string' && value.id.length > 0,
        );
        if (result.status === 'rejected') {
          rejectedFolders.add(folder.id);
          continue;
        }
        mappedFolders.set(folder.id, result.value.id);
        committed += 1;
      }

      for (const item of ir.items) {
        if (item.folderId && rejectedFolders.has(item.folderId)) {
          await assertPortableImportBoundary(operation, input.journal);
          await input.journal.recordSkipped('item', item.sourceIndex, 'folder_rejected');
          await assertPortableImportBoundary(operation, input.journal);
          continue;
        }
        const mappedFolderId = item.folderId ? mappedFolders.get(item.folderId) : undefined;
        if (item.folderId && !mappedFolderId) {
          await assertPortableImportBoundary(operation, input.journal);
          await input.journal.recordSkipped('item', item.sourceIndex, 'folder_unavailable');
          await assertPortableImportBoundary(operation, input.journal);
          continue;
        }
        await assertPortableImportBoundary(operation, input.journal);
        const request = preparedItems.get(item.sourceIndex);
        if (!request) throw new AppError('denied', 'The prepared import item is unavailable.');
        request.folderId = mappedFolderId ?? null;
        if (item.rawType === 5) {
          if (!sshAuthorization) throw new AppError('denied', 'SSH key writes are unavailable.');
          assertSshWriteAuthorizationCurrent(sshAuthorization);
          operation.assertCurrent();
        }
        if (item.archivedDate != null) {
          if (!archiveAuthorization) throw new AppError('denied', 'Cipher archiving is unavailable.');
          assertCipherArchiveAuthorizationCurrent(archiveAuthorization);
          operation.assertCurrent();
        }
        const result = await commitPortableRemote(
          operation,
          input.journal,
          remote,
          'item',
          item.sourceIndex,
          (accessToken) => guardedApi.createCipher(accessToken, request),
          (value) => validPersonalImportCipherReceipt(value, request),
        );
        if (result.status === 'committed') committed += 1;
      }

      if (committed > 0) {
        await assertPortableImportBoundary(operation, input.journal);
        await reconcile(() => this.syncAfterMutation(operation));
        await input.journal.assertCurrent();
        operation.assertCurrent();
      }
    }, { cache: true });
  }

  /**
   * Serialize the decrypted vault to a Bitwarden-compatible unencrypted JSON export. This deliberately
   * emits plaintext secrets — an explicit, user-initiated action — so callers must warn the user.
   */
  async exportVault(password?: string): Promise<string> {
    const operation = await this.beginVaultOperation({ cache: true });
    const view = await this.requireCacheView();
    operation.assertCurrent();
    if (view.envelope.rawGeneration !== operation.cacheEnvelope.rawGeneration) {
      throw new AppError('sync_required', 'Vault changed while preparing the export.');
    }
    this.deps.policyGate.assertAllowed(operation.policyLease, 'exportPersonalVault');
    const cache = operation.cacheEnvelope.response;
    const orgKeys = await this.buildOrgKeys(cache.profile);
    const folders = view.snapshot.listing.folders;
    const decrypted: DecryptedCipher[] = [];
    for (const cipher of cache.ciphers) {
      if (cipher.organizationId) continue; // Personal export must never include organization-owned data.
      if (cipher.deletedDate) continue; // trashed ciphers are excluded from exports
      this.assertCipherPolicyAllowed(operation.policyLease, cipher);
      const supported = this.requireSupportedCipher(cipher);
      if (supported.type === 5) {
        throw new AppError('denied', 'SSH keys are not supported by the personal export format yet');
      }
      const d = await decryptCipher(supported, operation.userKey, orgKeys);
      if (!d || d.undecryptable) {
        throw new AppError('denied', 'Vault export contains an item that cannot be safely decrypted');
      }
      decrypted.push(d);
    }
    const plaintext = buildExportJson(decrypted, folders);
    if (!password) {
      await operation.assertCacheCurrent();
      operation.assertCurrent();
      return plaintext;
    }
    // Password-protected export: wrap the plaintext payload under a password-derived key.
    const auth = await this.deps.session.getPersistedAuth();
    const encrypted = await buildEncryptedExportJson(
      plaintext,
      password,
      auth ?? { kdf: 0, kdfIterations: 600_000 },
    );
    await operation.assertCacheCurrent();
    operation.assertCurrent();
    return encrypted;
  }

  /**
   * Import a Bitwarden export (plaintext JSON, password-protected JSON, or CSV): parse, then create one
   * cipher per item and re-sync once. `password` is required for an encrypted export.
   *
   * Each item is imported independently: a single item's failure (e.g. a server 4xx) is recorded and
   * the batch continues, rather than aborting on the first rejection. Aborting would leave the items
   * created before the failure silently committed while the caller sees a total failure and retries —
   * duplicating those successes. The final `sync()` runs whenever at least one item landed so the local
   * cache reflects what was imported. Returns the imported/failed counts and per-item failure detail.
   */
  async importVault(content: string, password?: string): Promise<ImportResult> {
    let partial: ImportResult | undefined;
    try {
      return await this.runVaultMutation('vault.import', async ({ operation, remote, reconcile }) => {
    this.deps.policyGate.assertAllowed(operation.policyLease, 'createPersonalVaultItem');
    const inputs = await (this.deps.parseImport ?? parseImport)(content, password);
    operation.assertCurrent();
    for (const input of inputs) {
      this.assertCipherTargetPolicyAllowed(operation.policyLease, input.type, null);
    }
    let imported = 0;
    const failures: ImportResult['failures'] = [];
    for (const [index, input] of inputs.entries()) {
      const request = await encryptCipher(input, operation.userKey);
      // Keep this outside the per-item error accounting: an invalidated operation aborts the batch,
      // rather than being misreported as an ordinary item failure and retried for every remaining row.
      operation.assertCurrent();
      try {
        await remote((accessToken) => operation.api.createCipher(accessToken, request));
        imported++;
      } catch (err) {
        operation.assertCurrent();
        if (!(err instanceof VaultMutationCommitError) || err.status !== 'not_committed') throw err;
        failures.push({ index, message: err instanceof Error ? err.message : String(err) });
      }
    }
    partial = { imported, failed: failures.length, failures };
    if (imported > 0) {
      await reconcile(() => this.syncAfterMutation(operation));
    }
    return partial;
      });
    } catch (error) {
      if (partial && error instanceof AppError && error.code === 'committed_unsynced') {
        return { ...partial, refreshError: error.message };
      }
      throw error;
    }
  }

  private assertCipherCloneAllowed(
    operation: VaultOperationContext,
    cipher: SupportedCipherResponse,
  ): void {
    if (cipher.organizationId == null) return;
    const metadata = selectOrganizationMetadata(operation.cacheEnvelope.response.profile).entries
      .filter((entry) => entry.organization.id === cipher.organizationId);
    if (metadata.length !== 1 || !canCloneOrganizationCipher(
      toCollectionOrganizationAuthority(metadata[0]!.organization, metadata[0]!.isProviderUser),
      cipher,
      operation.cacheEnvelope.response.collections,
    )) {
      throw new AppError('denied', 'This organization item cannot be cloned.');
    }
  }

  private async decryptCipherById(
    id: string,
    assertRawAuthority?: (
      operation: VaultOperationContext,
      cipher: SupportedCipherResponse,
    ) => void,
  ): Promise<DecryptedCipherAccess | undefined> {
    const operation = await this.beginVaultOperation({ cache: true });
    const cache = operation.cacheEnvelope.response;
    const candidate = cache.ciphers.find((cipher) => cipher.id === id);
    if (!candidate) {
      operation.assertCurrent();
      return undefined;
    }
    const cipher = this.requireSupportedCipher(candidate);
    this.assertCipherPolicyAllowed(operation.policyLease, cipher);
    assertRawAuthority?.(operation, cipher);
    const orgKeys = await this.buildOrgKeys(cache.profile);
    const decrypted = await decryptCipher(cipher, operation.userKey, orgKeys);
    await operation.assertCacheCurrent();
    operation.assertCurrent();
    assertRawAuthority?.(operation, cipher);
    if (!decrypted) return undefined;
    return { cipher: decrypted, raw: cipher, operation };
  }

  async clearCache(): Promise<void> {
    this.revokeOrganizationDataOwnershipGrants();
    const publicationFence = Symbol('clearPolicyPublication');
    this.policyPublicationFence = publicationFence;
    this.deps.policyGate.invalidate();
    await this.withCacheMutation(async () => {
      this.deps.policyGate.invalidate();
      this.cacheEpoch++;
      await this.cache.clearAll();
    });
  }

  /** Explicit configured-server resets may discard otherwise fail-closed stamp state. */
  async resetSecurityStampBaselines(): Promise<void> {
    await this.securityStamps.clear();
  }

  async findAutofillCandidates(
    frameUrl: string,
    defaultStrategy: UriMatchStrategySetting,
    purpose: AutofillIntentPurpose = 'login',
    channel: 'interactive' | 'page-load' = 'interactive',
    pageLoadFillDefault = true,
  ): Promise<AutofillCandidate[]> {
    const operation = await this.beginVaultOperation({ cache: true });
    const view = await this.requireCacheView();
    operation.assertCurrent();
    if (view.envelope.rawGeneration !== operation.cacheEnvelope.rawGeneration) {
      throw new AppError('denied', 'Autofill discovery is no longer current.');
    }
    const summaries = view.snapshot.listing.items;
    const equivalentIndex = this.loadEquivalentIndex(view.snapshot);

    const candidates = summaries
      .filter((item) => item.type === 1 && !item.undecryptable && isActiveCipher(item))
      .filter((item) => channel !== 'page-load' || pageLoadAutofillAllowed(
        item.autofillOnPageLoad,
        pageLoadFillDefault,
      ))
      .filter((item) => purpose === 'login'
        || (item.hasTotp === true && summaryAllowsCipherAccess(item, 'autofillTotp')))
      .flatMap((item) => {
        const best = bestMatch(item.loginUris, frameUrl, defaultStrategy, equivalentIndex);
        if (!best) return [];
        const candidate: AutofillCandidate = {
          id: item.id,
          name: item.name,
          matchedUri: best.matchedUri,
          matchType: best.matchType,
          favorite: item.favorite,
        };
        if (item.username) candidate.username = item.username;
        if (item.hasTotp && summaryAllowsCipherAccess(item, 'autofillTotp')) candidate.hasTotp = true;
        if (item.reprompt) candidate.reprompt = true;
        return [candidate];
      });

    candidates.sort((a, b) => {
      if (a.favorite !== b.favorite) return a.favorite ? -1 : 1;
      const score = matchScore(a.matchType) - matchScore(b.matchType);
      if (score !== 0) return score;
      const name = a.name.localeCompare(b.name, undefined, { sensitivity: 'base' });
      if (name !== 0) return name;
      return (a.username ?? '').localeCompare(b.username ?? '', undefined, { sensitivity: 'base' });
    });
    operation.assertCurrent();
    return candidates;
  }

  /** Count matching active login summaries for a browser-owned top-level URL. This deliberately
   * returns no cipher identifiers or display metadata and does not inspect page DOM or subframes. */
  async countAutofillLoginMatches(
    frameUrl: string,
    defaultStrategy: UriMatchStrategySetting,
    bindFinalAuthority?: VaultFinalAuthorityBinder,
  ): Promise<number> {
    const operation = await this.beginVaultOperation({ cache: true });
    const view = await this.requireCacheView();
    operation.assertCurrent();
    if (view.envelope.rawGeneration !== operation.cacheEnvelope.rawGeneration) {
      throw new AppError('denied', 'Autofill discovery is no longer current.');
    }
    const equivalentIndex = this.loadEquivalentIndex(view.snapshot);
    let count = 0;
    for (const item of view.snapshot.listing.items) {
      if (item.type !== 1 || item.undecryptable || !isActiveCipher(item)) continue;
      if (bestMatch(item.loginUris, frameUrl, defaultStrategy, equivalentIndex)) count += 1;
    }
    operation.assertCurrent();
    this.bindOperationFinalAuthority(operation, bindFinalAuthority);
    return count;
  }

  /** List every card (type 3) or identity (type 4) as a fill candidate. No URL match — card/identity
   *  have no URI; authorization is the user's explicit popover selection. Never returns secrets. */
  async findFillItems(kind: FillKind): Promise<FillItemCandidate[]> {
    const operation = await this.beginVaultOperation({ cache: true });
    const view = await this.requireCacheView();
    operation.assertCurrent();
    if (view.envelope.rawGeneration !== operation.cacheEnvelope.rawGeneration) {
      throw new AppError('denied', 'Fill-item discovery is no longer current.');
    }
    const summaries = view.snapshot.listing.items;
    const wantType = kind === 'card' ? 3 : 4;
    const items = summaries
      .filter((item) => item.type === wantType && !item.undecryptable && isActiveCipher(item))
      .map((item) => {
        const candidate: FillItemCandidate = { id: item.id, name: item.name, favorite: item.favorite };
        if (item.subtitle) candidate.subtitle = item.subtitle;
        if (item.reprompt) candidate.reprompt = true;
        return candidate;
      });
    items.sort((a, b) => {
      if (a.favorite !== b.favorite) return a.favorite ? -1 : 1;
      return a.name.localeCompare(b.name, undefined, { sensitivity: 'base' });
    });
    operation.assertCurrent();
    return items;
  }

  /** Decrypt only the card/identity roles bound to a validated fill target. Reprompt items require
   *  a live background grant assertion; identity national-ID secrets are never projected. */
  async getFillData(
    cipherId: string,
    kind: FillKind,
    roles: readonly FillRole[],
    assertRepromptAuthorized?: () => void,
    bindFinalAuthority?: (assertCurrent: () => void) => void,
  ): Promise<CardFillData | IdentityFillData> {
    if (kind !== 'card' && kind !== 'identity') {
      throw new AppError('denied', 'Autofill item kind is invalid');
    }
    const requestedKeys = fillDataKeysForRoles(kind, roles);
    if (!requestedKeys) throw new AppError('denied', 'Autofill field roles are invalid');

    const operation = await this.beginVaultOperation({ cache: true });
    const envelope = operation.cacheEnvelope;
    const cache = envelope.response;
    const candidate = cache.ciphers.find((c) => c.id === cipherId);
    if (!candidate) throw new AppError('denied', 'Autofill item is not allowed');
    const wantType = kind === 'card' ? 3 : 4;
    const cipher = this.requireSupportedCipher(candidate, [wantType]);
    if (isCipherInactive(cipher)) throw new AppError('denied', 'Autofill item is not allowed');
    this.assertCipherPolicyAllowed(operation.policyLease, cipher);
    const assertRepromptCurrent = cipher.reprompt ? assertRepromptAuthorized : undefined;
    if (cipher.reprompt && !assertRepromptCurrent) {
      throw new AppError('reprompt_required', 'This item requires master-password verification in the extension');
    }
    assertRepromptCurrent?.();
    bindFinalAuthority?.(() => {
      operation.assertCurrent();
      this.assertCipherPolicyAllowed(operation.policyLease, cipher);
      assertRepromptCurrent?.();
    });
    let fieldKey: SymmetricKey;
    try {
      fieldKey = await this.cipherFieldKey(cipher, operation.userKey, cache.profile);
    } catch {
      throw new AppError('denied', 'Autofill item is not allowed');
    }
    assertRepromptCurrent?.();
    if (kind === 'card') {
      const c = cipher.card ?? {};
      const out: CardFillData = {};
      const fields: Array<keyof CardFillData> = ['cardholderName', 'brand', 'number', 'expMonth', 'expYear', 'code'];
      try {
        for (const key of fields) {
          if (!requestedKeys.includes(key)) continue;
          const encrypted = c[key];
          if (!encrypted) continue;
          const value = await decryptToText(encrypted, fieldKey);
          if (value) out[key] = value;
        }
      } catch {
        throw new AppError('denied', 'Autofill item is not allowed');
      }
      await operation.assertCacheCurrent();
      operation.assertCurrent();
      assertRepromptCurrent?.();
      return out;
    }
    const i = cipher.identity ?? {};
    const out: IdentityFillData = {};
    const fields: Array<keyof IdentityFillData> = [
      'title', 'firstName', 'middleName', 'lastName', 'address1', 'address2', 'address3',
      'city', 'state', 'postalCode', 'country', 'company', 'email', 'phone', 'username',
    ];
    try {
      for (const key of fields) {
        if (!requestedKeys.includes(key)) continue;
        const encrypted = (i as Record<string, string | null | undefined>)[key];
        if (!encrypted) continue;
        const value = await decryptToText(encrypted, fieldKey);
        if (value) out[key] = value;
      }
    } catch {
      throw new AppError('denied', 'Autofill item is not allowed');
    }
    await operation.assertCacheCurrent();
    operation.assertCurrent();
    assertRepromptCurrent?.();
    return out;
  }

  /** Resolve one active login for an explicitly confirmed URI-mismatch fill without relaxing the
   * normal match-gated autofill path. The returned authority never contains plaintext vault data. */
  async prepareManualAutofill(
    cipherId: string,
    frameUrl: string,
    defaultStrategy: UriMatchStrategySetting,
    tabUrl = frameUrl,
  ): Promise<ManualAutofillVaultPreparation> {
    const access = await this.prepareManualAutofillCipher(
      cipherId,
      frameUrl,
      defaultStrategy,
      undefined,
      undefined,
      tabUrl,
    );
    return Object.freeze({
      cipherRevision: access.cipherRevision,
      uriDigest: access.uriDigest,
      risk: access.risk,
      requiresReprompt: access.requiresReprompt,
      canSave: access.canSave,
      authority: access.authority,
    });
  }

  /** Decrypt a manually confirmed mismatched login. Snapshot equality and reprompt authorization are
   * checked before any secret is materialized; normal suggestions still use prepareAutofillSecret. */
  async getManualAutofillLoginData(
    cipherId: string,
    frameUrl: string,
    defaultStrategy: UriMatchStrategySetting,
    customPlanInput: LoginCustomTargetPlan,
    expected: ManualAutofillVaultBinding,
    assertRepromptAuthorized?: () => void,
    bindFinalAuthority?: VaultFinalAuthorityBinder,
  ): Promise<AutofillInteractiveLoginData> {
    const customPlan = parseLoginCustomTargetPlan(customPlanInput);
    if (!customPlan) throw new AppError('denied', 'Manual autofill target plan is invalid.');
    const access = await this.prepareManualAutofillCipher(
      cipherId,
      frameUrl,
      defaultStrategy,
      expected,
    );
    const assertRepromptCurrent = access.requiresReprompt ? assertRepromptAuthorized : undefined;
    if (access.requiresReprompt && !assertRepromptCurrent) {
      throw new AppError('reprompt_required', 'This item requires master-password verification.');
    }
    assertRepromptCurrent?.();

    const login: AutofillLoginData = {};
    let fieldKey: SymmetricKey | undefined;
    try {
      fieldKey = await this.cipherFieldKey(
        access.cipher,
        access.operation.userKey,
        access.operation.cacheEnvelope.response.profile,
      );
      const username = access.cipher.login?.username
        ? await decryptToText(access.cipher.login.username, fieldKey)
        : undefined;
      const password = access.cipher.login?.password
        ? await decryptToText(access.cipher.login.password, fieldKey)
        : undefined;
      if (username) login.username = username;
      if (password) login.password = password;
      const customAssignments = await projectLoginCustomAssignments(
        access.cipher.fields,
        fieldKey,
        customPlan,
        username,
        password,
      );
      await access.operation.assertCacheCurrent();
      access.authority.assertCurrent();
      assertRepromptCurrent?.();
      this.bindOperationFinalAuthority(access.operation, bindFinalAuthority, () => {
        access.authority.assertCurrent();
        assertRepromptCurrent?.();
      });
      return Object.freeze({ login: Object.freeze(login), customAssignments: Object.freeze(customAssignments) });
    } catch {
      throw new AppError('denied', 'Manual autofill authorization is no longer valid.');
    } finally {
      this.disposeManualAutofillFieldKey(access.cipher, fieldKey);
    }
  }

  /** Append the complete current tab URL after a confirmed fill. Every existing encrypted field is
   * copied byte-for-byte; the non-empty revision is the mandatory optimistic-concurrency token. */
  async saveManualAutofillUri(
    cipherId: string,
    frameUrl: string,
    tabUrl: string,
    defaultStrategy: UriMatchStrategySetting,
    expected: ManualAutofillVaultBinding,
    assertExternalCurrent: () => void,
  ): Promise<VaultListing> {
    const savedUrl = canonicalManualAutofillUrl(tabUrl);
    return this.runVaultMutation('manualAutofill.addUri', async ({ operation, remote, reconcile }) => {
      const access = await this.prepareManualAutofillCipher(
        cipherId,
        frameUrl,
        defaultStrategy,
        expected,
        operation,
        tabUrl,
      );
      if (!access.canSave || access.risk !== 'no_match') {
        throw new AppError('denied', 'This login cannot save the current site.');
      }
      assertExternalCurrent();
      let fieldKey: SymmetricKey | undefined;
      let encryptedUri: string;
      let encryptedChecksum: string;
      try {
        fieldKey = await this.cipherFieldKey(
          access.cipher,
          operation.userKey,
          operation.cacheEnvelope.response.profile,
        );
        const checksum = await computeLoginUriChecksum(savedUrl);
        encryptedUri = await encryptToText(savedUrl, fieldKey);
        encryptedChecksum = await encryptToText(checksum, fieldKey);
      } finally {
        this.disposeManualAutofillFieldKey(access.cipher, fieldKey);
      }
      access.authority.assertCurrent();
      assertExternalCurrent();

      const request = this.cipherResponseToRequest(access.cipher);
      request.login = {
        ...(access.cipher.login ?? {}),
        uris: [
          ...(access.cipher.login?.uris ?? []),
          { uri: encryptedUri, uriChecksum: encryptedChecksum },
        ],
      };
      request.lastKnownRevisionDate = expected.cipherRevision;
      await operation.assertCacheCurrent();
      const api = operation.api.withRequestGuard(() => {
        operation.assertCurrent();
        assertExternalCurrent();
      });
      await remote((accessToken) => api.updateCipher(accessToken, cipherId, request));
      const listing = await reconcile(() => this.syncAfterMutation(operation));

      await this.assertAuthoritativeLoginUriAdded(
        operation,
        access.cipher,
        savedUrl,
        expected.cipherRevision,
        undefined,
      );
      return listing;
    }, { cache: true });
  }

  private async assertAuthoritativeLoginUriAdded(
    operation: VaultOperationContext,
    expectedCipher: SupportedCipherResponse,
    url: string,
    previousRevision: string,
    expectedMatch: UriMatchStrategySetting | undefined,
  ): Promise<void> {
    const authoritativeMatches = operation.cacheEnvelope.response.ciphers.filter(
      (candidate) => candidate.id === expectedCipher.id,
    );
    if (authoritativeMatches.length !== 1) {
      throw new AppError('outcome_unknown', 'The saved site could not be verified after sync.');
    }
    const authoritative = this.requireSupportedCipher(authoritativeMatches[0]!, [1]);
    if (!sameKnownCipherWritablePreimage(expectedCipher, authoritative)
        || !sameLoginUriPrefix(expectedCipher.login?.uris, authoritative.login?.uris)
        || authoritative.organizationId !== expectedCipher.organizationId
        || authoritative.key !== expectedCipher.key
        || !revisionAdvanced(previousRevision, authoritative.revisionDate)) {
      throw new AppError('outcome_unknown', 'The saved site revision could not be verified after sync.');
    }
    const decrypted = await decryptCipher(
      authoritative,
      operation.userKey,
      await this.buildOrgKeys(operation.cacheEnvelope.response.profile),
    );
    operation.assertCurrent();
    if (!decrypted || decrypted.undecryptable || decrypted.type !== 1
        || !decrypted.loginUris.some((uri) => uri.uri === url && uri.match === expectedMatch)) {
      throw new AppError('outcome_unknown', 'The saved site could not be verified after sync.');
    }
  }

  private async prepareManualAutofillCipher(
    cipherId: string,
    frameUrl: string,
    defaultStrategy: UriMatchStrategySetting,
    expected?: ManualAutofillVaultBinding,
    capturedOperation?: VaultOperationContext,
    saveUrl = frameUrl,
  ): Promise<ManualAutofillCipherAccess> {
    if (!isUriMatchStrategySetting(defaultStrategy)) {
      throw new AppError('denied', 'Manual autofill matching policy is unavailable.');
    }
    const targetUrl = canonicalManualAutofillUrl(frameUrl);
    const operation = capturedOperation ?? await this.beginVaultOperation({ cache: true });
    const view = await this.requireCacheView();
    operation.assertCurrent();
    if (view.envelope.rawGeneration !== operation.cacheEnvelope.rawGeneration) {
      throw new AppError('conflict', 'The vault changed after manual autofill was reviewed.');
    }
    const rawMatches = operation.cacheEnvelope.response.ciphers.filter((entry) => entry.id === cipherId);
    const summaryMatches = view.snapshot.listing.items.filter((entry) => entry.id === cipherId);
    if (rawMatches.length !== 1 || summaryMatches.length !== 1) {
      throw new AppError('denied', 'Manual autofill login is unavailable.');
    }
    const cipher = this.requireSupportedCipher(rawMatches[0]!, [1]);
    const summary = summaryMatches[0]!;
    if (summary.type !== 1 || summary.undecryptable || isCipherInactive(summary)
        || isCipherInactive(cipher)) {
      throw new AppError('denied', 'Manual autofill login is unavailable.');
    }
    this.assertCipherPolicyAllowed(operation.policyLease, cipher);
    this.assertCipherPasswordViewAllowed(cipher);
    const cipherRevision = cipher.revisionDate;
    if (!isIsoTimestamp(cipherRevision)) {
      throw new AppError('denied', 'Manual autofill requires a current item revision.');
    }
    const uriDigest = await digestEncryptedLoginUris(cipher);
    operation.assertCurrent();
    const equivalentIndex = this.loadEquivalentIndex(view.snapshot);
    if (bestMatch(summary.loginUris, targetUrl, defaultStrategy, equivalentIndex)) {
      throw new AppError('conflict', 'This login now matches the current page.');
    }
    const risk = manualAutofillRisk(summary.loginUris, targetUrl, defaultStrategy, equivalentIndex);
    const canonicalSaveUrl = canonicalManualAutofillUrl(saveUrl);
    const saveRisk = manualAutofillRisk(
      summary.loginUris,
      canonicalSaveUrl,
      defaultStrategy,
      equivalentIndex,
    );
    const sameSaveOrigin = new URL(targetUrl).origin === new URL(canonicalSaveUrl).origin;
    const requiresReprompt = cipher.reprompt === 1;
    if (expected && (
      expected.cipherRevision !== cipherRevision
      || expected.uriDigest !== uriDigest
      || expected.risk !== risk
      || expected.requiresReprompt !== requiresReprompt
    )) throw new AppError('conflict', 'The login changed after manual autofill was reviewed.');

    await operation.assertCacheCurrent();
    const authority: ManualAutofillVaultAuthority = Object.freeze({
      assertCurrent: () => {
        operation.assertCurrent();
        this.assertCipherPolicyAllowed(operation.policyLease, cipher);
        this.assertCipherPasswordViewAllowed(cipher);
      },
    });
    authority.assertCurrent();
    return Object.freeze({
      cipher,
      operation,
      cipherRevision,
      uriDigest,
      risk,
      requiresReprompt,
      canSave: risk === 'no_match'
        && saveRisk === 'no_match'
        && sameSaveOrigin
        && !bestMatch(summary.loginUris, canonicalSaveUrl, defaultStrategy, equivalentIndex)
        && projectValidatedCipherAccess(cipher).edit,
      authority,
    });
  }

  private disposeManualAutofillFieldKey(
    cipher: SupportedCipherResponse,
    fieldKey: SymmetricKey | undefined,
  ): void {
    if (cipher.key == null || !fieldKey) return;
    destroySymmetricKey(fieldKey);
    this.deps.onManualAutofillFieldKeyDisposed?.(
      fieldKey.encKey.every((value) => value === 0)
        && fieldKey.macKey.every((value) => value === 0),
    );
  }

  /** Decrypt only username/password for a one-time login intent. TOTP is never materialized here. */
  async getAutofillLoginData(
    cipherId: string,
    frameUrl: string,
    defaultStrategy: UriMatchStrategySetting,
    options?: {
      requireUnique?: boolean;
      channel?: 'interactive' | 'page-load';
      pageLoadFillDefault?: boolean;
    },
    bindFinalAuthority?: VaultFinalAuthorityBinder,
  ): Promise<AutofillLoginData> {
    const access = await this.prepareAutofillSecret(cipherId, frameUrl, defaultStrategy, 'login', options);
    const out: AutofillLoginData = {};
    try {
      const username = access.cipher.login?.username
        ? await decryptToText(access.cipher.login.username, access.fieldKey)
        : undefined;
      const password = access.cipher.login?.password
        ? await decryptToText(access.cipher.login.password, access.fieldKey)
        : undefined;
      if (username) out.username = username;
      if (password) out.password = password;
    } catch {
      throw new AppError('denied', 'Autofill intent is invalid or expired');
    }
    await access.operation.assertCacheCurrent();
    access.operation.assertCurrent();
    this.bindOperationFinalAuthority(access.operation, bindFinalAuthority, () => {
      this.assertCipherPolicyAllowed(access.operation.policyLease, access.cipher);
      access.assertRepromptAuthorized?.();
    });
    return out;
  }

  /**
   * Resolve and decrypt HTTP Basic credentials inside one cache generation. The caller supplies no
   * cipher ID: uniqueness, reprompt state, exact origin, ciphertext, and final cache
   * authority are therefore evaluated as one vault operation.
   */
  async getHttpAuthLoginData(
    frameUrl: string,
    defaultStrategy: UriMatchStrategySetting,
    bindFinalAuthority?: VaultFinalAuthorityBinder,
  ): Promise<AutofillLoginData> {
    if (!isUriMatchStrategySetting(defaultStrategy)) {
      throw new AppError('denied', 'HTTP authentication matching is unavailable.');
    }
    const origin = canonicalHttpOrigin(frameUrl);
    if (!origin) throw new AppError('denied', 'HTTP authentication target is invalid.');

    const operation = await this.beginVaultOperation({ cache: true });
    const view = await this.requireCacheView();
    operation.assertCurrent();
    if (view.envelope.rawGeneration !== operation.cacheEnvelope.rawGeneration) {
      throw new AppError('denied', 'HTTP authentication vault state changed.');
    }

    const matches = view.snapshot.listing.items.filter((summary) => (
      summary.type === 1
      && !summary.undecryptable
      && isActiveCipher(summary)
      && summary.loginUris.some((uri) => httpAuthUriMatchesOrigin(uri, origin))
    ));
    if (matches.length !== 1) {
      throw new AppError('denied', 'HTTP authentication requires one matching login.');
    }
    const selected = matches[0]!;
    if (selected.reprompt) {
      throw new AppError('denied', 'HTTP authentication login is not eligible.');
    }

    const cache = operation.cacheEnvelope.response;
    const candidate = cache.ciphers.find((entry) => entry.id === selected.id);
    const cipher = candidate?.type === 1
      ? this.requireSupportedCipher(candidate, [1])
      : undefined;
    if (!cipher || isCipherInactive(cipher) || cipher.reprompt) {
      throw new AppError('denied', 'HTTP authentication login is not eligible.');
    }
    this.assertCipherPolicyAllowed(operation.policyLease, cipher);

    const fieldKey = await this.cipherFieldKey(cipher, operation.userKey, cache.profile);
    operation.assertCurrent();
    await this.deps.beforeHttpAuthCredentialDecrypt?.();
    operation.assertCurrent();
    let username: string | undefined;
    let password: string | undefined;
    try {
      username = cipher.login?.username
        ? await decryptToText(cipher.login.username, fieldKey)
        : undefined;
      password = cipher.login?.password
        ? await decryptToText(cipher.login.password, fieldKey)
        : undefined;
    } catch {
      throw new AppError('denied', 'HTTP authentication login is not eligible.');
    }
    if (
      typeof username !== 'string'
      || username.trim().length === 0
      || typeof password !== 'string'
      || password.length === 0
    ) {
      throw new AppError('denied', 'HTTP authentication login is incomplete.');
    }
    await operation.assertCacheCurrent();
    operation.assertCurrent();
    this.bindOperationFinalAuthority(operation, bindFinalAuthority, () => {
      this.assertCipherPolicyAllowed(operation.policyLease, cipher);
    });
    return Object.freeze({ username, password });
  }

  /**
   * Interactive login projection. Custom-field values are decrypted only after an exact target-hint
   * match; page-load and structured item fill never call this method.
   */
  async getInteractiveAutofillLoginData(
    cipherId: string,
    frameUrl: string,
    defaultStrategy: UriMatchStrategySetting,
    unsafePlan: LoginCustomTargetPlan,
    assertRepromptAuthorized?: () => void,
    bindFinalAuthority?: VaultFinalAuthorityBinder,
  ): Promise<AutofillInteractiveLoginData> {
    const customPlan = parseLoginCustomTargetPlan(unsafePlan);
    if (!customPlan) throw new AppError('denied', 'Autofill custom target plan is invalid');
    const access = await this.prepareAutofillSecret(
      cipherId,
      frameUrl,
      defaultStrategy,
      'login',
      assertRepromptAuthorized ? { assertRepromptAuthorized } : undefined,
    );
    const login: AutofillLoginData = {};
    let username: string | undefined;
    let password: string | undefined;
    try {
      username = access.cipher.login?.username
        ? await decryptToText(access.cipher.login.username, access.fieldKey)
        : undefined;
      password = access.cipher.login?.password
        ? await decryptToText(access.cipher.login.password, access.fieldKey)
        : undefined;
      if (username) login.username = username;
      if (password) login.password = password;
    } catch {
      throw new AppError('denied', 'Autofill intent is invalid or expired');
    }

    const customAssignments = await projectLoginCustomAssignments(
      access.cipher.fields,
      access.fieldKey,
      customPlan,
      username,
      password,
    );
    await access.operation.assertCacheCurrent();
    access.operation.assertCurrent();
    access.assertRepromptAuthorized?.();
    this.bindOperationFinalAuthority(access.operation, bindFinalAuthority, () => {
      this.assertCipherPolicyAllowed(access.operation.policyLease, access.cipher);
      access.assertRepromptAuthorized?.();
    });
    return Object.freeze({ login: Object.freeze(login), customAssignments: Object.freeze(customAssignments) });
  }

  /** Decrypt only the TOTP seed for a one-time TOTP intent. Password is never materialized here. */
  async getAutofillTotpData(
    cipherId: string,
    frameUrl: string,
    defaultStrategy: UriMatchStrategySetting,
    bindFinalAuthority?: VaultFinalAuthorityBinder,
    assertRepromptAuthorized?: () => void,
  ): Promise<AutofillTotpData> {
    const access = await this.prepareAutofillSecret(
      cipherId,
      frameUrl,
      defaultStrategy,
      'totp',
      assertRepromptAuthorized ? { assertRepromptAuthorized } : undefined,
    );
    let secret: string;
    let result: TotpResult | undefined;
    try {
      secret = await decryptToText(access.cipher.login!.totp!, access.fieldKey);
      result = await getTotp(secret, (this.deps.now ?? Date.now)());
    } catch {
      throw new AppError('denied', 'Autofill intent is invalid or expired');
    }
    if (!result) throw new AppError('denied', 'Autofill intent is invalid or expired');
    await access.operation.assertCacheCurrent();
    access.operation.assertCurrent();
    access.assertRepromptAuthorized?.();
    this.bindOperationFinalAuthority(access.operation, bindFinalAuthority, () => {
      this.assertCipherPolicyAllowed(access.operation.policyLease, access.cipher);
      this.assertCipherAutofillTotpAllowed(access.cipher);
      access.assertRepromptAuthorized?.();
    });
    return result;
  }

  private async prepareAutofillSecret(
    cipherId: string,
    frameUrl: string,
    defaultStrategy: UriMatchStrategySetting,
    purpose: AutofillIntentPurpose,
    options?: {
      requireUnique?: boolean;
      channel?: 'interactive' | 'page-load';
      pageLoadFillDefault?: boolean;
      assertRepromptAuthorized?: () => void;
    },
  ) {
    const operation = await this.beginVaultOperation({ cache: true });
    const view = await this.requireCacheView();
    operation.assertCurrent();
    if (view.envelope.rawGeneration !== operation.cacheEnvelope.rawGeneration) {
      throw new AppError('denied', 'Autofill intent is invalid or expired');
    }
    const cache = operation.cacheEnvelope.response;
    const candidate = cache.ciphers.find((entry) => entry.id === cipherId);
    const cipher = candidate?.type === 1
      ? this.requireSupportedCipher(candidate, [1])
      : undefined;
    const summary = view.snapshot.listing.items.find((candidate) => candidate.id === cipherId);
    const equivalentIndex = this.loadEquivalentIndex(view.snapshot);
    const matchingCandidates = options?.requireUnique
      ? view.snapshot.listing.items.filter((candidate) => (
          candidate.type === 1
          && !candidate.undecryptable
          && isActiveCipher(candidate)
          && (options?.channel !== 'page-load' || pageLoadAutofillAllowed(
            candidate.autofillOnPageLoad,
            options.pageLoadFillDefault ?? true,
          ))
          && bestMatch(candidate.loginUris, frameUrl, defaultStrategy, equivalentIndex) !== undefined
        ))
      : undefined;
    if (
      !cipher
      || cipher.type !== 1
      || !summary
      || summary.undecryptable
      || isCipherInactive(summary)
      || (options?.channel === 'page-load' && !pageLoadAutofillAllowed(
        summary.autofillOnPageLoad,
        options.pageLoadFillDefault ?? true,
      ))
      || !bestMatch(summary.loginUris, frameUrl, defaultStrategy, equivalentIndex)
      || (purpose === 'totp' && !cipher.login?.totp)
      || (matchingCandidates && (matchingCandidates.length !== 1 || matchingCandidates[0]!.id !== cipherId))
    ) {
      throw new AppError('denied', 'Autofill intent is invalid or expired');
    }
    const assertRepromptAuthorized = cipher.reprompt
      ? options?.assertRepromptAuthorized
      : undefined;
    if (cipher.reprompt && !assertRepromptAuthorized) {
      throw new AppError('reprompt_required', 'This item requires master-password verification in the extension');
    }
    assertRepromptAuthorized?.();
    this.assertCipherPolicyAllowed(operation.policyLease, cipher);
    if (purpose === 'totp') this.assertCipherAutofillTotpAllowed(cipher);
    const fieldKey = await this.cipherFieldKey(cipher, operation.userKey, cache.profile);
    operation.assertCurrent();
    assertRepromptAuthorized?.();
    return {
      cipher,
      fieldKey,
      operation,
      view,
      ...(assertRepromptAuthorized ? { assertRepromptAuthorized } : {}),
    };
  }

  /** Decide whether a submitted credential should be saved, updated, or have this origin attached to
   *  one existing personal login. The add-URI branch requires one exact credential match and never
   *  guesses across ambiguous, protected, organization-owned, or undecryptable items. */
  async checkSaveLogin(
    frameUrl: string,
    submitted: { username?: string; password: string },
    defaultStrategy: UriMatchStrategySetting,
  ): Promise<SaveLoginPrompt> {
    return this.decideSaveLogin(frameUrl, submitted, defaultStrategy);
  }

  private async decideSaveLogin(
    frameUrl: string,
    submitted: { username?: string; password: string },
    defaultStrategy: UriMatchStrategySetting,
    runtime?: VaultMutationRuntime,
  ): Promise<SaveLoginPrompt> {
    if (!submitted.password) return { action: 'none' };
    const operation = runtime?.operation ?? await this.beginVaultOperation({ cache: true });
    const view = await this.requireCacheView();
    operation.assertCurrent();
    if (view.envelope.rawGeneration !== operation.cacheEnvelope.rawGeneration) {
      throw new AppError('sync_required', 'Vault changed while checking the submitted login.');
    }
    const cache = operation.cacheEnvelope.response;
    const summaries = view.snapshot.listing.items;
    const equivalentIndex = this.loadEquivalentIndex(view.snapshot);
    const username = normalizeLoginUsername(submitted.username);
    // Reprompt summaries contain only list-safe URI and username metadata. If that metadata cannot
    // rule out a current credential match, do not decrypt the item or offer a duplicate save.
    const protectedCurrentCredential = summaries.some((summary) => {
      if (
        summary.type !== 1
        || !isActiveCipher(summary)
        || summary.undecryptable
        || !summary.reprompt
        || bestMatch(summary.loginUris, frameUrl, defaultStrategy, equivalentIndex) === undefined
      ) return false;
      const protectedUsername = normalizeLoginUsername(summary.username);
      return username === undefined || protectedUsername === undefined || protectedUsername === username;
    });
    if (protectedCurrentCredential) {
      await operation.assertCacheCurrent();
      return { action: 'none' };
    }
    const orgKeys = await this.buildOrgKeys(cache.profile);
    const visibleLogins = summaries.filter((summary) => (
      summary.type === 1
      && isActiveCipher(summary)
      && !summary.undecryptable
      && !summary.reprompt
    ));
    const currentUrlMatches = visibleLogins.filter((summary) => (
      bestMatch(summary.loginUris, frameUrl, defaultStrategy, equivalentIndex) !== undefined
    ));
    // Resolve every same-username current-site candidate before deciding. List order must never choose
    // which password gets updated: one exact password means no change, one different password may be
    // updated, and ambiguity or a decrypt failure fails closed without suggesting a duplicate create.
    const currentCredentialCandidates = currentUrlMatches.filter((summary) => (
      username ? normalizeLoginUsername(summary.username) === username : !summary.username
    ));
    const resolvedCurrentCandidates: Array<{
      cipherId: string;
      name: string;
      password?: string;
      canEdit: boolean;
    }> = [];
    let currentCandidatesIndeterminate = false;
    for (const summary of currentCredentialCandidates) {
      const raw = cache.ciphers.find((candidate) => candidate.id === summary.id);
      if (!raw) {
        currentCandidatesIndeterminate = true;
        continue;
      }
      let cipher: SupportedCipherResponse;
      try {
        cipher = this.requireSupportedCipher(raw, [1]);
        this.assertCipherPolicyAllowed(operation.policyLease, cipher);
      } catch {
        currentCandidatesIndeterminate = true;
        continue;
      }
      const access = projectValidatedCipherAccess(cipher);
      if (!access.viewPassword) {
        currentCandidatesIndeterminate = true;
        continue;
      }
      const decrypted = await decryptCipher(cipher, operation.userKey, orgKeys);
      operation.assertCurrent();
      if (!decrypted || decrypted.undecryptable) {
        currentCandidatesIndeterminate = true;
        continue;
      }
      resolvedCurrentCandidates.push({
        cipherId: decrypted.id,
        name: decrypted.name,
        canEdit: access.edit,
        ...(decrypted.password !== undefined ? { password: decrypted.password } : {}),
      });
    }
    if (resolvedCurrentCandidates.some((candidate) => equalSecretText(candidate.password, submitted.password))) {
      await operation.assertCacheCurrent();
      return { action: 'none' };
    }
    if (currentCredentialCandidates.length > 0) {
      await operation.assertCacheCurrent();
      if (currentCandidatesIndeterminate || resolvedCurrentCandidates.length !== 1) return { action: 'none' };
      const candidate = resolvedCurrentCandidates[0]!;
      if (!candidate.canEdit) return { action: 'none' };
      return { action: 'update', cipherId: candidate.cipherId, name: candidate.name };
    }

    // Only a username with no currently matching visible login can be attached to an existing item.
    // Another account already saved for this site does not block the submitted account's URI.
    // Restrict URI attachment to personal items so captured credentials never rewrite shared data.
    if (username && currentCredentialCandidates.length === 0) {
      const origin = canonicalHttpOrigin(frameUrl);
      const exactMatches: Array<{ cipherId: string; name: string; blockedByExistingRule: boolean }> = [];
      let indeterminate = false;
      for (const summary of visibleLogins) {
        if (summary.organizationId || normalizeLoginUsername(summary.username) !== username) continue;
        const candidate = cache.ciphers.find((cipher) => cipher.id === summary.id);
        if (!candidate || candidate.organizationId || isCipherInactive(candidate) || candidate.reprompt) continue;
        this.assertCipherPolicyAllowed(operation.policyLease, candidate);
        const decrypted = await decryptCipher(candidate, operation.userKey, orgKeys);
        operation.assertCurrent();
        if (!decrypted || decrypted.undecryptable) {
          indeterminate = true;
          continue;
        }
        if (!equalSecretText(decrypted.password, submitted.password)) continue;
        exactMatches.push({
          cipherId: candidate.id,
          name: decrypted.name,
          blockedByExistingRule: origin === undefined
            || hasCanonicalOriginUri(decrypted.loginUris, origin)
            || hasNeverRuleForOrigin(decrypted.loginUris, origin),
        });
      }
      if (!indeterminate && exactMatches.length === 1) {
        await operation.assertCacheCurrent();
        const exact = exactMatches[0]!;
        return exact.blockedByExistingRule
          ? { action: 'none' }
          : { action: 'addUri', cipherId: exact.cipherId, name: exact.name };
      }
    }

    // Do not show a prompt that enterprise policy guarantees cannot create successfully.
    await operation.assertCacheCurrent();
    return this.canCreatePersonalCipher(operation.policyLease, 1)
      ? { action: 'save', suggestedName: hostnameOf(frameUrl) }
      : { action: 'none' };
  }

  /** Revalidate and commit one captured login inside a single account mutation lane and raw-cache
   * generation. The expected decision came from the encrypted prompt claim; any drift aborts before
   * a remote write, while an invoked remote write is never retried by the coordinator. */
  async commitCapturedLogin(
    frameUrl: string,
    submitted: { username?: string; password: string },
    defaultStrategy: UriMatchStrategySetting,
    expected: CapturedLoginCommitDecision,
    requestGuard?: () => void,
  ): Promise<VaultListing> {
    if (!submitted.password) throw new AppError('denied', 'A captured login password is required');
    return this.runVaultMutation('capturedLogin.commit', async (runtime) => {
      const { operation, remote, reconcile } = runtime;
      const current = await this.decideSaveLogin(frameUrl, submitted, defaultStrategy, runtime);
      if (!sameCapturedLoginDecision(current, expected)) {
        throw new AppError('denied', 'The captured login decision is no longer current');
      }
      const api = requestGuard ? operation.api.withRequestGuard(requestGuard) : operation.api;

      if (current.action === 'save') {
        this.assertPersonalCreationAllowed(operation.policyLease, 1);
        const origin = originOf(frameUrl);
        const input: CipherInput = {
          type: 1,
          name: hostnameOf(frameUrl),
          login: {
            password: submitted.password,
            ...(submitted.username ? { username: submitted.username } : {}),
            ...(origin ? { uris: [{ uri: origin }] } : {}),
          },
        };
        const request = await encryptCipher(input, operation.userKey);
        await operation.assertCacheCurrent();
        await remote((accessToken) => api.createCipher(accessToken, request));
        return reconcile(() => this.syncAfterMutation(operation));
      }

      const cache = operation.cacheEnvelope.response;
      const candidate = cache.ciphers.find((item) => item.id === current.cipherId);
      const cipher = candidate ? this.requireSupportedCipher(candidate, [1]) : undefined;
      if (!cipher) throw new AppError('denied', 'The captured login target is no longer available');

      if (current.action === 'update') {
        this.assertCipherEditAllowed(operation.policyLease, cipher);
        this.assertCipherPasswordViewAllowed(cipher);
        const decrypted = await decryptCipher(
          cipher,
          operation.userKey,
          await this.buildOrgKeys(cache.profile),
        );
        operation.assertCurrent();
        if (!decrypted || decrypted.undecryptable || decrypted.type !== 1 || decrypted.reprompt) {
          throw new AppError('denied', 'The captured login update is no longer allowed');
        }
        const input = this.toCipherInput(decrypted);
        input.login = { ...(input.login ?? {}), password: submitted.password };
        return this.updateCipherWithOperation(current.cipherId, input, runtime, cipher, requestGuard);
      }

      const normalizedUsername = normalizeLoginUsername(submitted.username);
      const origin = canonicalHttpOrigin(frameUrl);
      if (!normalizedUsername || !origin || cipher.organizationId || isCipherInactive(cipher) || cipher.reprompt) {
        throw new AppError('denied', 'The captured login URI update is no longer allowed');
      }
      this.assertCipherEditAllowed(operation.policyLease, cipher);
      const decrypted = await decryptCipher(
        cipher,
        operation.userKey,
        await this.buildOrgKeys(cache.profile),
      );
      operation.assertCurrent();
      if (
        !decrypted
        || decrypted.undecryptable
        || normalizeLoginUsername(decrypted.username) !== normalizedUsername
        || !equalSecretText(decrypted.password, submitted.password)
      ) throw new AppError('denied', 'The captured login URI target changed');
      const equivalentIndex = buildEquivalentDomainIndex(
        cache.domains?.equivalentDomains ?? [],
        (cache.domains?.globalEquivalentDomains ?? [])
          .filter((group) => group.excluded)
          .flatMap((group) => group.domains ?? []),
      );
      if (
        bestMatch(decrypted.loginUris, frameUrl, defaultStrategy, equivalentIndex)
        || hasCanonicalOriginUri(decrypted.loginUris, origin)
        || hasNeverRuleForOrigin(decrypted.loginUris, origin)
      ) throw new AppError('denied', 'The captured login URI update is no longer allowed');
      const revision = cipher.revisionDate;
      if (!isIsoTimestamp(revision)) {
        throw new AppError('denied', 'The captured login URI update requires a current revision.');
      }
      let fieldKey: SymmetricKey | undefined;
      let encryptedUri: string;
      let encryptedChecksum: string;
      try {
        fieldKey = await this.cipherFieldKey(cipher, operation.userKey, cache.profile);
        encryptedUri = await encryptToText(origin, fieldKey);
        encryptedChecksum = await encryptToText(await computeLoginUriChecksum(origin), fieldKey);
      } finally {
        if (cipher.key != null) destroySymmetricKey(fieldKey);
      }
      const request = this.cipherResponseToRequest(cipher);
      request.login = {
        ...(cipher.login ?? {}),
        uris: [
          ...(cipher.login?.uris ?? []),
          { uri: encryptedUri, uriChecksum: encryptedChecksum, match: UriMatchStrategy.Host },
        ],
      };
      request.lastKnownRevisionDate = revision;
      await operation.assertCacheCurrent();
      await remote((accessToken) => api.updateCipher(accessToken, current.cipherId, request));
      const listing = await reconcile(() => this.syncAfterMutation(operation));
      await this.assertAuthoritativeLoginUriAdded(
        operation,
        cipher,
        origin,
        revision,
        UriMatchStrategy.Host,
      );
      return listing;
    }, { cache: true });
  }

  /** Create a new login cipher from a captured submission, scoped to the submitting page's origin. */
  async saveLogin(
    frameUrl: string,
    username: string | undefined,
    password: string,
    policyGuard?: () => void,
  ): Promise<VaultListing> {
    if (!password) throw new AppError('error', 'A password is required to save a login');
    return this.runVaultMutation('capturedLogin.create', async ({ operation, remote, reconcile }) => {
    this.assertPersonalCreationAllowed(operation.policyLease, 1);
    const origin = originOf(frameUrl);
    const input: CipherInput = {
      type: 1,
      name: hostnameOf(frameUrl),
      login: { password, ...(username ? { username } : {}), ...(origin ? { uris: [{ uri: origin }] } : {}) },
    };
    const request = await encryptCipher(input, operation.userKey);
    const api = policyGuard ? operation.api.withRequestGuard(policyGuard) : operation.api;
    await remote((accessToken) => api.createCipher(accessToken, request));
    return reconcile(() => this.syncAfterMutation(operation));
    });
  }

  /**
   * Update an existing login's password from a captured submission. Verifies the target still matches
   * the submitting page (a page cannot rewrite arbitrary ciphers) and refuses reprompt-protected items.
   */
  async updateLoginPassword(
    cipherId: string,
    password: string,
    frameUrl: string,
    defaultStrategy: UriMatchStrategySetting,
    policyGuard?: () => void,
  ): Promise<VaultListing> {
    if (!password) throw new AppError('error', 'A password is required');
    return this.runVaultMutation('capturedLogin.update', async (runtime) => {
    const { operation } = runtime;
    const cache = operation.cacheEnvelope!.response;
    const candidate = cache.ciphers.find((item) => item.id === cipherId);
    const cipher = candidate ? this.requireSupportedCipher(candidate, [1]) : undefined;
    if (!cipher || isCipherInactive(cipher)) {
      throw new AppError('denied', 'Login update is not allowed for this item');
    }
    this.assertCipherEditAllowed(operation.policyLease, cipher);
    this.assertCipherPasswordViewAllowed(cipher);
    const decrypted = await decryptCipher(cipher, operation.userKey, await this.buildOrgKeys(cache.profile));
    if (!decrypted || decrypted.undecryptable || decrypted.type !== 1) {
      throw new AppError('denied', 'Login update is not allowed for this item');
    }
    if (decrypted.reprompt) throw new AppError('reprompt_required', 'This item requires master-password verification in the extension');
    const excludedDomains = (cache.domains?.globalEquivalentDomains ?? [])
      .filter((group) => group.excluded)
      .flatMap((group) => group.domains ?? []);
    const equivalentIndex = buildEquivalentDomainIndex(cache.domains?.equivalentDomains ?? [], excludedDomains);
    if (!bestMatch(decrypted.loginUris, frameUrl, defaultStrategy, equivalentIndex)) {
      throw new AppError('denied', 'Login update is not allowed for this page');
    }
    const input = this.toCipherInput(decrypted);
    input.login = { ...(input.login ?? {}), password };
    return this.updateCipherWithOperation(cipherId, input, runtime, cipher, policyGuard);
    }, { cache: true });
  }

  /** Append the current canonical origin to one existing personal login. Every field other than the
   *  new URI remains byte-identical to the cached CipherResponse. */
  async addLoginUri(
    cipherId: string,
    username: string,
    password: string,
    frameUrl: string,
    defaultStrategy: UriMatchStrategySetting,
    policyGuard?: () => void,
  ): Promise<VaultListing> {
    const normalizedUsername = normalizeLoginUsername(username);
    const origin = canonicalHttpOrigin(frameUrl);
    if (!normalizedUsername || !password || !origin) {
      throw new AppError('denied', 'Login URI update is not allowed');
    }
    return this.runVaultMutation('capturedLogin.addUri', async ({ operation, remote, reconcile }) => {
      const view = await this.requireCacheView();
      operation.assertCurrent();
      if (view.envelope.rawGeneration !== operation.cacheEnvelope.rawGeneration) {
        throw new AppError('denied', 'Login URI update is no longer current');
      }
      const cache = operation.cacheEnvelope.response;
      const summary = view.snapshot.listing.items.find((item) => item.id === cipherId);
      const candidate = cache.ciphers.find((item) => item.id === cipherId);
      const cipher = candidate ? this.requireSupportedCipher(candidate, [1]) : undefined;
      if (
        !summary
        || summary.type !== 1
        || summary.organizationId
        || isCipherInactive(summary)
        || summary.undecryptable
        || summary.reprompt
        || !cipher
        || cipher.organizationId
        || isCipherInactive(cipher)
        || cipher.reprompt
      ) throw new AppError('denied', 'Login URI update is not allowed');
      this.assertCipherEditAllowed(operation.policyLease, cipher);

      const orgKeys = await this.buildOrgKeys(cache.profile);
      const decrypted = await decryptCipher(cipher, operation.userKey, orgKeys);
      operation.assertCurrent();
      if (
        !decrypted
        || decrypted.undecryptable
        || normalizeLoginUsername(decrypted.username) !== normalizedUsername
        || !equalSecretText(decrypted.password, password)
      ) throw new AppError('denied', 'Login URI update is not allowed');

      const exactCredentialIds: string[] = [];
      let credentialSetIndeterminate = false;
      for (const item of view.snapshot.listing.items) {
        if (
          item.type !== 1
          || item.organizationId
          || isCipherInactive(item)
          || item.undecryptable
          || item.reprompt
          || normalizeLoginUsername(item.username) !== normalizedUsername
        ) continue;
        const raw = cache.ciphers.find((entry) => entry.id === item.id);
        if (!raw || raw.organizationId || isCipherInactive(raw) || raw.reprompt) continue;
        this.assertCipherPolicyAllowed(operation.policyLease, raw);
        const candidateLogin = raw.id === cipherId
          ? decrypted
          : await decryptCipher(raw, operation.userKey, orgKeys);
        operation.assertCurrent();
        if (!candidateLogin || candidateLogin.undecryptable) {
          credentialSetIndeterminate = true;
          continue;
        }
        if (equalSecretText(candidateLogin.password, password)) exactCredentialIds.push(raw.id);
      }
      if (
        credentialSetIndeterminate
        || exactCredentialIds.length !== 1
        || exactCredentialIds[0] !== cipherId
      ) throw new AppError('denied', 'Login URI update is no longer unique');

      const equivalentIndex = this.loadEquivalentIndex(view.snapshot);
      if (
        bestMatch(decrypted.loginUris, frameUrl, defaultStrategy, equivalentIndex)
        || hasCanonicalOriginUri(decrypted.loginUris, origin)
        || hasNeverRuleForOrigin(decrypted.loginUris, origin)
      ) throw new AppError('denied', 'Login URI update is not allowed');

      const revision = cipher.revisionDate;
      if (!isIsoTimestamp(revision)) {
        throw new AppError('denied', 'Login URI update requires a current revision.');
      }
      let fieldKey: SymmetricKey | undefined;
      let encryptedUri: string;
      let encryptedChecksum: string;
      try {
        fieldKey = await this.cipherFieldKey(cipher, operation.userKey, cache.profile);
        encryptedUri = await encryptToText(origin, fieldKey);
        encryptedChecksum = await encryptToText(await computeLoginUriChecksum(origin), fieldKey);
      } finally {
        if (cipher.key != null) destroySymmetricKey(fieldKey);
      }
      const request = this.cipherResponseToRequest(cipher);
      request.login = {
        ...(cipher.login ?? {}),
        uris: [
          ...(cipher.login?.uris ?? []),
          { uri: encryptedUri, uriChecksum: encryptedChecksum, match: UriMatchStrategy.Host },
        ],
      };
      request.lastKnownRevisionDate = revision;
      await operation.assertCacheCurrent();
      const api = policyGuard ? operation.api.withRequestGuard(policyGuard) : operation.api;
      await remote((accessToken) => api.updateCipher(accessToken, cipherId, request));
      const listing = await reconcile(() => this.syncAfterMutation(operation));
      await this.assertAuthoritativeLoginUriAdded(
        operation,
        cipher,
        origin,
        revision,
        UriMatchStrategy.Host,
      );
      return listing;
    }, { cache: true });
  }

  private async decryptSummaries(
    ciphers: CipherResponse[],
    userKey: SymmetricKey,
    orgKeys: Map<string, SymmetricKey>,
    organizationCloneAllowed?: (cipher: CipherResponse) => boolean,
  ): Promise<CipherSummary[]> {
    const out: CipherSummary[] = [];
    for (const cipher of ciphers) {
      try {
        // Lightweight path: decrypt only the list-visible fields (name, URIs, username, subtitle) and
        // derive the presence flags from the encrypted shape. The password/TOTP/passkey key and other
        // secrets are decrypted on demand for detail/reveal/edit flows, never for the list.
        const summary = await decryptCipherSummary(cipher, userKey, orgKeys);
        if (summary?.organizationId && summary.access) {
          summary.access = {
            ...projectValidatedCipherAccess(cipher, organizationCloneAllowed?.(cipher) === true),
          };
        }
        if (summary) out.push(summary);
      } catch {
        out.push(undecryptableSummary(cipher));
      }
    }
    return out;
  }
}

const SSH_KEY_METADATA_FIELDS = new Set([
  'name',
  'notes',
  'favorite',
  'reprompt',
  'folderId',
  'fields',
]);
const SSH_KEY_CUSTOM_FIELD_KEYS = new Set(['type', 'name', 'value', 'linkedId']);
const MAX_SSH_METADATA_NAME_CHARS = 1_000;
const MAX_SSH_METADATA_NAME_BYTES = 4_000;
const MAX_SSH_METADATA_NOTES_CHARS = 10_000;
const MAX_SSH_METADATA_NOTES_BYTES = 40_000;
const MAX_SSH_METADATA_FOLDER_ID_CHARS = 256;
const MAX_SSH_METADATA_FOLDER_ID_BYTES = 1_024;
const MAX_SSH_METADATA_FIELDS = 256;
const MAX_SSH_FIELD_NAME_CHARS = 1_000;
const MAX_SSH_FIELD_NAME_BYTES = 4_000;
const MAX_SSH_FIELD_VALUE_CHARS = 10_000;
const MAX_SSH_FIELD_VALUE_BYTES = 40_000;

function parseSshKeyMetadataInput(value: unknown): Readonly<SshKeyMetadataInput> {
  if (!isPlainObject(value) || !hasOnlyDataProperties(value)) throw invalidSshMetadata();
  const keys = Object.keys(value);
  if (
    keys.length !== SSH_KEY_METADATA_FIELDS.size
    || keys.some((key) => !SSH_KEY_METADATA_FIELDS.has(key))
    || !Object.prototype.hasOwnProperty.call(value, 'name')
    || !Object.prototype.hasOwnProperty.call(value, 'notes')
    || !Object.prototype.hasOwnProperty.call(value, 'favorite')
    || !Object.prototype.hasOwnProperty.call(value, 'reprompt')
    || !Object.prototype.hasOwnProperty.call(value, 'folderId')
    || !Object.prototype.hasOwnProperty.call(value, 'fields')
  ) throw invalidSshMetadata();
  const { name: rawName, notes, favorite, reprompt, folderId: rawFolderId, fields } = value;
  const name = typeof rawName === 'string' ? rawName.trim() : undefined;
  const folderId = typeof rawFolderId === 'string' ? rawFolderId.trim() : rawFolderId;
  if (
    !isBoundedText(name, MAX_SSH_METADATA_NAME_CHARS, MAX_SSH_METADATA_NAME_BYTES, false)
    || !isBoundedText(notes, MAX_SSH_METADATA_NOTES_CHARS, MAX_SSH_METADATA_NOTES_BYTES, true)
    || typeof favorite !== 'boolean'
    || typeof reprompt !== 'boolean'
    || (folderId !== null
      && !isBoundedText(
        folderId,
        MAX_SSH_METADATA_FOLDER_ID_CHARS,
        MAX_SSH_METADATA_FOLDER_ID_BYTES,
        false,
      ))
  ) throw invalidSshMetadata();
  return Object.freeze({
    name,
    notes,
    favorite,
    reprompt,
    folderId,
    fields: parseSshMetadataFields(fields),
  });
}

function invalidSshMetadata(): AppError {
  return new AppError('error', 'SSH key metadata is invalid.');
}

function toSshCipherInput(
  metadata: Readonly<SshKeyMetadataInput>,
  sshKey: CompleteDecryptedSshKey,
): SshCipherInput {
  return {
    type: 5,
    name: metadata.name,
    ...(metadata.notes ? { notes: metadata.notes } : {}),
    favorite: metadata.favorite,
    reprompt: metadata.reprompt,
    folderId: metadata.folderId,
    fields: metadata.fields.map((field) => ({ ...field })),
    sshKey,
  };
}

function parseSshMetadataFields(value: unknown): DecryptedField[] {
  if (
    !Array.isArray(value)
    || Object.getPrototypeOf(value) !== Array.prototype
    || value.length > MAX_SSH_METADATA_FIELDS
  ) throw invalidSshMetadata();
  const expectedKeys = new Set<string>(['length']);
  for (let index = 0; index < value.length; index++) expectedKeys.add(String(index));
  const ownKeys = Reflect.ownKeys(value);
  if (
    ownKeys.length !== expectedKeys.size
    || ownKeys.some((key) => typeof key !== 'string' || !expectedKeys.has(key))
  ) throw invalidSshMetadata();
  for (let index = 0; index < value.length; index++) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    if (!descriptor || !('value' in descriptor)) throw invalidSshMetadata();
  }
  return value.map((candidate) => {
    if (!isPlainObject(candidate) || !hasOnlyDataProperties(candidate)) throw invalidSshMetadata();
    const keys = Object.keys(candidate);
    if (
      keys.some((key) => !SSH_KEY_CUSTOM_FIELD_KEYS.has(key))
      || !Object.prototype.hasOwnProperty.call(candidate, 'type')
      || !Object.prototype.hasOwnProperty.call(candidate, 'name')
    ) throw invalidSshMetadata();
    const { type, name, value: fieldValue, linkedId } = candidate;
    if (
      (type !== 0 && type !== 1 && type !== 2)
      || !isBoundedText(name, MAX_SSH_FIELD_NAME_CHARS, MAX_SSH_FIELD_NAME_BYTES, true)
    ) throw invalidSshMetadata();
    if (
      linkedId !== undefined
      || (fieldValue !== undefined
        && !isBoundedText(
          fieldValue,
          MAX_SSH_FIELD_VALUE_CHARS,
          MAX_SSH_FIELD_VALUE_BYTES,
          true,
        ))
      || (type === 2 && fieldValue !== undefined && fieldValue !== 'true' && fieldValue !== 'false')
    ) throw invalidSshMetadata();
    return fieldValue === undefined ? { type, name } : { type, name, value: fieldValue };
  });
}

async function encryptSshMetadataFields(
  fields: readonly DecryptedField[],
  fieldKey: SymmetricKey,
): Promise<CipherFieldData[]> {
  const encrypted: CipherFieldData[] = [];
  for (const field of fields) {
    const output: CipherFieldData = {
      type: field.type,
      name: field.name ? await encryptToText(field.name, fieldKey) : null,
    };
    if (field.type === 3) {
      output.value = null;
      output.linkedId = field.linkedId ?? null;
    } else {
      output.value = field.value ? await encryptToText(field.value, fieldKey) : null;
    }
    encrypted.push(output);
  }
  return encrypted;
}

async function encryptCompleteSshKey(
  sshKey: CompleteDecryptedSshKey,
  fieldKey: SymmetricKey,
): Promise<SshKeyCipherRequestData> {
  return parseCompleteSshKeyCipherData({
    privateKey: await encryptToText(sshKey.privateKey, fieldKey),
    publicKey: await encryptToText(sshKey.publicKey, fieldKey),
    keyFingerprint: await encryptToText(sshKey.keyFingerprint, fieldKey),
  });
}

async function decryptValidatedSshField(
  encrypted: string,
  fieldKey: SymmetricKey,
  field: SshKeyField,
): Promise<string> {
  try {
    return validateSshKeyPlaintextField(await decryptToText(encrypted, fieldKey), field);
  } catch {
    throw new AppError('denied', 'SSH key item cannot be safely read.');
  }
}

function sshKeyImportError(error: unknown): AppError {
  if (!(error instanceof SshKeyCodecError)) {
    return new AppError('error', 'SSH private key could not be imported.');
  }
  switch (error.code) {
    case 'invalid_key':
      return new AppError('error', 'SSH private key is invalid.');
    case 'unsupported_key_type':
      return new AppError('error', 'This SSH private key type is not supported.');
    case 'password_required':
      return new AppError('error', 'Encrypted SSH private keys are not supported.');
    case 'input_too_large':
      return new AppError('error', 'SSH private key exceeds the supported size limit.');
  }
}

function genericSshWriteDenied(): AppError {
  return new AppError('denied', 'SSH key writes require a dedicated SSH command.');
}

function assertSshWriteAuthorizationCurrent(
  authorization: SshCipherWriteAuthorization,
): void {
  try {
    authorization.assertCurrent();
  } catch {
    throw new SshWriteAuthorizationChangedError();
  }
}

function assertCipherArchiveAuthorizationCurrent(
  authorization: CipherArchiveAuthorization,
): void {
  try {
    authorization.assertCurrent();
  } catch {
    throw new CipherArchiveAuthorizationChangedError();
  }
}

function hasArchiveEntitlement(profile: SyncProfile): boolean {
  return profile.premium === true || profile.premiumFromOrganization === true;
}

function isOptionalLifecycleDate(value: unknown): value is string | null | undefined {
  return value === undefined || value === null || (typeof value === 'string' && value.length > 0);
}

function normalizeCipherCreateTarget(target: CipherCreateTarget): CipherCreateTarget {
  if (!isPlainObject(target) || !hasOnlyDataProperties(target)) {
    throw new AppError('denied', 'Cipher create target is invalid.');
  }
  const keys = Reflect.ownKeys(target);
  if (target.kind === 'personal') {
    if (keys.length !== 1 || keys[0] !== 'kind') {
      throw new AppError('denied', 'Cipher create target is invalid.');
    }
    return PERSONAL_CIPHER_CREATE_TARGET;
  }
  if (
    target.kind !== 'organization'
    || keys.length !== 3
    || !keys.includes('kind')
    || !keys.includes('organizationId')
    || !keys.includes('collectionIds')
  ) {
    throw new AppError('denied', 'Cipher create target is invalid.');
  }
  const organizationId = requireCreateTargetId(target.organizationId, 'organization');
  if (
    !Array.isArray(target.collectionIds)
    || target.collectionIds.length === 0
    || target.collectionIds.length > MAX_CREATE_TARGET_COLLECTIONS
    || !isDenseDataArray(target.collectionIds)
  ) {
    throw new AppError('denied', 'Cipher create collections are invalid.');
  }
  const collectionIds = target.collectionIds.map((id) => requireCreateTargetId(id, 'collection'));
  if (new Set(collectionIds).size !== collectionIds.length) {
    throw new AppError('denied', 'Cipher create collections must be unique.');
  }
  return Object.freeze({
    kind: 'organization',
    organizationId,
    collectionIds: Object.freeze(collectionIds),
  });
}

function normalizeCipherLocalMetadata(input: unknown): CipherPartialRequest {
  if (!isPlainObject(input) || !hasOnlyDataProperties(input)) {
    throw new AppError('denied', 'Cipher local metadata is invalid.');
  }
  const keys = Reflect.ownKeys(input);
  if (
    keys.length !== 2
    || !keys.includes('folderId')
    || !keys.includes('favorite')
    || keys.some((key) => {
      if (typeof key !== 'string') return true;
      const descriptor = Object.getOwnPropertyDescriptor(input, key);
      return !descriptor?.enumerable || !('value' in descriptor);
    })
    || typeof input.favorite !== 'boolean'
  ) {
    throw new AppError('denied', 'Cipher local metadata is invalid.');
  }
  const folderId = input.folderId === null
    ? null
    : requireLocalMetadataId(input.folderId, 'folder');
  return Object.freeze({ folderId, favorite: input.favorite });
}

function requireCipherFavorite(value: unknown): boolean {
  if (typeof value !== 'boolean') {
    throw new AppError('denied', 'Cipher favorite value is invalid.');
  }
  return value;
}

function requireLocalMetadataId(value: unknown, name: 'cipher' | 'folder'): string {
  if (
    typeof value !== 'string'
    || value.length === 0
    || value.length > MAX_CREATE_TARGET_ID_LENGTH
    || value !== value.trim()
    || containsAsciiControl(value)
  ) {
    throw new AppError('denied', `Cipher local metadata ${name} id is invalid.`);
  }
  return value;
}

function hasUniqueFolder(
  folders: readonly { readonly id: string }[] | null | undefined,
  folderId: string | null,
): boolean {
  return folderId === null || (folders ?? []).filter((folder) => folder.id === folderId).length === 1;
}

function assertLocalMetadataFolderAvailable(
  folders: readonly { readonly id: string }[] | null | undefined,
  folderId: string | null,
): void {
  if (!hasUniqueFolder(folders, folderId)) {
    throw new AppError('denied', 'The selected folder is not uniquely available to this account.');
  }
}

function assertCipherLocalMetadataUpdateCommitted(
  response: SyncResponse,
  cipherId: string,
  expected: CipherPartialRequest,
): void {
  const matches = response.ciphers.filter((cipher) => cipher.id === cipherId);
  const cipher = matches.length === 1 ? matches[0] : undefined;
  if (
    !cipher
    || !isOptionalLifecycleDate(cipher.deletedDate)
    || !isOptionalLifecycleDate(cipher.archivedDate)
    || !isActiveCipher(cipher)
    || cipher.favorite !== expected.favorite
    || (cipher.folderId ?? null) !== expected.folderId
    || !hasUniqueFolder(response.folders, expected.folderId)
  ) {
    throw new AppError(
      'committed_unsynced',
      'The cipher local metadata update could not be verified after sync.',
    );
  }
}

function requireCreateTargetId(value: unknown, name: string): string {
  if (
    typeof value !== 'string'
    || value.length === 0
    || value.length > MAX_CREATE_TARGET_ID_LENGTH
    || value !== value.trim()
    || containsAsciiControl(value)
  ) {
    throw new AppError('denied', `Cipher create ${name} id is invalid.`);
  }
  return value;
}

function isDenseDataArray(value: readonly unknown[]): boolean {
  const keys = Reflect.ownKeys(value);
  if (keys.length !== value.length + 1 || !keys.includes('length')) return false;
  for (let index = 0; index < value.length; index++) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    if (!descriptor || !descriptor.enumerable || !('value' in descriptor)) return false;
  }
  return true;
}

function containsAsciiControl(value: string): boolean {
  for (let index = 0; index < value.length; index++) {
    const code = value.charCodeAt(index);
    if (code <= 0x1f || code === 0x7f) return true;
  }
  return false;
}

function requireOrganizationDataOwnershipPopupDocumentId(value: string): string {
  if (typeof value !== 'string'
      || value.length === 0
      || value.length > 4_096
      || value.trim() !== value
      || containsAsciiControl(value)) {
    throw new AppError('denied', 'Organization data ownership popup identity is invalid.');
  }
  return value;
}

function compareOrganizationDataOwnershipItemRevisions(
  left: OrganizationDataOwnershipItemRevision,
  right: OrganizationDataOwnershipItemRevision,
): number {
  const cipher = left.cipherId.localeCompare(right.cipherId);
  if (cipher !== 0) return cipher;
  return (left.revisionDate ?? '').localeCompare(right.revisionDate ?? '');
}

function sameOrganizationDataOwnershipItemSet(
  left: readonly OrganizationDataOwnershipItemRevision[],
  right: readonly OrganizationDataOwnershipItemRevision[],
): boolean {
  return left.length === right.length
    && left.every((item, index) => item.cipherId === right[index]?.cipherId);
}

function sameOrganizationDataOwnershipItemRevisions(
  left: readonly OrganizationDataOwnershipItemRevision[],
  right: readonly OrganizationDataOwnershipItemRevision[],
): boolean {
  return sameOrganizationDataOwnershipItemSet(left, right)
    && left.every((item, index) => item.revisionDate === right[index]?.revisionDate);
}

async function organizationDataOwnershipReconciliationKey(accountKey: string): Promise<string> {
  const bytes = new TextEncoder().encode(accountKey);
  let digest: Uint8Array | undefined;
  try {
    digest = new Uint8Array(await globalThis.crypto.subtle.digest('SHA-256', bytes as BufferSource));
    return `${ORGANIZATION_DATA_OWNERSHIP_RECONCILIATION_PREFIX}${bytesToBase64Url(digest)}`;
  } finally {
    bytes.fill(0);
    digest?.fill(0);
  }
}

function parseOrganizationDataOwnershipReconciliation(
  value: unknown,
): StoredOrganizationDataOwnershipReconciliation | undefined {
  if (!isPlainObject(value) || !hasOnlyDataProperties(value)) return undefined;
  const keys = Object.keys(value).sort();
  if (keys.join(',') !== 'operation,reason,schemaVersion'
      || value.schemaVersion !== 1
      || (value.operation !== 'migrate' && value.operation !== 'leave')
      || (value.reason !== 'outcome_unknown' && value.reason !== 'committed_unsynced')) {
    return undefined;
  }
  return Object.freeze({
    schemaVersion: 1,
    operation: value.operation,
    reason: value.reason,
  });
}

function sameOrganizationDataOwnershipReconciliation(
  left: StoredOrganizationDataOwnershipReconciliation | undefined,
  right: StoredOrganizationDataOwnershipReconciliation,
): boolean {
  return left?.schemaVersion === right.schemaVersion
    && left.operation === right.operation
    && left.reason === right.reason;
}

async function createDataOwnershipSnapshotDigest(input: {
  readonly organizationId: string;
  readonly revisionDate: string | null;
  readonly collectionId: string | null;
  readonly itemRevisions: readonly OrganizationDataOwnershipItemRevision[];
}): Promise<string> {
  const canonical = JSON.stringify([
    'organization-data-ownership-consent-v2',
    input.organizationId,
    input.revisionDate,
    input.collectionId,
    [...input.itemRevisions]
      .sort(compareOrganizationDataOwnershipItemRevisions)
      .map((item) => [item.cipherId, item.revisionDate]),
  ]);
  const digest = new Uint8Array(await globalThis.crypto.subtle.digest(
    'SHA-256',
    new TextEncoder().encode(canonical) as BufferSource,
  ));
  return bytesToBase64Url(digest);
}

function validCollectionUpdateReceipt(
  value: CollectionResponse,
  organizationId: string,
  collectionId: string,
  encryptedName: string,
  externalId: string | null,
): boolean {
  if (!isPlainObject(value)) return false;
  const record = value as unknown as Record<string, unknown>;
  const actualExternalId = normalizeOptionalExternalId(record);
  return value.id === collectionId
    && value.organizationId === organizationId
    && value.name === encryptedName
    && actualExternalId.valid
    && actualExternalId.value === externalId;
}

function normalizeOptionalExternalId(
  record: Record<string, unknown>,
): { readonly valid: boolean; readonly value: string | null } {
  const descriptor = Object.getOwnPropertyDescriptor(record, 'externalId');
  if (!descriptor) return { valid: true, value: null };
  if (!('value' in descriptor)) return { valid: false, value: null };
  const value = descriptor.value;
  if (value === undefined || value === null) return { valid: true, value: null };
  return typeof value === 'string'
    ? { valid: true, value }
    : { valid: false, value: null };
}

function toCollectionOrganizationAuthority(
  organization: OrganizationResponse,
  isProviderUser: boolean,
): CollectionOrganizationAuthority {
  const permissions = organization.permissions;
  return Object.freeze({
    id: organization.id,
    isProviderUser,
    ...(organization.status === undefined ? {} : { status: organization.status }),
    ...(organization.enabled === undefined ? {} : { enabled: organization.enabled }),
    ...(organization.type === undefined ? {} : { type: organization.type }),
    ...(organization.limitCollectionCreation === undefined
      ? {}
      : { limitCollectionCreation: organization.limitCollectionCreation }),
    ...(organization.limitCollectionDeletion === undefined
      ? {}
      : { limitCollectionDeletion: organization.limitCollectionDeletion }),
    ...(organization.allowAdminAccessToAllCollectionItems === undefined
      ? {}
      : { allowAdminAccessToAllCollectionItems: organization.allowAdminAccessToAllCollectionItems }),
    ...(permissions === undefined
      ? {}
      : {
          permissions: permissions === null
            ? null
            : Object.freeze({
                ...(permissions.createNewCollections === undefined
                  ? {}
                  : { createNewCollections: permissions.createNewCollections }),
                ...(permissions.editAnyCollection === undefined
                  ? {}
                  : { editAnyCollection: permissions.editAnyCollection }),
                ...(permissions.deleteAnyCollection === undefined
                  ? {}
                  : { deleteAnyCollection: permissions.deleteAnyCollection }),
              }),
        }),
  });
}

function groupCollectionsById(
  collections: readonly CollectionResponse[],
): Map<string, CollectionResponse[]> {
  const grouped = new Map<string, CollectionResponse[]>();
  for (const collection of collections) {
    const existing = grouped.get(collection.id);
    if (existing) existing.push(collection);
    else grouped.set(collection.id, [collection]);
  }
  return grouped;
}

function requireClientEventAuthorityRecord(
  value: unknown,
  name: string,
): Record<string, unknown> {
  if (!isPlainObject(value) || !hasOnlyDataProperties(value)) {
    throw invalidClientEventAuthority(`Invalid ${name}`);
  }
  return value;
}

function clientEventAuthorityDataValue(
  record: Record<string, unknown>,
  key: string,
): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(record, key);
  if (!descriptor) return undefined;
  if (!descriptor.enumerable || !('value' in descriptor)) {
    throw invalidClientEventAuthority(`Invalid ${key}`);
  }
  return descriptor.value;
}

function requireClientEventAuthorityArray(value: unknown, name: string): readonly unknown[] {
  if (!Array.isArray(value) || !isDenseDataArray(value)) {
    throw invalidClientEventAuthority(`Invalid ${name}`);
  }
  return value;
}

function requireOptionalClientEventAuthorityArray(
  value: unknown,
  name: string,
): readonly unknown[] {
  return value === undefined || value === null
    ? Object.freeze([])
    : requireClientEventAuthorityArray(value, name);
}

function requireClientEventAuthorityId(value: unknown, name: string): string {
  if (typeof value !== 'string' || !CANONICAL_CLIENT_EVENT_UUID.test(value)) {
    throw invalidClientEventAuthority(`Invalid ${name} id`);
  }
  return value;
}

function invalidClientEventAuthority(message: string): AppError {
  return new AppError('denied', `Client event authority is invalid: ${message}.`);
}

function normalizeCollectionAssignmentIds(value: unknown): string[] {
  if (!Array.isArray(value)
      || value.length > MAX_CREATE_TARGET_COLLECTIONS
      || !isDenseDataArray(value)) {
    throw new AppError('denied', 'Collection assignment is invalid.');
  }
  const ids = value.map((id) => requireCreateTargetId(id, 'collection'));
  if (new Set(ids).size !== ids.length) {
    throw new AppError('denied', 'Collection assignment cannot contain duplicate ids.');
  }
  return ids;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value) as unknown;
  return prototype === Object.prototype || prototype === null;
}

function hasOnlyDataProperties(value: Record<string, unknown>): boolean {
  return Object.values(Object.getOwnPropertyDescriptors(value))
    .every((descriptor) => 'value' in descriptor);
}

function isBoundedText(
  value: unknown,
  maximumChars: number,
  maximumBytes: number,
  allowEmpty: boolean,
): value is string {
  if (
    typeof value !== 'string'
    || (!allowEmpty && value.length === 0)
    || value.length > maximumChars
    || value.includes('\0')
  ) return false;
  const encoded = new TextEncoder().encode(value);
  try {
    return encoded.byteLength <= maximumBytes;
  } finally {
    encoded.fill(0);
  }
}

async function projectLoginCustomAssignments(
  fields: readonly CipherFieldData[] | null | undefined,
  fieldKey: SymmetricKey,
  plan: LoginCustomTargetPlan,
  username: string | undefined,
  password: string | undefined,
): Promise<LoginCustomAssignment[]> {
  if (!fields?.length || fields.length > MAX_LOGIN_CUSTOM_FIELDS_SCANNED || plan.targets.length === 0) return [];
  const candidates: Array<Readonly<{
    field: CipherFieldData;
    matcher: LoginCustomFieldMatcher;
  }>> = [];

  for (const field of fields) {
    if (!field.name) continue;
    let name: string;
    try {
      name = canonicalLoginCustomName(await decryptToText(field.name, fieldKey));
    } catch {
      continue;
    }
    const matcher = parseLoginCustomFieldMatcher(name);
    if (!matcher || !plan.targets.some((target) => matchesLoginCustomTarget(matcher, target.hints))) continue;
    candidates.push(Object.freeze({ field, matcher }));
  }

  const assignments: LoginCustomAssignment[] = [];
  let totalBytes = 0;
  for (const target of plan.targets) {
    const matching = candidates.filter((candidate) => matchesLoginCustomTarget(candidate.matcher, target.hints));
    if (matching.length !== 1) continue;
    const field = matching[0]!.field;
    const type = field.type ?? 0;
    const checkbox = target.controlType === 'checkbox';

    if (type === 2) {
      if (!checkbox || !field.value) continue;
      let value: string;
      try { value = (await decryptToText(field.value, fieldKey)).trim().toLowerCase(); }
      catch { continue; }
      if (value !== 'true' && value !== 'false') continue;
      assignments.push(Object.freeze({ fieldId: target.fieldId, checked: value === 'true' }));
      continue;
    }

    if (checkbox) continue;
    let value: string | undefined;
    if (type === 0 || type === 1) {
      if (!field.value) continue;
      try { value = await decryptToText(field.value, fieldKey); }
      catch { continue; }
    } else if (type === 3) {
      if (field.linkedId === 100) value = username;
      else if (field.linkedId === 101) value = password;
      else continue;
    } else {
      continue;
    }
    if (value === undefined || value.length > MAX_LOGIN_CUSTOM_ASSIGNMENT_LENGTH) continue;
    const bytes = new TextEncoder().encode(value).byteLength;
    if (totalBytes + bytes > MAX_LOGIN_CUSTOM_ASSIGNMENT_BYTES) continue;
    totalBytes += bytes;
    assignments.push(Object.freeze({ fieldId: target.fieldId, value }));
  }
  return assignments;
}

function canonicalLoginCustomName(value: string): string {
  const canonical = value.trim().normalize('NFKC');
  return canonical.length <= MAX_LOGIN_CUSTOM_HINT_LENGTH ? canonical : '';
}

interface LoginCustomFieldMatcher {
  readonly kind?: LoginCustomTargetPlan['targets'][number]['hints'][number]['kind'];
  readonly values: readonly string[];
}

const LOGIN_CUSTOM_MATCH_PREFIXES = new Map<string, NonNullable<LoginCustomFieldMatcher['kind']>>([
  ['name', 'name'],
  ['id', 'id'],
  ['label', 'label'],
  ['placeholder', 'placeholder'],
]);

function parseLoginCustomFieldMatcher(name: string): LoginCustomFieldMatcher | undefined {
  const comparable = comparableLoginCustomHint(name);
  if (!comparable || comparable.startsWith('regex=')) return undefined;
  const separator = comparable.indexOf('=');
  if (separator > 0) {
    const prefix = comparable.slice(0, separator);
    const rawValue = comparable.slice(separator + 1);
    if (prefix === 'csv') {
      const values = [...new Set(rawValue.split(',').map((value) => value.trim()).filter(Boolean))];
      return values.length > 0 && values.length <= MAX_LOGIN_CUSTOM_TARGETS
        ? Object.freeze({ values: Object.freeze(values) })
        : undefined;
    }
    const kind = LOGIN_CUSTOM_MATCH_PREFIXES.get(prefix);
    if (kind && rawValue) return Object.freeze({ kind, values: Object.freeze([rawValue]) });
  }
  return Object.freeze({ values: Object.freeze([comparable]) });
}

function matchesLoginCustomTarget(
  matcher: LoginCustomFieldMatcher,
  hints: LoginCustomTargetPlan['targets'][number]['hints'],
): boolean {
  return hints.some((hint) => (
    (!matcher.kind || matcher.kind === hint.kind)
    && matcher.values.includes(comparableLoginCustomHint(hint.value))
  ));
}

function comparableLoginCustomHint(value: string): string {
  return value.trim().replace(/(?:\r\n|\r|\n)/g, '').normalize('NFKC').toLowerCase();
}

// Score map mirrors uri-match.ts MATCH_SCORE (lower = better match)
const AUTOFILL_MATCH_SCORES: Record<UriMatchStrategySetting, number> = {
  [UriMatchStrategy.Exact]: 0,
  [UriMatchStrategy.StartsWith]: 1,
  [UriMatchStrategy.Host]: 2,
  [UriMatchStrategy.Domain]: 3,
  [UriMatchStrategy.RegularExpression]: 4,
  [UriMatchStrategy.Never]: 99,
};

function bestMatch(
  loginUris: CipherSummary['loginUris'],
  frameUrl: string,
  defaultStrategy: UriMatchStrategySetting,
  equivalentIndex?: Map<string, number>,
): UriMatchResult | undefined {
  return loginUris
    .map((uri) => matchLoginUri(uri, frameUrl, defaultStrategy, equivalentIndex))
    .filter((match): match is UriMatchResult => Boolean(match))
    .sort(compareMatchResults)[0];
}

function validPersonalImportCipherReceipt(
  value: CipherResponse,
  request: CipherRequest,
): boolean {
  if (typeof value.id !== 'string'
    || value.id.length === 0
    || value.type !== request.type
    || value.organizationId != null) return false;

  const expectedHistory = request.passwordHistory;
  if (expectedHistory !== undefined && expectedHistory !== null) {
    if (!Array.isArray(value.passwordHistory)
      || value.passwordHistory.length !== expectedHistory.length) return false;
    for (let index = 0; index < expectedHistory.length; index += 1) {
      const expected = expectedHistory[index]!;
      const actual = value.passwordHistory[index];
      if (!actual) return false;
      if (actual.password !== expected.password
        || !sameOptionalPortableDate(actual.lastUsedDate, expected.lastUsedDate)) return false;
    }
  }

  const expectedPasswordRevisionDate = request.login?.passwordRevisionDate;
  if (typeof expectedPasswordRevisionDate === 'string'
    && !samePortableDate(value.login?.passwordRevisionDate, expectedPasswordRevisionDate)) {
    return false;
  }

  const expectedPasskeys = request.login?.fido2Credentials;
  if (expectedPasskeys !== undefined && expectedPasskeys !== null) {
    const actualPasskeys = value.login?.fido2Credentials;
    if (!Array.isArray(actualPasskeys) || actualPasskeys.length !== expectedPasskeys.length) {
      return false;
    }
    const requiredFields = [
      'credentialId', 'keyType', 'keyAlgorithm', 'keyCurve', 'keyValue', 'rpId',
      'counter', 'discoverable',
    ] as const;
    const optionalFields = [
      'userHandle', 'userName', 'rpName', 'userDisplayName',
    ] as const;
    for (let index = 0; index < expectedPasskeys.length; index += 1) {
      const expected = expectedPasskeys[index]!;
      const actual = actualPasskeys[index];
      if (!actual) return false;
      if (requiredFields.some((field) => actual[field] !== expected[field])
        || optionalFields.some((field) => !sameOptionalEncryptedValue(
          actual[field],
          expected[field],
        ))
        || typeof expected.creationDate !== 'string'
        || !samePortableDate(actual.creationDate, expected.creationDate)) return false;
    }
  }

  return typeof request.archivedDate !== 'string'
    || samePortableDate(value.archivedDate, request.archivedDate);
}

function requireShareAttachmentMetadata(
  value: unknown,
  original: readonly AttachmentData[] | null | undefined,
): readonly AttachmentData[] {
  const source = original ?? [];
  if (!Array.isArray(value) || value.length !== source.length) {
    if (source.length === 0 && (value === undefined || value === null)) return Object.freeze([]);
    throw new TypeError('Share attachment metadata does not match the source cipher');
  }
  const sourceIds = new Set<string>();
  for (const attachment of source) {
    if (typeof attachment?.id !== 'string' || !attachment.id || sourceIds.has(attachment.id)) {
      throw new TypeError('Source attachment metadata is invalid');
    }
    sourceIds.add(attachment.id);
  }

  const seen = new Set<string>();
  const attachments: AttachmentData[] = [];
  for (const entry of value) {
    if (!isPlainObject(entry) || !hasOnlyDataProperties(entry)) {
      throw new TypeError('Share attachment metadata is invalid');
    }
    const id = entry.id;
    const key = entry.key;
    const fileName = entry.fileName;
    if (typeof id !== 'string'
      || !sourceIds.has(id)
      || seen.has(id)
      || typeof key !== 'string'
      || key.length === 0
      || typeof fileName !== 'string'
      || fileName.length === 0) {
      throw new TypeError('Share attachment metadata is invalid');
    }
    seen.add(id);
    attachments.push(Object.freeze({
      id,
      key,
      fileName,
      ...(typeof entry.url === 'string' ? { url: entry.url } : {}),
      ...(typeof entry.size === 'string' ? { size: entry.size } : {}),
      ...(typeof entry.sizeName === 'string' ? { sizeName: entry.sizeName } : {}),
    }));
  }
  return Object.freeze(attachments);
}

async function validateKnownCipherEncryptedLeaves(
  cipher: SupportedCipherResponse,
  key: SymmetricKey,
): Promise<void> {
  await validateEncryptedLeaf(cipher.name, key, true);
  await validateEncryptedLeaf(cipher.notes, key);
  for (const field of cipher.fields ?? []) {
    await validateEncryptedLeaf(field.name, key);
    await validateEncryptedLeaf(field.value, key);
  }
  for (const history of cipher.passwordHistory ?? []) {
    await validateEncryptedLeaf(history.password, key, true);
  }
  for (const attachment of cipher.attachments ?? []) {
    await validateEncryptedLeaf(attachment.fileName, key, true);
  }

  if (cipher.type === 1) {
    const login = cipher.login!;
    for (const field of ['username', 'password', 'totp'] as const) {
      await validateEncryptedLeaf(login[field], key);
    }
    for (const uri of login.uris ?? []) {
      await validateEncryptedLeaf(uri.uri, key, true);
      await validateEncryptedLeaf(uri.uriChecksum, key);
    }
    const requiredPasskeyFields = [
      'credentialId', 'keyType', 'keyAlgorithm', 'keyCurve', 'keyValue', 'rpId',
      'counter', 'discoverable',
    ] as const;
    const optionalPasskeyFields = [
      'userHandle', 'userName', 'rpName', 'userDisplayName',
    ] as const;
    for (const credential of login.fido2Credentials ?? []) {
      for (const field of requiredPasskeyFields) {
        await validateEncryptedLeaf(credential[field], key, true);
      }
      for (const field of optionalPasskeyFields) {
        await validateEncryptedLeaf(credential[field], key);
      }
    }
    return;
  }

  if (cipher.type === 3) {
    const card = cipher.card as Record<string, string | null | undefined>;
    for (const field of CARD_FIELDS) await validateEncryptedLeaf(card[field], key);
    return;
  }
  if (cipher.type === 4) {
    const identity = cipher.identity as Record<string, string | null | undefined>;
    for (const field of IDENTITY_FIELDS) await validateEncryptedLeaf(identity[field], key);
    return;
  }
  if (cipher.type === 5) {
    await validateEncryptedLeaf(cipher.sshKey?.privateKey, key, true);
    await validateEncryptedLeaf(cipher.sshKey?.publicKey, key);
    await validateEncryptedLeaf(cipher.sshKey?.keyFingerprint, key);
  }
}

async function validateEncryptedLeaf(
  value: unknown,
  key: SymmetricKey,
  required = false,
): Promise<void> {
  if (value === undefined || value === null) {
    if (required) throw new TypeError('Required encrypted field is missing');
    return;
  }
  if (typeof value !== 'string' || value.length === 0) {
    throw new TypeError('Encrypted field is invalid');
  }
  const plaintext = await decryptToBytes(value, key);
  plaintext.fill(0);
}

function validSharedCipherReceipt(
  value: CipherResponse,
  cipherId: string,
  organizationId: string,
  request: CipherRequest,
  expectedAttachments: readonly AttachmentData[],
): boolean {
  return validSharedCipherContent(
    value,
    cipherId,
    organizationId,
    request,
    expectedAttachments,
  );
}

function validAuthoritativeSharedCipher(
  value: CipherResponse,
  cipherId: string,
  organizationId: string,
  collectionIds: readonly string[],
  request: CipherRequest,
  expectedAttachments: readonly AttachmentData[],
): boolean {
  return sameCollectionIds(value.collectionIds, collectionIds)
    && validSharedCipherContent(
      value,
      cipherId,
      organizationId,
      request,
      expectedAttachments,
  );
}

function validBulkShareReceipts(
  values: readonly CipherResponse[],
  prepared: readonly {
    readonly original: SupportedCipherResponse;
    readonly share: PreparedCipherShare;
  }[],
  organizationId: string,
): boolean {
  if (values.length > prepared.length) return false;
  const expected = new Map(prepared.map((entry) => [entry.original.id, entry]));
  const seen = new Set<string>();
  for (const value of values) {
    const entry = expected.get(value.id);
    if (!entry
        || seen.has(value.id)
        || value.organizationId !== organizationId
        || value.type !== entry.original.type) return false;
    seen.add(value.id);
  }
  return seen.size === values.length;
}

function validAuthoritativeBulkShare(
  values: readonly CipherResponse[],
  prepared: readonly {
    readonly original: SupportedCipherResponse;
    readonly share: PreparedCipherShare;
  }[],
  organizationId: string,
  collectionIds: readonly string[],
): boolean {
  const byId = new Map<string, CipherResponse[]>();
  for (const value of values) {
    const matches = byId.get(value.id);
    if (matches) matches.push(value);
    else byId.set(value.id, [value]);
  }
  return prepared.every((entry) => {
    const matches = byId.get(entry.original.id);
    return matches?.length === 1 && validDataOwnershipSharedCipher(
      matches[0]!,
      entry,
      organizationId,
      collectionIds,
    );
  });
}

function validDataOwnershipSharedCipher(
  value: CipherResponse,
  prepared: {
    readonly original: SupportedCipherResponse;
    readonly share: PreparedCipherShare;
  },
  organizationId: string,
  collectionIds: readonly string[],
): boolean {
  return sameCollectionIds(value.collectionIds, collectionIds)
    && sameOptionalPortableDate(value.deletedDate, prepared.original.deletedDate)
    && sameOptionalPortableDate(value.archivedDate, prepared.original.archivedDate)
    && validSharedCipherContent(
      value,
      prepared.original.id,
      organizationId,
      prepared.share.request,
      prepared.share.attachments,
      true,
    );
}

function validSharedCipherContent(
  value: CipherResponse,
  cipherId: string,
  organizationId: string,
  request: CipherRequest,
  expectedAttachments: readonly AttachmentData[],
  allowInactive = false,
): boolean {
  try {
    const compatibility = validateRawSyncCipherCompatibility(value);
    if (!compatibility.ok
      || value.id !== cipherId
      || value.type !== request.type
      || value.organizationId !== organizationId
      || (!allowInactive && isCipherInactive(value))) return false;

    const actualRecord = value as unknown as Record<string, unknown>;
    const requestRecord = request as unknown as Record<string, unknown>;
    if (!sameShareProjection(actualRecord.key, requestRecord.key, 'key')) return false;
    for (const field of [
      'name', 'notes', 'favorite', 'folderId', 'login', 'secureNote', 'card', 'identity',
      'sshKey', 'fields', 'passwordHistory', 'reprompt', 'archivedDate',
    ] as const) {
      if (!Object.prototype.hasOwnProperty.call(requestRecord, field)) continue;
      if (!sameShareProjection(actualRecord[field], requestRecord[field], field)) return false;
    }

    const actualAttachments = requireShareAttachmentMetadata(value.attachments, expectedAttachments);
    const expectedById = new Map(expectedAttachments.map((attachment) => [attachment.id, attachment]));
    return actualAttachments.every((attachment) => {
      const expected = expectedById.get(attachment.id);
      return Boolean(expected)
        && attachment.key === expected!.key
        && attachment.fileName === expected!.fileName
        && sameNullableScalar(attachment.size, expected!.size);
    });
  } catch {
    return false;
  }
}

function sameCollectionIds(
  actual: readonly string[] | null | undefined,
  expected: readonly string[],
): boolean {
  if (!Array.isArray(actual) || actual.length !== expected.length) return false;
  const actualSet = new Set(actual);
  return actualSet.size === actual.length && expected.every((id) => actualSet.has(id));
}

function sameShareProjection(actual: unknown, expected: unknown, field?: string): boolean {
  if (expected === null || expected === undefined) return actual === null || actual === undefined;
  if (typeof expected === 'string' && field?.endsWith('Date')) {
    return samePortableDate(actual, expected);
  }
  if (typeof expected !== 'object') return actual === expected;
  if (Array.isArray(expected)) {
    if (!Array.isArray(actual) || actual.length !== expected.length) return false;
    return expected.every((entry, index) => sameShareProjection(actual[index], entry));
  }
  if (!isPlainObject(expected) || !isPlainObject(actual)) return false;
  return Object.keys(expected).every((key) => (
    sameShareProjection(actual[key], expected[key], key)
  ));
}

function assertPasskeyCounterUpdateCommitted(
  response: SyncResponse,
  cipherId: string,
  expectedCredentials: readonly Fido2CredentialData[],
): void {
  const matchingCiphers = response.ciphers.filter((cipher) => cipher.id === cipherId);
  if (
    matchingCiphers.length !== 1
    || !sameShareProjection(
      matchingCiphers[0]!.login?.fido2Credentials,
      expectedCredentials,
    )
  ) {
    throw new AppError(
      'committed_unsynced',
      'The passkey signature counter update could not be verified.',
    );
  }
}

function assertPasskeyCreationCommitted(
  response: SyncResponse,
  cipherId: string,
  expectedCredential: Fido2CredentialData,
): void {
  const matchingCiphers = response.ciphers.filter((cipher) => cipher.id === cipherId);
  const actualCredentials = matchingCiphers[0]?.login?.fido2Credentials;
  if (
    matchingCiphers.length !== 1
    || !Array.isArray(actualCredentials)
    || actualCredentials.length !== 1
    || !sameCreatedPasskeyCredential(actualCredentials[0]!, expectedCredential)
  ) {
    throw new AppError(
      'committed_unsynced',
      'The created passkey could not be verified after synchronization.',
    );
  }
}

function sameCreatedPasskeyCredential(
  actual: Fido2CredentialData,
  expected: Fido2CredentialData,
): boolean {
  const requiredFields = [
    'credentialId', 'keyType', 'keyAlgorithm', 'keyCurve', 'keyValue', 'rpId',
    'counter', 'discoverable',
  ] as const;
  const optionalFields = [
    'userHandle', 'userName', 'rpName', 'userDisplayName',
  ] as const;
  return requiredFields.every((field) => actual[field] === expected[field])
    && optionalFields.every((field) => sameOptionalEncryptedValue(actual[field], expected[field]))
    && typeof expected.creationDate === 'string'
    && samePortableDate(actual.creationDate, expected.creationDate);
}

function sameNullableScalar(actual: unknown, expected: unknown): boolean {
  return expected === null || expected === undefined
    ? actual === null || actual === undefined
    : actual === expected;
}

function sameOptionalEncryptedValue(
  actual: string | null | undefined,
  expected: string | null | undefined,
): boolean {
  return typeof expected === 'string' ? actual === expected : actual == null;
}

function sameOptionalPortableDate(
  actual: string | null | undefined,
  expected: string | null | undefined,
): boolean {
  return typeof expected === 'string'
    ? samePortableDate(actual, expected)
    : actual == null;
}

function samePortableDate(actual: unknown, expected: string): boolean {
  return isIsoTimestamp(actual) && Date.parse(actual) === Date.parse(expected);
}

type PortableRemoteResult<T> =
  | { readonly status: 'committed'; readonly value: T }
  | { readonly status: 'rejected' };

async function commitPortableRemote<T>(
  operation: VaultOperationContext,
  journal: PortableVaultImportJournal,
  remote: VaultMutationRuntime['remote'],
  kind: 'folder' | 'item',
  sourceIndex: number,
  request: (accessToken: string) => Promise<T>,
  validReceipt: (value: T) => boolean,
): Promise<PortableRemoteResult<T>> {
  const marker = await journal.markInFlight(kind, sourceIndex);
  await assertPortableImportBoundary(operation, journal);

  let value: T;
  try {
    value = await remote(request);
  } catch (error) {
    const authorizationError = portableWriteAuthorizationError(error);
    if (authorizationError) {
      await journal.settleInFlight({
        operationId: marker.operationId,
        status: 'rejected',
        code: 'capability_blocked',
      });
      await assertPortableImportBoundary(operation, journal);
      throw error instanceof VaultNotCommittedError
        ? error
        : new VaultNotCommittedError(authorizationError);
    }
    const rejectedCode = portableRejectedCode(error);
    if (rejectedCode) {
      await journal.settleInFlight({
        operationId: marker.operationId,
        status: 'rejected',
        code: rejectedCode,
      });
      await assertPortableImportBoundary(operation, journal);
      return { status: 'rejected' };
    }
    await journal.settleInFlight({
      operationId: marker.operationId,
      status: 'outcome_unknown',
      code: isPortableConflict(error) ? 'remote_conflict' : 'remote_outcome_unknown',
    });
    throw new AppError('outcome_unknown', 'The import write may have reached the server.');
  }

  if (!validReceipt(value)) {
    await journal.settleInFlight({
      operationId: marker.operationId,
      status: 'outcome_unknown',
      code: 'invalid_commit_receipt',
    });
    throw new AppError('outcome_unknown', 'The import write returned an invalid commit receipt.');
  }
  await journal.settleInFlight({ operationId: marker.operationId, status: 'committed' });
  await assertPortableImportBoundary(operation, journal);
  return { status: 'committed', value };
}

function portableWriteAuthorizationError(
  error: unknown,
): SshWriteAuthorizationChangedError | CipherArchiveAuthorizationChangedError | undefined {
  if (error instanceof SshWriteAuthorizationChangedError
    || error instanceof CipherArchiveAuthorizationChangedError) return error;
  if (
    error instanceof VaultNotCommittedError
    && (error.original instanceof SshWriteAuthorizationChangedError
      || error.original instanceof CipherArchiveAuthorizationChangedError)
  ) return error.original;
  return undefined;
}

async function assertPortableImportBoundary(
  operation: VaultOperationContext,
  journal: PortableVaultImportJournal,
): Promise<void> {
  if (journal.signal.aborted) throw new AppError('error', 'Vault transfer was cancelled.');
  operation.assertCurrent();
  await journal.assertCurrent();
  operation.assertCurrent();
  if (journal.signal.aborted) throw new AppError('error', 'Vault transfer was cancelled.');
}

function portableRejectedCode(error: unknown): string | undefined {
  if (!(error instanceof VaultMutationCommitError) || error.status !== 'not_committed') return undefined;
  const original = error instanceof VaultNotCommittedError ? error.original : undefined;
  if (original instanceof ApiHttpError
    && original.status >= 400
    && original.status < 500
    && original.status !== 408) {
    return `remote_rejected_${original.status}`;
  }
  return 'remote_rejected';
}

function isPortableConflict(error: unknown): boolean {
  return (error instanceof VaultMutationCommitError && error.status === 'conflict')
    || isVaultConflictError(error);
}

function validatePortableImportInput(input: PortableVaultImportInput): void {
  if (!input
    || input.source?.status !== 'ok'
    || !isSupportedPortableImportCapabilities(input.capabilities)
    || input.source.inspection.canCommit !== true
    || input.source.inspection.ir?.scope !== 'personal'
    || input.source.attachmentCount !== 0
    || input.source.attachments.length !== 0
    || input.source.skippedAttachmentCount !== 0
    || !input.journal.signal
    || typeof input.journal.signal.aborted !== 'boolean'
    || typeof input.journal.assertCurrent !== 'function'
    || typeof input.journal.markInFlight !== 'function'
    || typeof input.journal.settleInFlight !== 'function'
    || typeof input.journal.recordSkipped !== 'function'
    || typeof input.journal.getAlias !== 'function') {
    throw new AppError('denied', 'The vault transfer input is not supported.');
  }
}

function isSupportedPortableImportCapabilities(
  capabilities: PersonalImportCapabilityPolicy,
): boolean {
  return sameImportCapabilities(capabilities, VAULT_SERVICE_IMPORT_CAPABILITIES)
    || sameImportCapabilities(capabilities, VAULT_SERVICE_ARCHIVE_IMPORT_CAPABILITIES)
    || sameImportCapabilities(capabilities, VAULT_SERVICE_SSH_IMPORT_CAPABILITIES)
    || sameImportCapabilities(capabilities, VAULT_SERVICE_SSH_ARCHIVE_IMPORT_CAPABILITIES);
}

function sameImportCapabilities(
  actual: PersonalImportCapabilityPolicy,
  expected: PersonalImportCapabilityPolicy,
): boolean {
  if (!actual || typeof actual !== 'object') return false;
  const actualTypes = actual?.supportedItemTypes;
  return Array.isArray(actualTypes)
    && actualTypes.length === expected.supportedItemTypes.length
    && actualTypes.every((type, index) => type === expected.supportedItemTypes[index])
    && actual.folders === expected.folders
    && actual.customFields === expected.customFields
    && actual.reprompt === expected.reprompt
    && actual.loginUriMatch === expected.loginUriMatch
    && actual.autofillOnPageLoad === expected.autofillOnPageLoad
    && actual.passwordHistory === expected.passwordHistory
    && actual.passkeys === expected.passkeys
    && actual.itemDates === expected.itemDates
    && actual.nonGenericSecureNotes === expected.nonGenericSecureNotes;
}

function validatePortableExportRequest(
  format: PortableVaultExportFormat,
  password: string | undefined,
  target: VaultTransferExportTarget = PERSONAL_VAULT_TRANSFER_EXPORT_TARGET,
): void {
  if (format !== 'json' && format !== 'encrypted-json' && format !== 'csv' && format !== 'zip') {
    throw new AppError('error', 'Unsupported vault export format.');
  }
  if (target.kind === 'organization' && format === 'zip') {
    throw new AppError('denied', 'ZIP export is not supported for organizations.');
  }
  if (format !== 'encrypted-json') {
    if (password !== undefined) throw new AppError('error', 'This export format does not use a password.');
    return;
  }
  if (password === undefined) return;
  if (typeof password !== 'string' || password.length > MAX_PORTABLE_EXPORT_PASSWORD_BYTES) {
    throw new AppError('error', 'A bounded export password is required.');
  }
  const bytes = new TextEncoder().encode(password);
  const valid = bytes.byteLength > 0 && bytes.byteLength <= MAX_PORTABLE_EXPORT_PASSWORD_BYTES;
  bytes.fill(0);
  if (!valid) throw new AppError('error', 'A bounded export password is required.');
}

function requirePortableExportTarget(value: unknown): VaultTransferExportTarget {
  try {
    return canonicalizeVaultTransferExportTarget(value);
  } catch {
    throw new AppError('denied', 'The vault export target is invalid.');
  }
}

function canonicalOrganizationIdOrUndefined(value: unknown): string | undefined {
  try {
    return canonicalizeVaultTransferOrganizationId(value);
  } catch {
    return undefined;
  }
}

const CSV_WARNING_CODE_MAP: Readonly<Record<string, VaultTransferExportWarningCode | undefined>> =
  Object.freeze({
    card_item_omitted: 'card_items_omitted',
    identity_item_omitted: 'identity_items_omitted',
    ssh_key_item_omitted: 'ssh_key_items_omitted',
    new_item_type_omitted: 'new_item_types_omitted',
    organization_item_omitted: 'other_items_omitted',
    trashed_item_omitted: 'other_items_omitted',
    attachments_omitted: 'attachments_omitted',
    passkeys_omitted: 'passkeys_omitted',
    password_history_omitted: 'password_history_omitted',
    custom_field_type_flattened: 'fields_flattened',
    custom_field_round_trip_ambiguous: 'fields_flattened',
    uri_match_rules_omitted: 'login_metadata_omitted',
    uri_list_round_trip_ambiguous: 'login_metadata_omitted',
    autofill_override_omitted: 'login_metadata_omitted',
    password_revision_date_omitted: 'login_metadata_omitted',
    organization_favorite_omitted: 'unknown_data_omitted',
    organization_folder_omitted: 'unknown_data_omitted',
    collection_external_id_omitted: 'unknown_data_omitted',
    collection_list_round_trip_ambiguous: 'unknown_data_omitted',
    duplicate_collection_name_ambiguous: 'unknown_data_omitted',
    unrepresented_collection_omitted: 'unknown_data_omitted',
    unknown_collection_data_omitted: 'unknown_data_omitted',
    secure_note_subtype_omitted: 'secure_note_metadata_omitted',
    unknown_transfer_data_omitted: 'unknown_data_omitted',
    unknown_folder_data_omitted: 'unknown_data_omitted',
    unknown_item_data_omitted: 'unknown_data_omitted',
    unknown_custom_field_data_omitted: 'unknown_data_omitted',
    unknown_secure_note_data_omitted: 'unknown_data_omitted',
    unknown_login_data_omitted: 'unknown_data_omitted',
    unknown_uri_data_omitted: 'unknown_data_omitted',
    folder_reference_omitted: 'unknown_data_omitted',
    diagnostics_truncated: 'diagnostics_omitted',
  });

function buildPortableCsvExportReview(
  encoded: EncodeVaultTransferCsvResult,
  attachmentCount: number,
): VaultTransferExportReview {
  const counts = new Map<VaultTransferExportWarningCode, number>();
  for (const diagnostic of encoded.diagnostics) {
    if (diagnostic.severity !== 'warning') continue;
    incrementCsvWarning(counts, csvWarningCode(diagnostic));
  }
  if (attachmentCount > 0) incrementCsvWarning(counts, 'attachments_omitted', attachmentCount);
  const warnings = VAULT_TRANSFER_EXPORT_WARNING_CODES.flatMap((code) => {
    const count = counts.get(code);
    return count === undefined ? [] : [Object.freeze({ code, count })];
  });
  return Object.freeze({
    exportedItemCount: encoded.exportedItemCount,
    omittedItemCount: encoded.omittedItemCount,
    warnings: Object.freeze(warnings),
  });
}

function csvWarningCode(
  diagnostic: VaultTransferCsvDiagnostic,
): VaultTransferExportWarningCode | undefined {
  return CSV_WARNING_CODE_MAP[diagnostic.code];
}

function incrementCsvWarning(
  counts: Map<VaultTransferExportWarningCode, number>,
  code: VaultTransferExportWarningCode | undefined,
  increment = 1,
): void {
  if (!code) return;
  const count = counts.get(code) ?? 0;
  counts.set(code, Math.min(Number.MAX_SAFE_INTEGER, count + increment));
}

function parsePortableAttachmentSize(value: string | null | undefined): number | undefined {
  if (value == null) return undefined;
  if (!/^\d+$/.test(value)) throw new AppError('denied', 'Attachment size is invalid.');
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 0) {
    throw new AppError('denied', 'Attachment size is invalid.');
  }
  return parsed;
}

function parseAttachmentInput(fileName: string, dataB64: string): Uint8Array {
  assertAttachmentFileName(fileName);
  if (typeof dataB64 !== 'string'
      || dataB64.length > 4 * Math.ceil(MAX_ATTACHMENT_PLAINTEXT_BYTES / 3)) {
    throw new AppError('error', 'Attachment exceeds this client\'s size limit.');
  }
  let data: Uint8Array;
  try {
    data = base64ToBytes(dataB64);
  } catch {
    throw new AppError('error', 'Attachment data is invalid.');
  }
  if (data.byteLength > MAX_ATTACHMENT_PLAINTEXT_BYTES || bytesToBase64(data) !== dataB64) {
    data.fill(0);
    throw new AppError('error', data.byteLength > MAX_ATTACHMENT_PLAINTEXT_BYTES
      ? 'Attachment exceeds this client\'s size limit.'
      : 'Attachment data is invalid.');
  }
  return data;
}

function assertAttachmentFileNameAvailable(
  attachments: readonly { readonly fileName: string }[] | undefined,
  fileName: string,
): void {
  if (attachments?.some((attachment) => attachment.fileName === fileName)) {
    throw new AppError('conflict', 'An attachment with this file name already exists.');
  }
}

function assertAttachmentFileName(fileName: string): void {
  if (typeof fileName !== 'string' || fileName.length === 0) {
    throw new AppError('error', 'Attachment file name is required.');
  }
  const fileNameBytes = new TextEncoder().encode(fileName);
  try {
    if (fileNameBytes.byteLength > MAX_ATTACHMENT_FILE_NAME_BYTES
        || Array.from(fileName).some((character) => {
          const codePoint = character.codePointAt(0) ?? 0;
          return codePoint < 32 || codePoint === 127;
        })) {
      throw new AppError('error', 'Attachment file name is invalid.');
    }
  } finally {
    fileNameBytes.fill(0);
  }
}

function assertAttachmentUploadCommitted(
  response: SyncResponse,
  cipherId: string,
  attachmentId: string,
  expectedKey: string,
  expectedFileName: string,
  expectedSize: number,
): void {
  const ciphers = response.ciphers.filter((cipher) => cipher.id === cipherId);
  if (ciphers.length !== 1) {
    throw new AppError('committed_unsynced', 'The uploaded attachment could not be verified.');
  }
  const attachments = ciphers[0]!.attachments?.filter(
    (attachment) => attachment.id === attachmentId,
  ) ?? [];
  if (attachments.length !== 1
      || attachments[0]!.key !== expectedKey
      || attachments[0]!.fileName !== expectedFileName
      || attachments[0]!.size !== String(expectedSize)) {
    throw new AppError('committed_unsynced', 'The uploaded attachment metadata could not be verified.');
  }
}

function assertAttachmentUploadRolledBack(response: SyncResponse, attachmentId: string): void {
  if (response.ciphers.some((cipher) => (
    cipher.attachments?.some((attachment) => attachment.id === attachmentId) === true
  ))) {
    throw new AppError('committed_unsynced', 'The rolled-back attachment slot is still present.');
  }
}

function attachmentUploadFailure(error: unknown): Error {
  if (error instanceof VaultNotCommittedError) {
    return error.original instanceof Error
      ? error.original
      : new AppError('error', String(error.original));
  }
  if (error instanceof VaultMutationCommitError) {
    return error.status === 'conflict'
      ? new AppError('conflict', 'The vault changed on the server. Sync before retrying.')
      : new AppError('error', error.message);
  }
  return error instanceof Error ? error : new AppError('error', String(error));
}

function portableAttachmentPath(attachment: VaultTransferExportAttachment): string {
  const withoutControls = Array.from(attachment.fileName.normalize('NFKC'), (character) => {
    const codePoint = character.codePointAt(0) ?? 0;
    return codePoint < 32 || codePoint === 127 ? '_' : character;
  }).join('');
  const normalized = withoutControls
    .replace(/[\\/:*?"<>|]/g, '_')
    .replace(/^\.+|\.+$/g, '_')
    .slice(0, MAX_ARCHIVE_FILE_NAME_CHARS);
  const fileName = normalized || 'attachment.bin';
  return `attachments/item-${attachment.itemSourceIndex}/attachment-${attachment.sourceIndex}-${fileName}`;
}

function optionalText(value: string | null | undefined): string | undefined {
  return value == null ? undefined : value;
}

function optionalBoundedPasskeyText(
  value: string | undefined,
  maximumBytes: number,
  field: string,
): string | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== 'string' || value.length === 0 || value.includes('\0')) {
    throw new AppError('denied', `Invalid passkey ${field}`);
  }
  const bytes = new TextEncoder().encode(value);
  const valid = bytes.byteLength <= maximumBytes;
  bytes.fill(0);
  if (!valid) throw new AppError('denied', `Invalid passkey ${field}`);
  return value;
}

function passkeySelectionMatches(
  credential: Pick<DecryptedFido2Credential, 'credentialId' | 'discoverable'>,
  selection: PasskeyCredentialSelection,
): boolean {
  return selection.mode === 'resident'
    ? credential.discoverable
    : selection.credentialIds.includes(credential.credentialId);
}

function hasNoStoredPasskey(cipher: CipherResponse): boolean {
  const credentials = cipher.login?.fido2Credentials;
  return credentials == null || (Array.isArray(credentials) && credentials.length === 0);
}

function parsePasskeyCounter(value: string): number {
  if (!/^(?:0|[1-9]\d{0,9})$/u.test(value)) throw invalidPasskeyCounter();
  const counter = Number(value);
  if (!isUint32(counter)) throw invalidPasskeyCounter();
  return counter;
}

function isUint32(value: number): boolean {
  return Number.isSafeInteger(value) && value >= 0 && value <= MAX_FIDO2_SIGNATURE_COUNTER;
}

function invalidPasskeyCounter(): AppError {
  return new AppError('denied', 'Passkey signature counter is invalid.');
}

function duplicatePasskeyError(): AppError {
  return new AppError(
    'conflict',
    'An excluded passkey already exists for this relying party',
  );
}

function requirePasskeyCredentialId(value: unknown): string {
  try {
    if (typeof value !== 'string') throw new TypeError('Invalid passkey credential ID');
    const selection = normalizePasskeyCredentialSelection([value]);
    if (selection.mode !== 'allow-list' || selection.credentialIds.length !== 1) {
      throw new TypeError('Invalid passkey credential ID');
    }
    return selection.credentialIds[0]!;
  } catch {
    throw unavailablePasskeyCredential();
  }
}

function unavailablePasskeyCredential(): AppError {
  return new AppError('denied', 'Passkey credential is unavailable.');
}

function destroySymmetricKey(key: SymmetricKey | undefined): void {
  key?.encKey.fill(0);
  key?.macKey.fill(0);
}

function matchScore(matchType: UriMatchStrategySetting): number {
  return AUTOFILL_MATCH_SCORES[matchType] ?? 99;
}

function normalizeLoginUsername(value: string | undefined): string | undefined {
  const normalized = value?.trim().toLowerCase();
  return normalized || undefined;
}

function sameCapturedLoginDecision(
  current: SaveLoginPrompt,
  expected: CapturedLoginCommitDecision,
): current is CapturedLoginCommitDecision {
  if (current.action === 'none' || current.action !== expected.action) return false;
  if (current.action === 'save') {
    return expected.action === 'save' && current.suggestedName === expected.suggestedName;
  }
  return expected.action === current.action
    && current.cipherId === expected.cipherId
    && current.name === expected.name;
}

/** Exact code-unit comparison without password normalization or an early mismatch exit. */
function equalSecretText(left: string | undefined, right: string): boolean {
  if (typeof left !== 'string') return false;
  let difference = left.length ^ right.length;
  const length = Math.max(left.length, right.length);
  for (let index = 0; index < length; index += 1) {
    difference |= (left.charCodeAt(index) || 0) ^ (right.charCodeAt(index) || 0);
  }
  return difference === 0;
}

function canonicalManualAutofillUrl(value: string): string {
  if (typeof value !== 'string' || value.length === 0 || value.length > 16_384) {
    throw new AppError('denied', 'Manual autofill target URL is invalid.');
  }
  try {
    const url = new URL(value);
    if ((url.protocol !== 'http:' && url.protocol !== 'https:') || url.username || url.password) {
      throw new Error('unsupported URL');
    }
    return url.href;
  } catch {
    throw new AppError('denied', 'Manual autofill target URL is invalid.');
  }
}

async function digestEncryptedLoginUris(cipher: CipherResponse): Promise<string> {
  const login = cipher.login;
  const uriField = login && Object.hasOwn(login, 'uri')
    ? ['present', login.uri ?? null]
    : ['absent'];
  const urisField = login && Object.hasOwn(login, 'uris')
    ? login.uris === null
      ? ['present', null]
      : ['present', (login.uris ?? []).map((uri) => [
          Object.hasOwn(uri, 'uri') ? ['present', uri.uri ?? null] : ['absent'],
          Object.hasOwn(uri, 'uriChecksum') ? ['present', uri.uriChecksum ?? null] : ['absent'],
          Object.hasOwn(uri, 'match') ? ['present', uri.match ?? null] : ['absent'],
        ])]
    : ['absent'];
  const encoded = utf8ToBytes(JSON.stringify([
    login === undefined ? 'login_absent' : login === null ? 'login_null' : 'login_present',
    uriField,
    urisField,
  ]));
  let digest: Uint8Array | undefined;
  try {
    digest = new Uint8Array(await globalThis.crypto.subtle.digest('SHA-256', encoded as BufferSource));
    return bytesToHex(digest);
  } finally {
    encoded.fill(0);
    digest?.fill(0);
  }
}

function manualAutofillRisk(
  uris: readonly { readonly uri: string; readonly match?: number | null }[],
  targetUrl: string,
  defaultStrategy: UriMatchStrategySetting,
  equivalentIndex: Map<string, number>,
): ManualAutofillRisk {
  const targetHost = getHostAndPort(targetUrl)?.host;
  if (targetHost && uris.some((uri) => (
    uri.match === UriMatchStrategy.Never && getHostAndPort(uri.uri)?.host === targetHost
  ))) return 'never';

  const target = new URL(targetUrl);
  if (target.protocol === 'http:') {
    target.protocol = 'https:';
    if (uris.some((uri) => {
      try {
        return new URL(uri.uri).protocol === 'https:'
          && matchLoginUri(uri, target.href, defaultStrategy, equivalentIndex) !== undefined;
      } catch {
        return false;
      }
    })) return 'https_downgrade';
  }
  return 'no_match';
}

function revisionAdvanced(previous: string, current: string | null | undefined): boolean {
  const previousTicks = revisionInstantTicks(previous);
  const currentTicks = revisionInstantTicks(current);
  return previousTicks !== undefined && currentTicks !== undefined && currentTicks > previousTicks;
}

function revisionInstantTicks(value: unknown): bigint | undefined {
  if (!isIsoTimestamp(value)) return undefined;
  const fraction = /\.(\d{1,7})(?:Z|[+-]\d{2}:\d{2})$/.exec(value)?.[1] ?? '';
  const milliseconds = Date.parse(value);
  if (!Number.isFinite(milliseconds)) return undefined;
  const subMillisecondTicks = BigInt(fraction.padEnd(7, '0').slice(3) || '0');
  return BigInt(milliseconds) * 10_000n + subMillisecondTicks;
}

function sameKnownCipherWritablePreimage(
  before: CipherResponse,
  after: CipherResponse,
): boolean {
  const topLevelKeys = [
    'type', 'name', 'notes', 'favorite', 'folderId', 'organizationId', 'key',
    'card', 'identity', 'sshKey', 'fields', 'passwordHistory', 'reprompt', 'archivedDate',
  ] as const;
  const loginKeys = [
    'uri', 'username', 'password', 'totp', 'fido2Credentials',
    'autofillOnPageLoad', 'passwordRevisionDate',
  ] as const;
  return JSON.stringify(topLevelKeys.map((key) => propertySnapshot(before, key)))
      === JSON.stringify(topLevelKeys.map((key) => propertySnapshot(after, key)))
    && JSON.stringify(loginKeys.map((key) => propertySnapshot(before.login, key)))
      === JSON.stringify(loginKeys.map((key) => propertySnapshot(after.login, key)));
}

function sameLoginUriPrefix(
  before: CipherResponse['login'] extends infer _Login ? NonNullable<CipherResponse['login']>['uris'] : never,
  after: CipherResponse['login'] extends infer _Login ? NonNullable<CipherResponse['login']>['uris'] : never,
): boolean {
  const original = before ?? [];
  const current = after ?? [];
  return current.length === original.length + 1
    && original.every((uri, index) => JSON.stringify(uri) === JSON.stringify(current[index]));
}

function propertySnapshot(value: unknown, key: string): readonly [boolean, unknown] {
  if (typeof value !== 'object' || value === null || !Object.hasOwn(value, key)) {
    return [false, null] as const;
  }
  return [true, (value as Record<string, unknown>)[key]] as const;
}

function canonicalHttpOrigin(value: string): string | undefined {
  try {
    const url = new URL(value);
    if ((url.protocol !== 'http:' && url.protocol !== 'https:') || url.username || url.password) return undefined;
    return url.origin;
  } catch {
    return undefined;
  }
}

function httpAuthUriMatchesOrigin(
  uri: { readonly uri: string; readonly match?: number | null },
  origin: string,
): boolean {
  return uri.match !== UriMatchStrategy.Never && canonicalHttpOrigin(uri.uri) === origin;
}

function hasCanonicalOriginUri(
  uris: readonly { readonly uri: string; readonly match?: number | null }[],
  origin: string,
): boolean {
  return uris.some(({ uri }) => {
    try {
      const parsed = new URL(uri);
      return canonicalHttpOrigin(uri) === origin
        && parsed.pathname === '/'
        && parsed.search === ''
        && parsed.hash === '';
    } catch {
      return false;
    }
  });
}

function hasNeverRuleForOrigin(
  uris: readonly { readonly uri: string; readonly match?: number | null }[],
  origin: string,
): boolean {
  return uris.some((uri) => (
    uri.match === UriMatchStrategy.Never && canonicalHttpOrigin(uri.uri) === origin
  ));
}

/** The hostname of a URL (for a default cipher name), falling back to the raw string. */
function hostnameOf(url: string): string {
  try {
    return new URL(url).hostname || url;
  } catch {
    return url;
  }
}

/** The origin of a URL (the saved login's URI), or undefined when it cannot be parsed. */
function originOf(url: string): string | undefined {
  try {
    return new URL(url).origin;
  } catch {
    return undefined;
  }
}

function isNonBlank(value: string | null | undefined): boolean {
  return typeof value === 'string' && value.trim().length > 0;
}

function accountKeyFor(lease: Pick<AccountLease, 'serverUrl' | 'accountIdentity'>): string {
  return `${lease.serverUrl}\n${lease.accountIdentity}`;
}

function emptyListing(): VaultListing {
  return {
    items: [],
    folders: [],
    collections: [],
    orgPermissions: [],
    personalCreationAllowed: false,
  };
}

function isObsoleteCacheError(error: unknown): boolean {
  return error instanceof Error && /cache changed|raw cache write|rebuilding derived/i.test(error.message);
}

function securityStampRevocationFrom(
  error: unknown,
): SecurityStampMismatchError | SecurityStampStateUnavailableError | undefined {
  if (error instanceof SecurityStampMismatchError
    || error instanceof SecurityStampStateUnavailableError) return error;
  if (error instanceof VaultNotCommittedError
    && (error.original instanceof SecurityStampMismatchError
      || error.original instanceof SecurityStampStateUnavailableError)) return error.original;
  return undefined;
}

function classifyRemoteMutationError(error: unknown): unknown {
  if (error instanceof VaultMutationCommitError) return error;
  if (isVaultConflictError(error)) {
    return new VaultMutationCommitError('conflict', 'The remote vault revision changed');
  }
  if (
    error instanceof ApiHttpError
    && error.status >= 400
    && error.status < 500
    && error.status !== 408
  ) {
    return new VaultMutationCommitError(
      'not_committed',
      typeof error.body === 'string' ? error.body : error.message,
    );
  }
  return error;
}
