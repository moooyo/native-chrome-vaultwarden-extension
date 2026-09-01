import { symmetricKeyFromBytes, type SymmetricKey } from '../crypto/keys.js';
import { deriveMasterKey, deriveMasterPasswordHash, stretchMasterKey, type KdfConfig } from '../crypto/kdf.js';
import { encryptToBytes } from '../crypto/encstring.js';
import { rsaOaepEncrypt } from '../crypto/primitives.js';
import { base64ToBytes, bytesToBase64 } from '../crypto/encoding.js';
import { rotateCipher, rotateFolder, rotateSend, verifyRotatedCipher, type RotatedCipher } from '../vault/rotate.js';
import type {
  KeyRotationUnlockRecordsStatus,
  RotateKeyData,
  RotateOrgRecoveryData,
  SyncResponse,
} from '../api/types.js';
import { AppError } from '../errors.js';

export interface KeyRotationDeps {
  api: {
    sync(token: string): Promise<SyncResponse & { sends?: unknown[] }>;
    getTrustedEmergencyAccess(token: string): Promise<Array<{ id: string }>>;
    getOrganizationPublicKey(token: string, orgId: string): Promise<{ publicKey: string }>;
    getAccountPublicKey(token: string): Promise<{ publicKey: string }>;
    getKeyRotationUnlockRecordsStatus(token: string): Promise<KeyRotationUnlockRecordsStatus>;
    rotateAccountKey(token: string, body: RotateKeyData): Promise<void>;
  };
  session: {
    getPersistedAuth(): Promise<({ email: string; accessToken: string; encPrivateKey?: string } & KdfConfig) | undefined>;
    loadUserKey(): Promise<SymmetricKey | undefined>;
    loadPrivateKey(): Promise<Uint8Array | undefined>;
  };
  verifyMasterPassword(masterPassword: string): Promise<boolean>;
}

/** Rotate the account UserKey: fresh sync, re-encrypt everything, atomic POST, then log out. Fails closed. */
export async function rotateAccountKey(masterPassword: string, deps: KeyRotationDeps): Promise<void> {
  const auth = await deps.session.getPersistedAuth();
  if (!auth) throw new AppError('error', 'Not logged in');
  const oldUserKey = await deps.session.loadUserKey();
  if (!oldUserKey) throw new AppError('locked', 'Vault is locked');
  if (!(await deps.verifyMasterPassword(masterPassword))) throw new AppError('error', 'Master password is incorrect');
  const token = auth.accessToken;

  // The first remote preflight is an authoritative full sync taken inside the account barrier.
  const sync = await deps.api.sync(token);
  if (sync.profile.email.trim().toLowerCase() !== auth.email.trim().toLowerCase()) {
    throw new AppError('session_expired', 'The synchronized vault belongs to a different account.');
  }

  // Fail-close: emergency-access grants can't be re-wrapped in this milestone.
  if ((await deps.api.getTrustedEmergencyAccess(token)).length > 0) {
    throw new AppError('error', 'Remove your emergency-access contacts before rotating your encryption key.');
  }
  const newUserKeyBytes = globalThis.crypto.getRandomValues(new Uint8Array(64));
  const newUserKey = symmetricKeyFromBytes(newUserKeyBytes);

  // Re-encrypt personal items (organizationId==null), including trashed. Fail-close on any undecryptable.
  const personal = (sync.ciphers as Array<{ organizationId?: string | null }>).filter((c) => !c.organizationId);
  const ciphers = [] as unknown[];
  for (const c of personal) ciphers.push(await rotateCipher(c as never, oldUserKey, newUserKey));
  const folders = [] as unknown[];
  for (const f of (sync.folders ?? [])) folders.push(await rotateFolder(f as never, oldUserKey, newUserKey));
  const sends = [] as unknown[];
  for (const s of (sync.sends ?? [])) sends.push(await rotateSend(s as never, oldUserKey, newUserKey));

  // Wrap the new UserKey under the current (stretched) master key; re-wrap the private key under the new UserKey.
  const masterKey = await deriveMasterKey(masterPassword, auth.email, auth);
  const masterHash = await deriveMasterPasswordHash(masterKey, masterPassword);
  const masterKeyEncryptedUserKey = await encryptToBytes(newUserKeyBytes, await stretchMasterKey(masterKey));
  const pkcs8 = await deps.session.loadPrivateKey();
  if (!pkcs8) throw new AppError('error', 'Account private key unavailable');
  const userKeyEncryptedAccountPrivateKey = await encryptToBytes(pkcs8, newUserKey);
  const accountPublicKey = (await deps.api.getAccountPublicKey(token)).publicKey;

  // Org account-recovery re-enrollment for enrolled orgs.
  const orgRecovery: RotateOrgRecoveryData[] = [];
  for (const org of (sync.profile?.organizations ?? []) as Array<{ id: string; resetPasswordEnrolled?: boolean | null }>) {
    if (!org.resetPasswordEnrolled) continue;
    const pub = base64ToBytes((await deps.api.getOrganizationPublicKey(token, org.id)).publicKey);
    orgRecovery.push({ organizationId: org.id, resetPasswordKey: `4.${bytesToBase64(await rsaOaepEncrypt(pub, newUserKeyBytes))}` });
  }

  // Strict pre-POST self-verify: every re-encrypted personal cipher must be fully decryptable with
  // the NEW UserKey (keyed: item key + every attachment key under it; keyless: every EncString leaf,
  // including passwordHistory/attachment-keys/sshKey that a plain decryptCipher check would miss).
  try {
    for (const c of ciphers) await verifyRotatedCipher(c as RotatedCipher, newUserKey);
  } catch {
    throw new AppError('error', 'Rotation self-check failed; aborting.');
  }

  // These key sets can unlock the existing UserKey and therefore must be re-wrapped atomically with
  // rotation. Until that implementation exists, only strict, authoritative empty inventories are
  // safe. A malformed, unsupported, or failed inventory request rejects before the terminal POST.
  const unlockRecords = await deps.api.getKeyRotationUnlockRecordsStatus(token);
  if (unlockRecords.passkeyUnlockData !== 'empty') {
    throw new AppError(
      'error',
      'Remove every passkey used for account login before rotating your encryption key.',
    );
  }
  if (unlockRecords.deviceKeyUnlockData !== 'empty') {
    throw new AppError(
      'error',
      'Remove trust from every trusted device before rotating your encryption key.',
    );
  }

  const body: RotateKeyData = {
    oldMasterKeyAuthenticationHash: masterHash,
    accountUnlockData: {
      masterPasswordUnlockData: {
        kdfType: auth.kdf,
        kdfIterations: auth.kdfIterations,
        kdfParallelism: auth.kdf === 1 ? auth.kdfParallelism : null,
        kdfMemory: auth.kdf === 1 ? auth.kdfMemory : null,
        email: auth.email,
        masterKeyAuthenticationHash: masterHash,
        masterKeyEncryptedUserKey,
      },
      emergencyAccessUnlockData: [],
      organizationAccountRecoveryUnlockData: orgRecovery,
      passkeyUnlockData: [],
      deviceKeyUnlockData: [],
    },
    accountKeys: { userKeyEncryptedAccountPrivateKey, accountPublicKey },
    accountData: { ciphers, folders, sends },
  };

  // The caller owns the durable marker and unconditional local cleanup around this irreversible POST.
  await deps.api.rotateAccountKey(token, body);
}
