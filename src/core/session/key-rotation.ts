import { symmetricKeyFromBytes, type SymmetricKey } from '../crypto/keys.js';
import { deriveMasterKey, deriveMasterPasswordHash, stretchMasterKey } from '../crypto/kdf.js';
import { encryptToBytes } from '../crypto/encstring.js';
import { rsaOaepEncrypt } from '../crypto/primitives.js';
import { base64ToBytes, bytesToBase64 } from '../crypto/encoding.js';
import { decryptCipher } from '../vault/decrypt.js';
import { rotateCipher, rotateFolder, rotateSend } from '../vault/rotate.js';
import type { RotateKeyData, RotateOrgRecoveryData } from '../api/types.js';
import { AppError } from '../errors.js';

export interface KeyRotationDeps {
  api: {
    sync(token: string): Promise<any>;
    getTrustedEmergencyAccess(token: string): Promise<Array<{ id: string }>>;
    getOrganizationPublicKey(token: string, orgId: string): Promise<{ publicKey: string }>;
    getAccountPublicKey(token: string): Promise<{ publicKey: string }>;
    rotateAccountKey(token: string, body: RotateKeyData): Promise<void>;
  };
  session: {
    getPersistedAuth(): Promise<{ email: string; accessToken: string; kdfIterations: number; encPrivateKey?: string } | undefined>;
    loadUserKey(): Promise<SymmetricKey | undefined>;
    loadPrivateKey(): Promise<Uint8Array | undefined>;
    logout(): Promise<void>;
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

  // Fail-close: emergency-access grants can't be re-wrapped in this milestone.
  if ((await deps.api.getTrustedEmergencyAccess(token)).length > 0) {
    throw new AppError('error', 'Remove your emergency-access contacts before rotating your encryption key.');
  }

  const sync = await deps.api.sync(token); // authoritative full current vault
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
  const masterKey = await deriveMasterKey(masterPassword, auth.email, auth.kdfIterations);
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

  // Strict pre-POST self-verify: every re-encrypted personal cipher must decrypt with the NEW UserKey.
  for (let i = 0; i < ciphers.length; i++) {
    const check = await decryptCipher(ciphers[i] as never, newUserKey);
    if (!check || check.name === undefined || check.name === '(error)') throw new AppError('error', 'Rotation self-check failed; aborting.');
  }

  const body: RotateKeyData = {
    oldMasterKeyAuthenticationHash: masterHash,
    accountUnlockData: {
      masterPasswordUnlockData: { kdfType: 0, kdfIterations: auth.kdfIterations, kdfParallelism: null, kdfMemory: null, email: auth.email, masterKeyAuthenticationHash: masterHash, masterKeyEncryptedUserKey },
      emergencyAccessUnlockData: [],
      organizationAccountRecoveryUnlockData: orgRecovery,
    },
    accountKeys: { userKeyEncryptedAccountPrivateKey, accountPublicKey },
    accountData: { ciphers, folders, sends },
  };

  await deps.api.rotateAccountKey(token, body); // atomic; throws on non-2xx (local material unchanged, retryable)
  await deps.session.logout(); // security stamp rotated → old tokens dead; re-login refetches new material
}
