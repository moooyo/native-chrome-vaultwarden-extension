// Seeds a disposable test Vaultwarden (configure MIYU_SERVER / MIYU_EMAIL / MIYU_PASSWORD) with items
// that match the autofill test page (test-page/, served on http://localhost:8770). Idempotent: skips
// any item whose name already exists, so re-running never duplicates. Reuses the extension's own core,
// so it exercises the real crypto/API path — the same one test/live/crud.live.test.ts uses.
//
// Not runnable by plain `node` (core is TS with .js-extension imports); bundled + run via esbuild by
// `npm run seed:testvault`. After it finishes, click Sync in the popup to pull the items.
import { ApiClient } from '../src/core/api/client.js';
import { deriveMasterKey, deriveMasterPasswordHash, stretchMasterKey } from '../src/core/crypto/kdf.js';
import { unwrapSymmetricKey, type SymmetricKey } from '../src/core/crypto/keys.js';
import { encryptToText } from '../src/core/crypto/encstring.js';
import { bytesToBase64Url } from '../src/core/crypto/encoding.js';
import { encryptCipher } from '../src/core/vault/encrypt.js';
import { decryptCipher } from '../src/core/vault/decrypt.js';
import { generateFido2Keypair, encryptFido2Credential } from '../src/core/vault/fido2-create.js';
import type { CipherInput } from '../src/core/vault/models.js';
import type { CipherRequest } from '../src/core/api/types.js';
import type { KeyValueStore } from '../src/platform/store.js';

const SERVER = process.env.MIYU_SERVER || 'http://localhost:8080';
const EMAIL = process.env.MIYU_EMAIL || 'test@example.com';
const PASSWORD = process.env.MIYU_PASSWORD || '';

// URIs the test page is served from, so the localhost login is URI-matched there.
const LOCAL_URIS = [{ uri: 'localhost' }, { uri: 'http://localhost:8770' }];

// Marker prefix makes the seed items easy to spot and lets re-runs skip existing ones.
const SEEDS: CipherInput[] = [
  {
    type: 1,
    name: 'MiYu-Test: Localhost Login',
    login: {
      username: 'test-user@localhost',
      password: 'Localhost-Fill-1!',
      // Base32 TOTP secret so the standalone 2FA panel shows a live code on the test page.
      totp: 'JBSWY3DPEHPK3PXP',
      uris: LOCAL_URIS,
    },
  },
  {
    type: 3,
    name: 'MiYu-Test: Localhost Card',
    card: {
      cardholderName: 'MiYu Test',
      brand: 'Visa',
      number: '4111111111111111',
      expMonth: '08',
      expYear: '2030',
      code: '123',
    },
  },
  {
    type: 4,
    name: 'MiYu-Test: Localhost Identity',
    identity: {
      title: 'Mr',
      firstName: 'Test',
      middleName: 'Q',
      lastName: 'User',
      email: 'test-user@localhost',
      phone: '+1 555 0100',
      company: 'MiYu QA',
      address1: '1 Test Street',
      address2: 'Suite 200',
      city: 'Testville',
      state: 'CA',
      postalCode: '94016',
      country: 'United States',
    },
  },
];

// Two localhost logins that each carry a stored passkey, so the passkey get() flow on the test page
// has MORE THAN ONE match and shows the account picker. rpId is 'localhost' (the test page's host).
const PASSKEY_ACCOUNTS = [
  { name: 'MiYu-Test: Passkey Work', username: 'work@localhost' },
  { name: 'MiYu-Test: Passkey Personal', username: 'me@localhost' },
];
const RP_ID = 'localhost';

/** Build a login write request carrying a freshly generated (signable ES256) passkey for RP_ID. */
async function passkeyLoginRequest(name: string, username: string, userKey: SymmetricKey): Promise<CipherRequest> {
  const kp = await generateFido2Keypair();
  const cred = await encryptFido2Credential({
    credentialId: bytesToBase64Url(kp.credentialId),
    keyValue: bytesToBase64Url(kp.pkcs8), // PKCS#8 private key, encrypted under the user key
    rpId: RP_ID,
    counter: 0,
    userName: username,
  }, userKey);
  return {
    type: 1,
    name: await encryptToText(name, userKey),
    favorite: false,
    folderId: null,
    reprompt: 0,
    login: {
      username: await encryptToText(username, userKey),
      fido2Credentials: [cred],
      uris: [
        { uri: await encryptToText('localhost', userKey), match: null },
        { uri: await encryptToText('http://localhost:8770', userKey), match: null },
      ],
    },
  };
}

function memStore(): KeyValueStore {
  const m = new Map<string, unknown>();
  return {
    get: async <T>(k: string) => m.get(k) as T | undefined,
    set: async (k: string, v: unknown) => { m.set(k, v); },
    remove: async (k: string) => { m.delete(k); },
  } as KeyValueStore;
}

async function main(): Promise<void> {
  const api = new ApiClient({ serverUrlProvider: async () => SERVER, fetchFn: fetch, localStore: memStore() });

  console.log(`Server: ${SERVER}\nAccount: ${EMAIL}`);
  const pre = await api.prelogin(EMAIL);
  if (pre.kdf !== 0) {
    throw new Error(`Account KDF is ${pre.kdf} (Argon2id) — the client only supports PBKDF2 (see CLAUDE.md). Cannot seed.`);
  }
  const masterKey = await deriveMasterKey(PASSWORD, EMAIL, pre.kdfIterations);
  const hash = await deriveMasterPasswordHash(masterKey, PASSWORD);
  const login = await api.passwordLogin({ email: EMAIL, masterPasswordHash: hash });
  if (login.kind !== 'success') {
    throw new Error(`Login failed: ${login.kind}`);
  }
  const token = login.data.access_token;
  const userKey = await unwrapSymmetricKey(login.data.Key, await stretchMasterKey(masterKey));
  console.log('Logged in.');

  // Idempotency: pull existing ciphers and collect their (decrypted) names.
  const sync = await api.sync(token);
  const existing = new Set(
    (await Promise.all(sync.ciphers.map((c) => decryptCipher(c, userKey))))
      .map((d) => d?.name)
      .filter((n): n is string => Boolean(n)),
  );

  let created = 0;
  let skipped = 0;
  for (const seed of SEEDS) {
    if (existing.has(seed.name)) {
      console.log(`  skip  ${seed.name} (already present)`);
      skipped += 1;
      continue;
    }
    await api.createCipher(token, await encryptCipher(seed, userKey));
    console.log(`  add   ${seed.name}`);
    created += 1;
  }

  // Two passkey-bearing logins so the get() account picker has more than one candidate on localhost.
  for (const acct of PASSKEY_ACCOUNTS) {
    if (existing.has(acct.name)) {
      console.log(`  skip  ${acct.name} (already present)`);
      skipped += 1;
      continue;
    }
    await api.createCipher(token, await passkeyLoginRequest(acct.name, acct.username, userKey));
    console.log(`  add   ${acct.name} (passkey)`);
    created += 1;
  }

  console.log(`\nDone: ${created} created, ${skipped} skipped. Open the popup and click Sync to pull them.`);
}

main().catch((error) => {
  console.error('Seed failed:', error instanceof Error ? error.message : error);
  process.exit(1);
});
