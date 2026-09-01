import { ApiClient } from '../../src/core/api/client.js';
import { deriveMasterKey, stretchMasterKey } from '../../src/core/crypto/kdf.js';
import { unwrapSymmetricKey } from '../../src/core/crypto/keys.js';
import { encryptCipher } from '../../src/core/vault/encrypt.js';
import type { KeyValueStore } from '../../src/platform/store.js';
import {
  cleanupSshE2eAccount,
  createSshE2eIdentity,
  prepareSshE2eAccount,
  registerSshE2eAccount,
  type PreparedSshE2eAccount,
  type RegisteredSshE2eAccount,
} from './ssh-e2e-account.js';

export {
  cleanupSshE2eAccount,
  createSshE2eIdentity,
  prepareSshE2eAccount,
  registerSshE2eAccount,
};

export async function seedHttpAuthLogin(
  serverUrl: string,
  account: PreparedSshE2eAccount,
  registered: RegisteredSshE2eAccount,
  masterPassword: string,
  input: {
    readonly name: string;
    readonly origin: string;
    readonly username: string;
    readonly password: string;
  },
): Promise<void> {
  const masterKey = await deriveMasterKey(
    masterPassword,
    account.email,
    account.registration,
  );
  const stretched = await stretchMasterKey(masterKey);
  let userKey;
  try {
    userKey = await unwrapSymmetricKey(registered.login.Key, stretched);
    const api = new ApiClient({
      serverUrlProvider: async () => serverUrl,
      fetchFn: fetch,
      localStore: memoryStore(),
    });
    const request = await encryptCipher({
      type: 1,
      name: input.name,
      login: {
        username: input.username,
        password: input.password,
        uris: [{ uri: input.origin }],
      },
    }, userKey);
    await api.createCipher(registered.accessToken, request);
  } finally {
    masterKey.fill(0);
    stretched.encKey.fill(0);
    stretched.macKey.fill(0);
    userKey?.encKey.fill(0);
    userKey?.macKey.fill(0);
  }
}

function memoryStore(): KeyValueStore {
  const values = new Map<string, unknown>();
  return {
    async get<T>(key: string): Promise<T | undefined> {
      return values.get(key) as T | undefined;
    },
    async set(key, value) { values.set(key, value); },
    async remove(key) { values.delete(key); },
    async clear() { values.clear(); },
  };
}
