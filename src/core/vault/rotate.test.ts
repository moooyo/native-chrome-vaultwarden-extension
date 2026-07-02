import { describe, it, expect } from 'vitest';
import { rotateCipher } from './rotate.js';
import { symmetricKeyFromBytes } from '../crypto/keys.js';
import { encryptToText, encryptToBytes, decryptToBytes } from '../crypto/encstring.js';
import type { CipherResponse } from '../api/types.js';

const oldK = symmetricKeyFromBytes(new Uint8Array(64).fill(7));
const newK = symmetricKeyFromBytes(new Uint8Array(64).fill(9));
const dec = new TextDecoder();

it('keyed cipher: re-wraps only the item key, leaves field ciphertext byte-identical', async () => {
  const itemKeyBytes = new Uint8Array(64).fill(3);
  const wrappedItemKey = await encryptToBytes(itemKeyBytes, oldK);
  const raw = { id: 'c1', type: 1, key: wrappedItemKey, name: '2.field-ciphertext-unchanged==', login: { password: '2.pw-unchanged==' } } as unknown as CipherResponse;
  const out = await rotateCipher(raw, oldK, newK) as any;
  expect(out.name).toBe('2.field-ciphertext-unchanged=='); // untouched
  expect(out.login.password).toBe('2.pw-unchanged==');
  expect(out.key).not.toBe(wrappedItemKey);
  expect([...await decryptToBytes(out.key, newK)]).toEqual([...itemKeyBytes]); // item key preserved
});

it('keyless cipher: re-wraps every EncString field under the new UserKey; preserves id/type/deletedDate', async () => {
  const raw = { id: 'c2', type: 1, deletedDate: '2026-07-01T00:00:00Z', name: await encryptToText('MyItem', oldK), notes: await encryptToText('note', oldK), login: { username: await encryptToText('u', oldK), uris: [{ uri: await encryptToText('https://x', oldK), match: null }] }, fields: [{ type: 1, name: await encryptToText('fn', oldK), value: await encryptToText('fv', oldK) }] } as unknown as CipherResponse;
  const out = await rotateCipher(raw, oldK, newK) as any;
  expect(out.id).toBe('c2'); expect(out.type).toBe(1); expect(out.deletedDate).toBe('2026-07-01T00:00:00Z');
  expect(out.login.uris[0].match).toBeNull();
  expect(dec.decode(await decryptToBytes(out.name, newK))).toBe('MyItem');
  expect(dec.decode(await decryptToBytes(out.login.username, newK))).toBe('u');
  expect(dec.decode(await decryptToBytes(out.login.uris[0].uri, newK))).toBe('https://x');
  expect(dec.decode(await decryptToBytes(out.fields[0].value, newK))).toBe('fv');
});

it('keyless cipher with attachments: re-wraps attachment keys into attachments2', async () => {
  const raw = { id: 'c3', type: 1, name: await encryptToText('n', oldK), attachments: [{ id: 'a1', key: await encryptToText('attkey', oldK), fileName: await encryptToText('file.txt', oldK), size: '10', url: 'u' }] } as unknown as CipherResponse;
  const out = await rotateCipher(raw, oldK, newK) as any;
  expect(out.attachments2).toBeDefined();
  expect(dec.decode(await decryptToBytes(out.attachments2.a1.key, newK))).toBe('attkey');
  expect(out.attachments2.a1.fileName).toBe(out.attachments.find((a: any) => a.id === 'a1').fileName); // fileName carried (re-wrapped)
});

it('throws (fail-close) when a personal cipher field cannot be decrypted with the old key', async () => {
  const raw = { id: 'c4', type: 1, name: await encryptToText('n', newK) /* wrong key */ } as unknown as CipherResponse;
  await expect(rotateCipher(raw, oldK, newK)).rejects.toBeTruthy();
});
