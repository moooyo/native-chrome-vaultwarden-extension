// Temporary generator for test vectors that must be cryptographically valid.
// Produces:
//   USER_KEY_VECTOR_600K.akey  — the 64-byte userKey wrapped under stretch(masterKey@600000)
//   RSA_VECTOR                 — RSA-2048-OAEP-SHA1 keypair + a short round-trip ciphertext (encType=4)
//   RSA_PRIVATE_KEY_VECTOR     — the same PKCS8 wrapped as an encType=2 EncString under USER_KEY_VECTOR.userKeyHex
// Run: node tools/gen-vectors.mjs
const subtle = globalThis.crypto.subtle;

const enc = new TextEncoder();
const b64 = (u8) => Buffer.from(u8).toString('base64');
const hexToBytes = (h) => Uint8Array.from(h.match(/.{2}/g).map((p) => parseInt(p, 16)));

async function pbkdf2(password, salt, iterations, lengthBytes) {
  const baseKey = await subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await subtle.deriveBits({ name: 'PBKDF2', salt: enc.encode(salt), iterations, hash: 'SHA-256' }, baseKey, lengthBytes * 8);
  return new Uint8Array(bits);
}
async function hmac(key, data) {
  const k = await subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return new Uint8Array(await subtle.sign('HMAC', k, data));
}
async function hkdfExpand(prk, info, lengthBytes) {
  const infoBytes = enc.encode(info);
  const input = new Uint8Array(infoBytes.length + 1);
  input.set(infoBytes, 0);
  input[infoBytes.length] = 0x01;
  return (await hmac(prk, input)).slice(0, lengthBytes);
}
async function stretch(masterKey) {
  return { encKey: await hkdfExpand(masterKey, 'enc', 32), macKey: await hkdfExpand(masterKey, 'mac', 32) };
}
// Encrypt-then-MAC EncString (encType=2) with a fixed IV for reproducibility.
async function encEncString(plaintext, key, iv) {
  const aesKey = await subtle.importKey('raw', key.encKey, { name: 'AES-CBC' }, false, ['encrypt']);
  const ct = new Uint8Array(await subtle.encrypt({ name: 'AES-CBC', iv }, aesKey, plaintext));
  const macData = new Uint8Array(iv.length + ct.length);
  macData.set(iv, 0);
  macData.set(ct, iv.length);
  const mac = await hmac(key.macKey, macData);
  return `2.${b64(iv)}|${b64(ct)}|${b64(mac)}`;
}

const EMAIL = 'user@example.com';
const PASSWORD = 'p4ssw0rd-Master!';
const USER_KEY_HEX =
  '00112233445566778899aabbccddeeff102132435465768798a9bacbdcedfe0ffedcba98765432100123456789abcdefcafebabedeadbeef0badc0ffee123456';

// 1) 600k-iteration akey wrapping the same 64-byte userKey.
const masterKey600k = await pbkdf2(PASSWORD, EMAIL, 600000, 32);
console.log('// masterKey@600000 =', Buffer.from(masterKey600k).toString('hex'));
const stretched600k = await stretch(masterKey600k);
const userKeyBytes = hexToBytes(USER_KEY_HEX);
const fixedIvA = Uint8Array.from({ length: 16 }, (_, i) => i + 1); // 0x01..0x10
const akey600k = await encEncString(userKeyBytes, stretched600k, fixedIvA);
console.log('akey600k =', akey600k);

// 2) RSA-2048-OAEP-SHA1 keypair + short round-trip ciphertext (encType=4).
const kp = await subtle.generateKey(
  { name: 'RSA-OAEP', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-1' },
  true,
  ['encrypt', 'decrypt'],
);
const pkcs8 = new Uint8Array(await subtle.exportKey('pkcs8', kp.privateKey));
const rsaPlain = 'rsa-roundtrip-vector';
const rsaCt = new Uint8Array(await subtle.encrypt({ name: 'RSA-OAEP' }, kp.publicKey, enc.encode(rsaPlain)));
console.log('pkcs8B64 =', b64(pkcs8));
console.log('encType4 =', `4.${b64(rsaCt)}`);
console.log('rsaCtLen =', rsaCt.length);

// 3) The same PKCS8 wrapped as encType=2 under the 64-byte userKey (symmetric).
const symKey = { encKey: userKeyBytes.slice(0, 32), macKey: userKeyBytes.slice(32, 64) };
const fixedIvB = Uint8Array.from({ length: 16 }, (_, i) => 16 - i); // 0x10..0x01
const encPrivateKey = await encEncString(pkcs8, symKey, fixedIvB);
console.log('encPrivateKey =', encPrivateKey);
