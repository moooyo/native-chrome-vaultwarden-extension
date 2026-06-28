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

// 4) ORG_KEY_VECTOR — a fixed 64-byte organization symmetric key wrapped under the EXISTING
//    RSA_VECTOR public key (encType=4 Rsa2048_OaepSha1_B64), reproducing the org-key unwrap chain:
//      Profile.organizations[].key -> rsaOaepDecrypt(privateKey) -> 64-byte org SymmetricKey.
//    The public key is reconstructed from the committed RSA_VECTOR private key so existing RSA
//    vectors stay stable. RSA-OAEP is randomized, so encOrgKey differs each run but always decrypts
//    back to orgKeyHex with RSA_VECTOR.privateKeyPkcs8B64.
const RSA_VECTOR_PKCS8_B64 =
  'MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDQRrnISMNatq9liE6u1Tn9rJWLZ2+9qjwFIbjQ0stznUFaA2R3w5/wQJu4mJDFOdDSLrWRZm8gC4khqekMzX6rSPNy+MALcXP4eBWYOD0CtSAGr1n5YydYl71J5bh47V67xEanZy8pkohPJXfkEAfrHzR/EboOTn8otGK/AT0a5NtQdMfPRuqEqRGOZjnGpsVKsh1wY0SbqqPjX9sT9eb7WtQ6FvAdoL9HJ7DBUrnqRUXO/d3LqmPiqIZm5Zw8LGb7EgLg/Hs6h3hws5+M/Qjb1WpPTZaKCcWQf3e3FqSvlq2mGbNbXlMlKkP1P6iWrKK6ILKpOnocekznhhlkAvihAgMBAAECggEAAtkVPDTJwlJDQCuExStwcNh61eRx6s9epUyxh246+sl1q9eWGJTG0ZMOGBBSwjYm9cFOkXqzwj3DJAAb8h1HHiwr60yFSoDEXttkQvPhqnFX6wx7udMwLgQK6i1NZD6tcfqKU2qf4pD8yv2Eg/RvychgLDzFqTF7x9aN3z4S7/y24iUqvWdYwXa6gHEqgceOqltFGMtRrFAoEJQGUrsEif5we00MZ3e4Kl/XcsXB/NOmktwCuMFAw5IDaF+xoGK0GOdYzozpTQhrDIIlchp+Ure3PSspaTv8Gb79hloXrIgncqgtTKTsv77/B1283vlcUWPC/pLto/apPWo0UMYBwQKBgQD3a/JFiF5wmIlr8lfsgmmY32luGTsqXPkptro0c1Sv7pYuRvRM1iaDMHesXtqAGTSzGoEO9EjF8ERJugy25pc6Mw6ElWBsyUPlIZXqtCSR7IEoUfJE4ApDODPsaxchrQhQ9LCedBrjFnVl603a8RrRGBb0QhA3iC3/fQ0oUjHaYQKBgQDXf1WhQqSfAXj9SWEmcM+gw0BXsc7HewIa77r4USvUAFbIElFUedE8LYnnn/r6GSfPzrxTyXQXLC+pxM4cpnKR3fIGiHcYrgeySfaFYdbMYKV/QMr//mNcP/hEWGrzLZkEjphc1/zdTVS1FdbrNwpiUmnCl5JS0lgLuiKa7iRGQQKBgQDhhWsXJe2vA9p+oi6yTUyjI0CeMjFTs9sIwp2HIXiXxAjvtY0IXEpOWec7HlpbWJ5IgmgQkWmjwhT8frEIJbbCPbeF8gIqJmnUeICFph2PRNuVPNxvGyc/jgMGA7bZ4zYpVF+IjpvTUa1AcPJOFmYzIJoLmgveEiqbLgjIL+NxAQKBgBNsW7h8PEBErrYNrh773gr8bkk5Mo0STj9FSlHlZxDlsuy3kfMOQ8irxhlFdyahq8/0L09SAg+woN8paPZ2Hi99lLn4BNwJm5H7Tqf5CJZFQ8VzfpiSQjxnW6Y1XfZrLraVb7A2m4kK1k64GDX9MQdprDSo2rxyTxNHhKT4P/bBAoGBAMzqclD2tXf9cCGNa5YoVsr0EFp4nH8OD3EfCuHQjTqYYH50VOiaLoD0QiKK9gq7QvOuvEviE3TxUPitjoB4QoBJe6b/xj61tbN+9C/Tz3BvA+orKXCsCFfVkYLXKgdWTDOcioLp4zAwf6FkYDfg/CGZKbUusoySIa1F0lE0ExNU';
const orgPkcs8 = Uint8Array.from(Buffer.from(RSA_VECTOR_PKCS8_B64, 'base64'));
const orgPriv = await subtle.importKey('pkcs8', orgPkcs8, { name: 'RSA-OAEP', hash: 'SHA-1' }, true, ['decrypt']);
const orgJwk = await subtle.exportKey('jwk', orgPriv);
const orgPub = await subtle.importKey('jwk', { kty: orgJwk.kty, n: orgJwk.n, e: orgJwk.e, ext: true }, { name: 'RSA-OAEP', hash: 'SHA-1' }, true, ['encrypt']);
const orgKeyBytes = Uint8Array.from({ length: 64 }, (_, i) => (i + 1) & 0xff); // 0x01..0x40
const orgKeyCt = new Uint8Array(await subtle.encrypt({ name: 'RSA-OAEP' }, orgPub, orgKeyBytes));
console.log('orgKeyHex =', Buffer.from(orgKeyBytes).toString('hex'));
console.log('encOrgKey =', `4.${b64(orgKeyCt)}`);
// Sanity round-trip: decrypt back with the private key and confirm it matches orgKeyBytes.
const orgKeyRound = new Uint8Array(await subtle.decrypt({ name: 'RSA-OAEP' }, orgPriv, orgKeyCt));
console.log('orgKey round-trip OK =', Buffer.from(orgKeyRound).toString('hex') === Buffer.from(orgKeyBytes).toString('hex'));

// 5) The SAME org key wrapped under the SAME RSA public key but as encType=3 (Rsa2048_OaepSha256_B64).
//    RSA-OAEP key material is hash-independent, so the committed private key is re-imported with
//    SHA-256 to encrypt/decrypt. Exercises the SHA-256 OAEP path (encType 3/5).
const orgPriv256 = await subtle.importKey('pkcs8', orgPkcs8, { name: 'RSA-OAEP', hash: 'SHA-256' }, true, ['decrypt']);
const orgJwk256 = await subtle.exportKey('jwk', orgPriv256);
const orgPub256 = await subtle.importKey('jwk', { kty: orgJwk256.kty, n: orgJwk256.n, e: orgJwk256.e, ext: true }, { name: 'RSA-OAEP', hash: 'SHA-256' }, true, ['encrypt']);
const orgKeyCt256 = new Uint8Array(await subtle.encrypt({ name: 'RSA-OAEP' }, orgPub256, orgKeyBytes));
console.log('encOrgKeySha256 =', `3.${b64(orgKeyCt256)}`);
const orgKeyRound256 = new Uint8Array(await subtle.decrypt({ name: 'RSA-OAEP' }, orgPriv256, orgKeyCt256));
console.log('encOrgKeySha256 round-trip OK =', Buffer.from(orgKeyRound256).toString('hex') === Buffer.from(orgKeyBytes).toString('hex'));
