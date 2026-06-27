export const KDF_VECTOR = {
  email: 'user@example.com',
  password: 'p4ssw0rd-Master!',
  iterations: 1000,
  masterKeyHex: 'c6e36acf506a7d05ec07ebe2c4f8406ccb1b69e761e71e61e7e24edc0b7736bd',
  masterPasswordHashB64: 'Zdrx2SQE0KLpsOmYbeUrSxqDlYP4kBxA2gckh8YR6Zg=',
};

export const KDF_VECTOR_600K = {
  email: 'user@example.com',
  password: 'p4ssw0rd-Master!',
  iterations: 600000,
  masterKeyHex: '0ec2123c51cbd5690086201e28957a85ffdfad6ce382983f27c73960aa6d20ee',
  masterPasswordHashB64: 'Ed32k/NteQHP1mkPQDcCsxylmWzEly7BxSD48blLBEQ=',
};

export const STRETCH_VECTOR = {
  encKeyHex: 'd2425697ee6622bac49a08c019c169ad0aa04ccb08f1ec76b580938e5c4d71ac',
  macKeyHex: '0586d3103bfe6a5e5c72ec94d05907bda43b6b26bafeb67e896885e5addab596',
};

export const USER_KEY_VECTOR = {
  akey:
    '2.SgDNFMTxhFrnqEdZTCSm6g==|dQ8ObREVFKlklPLeWSqsWkaWQQ4ezGoBddju71qRwUWuR/AdYm4voNb24Nh1kUhrtMJPdZKGzSS42fdAnvZeZcXFaanRpicPVUdqyZUrZUM=|yL4+bZWGI2eZ8bwHzgDzcEIUoR6LjfrE+jIZFoRlj+Y=',
  userKeyHex:
    '00112233445566778899aabbccddeeff102132435465768798a9bacbdcedfe0ffedcba98765432100123456789abcdefcafebabedeadbeef0badc0ffee123456',
};

export const FIELD_VECTOR = {
  encString:
    '2.q1vT7cBqU9RjFUCj5KxSfw==|Njj6Rz3WuZoxIP6/zklx8w==|/1UdG6Q68nXxuAFWjRiAk2ZZwpFpcZ+x1V+9d4baXAs=',
  plaintext: 'Hello, Vault!',
};

export const TAMPERED_FIELD_ENCSTRING =
  '2.q1vT7cBqU9RjFUCj5KxSfw==|Njj6Rz3WuZoxIP6/zklx8w==|/1UdG6Q68nXxuAFWjRiAk2ZZwpFpcZ+x1V+9d4baXAo=';
