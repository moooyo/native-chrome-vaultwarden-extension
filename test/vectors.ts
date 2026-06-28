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

// URL_VECTOR: 'https://example.com' encrypted with USER_KEY_VECTOR (fixed IV 0x01*16)
export const URL_VECTOR = {
  encString:
    '2.AQEBAQEBAQEBAQEBAQEBAQ==|cpKJ58ZKd7YpYLGDexqBQzFMTABy8MpyGJIsYZp1iCI=|WNwvD0GxRF7DZw5+mOFTUoxm2XlC+3Sb7j1VKbRA6AM=',
  plaintext: 'https://example.com',
};

// USER_KEY_VECTOR_600K.akey: the SAME 64-byte userKey as USER_KEY_VECTOR.userKeyHex, but wrapped
// under stretch(masterKey @ 600000 iterations) so it unwraps for KDF_VECTOR_600K-based logins.
// Needed because the 5000-iteration KDF floor forbids the 1000-iteration KDF_VECTOR happy-path.
// Reproduce with tools/gen-vectors.mjs (fixed IV 0x01..0x10).
export const USER_KEY_VECTOR_600K = {
  akey:
    '2.AQIDBAUGBwgJCgsMDQ4PEA==|oZyi8ybO90QdBJk97sKUq0kQAjla0TRxUCEppeOSvTvq0mebmW7yKWgMJ03iA6RDI/Zqe5KhLdr1yibJ8WzAPDQc6MHjfGnvmY55Zdhv4GM=|dx/tt7TErcVhibbF1tTl//DokQLQe93KqXAtvUsqO/0=',
  userKeyHex: USER_KEY_VECTOR.userKeyHex,
};

// RSA-2048-OAEP-SHA1 keypair (Bitwarden encType=4 Rsa2048_OaepSha1_B64) + a short round-trip
// ciphertext. Generated once with tools/gen-vectors.mjs (subtle.generateKey RSA-OAEP SHA-1, 2048).
export const RSA_VECTOR = {
  privateKeyPkcs8B64:
    'MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDQRrnISMNatq9liE6u1Tn9rJWLZ2+9qjwFIbjQ0stznUFaA2R3w5/wQJu4mJDFOdDSLrWRZm8gC4khqekMzX6rSPNy+MALcXP4eBWYOD0CtSAGr1n5YydYl71J5bh47V67xEanZy8pkohPJXfkEAfrHzR/EboOTn8otGK/AT0a5NtQdMfPRuqEqRGOZjnGpsVKsh1wY0SbqqPjX9sT9eb7WtQ6FvAdoL9HJ7DBUrnqRUXO/d3LqmPiqIZm5Zw8LGb7EgLg/Hs6h3hws5+M/Qjb1WpPTZaKCcWQf3e3FqSvlq2mGbNbXlMlKkP1P6iWrKK6ILKpOnocekznhhlkAvihAgMBAAECggEAAtkVPDTJwlJDQCuExStwcNh61eRx6s9epUyxh246+sl1q9eWGJTG0ZMOGBBSwjYm9cFOkXqzwj3DJAAb8h1HHiwr60yFSoDEXttkQvPhqnFX6wx7udMwLgQK6i1NZD6tcfqKU2qf4pD8yv2Eg/RvychgLDzFqTF7x9aN3z4S7/y24iUqvWdYwXa6gHEqgceOqltFGMtRrFAoEJQGUrsEif5we00MZ3e4Kl/XcsXB/NOmktwCuMFAw5IDaF+xoGK0GOdYzozpTQhrDIIlchp+Ure3PSspaTv8Gb79hloXrIgncqgtTKTsv77/B1283vlcUWPC/pLto/apPWo0UMYBwQKBgQD3a/JFiF5wmIlr8lfsgmmY32luGTsqXPkptro0c1Sv7pYuRvRM1iaDMHesXtqAGTSzGoEO9EjF8ERJugy25pc6Mw6ElWBsyUPlIZXqtCSR7IEoUfJE4ApDODPsaxchrQhQ9LCedBrjFnVl603a8RrRGBb0QhA3iC3/fQ0oUjHaYQKBgQDXf1WhQqSfAXj9SWEmcM+gw0BXsc7HewIa77r4USvUAFbIElFUedE8LYnnn/r6GSfPzrxTyXQXLC+pxM4cpnKR3fIGiHcYrgeySfaFYdbMYKV/QMr//mNcP/hEWGrzLZkEjphc1/zdTVS1FdbrNwpiUmnCl5JS0lgLuiKa7iRGQQKBgQDhhWsXJe2vA9p+oi6yTUyjI0CeMjFTs9sIwp2HIXiXxAjvtY0IXEpOWec7HlpbWJ5IgmgQkWmjwhT8frEIJbbCPbeF8gIqJmnUeICFph2PRNuVPNxvGyc/jgMGA7bZ4zYpVF+IjpvTUa1AcPJOFmYzIJoLmgveEiqbLgjIL+NxAQKBgBNsW7h8PEBErrYNrh773gr8bkk5Mo0STj9FSlHlZxDlsuy3kfMOQ8irxhlFdyahq8/0L09SAg+woN8paPZ2Hi99lLn4BNwJm5H7Tqf5CJZFQ8VzfpiSQjxnW6Y1XfZrLraVb7A2m4kK1k64GDX9MQdprDSo2rxyTxNHhKT4P/bBAoGBAMzqclD2tXf9cCGNa5YoVsr0EFp4nH8OD3EfCuHQjTqYYH50VOiaLoD0QiKK9gq7QvOuvEviE3TxUPitjoB4QoBJe6b/xj61tbN+9C/Tz3BvA+orKXCsCFfVkYLXKgdWTDOcioLp4zAwf6FkYDfg/CGZKbUusoySIa1F0lE0ExNU',
  encType4EncString:
    '4.dBUfhFJN7JqOf3jKOEb2WUfdLqWmNn/oDUXp8MSMEtX3rbCWS+CXBKC0z21ddWbuLbCH58kbOzLMY/DmaXHrROii9FNdE5GzSmHRFuopijjjaApXbZPpD6wqiMo7BMFOX75A4jWvyYdyCcwSL+QlixsF/VrS/Gy5ySi81KsvGyWFWht7bkNpBgnr9S4WIcYf11tXJca1h4pZ73ea7ZDbId0/ifzmw2XvyR9BHoPHiG4aC80FMkJFxNNr/cM1Aydj6HdgpqHd7HG1L1MHcFI6+ihTvYcdHPdMSspjYJG6zA0NMKq1X9cztEHhdXJ2LlEVJp0EiTCAFPQ64kzZhZSirg==',
  plaintext: 'rsa-roundtrip-vector',
};

// RSA_PRIVATE_KEY_VECTOR: the same PKCS8 private key as RSA_VECTOR, wrapped as an encType=2
// EncString under the 64-byte USER_KEY_VECTOR.userKeyHex (this is how the account PrivateKey field
// is protected — userKey-wrapped, NOT RSA). Reproduce with tools/gen-vectors.mjs (fixed IV 0x10..0x01).
export const RSA_PRIVATE_KEY_VECTOR = {
  userKeyHex: USER_KEY_VECTOR.userKeyHex,
  pkcs8B64: RSA_VECTOR.privateKeyPkcs8B64,
  encPrivateKey:
    '2.EA8ODQwLCgkIBwYFBAMCAQ==|0YTjHF1hlV3fLKKQF+QCtQqw+9oX5T62EYPhi91+h8GZQslgYBvpdc8YLRQ4+J3uqx8YBQy9tocBla6zhT6n7eX9O6gdu59S76E8s5bQV8pHD7jzAfzY+RzBilEcyR4UyaD6zHeYb0KCDiI/WK2VewgC88JCI5iP40tdrvJ5LuFq0dsZUKDGclx0Cy4n2v31CK+mYuErB7lhSLvS1LTqCiJ6ZkAnUbjsSzLzLF+MrJRTbrRU1UWAB2QvSCUdhaeJihjOu2BNyRpS/BeVxW8HiCymdai6O/gxQajPLQ193GU0ox8irbpkeRIbBPv78+dVlT2eqtTiGyQYq2uJQtIHh6pYQLYWeHC/RTMIsl3GX/sGYG3duC62IvOpa7GQWic1Rvol1nhCKxgk7PHcO1GmrwMFNF7dDelWU5tTBuwSI/09aW+9gyPJXAzF4dPheP70qBWoP2J4lli/jEmgBkiJxp++aVjiUWdPzsQV2+eJIbqWwA9lf6Jb6AnGH9BC4lNlkGYySMHV/GUUzmm0DBcswfKMn2g5mwg6UrF6qsOCtdszNo2O6I1tLnnqMg47eZnVTYCarMAeqgFfu6n9ZErH1xtYMTB4e7083NjESBdIZehdIadIVINHus2LMjYxsUBKLMymahdyxNyvPtRkwQ88JhMLo2wGf80wiCeT9cXPgxv4umCK7JT0QpCjQufUMz3KDNSzJ7cy6R67wdz8HYOTW1r63oV02+h5iDO74F9FE/jh7lWFp01L3L0dZ6wWdXXvdeKa0b5wcoJOs6h8dudzQ3dv8rSxVFJS7J2xYTXfAOlJ4SkA8QBmJaE6X/+CVFty4iTLttS4U74JtBWLlP2qWKN9eMKCZgvyc3cG2xvhTpG0zUvsfGcbslxY6547Agg8BTBYx2gXtInmLStu/Na6XR7ZrE5/n8AdL1Lv7ppL7UY1+L2A1522s6RWRB8QTda0DCHDJdePcwwrX4z5lohUvufrOmpXtnJGIg7EYTZCG8tTVyN9G9HwfsuIqrlu216D4sxqEASldPM7fDJMP3pD62YTKBSRvsq+foxd9oNs9SYwLR1AGRgRHgCEvEL9jbGNizql3MoO1K4Daba4BdJbw+8v2NNkySxT5BUb8y5Czkafykkr5nm/j3dnD7uS4z9WDiopEpRJt43KwshIgLxIkdz7/2xyu3H3kLg8f6L7/M0QFfslnEKJ9UdPTrOAlwtyOLv75IzzwqiLNWe9T/0KSc0gS+qdTWwZjMxKd+tgozymkrJ8JkfuX5Y9z49SKvzxJYjI9dBI/oiG2ncRj0yFjRKiaaIjhNYNXFkwlITzycXAV8NM4J2OeetLJEYnVXg9YEaq6GCEYE3VUkXr47XG7lra8LyoEUo806pc/XJ2a2viYGv2yEH+/97zD+Wr62wHKggaM//vZQD3YVucZuT4D6kT80zyWeBVoaEUPGcVTEuF2ULUactM+c/toWPTbszmU9KjmoKLQWqrQSUXgTyV1B8xrP/Zafw/Ve41FOAve0JPbMLTaGiUTAGqjWDp+r8b0wvmvX44fk29KsaIAPfc81PlPew9yNqEVDlB9RhYScfU78V61MxjyQyhMMEt24JH+R4jmJtBfpL28mjbRgMGXYF2hoGwbbgwk4UNkpGj3XU=|PZ8w/1b+DvnvAtLBolMiC893qsGsQhNgrGRrkX6lLj4=',
};
