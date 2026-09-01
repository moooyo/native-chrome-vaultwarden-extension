import { describe, expect, it } from 'vitest';
import { bytesToBase64Url, utf8ToBytes } from '../crypto/encoding.js';
import {
  consumeValidatedFido2TwoFactorSubmission,
  parseFido2TwoFactorRequest,
  serializeFido2TwoFactorAssertion,
  validateFido2TwoFactorAssertionToken,
  validateFido2TwoFactorSubmission,
  type Fido2TwoFactorRequest,
} from './fido2-two-factor.js';

const ORIGIN = 'https://vault.example.com';
const RP_ID = 'vault.example.com';
const CHALLENGE_BYTES = Uint8Array.from({ length: 32 }, (_, index) => index + 1);
const CREDENTIAL_ID_BYTES = Uint8Array.from({ length: 32 }, (_, index) => 255 - index);
const CHALLENGE = bytesToBase64Url(CHALLENGE_BYTES);
const CREDENTIAL_ID = bytesToBase64Url(CREDENTIAL_ID_BYTES);
const SIGNATURE = Uint8Array.from([0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01]);

// Mirrors Vaultwarden 1.35+/main generate_webauthn_login output in TwoFactorProviders2["7"].
const VAULTWARDEN_PROVIDER = {
  challenge: CHALLENGE,
  timeout: 60_000,
  rpId: RP_ID,
  allowCredentials: [{
    type: 'public-key',
    id: CREDENTIAL_ID,
    transports: ['usb', 'nfc', 'ble', 'internal'],
  }],
  userVerification: 'discouraged',
  extensions: { appid: `${ORIGIN}/app-id.json` },
};

// Fido2NetLib's Bitwarden provider also emits response status fields and requests UVM output.
const BITWARDEN_PROVIDER = {
  ...VAULTWARDEN_PROVIDER,
  status: 'ok',
  errorMessage: '',
  extensions: { appid: `${ORIGIN}/app-id.json`, uvm: true },
};

describe('parseFido2TwoFactorRequest', () => {
  it('parses Vaultwarden provider 7 metadata into navigator.credentials.get options', () => {
    const parsed = parseFido2TwoFactorRequest({
      error: 'invalid_grant',
      TwoFactorProviders: ['7'],
      TwoFactorProviders2: { '7': VAULTWARDEN_PROVIDER },
    }, { origin: ORIGIN, rpId: RP_ID });

    expect(parsed).toMatchObject({ origin: ORIGIN, rpId: RP_ID, challenge: CHALLENGE });
    expect(parsed.navigatorRequest.publicKey).toMatchObject({
      timeout: 60_000,
      rpId: RP_ID,
      userVerification: 'discouraged',
      extensions: { appid: `${ORIGIN}/app-id.json` },
    });
    expect(bytes(parsed.navigatorRequest.publicKey.challenge)).toEqual(CHALLENGE_BYTES);
    expect(bytes(parsed.navigatorRequest.publicKey.allowCredentials![0]!.id)).toEqual(CREDENTIAL_ID_BYTES);
    expect(parsed.navigatorRequest.publicKey.allowCredentials![0]!.transports)
      .toEqual(['usb', 'nfc', 'ble', 'internal']);
    expect(JSON.parse(parsed.connectorData)).toEqual(VAULTWARDEN_PROVIDER);
    expect(Object.isFrozen(parsed.navigatorRequest.publicKey)).toBe(true);
  });

  it('accepts both a provider map and direct Bitwarden options', () => {
    const fromMap = parseFido2TwoFactorRequest({ '7': BITWARDEN_PROVIDER }, {
      origin: `${ORIGIN}/`,
      rpId: RP_ID,
    });
    const direct = parseFido2TwoFactorRequest(BITWARDEN_PROVIDER, { origin: ORIGIN, rpId: RP_ID });

    expect(fromMap.navigatorRequest.publicKey.extensions).toEqual({
      appid: `${ORIGIN}/app-id.json`,
      uvm: true,
    });
    expect(direct.challenge).toBe(CHALLENGE);
  });

  it('allows HTTP only for exact localhost development origins', () => {
    expect(() => parseFido2TwoFactorRequest({
      ...VAULTWARDEN_PROVIDER,
      rpId: 'localhost',
      extensions: { appid: 'http://localhost:8080/app-id.json' },
    }, { origin: 'http://localhost:8080', rpId: 'localhost' })).not.toThrow();
    expect(() => parseFido2TwoFactorRequest({
      ...VAULTWARDEN_PROVIDER,
      rpId: '127.0.0.1',
      extensions: { appid: 'http://127.0.0.1:8080/app-id.json' },
    }, { origin: 'http://127.0.0.1:8080', rpId: '127.0.0.1' })).not.toThrow();

    expect(() => parseFido2TwoFactorRequest(VAULTWARDEN_PROVIDER, {
      origin: 'http://vault.example.com',
      rpId: RP_ID,
    })).toThrow(/HTTPS or HTTP on loopback/);
  });

  it('rejects cross-RP, cross-origin appid, and invalid expected RP bindings', () => {
    expect(() => parseFido2TwoFactorRequest({ ...VAULTWARDEN_PROVIDER, rpId: 'evil.example' }, {
      origin: ORIGIN,
      rpId: RP_ID,
    })).toThrow(/does not match/);
    expect(() => parseFido2TwoFactorRequest({
      ...VAULTWARDEN_PROVIDER,
      extensions: { appid: 'https://evil.example/app-id.json' },
    }, { origin: ORIGIN, rpId: RP_ID })).toThrow(/appid.*expected origin/);
    expect(() => parseFido2TwoFactorRequest(VAULTWARDEN_PROVIDER, {
      origin: ORIGIN,
      rpId: 'example.net',
    })).toThrow(/not valid for the expected origin/);
  });

  it.each([
    ['padding', `${CHALLENGE}=`],
    ['standard alphabet', '//////////////////////8'],
    ['impossible length', 'A'],
    ['empty', ''],
  ])('rejects malformed challenge base64url: %s', (_label, challenge) => {
    expect(() => parseFido2TwoFactorRequest({ ...VAULTWARDEN_PROVIDER, challenge }, {
      origin: ORIGIN,
      rpId: RP_ID,
    })).toThrow(/challenge.*base64url|challenge byte length/);
  });

  it('rejects malformed descriptors, unknown fields, and oversized input', () => {
    expect(() => parseFido2TwoFactorRequest({
      ...VAULTWARDEN_PROVIDER,
      allowCredentials: [
        { type: 'public-key', id: CREDENTIAL_ID },
        { type: 'public-key', id: CREDENTIAL_ID },
      ],
    }, { origin: ORIGIN, rpId: RP_ID })).toThrow(/duplicate credential/);
    expect(() => parseFido2TwoFactorRequest({
      ...VAULTWARDEN_PROVIDER,
      allowCredentials: [{ type: 'public-key', id: CREDENTIAL_ID, transports: ['cable'] }],
    }, { origin: ORIGIN, rpId: RP_ID })).toThrow(/unsupported transport/);
    expect(() => parseFido2TwoFactorRequest({ ...VAULTWARDEN_PROVIDER, attestation: 'direct' }, {
      origin: ORIGIN,
      rpId: RP_ID,
    })).toThrow(/unsupported field: attestation/);
    expect(() => parseFido2TwoFactorRequest({ ...VAULTWARDEN_PROVIDER, timeout: 300_001 }, {
      origin: ORIGIN,
      rpId: RP_ID,
    })).toThrow(/timeout/);
    expect(() => parseFido2TwoFactorRequest({
      ...VAULTWARDEN_PROVIDER,
      challenge: bytesToBase64Url(new Uint8Array(129)),
    }, { origin: ORIGIN, rpId: RP_ID })).toThrow(/challenge/);
  });

  it('rejects unknown request extensions instead of forwarding them to WebAuthn', () => {
    expect(() => parseFido2TwoFactorRequest({
      ...VAULTWARDEN_PROVIDER,
      extensions: { appid: `${ORIGIN}/app-id.json`, prf: { eval: {} } },
    }, { origin: ORIGIN, rpId: RP_ID })).toThrow(/unsupported field: prf/);
  });
});

describe('serializeFido2TwoFactorAssertion', () => {
  it('serializes a credential-like assertion to the Vaultwarden/Bitwarden token contract', async () => {
    const request = parseRequest(BITWARDEN_PROVIDER);
    const assertion = await makeAssertion(request, {
      extensionResults: { appid: false, uvm: [[1, 2, 3]] },
      userHandle: Uint8Array.from([9, 8, 7]),
    });

    const token = await serializeFido2TwoFactorAssertion(assertion, request);
    expect(JSON.parse(token)).toEqual({
      id: CREDENTIAL_ID,
      rawId: CREDENTIAL_ID,
      type: 'public-key',
      extensions: { appid: false, uvm: [[1, 2, 3]] },
      response: {
        authenticatorData: bytesToBase64Url(assertion.response.authenticatorData),
        clientDataJson: bytesToBase64Url(assertion.response.clientDataJSON),
        signature: bytesToBase64Url(SIGNATURE),
        userHandle: 'CQgH',
      },
    });
    expect(token).not.toContain('clientExtensionResults');
    expect(token).not.toContain('clientDataJSON');
  });

  it('accepts PublicKeyCredential.toJSON-style base64url strings', async () => {
    const request = parseRequest();
    const live = await makeAssertion(request, { extensionResults: {} });
    const jsonLike = {
      id: live.id,
      rawId: bytesToBase64Url(live.rawId),
      type: live.type,
      authenticatorAttachment: 'cross-platform',
      clientExtensionResults: {},
      response: {
        authenticatorData: bytesToBase64Url(live.response.authenticatorData),
        clientDataJSON: bytesToBase64Url(live.response.clientDataJSON),
        signature: bytesToBase64Url(live.response.signature),
        userHandle: null,
      },
    };

    await expect(serializeFido2TwoFactorAssertion(jsonLike, request)).resolves.toEqual(
      JSON.stringify({
        id: CREDENTIAL_ID,
        rawId: CREDENTIAL_ID,
        type: 'public-key',
        extensions: {},
        response: {
          authenticatorData: jsonLike.response.authenticatorData,
          clientDataJson: jsonLike.response.clientDataJSON,
          signature: jsonLike.response.signature,
        },
      }),
    );
  });

  it('supports a validated same-origin appid result for migrated U2F credentials', async () => {
    const request = parseRequest();
    const assertion = await makeAssertion(request, {
      extensionResults: { appid: true },
      rpIdHashInput: `${ORIGIN}/app-id.json`,
    });

    const token = JSON.parse(await serializeFido2TwoFactorAssertion(assertion, request));
    expect(token.extensions).toEqual({ appid: true });
  });

  it('binds assertion ID, challenge, origin, and RP ID hash to the parsed request', async () => {
    await expectRejectedAssertion(async (request) => ({
      ...(await makeAssertion(request)),
      id: bytesToBase64Url(Uint8Array.from([1, 2, 3])),
    }), /id and rawId/);
    await expectRejectedAssertion(
      (request) => makeAssertion(request, { clientChallenge: bytesToBase64Url(new Uint8Array(32).fill(8)) }),
      /challenge does not match/,
    );
    await expectRejectedAssertion(
      (request) => makeAssertion(request, { clientOrigin: 'https://evil.example' }),
      /origin does not match/,
    );
    await expectRejectedAssertion(
      (request) => makeAssertion(request, { rpIdHashInput: 'evil.example' }),
      /RP ID hash/,
    );
  });

  it('rejects credentials outside allowCredentials and unrequested appid output', async () => {
    const otherId = Uint8Array.from({ length: 32 }, (_, index) => index + 20);
    await expectRejectedAssertion(async (request) => ({
      ...(await makeAssertion(request)),
      id: bytesToBase64Url(otherId),
      rawId: otherId,
    }), /not present in allowCredentials/);

    const providerWithoutExtensions = { ...VAULTWARDEN_PROVIDER };
    delete (providerWithoutExtensions as { extensions?: unknown }).extensions;
    const request = parseRequest(providerWithoutExtensions);
    const assertion = await makeAssertion(request, { extensionResults: { appid: true } });
    await expect(serializeFido2TwoFactorAssertion(assertion, request))
      .rejects.toThrow(/appid was not requested/);
  });

  it('requires user presence and required user verification flags', async () => {
    await expectRejectedAssertion((request) => makeAssertion(request, { flags: 0 }), /user presence/);
    const request = parseRequest({ ...VAULTWARDEN_PROVIDER, userVerification: 'required' });
    const assertion = await makeAssertion(request, { flags: 0x01 });
    await expect(serializeFido2TwoFactorAssertion(assertion, request))
      .rejects.toThrow(/required user verification/);
  });

  it('rejects malformed, unknown, and oversized assertion fields', async () => {
    await expectRejectedAssertion(async (request) => {
      const assertion = await makeAssertion(request);
      return { ...assertion, response: { ...assertion.response, attestationObject: 'AA' } };
    }, /unsupported field: attestationObject/);
    await expectRejectedAssertion(async (request) => {
      const assertion = await makeAssertion(request);
      return { ...assertion, response: { ...assertion.response, signature: new Uint8Array(1_025) } };
    }, /signature byte length/);
    await expectRejectedAssertion(async (request) => {
      const assertion = await makeAssertion(request);
      return { ...assertion, getClientExtensionResults: undefined, clientExtensionResults: { prf: {} } };
    }, /unsupported field: prf/);
  });

  it('rejects malformed clientDataJSON and cross-origin ceremonies', async () => {
    await expectRejectedAssertion(async (request) => {
      const assertion = await makeAssertion(request);
      return { ...assertion, response: { ...assertion.response, clientDataJSON: utf8ToBytes('{') } };
    }, /valid JSON/);
    await expectRejectedAssertion(
      (request) => makeAssertion(request, { crossOrigin: true }),
      /cross-origin/,
    );
  });

  it('allows each parsed challenge binding to be serialized only once', async () => {
    const request = parseRequest();
    const assertion = await makeAssertion(request);
    await serializeFido2TwoFactorAssertion(assertion, request);
    await expect(serializeFido2TwoFactorAssertion(assertion, request))
      .rejects.toThrow(/already been consumed/);
    await expect(serializeFido2TwoFactorAssertion(assertion, { ...request }))
      .rejects.toThrow(/not issued by this parser/);
  });

  it('validates and canonicalizes the official connector assertion JSON token', async () => {
    const request = parseRequest(BITWARDEN_PROVIDER);
    const assertion = await makeAssertion(request, {
      extensionResults: { appid: false, uvm: [[1, 2, 3]] },
      userHandle: Uint8Array.from([9, 8, 7]),
    });
    const connectorToken = connectorTokenFromAssertion(assertion, { appid: false, uvm: [[1, 2, 3]] });

    const validated = await validateFido2TwoFactorAssertionToken(connectorToken, request);
    expect(JSON.parse(validated)).toMatchObject({
      id: CREDENTIAL_ID,
      rawId: CREDENTIAL_ID,
      type: 'public-key',
      extensions: { appid: false, uvm: [[1, 2, 3]] },
      response: { userHandle: 'CQgH' },
    });
    await expect(validateFido2TwoFactorAssertionToken(connectorToken, request))
      .rejects.toThrow(/already been consumed/);
  });

  it('brands a device-login assertion for one AuthService consumption only', async () => {
    const request = parseRequest();
    const assertion = await makeAssertion(request, { extensionResults: { appid: false } });
    const token = connectorTokenFromAssertion(assertion, { appid: false });

    const submission = await validateFido2TwoFactorSubmission(token, request, true);
    expect(consumeValidatedFido2TwoFactorSubmission(submission)).toEqual({
      token,
      remember: true,
      origin: ORIGIN,
    });
    expect(() => consumeValidatedFido2TwoFactorSubmission(submission))
      .toThrow(/already consumed/);
    expect(() => consumeValidatedFido2TwoFactorSubmission({ token, remember: true, origin: ORIGIN }))
      .toThrow(/not issued/);
  });

  it('rejects connector aliases, missing extensions, malformed JSON, and oversized tokens', async () => {
    const request = parseRequest();
    const assertion = await makeAssertion(request);
    const parsed = JSON.parse(connectorTokenFromAssertion(assertion, {})) as Record<string, unknown>;
    const response = parsed.response as Record<string, unknown>;
    response.clientDataJSON = response.clientDataJson;
    delete response.clientDataJson;
    await expect(validateFido2TwoFactorAssertionToken(JSON.stringify(parsed), request))
      .rejects.toThrow(/unsupported field: clientDataJSON/);

    await expect(validateFido2TwoFactorAssertionToken('{}', parseRequest()))
      .rejects.toThrow(/missing extensions/);
    await expect(validateFido2TwoFactorAssertionToken('{', parseRequest()))
      .rejects.toThrow(/not valid JSON/);
    await expect(validateFido2TwoFactorAssertionToken('x'.repeat(32 * 1_024 + 1), parseRequest()))
      .rejects.toThrow(/too large/);
  });
});

function parseRequest(provider: Record<string, unknown> = VAULTWARDEN_PROVIDER): Fido2TwoFactorRequest {
  return parseFido2TwoFactorRequest({ TwoFactorProviders2: { '7': provider } }, {
    origin: ORIGIN,
    rpId: RP_ID,
  });
}

async function makeAssertion(
  request: Fido2TwoFactorRequest,
  options: {
    clientChallenge?: string;
    clientOrigin?: string;
    crossOrigin?: boolean;
    extensionResults?: Record<string, unknown>;
    flags?: number;
    rpIdHashInput?: string;
    userHandle?: Uint8Array;
  } = {},
) {
  const clientData = {
    type: 'webauthn.get',
    challenge: options.clientChallenge ?? request.challenge,
    origin: options.clientOrigin ?? request.origin,
    crossOrigin: options.crossOrigin ?? false,
  };
  const authenticatorData = await buildAuthenticatorData(
    options.rpIdHashInput ?? request.rpId,
    options.flags ?? 0x01,
  );
  return {
    id: CREDENTIAL_ID,
    rawId: CREDENTIAL_ID_BYTES.slice(),
    type: 'public-key',
    response: {
      authenticatorData,
      clientDataJSON: utf8ToBytes(JSON.stringify(clientData)),
      signature: SIGNATURE.slice(),
      ...(options.userHandle ? { userHandle: options.userHandle } : { userHandle: null }),
    },
    getClientExtensionResults: () => options.extensionResults ?? {},
  };
}

async function buildAuthenticatorData(rpIdHashInput: string, flags: number): Promise<Uint8Array> {
  const hash = new Uint8Array(
    await globalThis.crypto.subtle.digest('SHA-256', utf8ToBytes(rpIdHashInput) as BufferSource),
  );
  const output = new Uint8Array(37);
  output.set(hash, 0);
  output[32] = flags;
  return output;
}

function connectorTokenFromAssertion(
  assertion: Awaited<ReturnType<typeof makeAssertion>>,
  extensions: Record<string, unknown>,
): string {
  return JSON.stringify({
    id: assertion.id,
    rawId: bytesToBase64Url(assertion.rawId),
    type: assertion.type,
    extensions,
    response: {
      authenticatorData: bytesToBase64Url(assertion.response.authenticatorData),
      clientDataJson: bytesToBase64Url(assertion.response.clientDataJSON),
      signature: bytesToBase64Url(assertion.response.signature),
      ...(assertion.response.userHandle
        ? { userHandle: bytesToBase64Url(assertion.response.userHandle) }
        : {}),
    },
  });
}

async function expectRejectedAssertion(
  build: (request: Fido2TwoFactorRequest) => Promise<unknown>,
  message: RegExp,
): Promise<void> {
  const request = parseRequest();
  await expect(serializeFido2TwoFactorAssertion(await build(request), request)).rejects.toThrow(message);
}

function bytes(value: BufferSource): Uint8Array {
  return value instanceof ArrayBuffer
    ? new Uint8Array(value)
    : new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
}
