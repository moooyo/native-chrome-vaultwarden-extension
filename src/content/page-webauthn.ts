// Runs in the page's MAIN world (document_start). Wraps navigator.credentials.get() so a stored
// passkey can satisfy a WebAuthn request. Falls back to the browser's native authenticator whenever
// the request isn't a publicKey get, the rpId isn't valid for this origin, or no matching passkey
// exists — so installing the extension never breaks a site.
//
// Known limitation: the resolved credential is a duck-typed object, not a real PublicKeyCredential,
// so sites that assert `instanceof PublicKeyCredential` won't accept it. Most read the response fields.

import { bytesToBase64Url, base64UrlToBytes } from '../core/crypto/encoding.js';

const REQUEST = 'vw-webauthn-request';
const RESPONSE = 'vw-webauthn-response';

interface BridgeAssertion {
  credentialId: string;
  authenticatorData: string;
  clientDataJSON: string;
  signature: string;
  userHandle?: string;
}

const credentials = navigator.credentials as CredentialsContainer | undefined;
const originalGet = credentials?.get?.bind(credentials);

if (originalGet && window.isSecureContext) {
  credentials!.get = async function vaultwardenGet(options?: CredentialRequestOptions): Promise<Credential | null> {
    const publicKey = options?.publicKey;
    if (!publicKey) return originalGet(options);
    const rpId = publicKey.rpId ?? location.hostname;
    if (!isRegistrableSuffix(rpId, location.hostname)) return originalGet(options);
    try {
      const assertion = await requestAssertion({
        rpId,
        origin: location.origin,
        challenge: bytesToBase64Url(toBytes(publicKey.challenge)),
        allowedCredentialIds: (publicKey.allowCredentials ?? []).map((c) => bytesToBase64Url(toBytes(c.id))),
      });
      if (!assertion) return originalGet(options); // no stored passkey → native authenticator
      return buildCredential(assertion);
    } catch {
      return originalGet(options);
    }
  };
}

function requestAssertion(payload: {
  rpId: string;
  origin: string;
  challenge: string;
  allowedCredentialIds: string[];
}): Promise<BridgeAssertion | null> {
  return new Promise((resolve) => {
    const id = `${Date.now()}-${Math.random().toString(36).slice(2)}`;
    const onMessage = (event: MessageEvent) => {
      if (event.source !== window) return;
      const data = event.data as { source?: string; id?: string; assertion?: BridgeAssertion | null; error?: boolean };
      if (data?.source !== RESPONSE || data.id !== id) return;
      window.removeEventListener('message', onMessage);
      resolve(data.error ? null : (data.assertion ?? null));
    };
    window.addEventListener('message', onMessage);
    window.postMessage({ source: REQUEST, id, payload }, location.origin);
  });
}

/** Build a duck-typed PublicKeyCredential the page can read (id/rawId/type/response). */
function buildCredential(assertion: BridgeAssertion): Credential {
  const rawId = base64UrlToBytes(assertion.credentialId);
  const response = {
    authenticatorData: toArrayBuffer(base64UrlToBytes(assertion.authenticatorData)),
    clientDataJSON: toArrayBuffer(base64UrlToBytes(assertion.clientDataJSON)),
    signature: toArrayBuffer(base64UrlToBytes(assertion.signature)),
    userHandle: assertion.userHandle ? toArrayBuffer(base64UrlToBytes(assertion.userHandle)) : null,
  };
  return {
    id: assertion.credentialId,
    rawId: toArrayBuffer(rawId),
    type: 'public-key',
    authenticatorAttachment: 'platform',
    response,
    getClientExtensionResults: () => ({}),
  } as unknown as Credential;
}

function isRegistrableSuffix(rpId: string, host: string): boolean {
  return host === rpId || host.endsWith(`.${rpId}`);
}

function toBytes(source: BufferSource): Uint8Array {
  return source instanceof ArrayBuffer ? new Uint8Array(source) : new Uint8Array(source.buffer, source.byteOffset, source.byteLength);
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}
