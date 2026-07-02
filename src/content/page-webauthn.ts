// Runs in the page's MAIN world (document_start). Wraps navigator.credentials.get() and .create() so
// a stored passkey can satisfy a WebAuthn assertion or registration ceremony. Falls back to the
// browser's native authenticator whenever the request isn't a publicKey request, the rpId isn't valid
// for this origin, the create() options don't qualify (see shouldInterceptCreate), or no matching
// passkey / stored vault exists — so installing the extension never breaks a site.
//
// Known limitation: the resolved credential is a duck-typed object, not a real PublicKeyCredential,
// so sites that assert `instanceof PublicKeyCredential` won't accept it. Most read the response fields.

import { bytesToBase64Url, base64UrlToBytes } from '../core/crypto/encoding.js';

const REQUEST = 'vw-webauthn-request';
const RESPONSE = 'vw-webauthn-response';
const CREATE_REQUEST = 'vw-webauthn-create-request';
const CREATE_RESPONSE = 'vw-webauthn-create-response';

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
        // Forward the RP's user-verification requirement so the worker can set the UV flag honestly.
        ...(publicKey.userVerification ? { userVerification: publicKey.userVerification } : {}),
      });
      if (!assertion) return originalGet(options); // no stored passkey → native authenticator
      return buildCredential(assertion);
    } catch {
      return originalGet(options);
    }
  };
}

/** Whether to intercept a create() for the vault (else defer to the native authenticator). Uses the
 *  cheap MAIN-world suffix check as a native-fallback gate; the worker re-validates rpId via PSL. */
export function shouldInterceptCreate(publicKey: PublicKeyCredentialCreationOptions, host: string): boolean {
  const rpId = publicKey.rp?.id ?? host;
  if (!isRegistrableSuffix(rpId, host)) return false;
  if (!(publicKey.pubKeyCredParams ?? []).some((p) => p.alg === -7)) return false;
  if (publicKey.authenticatorSelection?.authenticatorAttachment === 'cross-platform') return false;
  return true;
}

const originalCreate = credentials?.create?.bind(credentials);
if (originalCreate && window.isSecureContext) {
  credentials!.create = async function vaultwardenCreate(options?: CredentialCreationOptions): Promise<Credential | null> {
    const publicKey = options?.publicKey;
    if (!publicKey) return originalCreate(options);
    if (options?.signal?.aborted) return originalCreate(options);
    if (!shouldInterceptCreate(publicKey, location.hostname)) return originalCreate(options);
    try {
      const registration = await requestRegistration({
        rpId: publicKey.rp?.id ?? location.hostname,
        rpName: publicKey.rp?.name,
        userHandle: bytesToBase64Url(toBytes(publicKey.user.id)),
        userName: publicKey.user.name,
        userDisplayName: publicKey.user.displayName,
        challenge: bytesToBase64Url(toBytes(publicKey.challenge)),
        excludeCredentialIds: (publicKey.excludeCredentials ?? []).map((c) => bytesToBase64Url(toBytes(c.id))),
        ...(publicKey.authenticatorSelection?.userVerification ? { userVerification: publicKey.authenticatorSelection.userVerification } : {}),
      });
      if (!registration) return originalCreate(options); // declined / no store → native
      return buildAttestationCredential(registration);
    } catch {
      return originalCreate(options);
    }
  };
}

interface BridgeRegistration {
  credentialId: string; attestationObject: string; clientDataJSON: string;
  authData: string; publicKeySpki: string; publicKeyAlgorithm: number;
}

function requestRegistration(payload: {
  rpId: string; rpName?: string; userHandle: string; userName?: string; userDisplayName?: string;
  challenge: string; excludeCredentialIds: string[]; userVerification?: string;
}): Promise<BridgeRegistration | null> {
  return new Promise((resolve) => {
    const id = `${Date.now()}-${Math.random().toString(36).slice(2)}`;
    const onMessage = (event: MessageEvent) => {
      if (event.source !== window) return;
      const data = event.data as { source?: string; id?: string; registration?: BridgeRegistration | null; error?: boolean };
      if (data?.source !== CREATE_RESPONSE || data.id !== id) return;
      window.removeEventListener('message', onMessage);
      resolve(data.error ? null : (data.registration ?? null));
    };
    window.addEventListener('message', onMessage);
    window.postMessage({ source: CREATE_REQUEST, id, payload }, location.origin);
  });
}

/** Build a duck-typed PublicKeyCredential with an AuthenticatorAttestationResponse the RP can read. */
function buildAttestationCredential(reg: BridgeRegistration): Credential {
  const rawId = base64UrlToBytes(reg.credentialId);
  const attestationObject = toArrayBuffer(base64UrlToBytes(reg.attestationObject));
  const clientDataJSON = toArrayBuffer(base64UrlToBytes(reg.clientDataJSON));
  const authData = toArrayBuffer(base64UrlToBytes(reg.authData));
  const publicKey = toArrayBuffer(base64UrlToBytes(reg.publicKeySpki));
  const response = {
    attestationObject,
    clientDataJSON,
    getAuthenticatorData: () => authData,
    getPublicKey: () => publicKey,
    getPublicKeyAlgorithm: () => reg.publicKeyAlgorithm,
    getTransports: () => [] as string[],
  };
  return {
    id: reg.credentialId,
    rawId: toArrayBuffer(rawId),
    type: 'public-key',
    authenticatorAttachment: 'platform',
    response,
    getClientExtensionResults: () => ({}),
  } as unknown as Credential;
}

function requestAssertion(payload: {
  rpId: string;
  origin: string;
  challenge: string;
  allowedCredentialIds: string[];
  userVerification?: string;
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
