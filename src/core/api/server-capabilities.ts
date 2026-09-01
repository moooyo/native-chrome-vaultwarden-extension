export const ARCHIVE_FEATURE_FLAG = 'pm-19148-innovation-archive';
export const MIN_ARCHIVE_PROTOCOL_VERSION = '2026.4.0';
export const SSH_CIPHER_TYPE = 5;
export const MIN_SSH_PROTOCOL_VERSION = '2024.12.0';
export const MIN_VAULTWARDEN_SSO_PROTOCOL_VERSION = '2025.12.0';
export const MIN_SAFE_VAULTWARDEN_SSO_RELEASE = '1.36.0';

const MAX_FEATURE_STATES = 512;
const MAX_FEATURE_KEY_LENGTH = 256;
const MAX_FEATURE_STRING_LENGTH = 4_096;
const MAX_ENVIRONMENT_PROPERTIES = 32;
const MAX_ENVIRONMENT_URL_LENGTH = 2_048;
const MAX_ENVIRONMENT_PATH_LENGTH = 1_024;

const ENVIRONMENT_URL_KEYS = [
  'vault',
  'api',
  'identity',
  'notifications',
  'sso',
] as const;

export type ServerKind = 'vaultwarden' | 'bitwarden' | 'unknown';
export type CapabilityAvailability = 'available' | 'unavailable' | 'unknown';
export type EndpointProbeState = 'supported' | 'unsupported' | 'unprobed' | 'transient_error';
export type FeatureStateValue = boolean | number | string;

export interface ServerCapabilityScope {
  /** Canonical server base URL, including a self-hosted base path and one trailing slash. */
  readonly serverUrl: string;
  readonly serverGeneration: number;
}

export interface ScopedObservation<T> extends ServerCapabilityScope {
  readonly value: T;
}

export interface ScopedEndpointProbe extends ServerCapabilityScope {
  readonly state: EndpointProbeState;
}

export interface NormalizedServerConfig {
  readonly serverKind: ServerKind;
  readonly serverName?: string;
  /** Bitwarden protocol/config version, not necessarily the server implementation release. */
  readonly protocolVersion?: string;
  /** Canonical service bases projected from /api/config.environment. */
  readonly environment: NormalizedServerEnvironment;
  readonly featureStates: Readonly<Record<string, FeatureStateValue>>;
}

export interface NormalizedServerEnvironment {
  readonly vault?: string;
  readonly api?: string;
  readonly identity?: string;
  readonly notifications?: string;
  readonly sso?: string;
}

export interface ClientCapabilityDeclaration {
  /** Value intended for the Bitwarden-Client-Version header. */
  readonly advertisedProtocolVersion?: string;
  /** Cipher types for which this client can safely decrypt, edit, and export the complete payload. */
  readonly supportedCipherTypes?: readonly number[];
}

export interface ServerCapabilityObservations {
  readonly config?: ScopedObservation<unknown>;
  /** Product release from /api/version. Vaultwarden config.version is only a protocol version. */
  readonly implementationVersion?: ScopedObservation<unknown>;
  /** Provider 7 metadata from a two-factor-required response, or its containing provider map. */
  readonly fido2TwoFactorProviderMetadata?: ScopedObservation<unknown>;
  readonly loginWithDevice?: ScopedEndpointProbe;
  readonly vaultwardenSso?: ScopedEndpointProbe;
  /** Successful /identity/accounts/webauthn/assertion-options response. */
  readonly accountPasskeyAssertionOptions?: ScopedObservation<unknown>;
}

export interface ServerCapabilities {
  readonly scope: ServerCapabilityScope;
  readonly config: NormalizedServerConfig;
  readonly implementationVersion?: string;
  readonly client: {
    readonly advertisedProtocolVersion?: string;
    readonly supportedCipherTypes: readonly number[];
  };
  readonly features: {
    /** Determined only by a concrete provider-7 challenge, never by config or version alone. */
    readonly fido2TwoFactor: CapabilityAvailability;
    readonly loginWithDevice: CapabilityAvailability;
    readonly vaultwardenSso: CapabilityAvailability;
    /** Unavailable until a concrete assertion-options payload is observed. */
    readonly accountPasskey: CapabilityAvailability;
    readonly sshCipherType5: CapabilityAvailability;
    readonly archive: CapabilityAvailability;
  };
  readonly unknownCipherTypePolicy: typeof UNKNOWN_CIPHER_TYPE_POLICY;
}

export type CipherTypeDisposition =
  | {
      readonly kind: 'supported';
      readonly type: number;
      readonly preserveEncrypted: true;
      readonly allowSecretMaterialization: true;
      readonly allowMutation: true;
      readonly exportBehavior: 'include';
    }
  | {
      readonly kind: 'unknown';
      readonly type: number;
      readonly preserveEncrypted: true;
      readonly allowSecretMaterialization: false;
      readonly allowMutation: false;
      readonly exportBehavior: 'reject';
    }
  | {
      readonly kind: 'invalid';
      readonly preserveEncrypted: false;
      readonly allowSecretMaterialization: false;
      readonly allowMutation: false;
      readonly exportBehavior: 'reject';
    };

export const UNKNOWN_CIPHER_TYPE_POLICY = Object.freeze({
  preserveEncrypted: true as const,
  allowSecretMaterialization: false as const,
  allowMutation: false as const,
  exportBehavior: 'reject' as const,
});

/** Canonical identity used to bind every capability observation to one server generation. */
export function createServerCapabilityScope(
  serverUrl: string,
  serverGeneration: number,
): ServerCapabilityScope {
  if (!Number.isSafeInteger(serverGeneration) || serverGeneration < 0) {
    throw new RangeError('serverGeneration must be a non-negative safe integer');
  }
  return Object.freeze({
    serverUrl: canonicalizeServerCapabilityUrl(serverUrl),
    serverGeneration,
  });
}

/** Canonicalize the complete capability boundary without collapsing self-hosted base paths. */
export function canonicalizeServerCapabilityUrl(serverUrl: string): string {
  const input = serverUrl.trim();
  if (!input || input.length > 2_048 || /[\\?#]/u.test(input)) {
    throw new TypeError('serverUrl must be a bounded HTTP(S) base URL without query or fragment');
  }
  let parsed: URL;
  try {
    parsed = new URL(input);
  } catch {
    throw new TypeError('serverUrl must be an absolute HTTP(S) URL');
  }
  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
    throw new TypeError('serverUrl must be an absolute HTTP(S) URL');
  }
  if (parsed.protocol === 'http:' && !isLoopbackHostname(parsed.hostname)) {
    throw new TypeError('serverUrl must use HTTPS unless it targets a loopback host');
  }
  if (parsed.username || parsed.password || parsed.origin === 'null') {
    throw new TypeError('serverUrl must not contain credentials');
  }
  if (parsed.search || parsed.hash || parsed.pathname.length > 1_024) {
    throw new TypeError('serverUrl must be a bounded base URL without query or fragment');
  }
  if (/%(?:00|0a|0d|2f|5c)/iu.test(parsed.pathname)) {
    throw new TypeError('serverUrl contains an ambiguous encoded path separator or control');
  }
  parsed.pathname = `${parsed.pathname.replace(/\/+$/u, '')}/`;
  return parsed.toString();
}

/** Canonicalize one untrusted service base from /api/config.environment. */
export function normalizeServerEnvironmentUrl(value: unknown): string | undefined {
  if (
    typeof value !== 'string'
    || value.length === 0
    || value.length > MAX_ENVIRONMENT_URL_LENGTH
    || value.trim() !== value
    || hasAsciiControlOrSpace(value)
    || /[\\?#]/u.test(value)
    || hasDotPathSegment(value)
  ) return undefined;

  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    return undefined;
  }
  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') return undefined;
  if (parsed.protocol === 'http:' && !isLoopbackHostname(parsed.hostname)) return undefined;
  if (parsed.username || parsed.password || parsed.origin === 'null') return undefined;
  if (parsed.search || parsed.hash || parsed.pathname.length > MAX_ENVIRONMENT_PATH_LENGTH) {
    return undefined;
  }
  if (/%(?:00|0a|0d|2f|5c)/iu.test(parsed.pathname)) return undefined;

  parsed.pathname = `${parsed.pathname.replace(/\/+$/u, '')}/`;
  return parsed.toString();
}

export function scopeServerObservation<T>(
  scope: ServerCapabilityScope,
  value: T,
): ScopedObservation<T> {
  const checked = assertCanonicalScope(scope);
  return Object.freeze({ ...checked, value });
}

export function scopeEndpointProbe(
  scope: ServerCapabilityScope,
  state: EndpointProbeState,
): ScopedEndpointProbe {
  const checked = assertCanonicalScope(scope);
  if (!isEndpointProbeState(state)) throw new TypeError('invalid endpoint probe state');
  return Object.freeze({ ...checked, state });
}

/** Convert untrusted /api/config JSON into a bounded, read-only view. */
export function normalizeServerConfig(value: unknown): NormalizedServerConfig {
  if (!isRecord(value)) return emptyServerConfig();
  const rawServer = ownDataProperty(value, 'server');
  const server = isRecord(rawServer) ? rawServer : undefined;
  const rawServerName = server ? ownDataProperty(server, 'name') : undefined;
  const rawName = typeof rawServerName === 'string' ? rawServerName.trim() : '';
  const serverName = rawName && rawName.length <= 256 ? rawName : undefined;
  const loweredName = serverName?.toLowerCase();
  const serverKind: ServerKind = loweredName === 'vaultwarden'
    ? 'vaultwarden'
    : loweredName === 'bitwarden'
      ? 'bitwarden'
      : 'unknown';
  const protocolVersion = normalizeSemver(ownDataProperty(value, 'version'));
  const environment = normalizeServerEnvironment(ownDataProperty(value, 'environment'));
  const featureStates = normalizeFeatureStates(ownDataProperty(value, 'featureStates'));
  return Object.freeze({
    serverKind,
    ...(serverName ? { serverName } : {}),
    ...(protocolVersion ? { protocolVersion } : {}),
    environment,
    featureStates,
  });
}

/**
 * Build a fail-closed capability snapshot. Scoped evidence from another origin or generation is
 * ignored, so an old probe cannot authorize behavior after a server transition.
 */
export function evaluateServerCapabilities(
  scope: ServerCapabilityScope,
  observations: ServerCapabilityObservations = {},
  clientDeclaration: ClientCapabilityDeclaration = {},
): ServerCapabilities {
  const checkedScope = assertCanonicalScope(scope);
  const configObservation = matchingObservation(checkedScope, observations.config);
  const config = configObservation
    ? normalizeServerConfig(configObservation.value)
    : emptyServerConfig();
  const implementationVersionObservation = matchingObservation(
    checkedScope,
    observations.implementationVersion,
  );
  const implementationVersion = normalizeSemver(implementationVersionObservation?.value);
  const advertisedProtocolVersion = normalizeSemver(clientDeclaration.advertisedProtocolVersion);
  const supportedCipherTypes = normalizeCipherTypes(clientDeclaration.supportedCipherTypes);
  const fido2Metadata = matchingObservation(
    checkedScope,
    observations.fido2TwoFactorProviderMetadata,
  );
  const accountPasskeyOptions = matchingObservation(
    checkedScope,
    observations.accountPasskeyAssertionOptions,
  );

  const client = Object.freeze({
    ...(advertisedProtocolVersion ? { advertisedProtocolVersion } : {}),
    supportedCipherTypes,
  });
  const features = Object.freeze({
    fido2TwoFactor: decideFido2TwoFactor(fido2Metadata),
    loginWithDevice: availabilityFromProbe(checkedScope, observations.loginWithDevice),
    vaultwardenSso: decideVaultwardenSso(
      checkedScope,
      configObservation !== undefined,
      config,
      implementationVersion,
      observations.vaultwardenSso,
    ),
    accountPasskey: accountPasskeyOptions && isAccountPasskeyAssertionOptions(accountPasskeyOptions.value)
      ? 'available'
      : 'unavailable',
    sshCipherType5: decideSshCipherType5(configObservation !== undefined, config, client),
    archive: decideArchive(configObservation !== undefined, config),
  } satisfies ServerCapabilities['features']);

  return Object.freeze({
    scope: checkedScope,
    config,
    ...(implementationVersion ? { implementationVersion } : {}),
    client,
    features,
    unknownCipherTypePolicy: UNKNOWN_CIPHER_TYPE_POLICY,
  });
}

export function isCapabilityAvailable(value: CapabilityAvailability): boolean {
  return value === 'available';
}

/** Decide how callers must handle a server cipher type before reading its encrypted payload. */
export function classifyCipherType(
  value: unknown,
  supportedCipherTypes: readonly number[],
): CipherTypeDisposition {
  if (!isValidRawCipherType(value)) {
    return Object.freeze({
      kind: 'invalid',
      preserveEncrypted: false,
      allowSecretMaterialization: false,
      allowMutation: false,
      exportBehavior: 'reject',
    });
  }
  if (normalizeCipherTypes(supportedCipherTypes).includes(value)) {
    return Object.freeze({
      kind: 'supported',
      type: value,
      preserveEncrypted: true,
      allowSecretMaterialization: true,
      allowMutation: true,
      exportBehavior: 'include',
    });
  }
  return Object.freeze({ kind: 'unknown', type: value, ...UNKNOWN_CIPHER_TYPE_POLICY });
}

function decideFido2TwoFactor(
  observation: ScopedObservation<unknown> | undefined,
): CapabilityAvailability {
  if (!observation) return 'unknown';
  const provider = extractFido2ProviderMetadata(observation.value);
  return isWebAuthnRequestOptions(provider) ? 'available' : 'unavailable';
}

function decideVaultwardenSso(
  scope: ServerCapabilityScope,
  hasConfig: boolean,
  config: NormalizedServerConfig,
  implementationVersion: string | undefined,
  probe: ScopedEndpointProbe | undefined,
): CapabilityAvailability {
  const probeAvailability = availabilityFromProbe(scope, probe);
  if (probeAvailability === 'unavailable') return 'unavailable';
  if (!hasConfig || config.serverKind === 'unknown') return 'unknown';
  if (config.serverKind !== 'vaultwarden') return 'unavailable';
  if (!config.protocolVersion || !isVersionAtLeast(
    config.protocolVersion,
    MIN_VAULTWARDEN_SSO_PROTOCOL_VERSION,
  )) return config.protocolVersion ? 'unavailable' : 'unknown';
  if (!implementationVersion) return 'unknown';
  if (!isVersionAtLeast(implementationVersion, MIN_SAFE_VAULTWARDEN_SSO_RELEASE)) {
    return 'unavailable';
  }
  return probeAvailability;
}

function decideSshCipherType5(
  hasConfig: boolean,
  config: NormalizedServerConfig,
  client: ServerCapabilities['client'],
): CapabilityAvailability {
  const clientDeclared = client.supportedCipherTypes.includes(SSH_CIPHER_TYPE)
    && client.advertisedProtocolVersion !== undefined
    && isVersionAtLeast(client.advertisedProtocolVersion, MIN_SSH_PROTOCOL_VERSION);
  if (!clientDeclared) return 'unavailable';
  if (!hasConfig || !config.protocolVersion) return 'unknown';
  if (!isVersionAtLeast(config.protocolVersion, MIN_SSH_PROTOCOL_VERSION)) return 'unavailable';
  return 'available';
}

function decideArchive(
  hasConfig: boolean,
  config: NormalizedServerConfig,
): CapabilityAvailability {
  if (!hasConfig) return 'unknown';
  const explicitState = config.featureStates[ARCHIVE_FEATURE_FLAG];
  if (explicitState === true) return 'available';
  if (explicitState === false) return 'unavailable';
  if (explicitState !== undefined) return 'unknown';
  if (!config.protocolVersion) return 'unknown';
  return isVersionAtLeast(config.protocolVersion, MIN_ARCHIVE_PROTOCOL_VERSION)
    ? 'available'
    : 'unavailable';
}

function availabilityFromProbe(
  scope: ServerCapabilityScope,
  probe: ScopedEndpointProbe | undefined,
): CapabilityAvailability {
  if (!probe || !sameScope(scope, probe) || !isEndpointProbeState(probe.state)) return 'unknown';
  if (probe.state === 'supported') return 'available';
  if (probe.state === 'unsupported') return 'unavailable';
  return 'unknown';
}

function extractFido2ProviderMetadata(value: unknown): unknown {
  if (!isRecord(value)) return value;
  const providerMap = isRecord(value.TwoFactorProviders2) ? value.TwoFactorProviders2 : value;
  return Object.prototype.hasOwnProperty.call(providerMap, '7') ? providerMap['7'] : value;
}

function isWebAuthnRequestOptions(value: unknown): boolean {
  if (!isRecord(value)) return false;
  if (typeof value.challenge !== 'string' || !isBase64Url(value.challenge)) return false;
  if (typeof value.rpId !== 'string' || !isRpId(value.rpId)) return false;
  return value.allowCredentials === undefined || Array.isArray(value.allowCredentials);
}

function isAccountPasskeyAssertionOptions(value: unknown): boolean {
  if (!isRecord(value) || typeof value.token !== 'string' || value.token.trim().length === 0) {
    return false;
  }
  return isWebAuthnRequestOptions(value.options);
}

function normalizeFeatureStates(value: unknown): Readonly<Record<string, FeatureStateValue>> {
  if (!isRecord(value)) return Object.freeze({});
  const entries = Object.entries(value);
  if (entries.length > MAX_FEATURE_STATES) return Object.freeze({});
  const normalized = Object.create(null) as Record<string, FeatureStateValue>;
  for (const [key, state] of entries) {
    if (!key || key.length > MAX_FEATURE_KEY_LENGTH) continue;
    if (typeof state === 'boolean') normalized[key] = state;
    if (typeof state === 'string' && state.length <= MAX_FEATURE_STRING_LENGTH) {
      normalized[key] = state;
    }
    if (typeof state === 'number' && Number.isFinite(state)) normalized[key] = state;
  }
  return Object.freeze(normalized);
}

function normalizeServerEnvironment(value: unknown): NormalizedServerEnvironment {
  if (!isRecord(value) || Object.keys(value).length > MAX_ENVIRONMENT_PROPERTIES) {
    return Object.freeze({});
  }
  const normalized: Record<string, string> = Object.create(null) as Record<string, string>;
  for (const key of ENVIRONMENT_URL_KEYS) {
    const url = normalizeServerEnvironmentUrl(ownDataProperty(value, key));
    if (url) normalized[key] = url;
  }
  return Object.freeze(normalized);
}

function normalizeCipherTypes(values: readonly number[] | undefined): readonly number[] {
  if (!values) return Object.freeze([]);
  const normalized = [...new Set(values.filter(isValidRawCipherType))].sort((left, right) => left - right);
  return Object.freeze(normalized);
}

export function isValidRawCipherType(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 1;
}

function emptyServerConfig(): NormalizedServerConfig {
  return Object.freeze({
    serverKind: 'unknown',
    environment: Object.freeze({}),
    featureStates: Object.freeze({}),
  });
}

function matchingObservation<T>(
  scope: ServerCapabilityScope,
  observation: ScopedObservation<T> | undefined,
): ScopedObservation<T> | undefined {
  return observation && sameScope(scope, observation) ? observation : undefined;
}

function sameScope(left: ServerCapabilityScope, right: ServerCapabilityScope): boolean {
  return left.serverGeneration === right.serverGeneration && left.serverUrl === right.serverUrl;
}

function assertCanonicalScope(scope: ServerCapabilityScope): ServerCapabilityScope {
  const canonical = createServerCapabilityScope(scope.serverUrl, scope.serverGeneration);
  if (canonical.serverUrl !== scope.serverUrl) {
    throw new TypeError('serverUrl must be canonical');
  }
  return canonical;
}

function isLoopbackHostname(hostname: string): boolean {
  const normalized = hostname.toLowerCase();
  if (normalized === 'localhost' || normalized.endsWith('.localhost')) return true;
  if (normalized === '::1' || normalized === '[::1]') return true;
  const octets = normalized.split('.');
  return octets.length === 4
    && octets[0] === '127'
    && octets.every((octet) => /^\d{1,3}$/u.test(octet) && Number(octet) <= 255);
}

function hasDotPathSegment(value: string): boolean {
  const schemeEnd = value.indexOf('://');
  if (schemeEnd < 0) return false;
  const pathStart = value.indexOf('/', schemeEnd + 3);
  if (pathStart < 0) return false;
  return value.slice(pathStart).split('/').some((segment) => {
    const decodedDots = segment.replace(/%2e/giu, '.');
    return decodedDots === '.' || decodedDots === '..';
  });
}

function hasAsciiControlOrSpace(value: string): boolean {
  for (let index = 0; index < value.length; index++) {
    const code = value.charCodeAt(index);
    if (code <= 0x20 || code === 0x7f) return true;
  }
  return false;
}

function isEndpointProbeState(value: unknown): value is EndpointProbeState {
  return value === 'supported'
    || value === 'unsupported'
    || value === 'unprobed'
    || value === 'transient_error';
}

function isVersionAtLeast(value: string, minimum: string): boolean {
  const parsed = parseSemver(value);
  const parsedMinimum = parseSemver(minimum);
  if (!parsed || !parsedMinimum) return false;
  for (const key of ['major', 'minor', 'patch'] as const) {
    if (parsed[key] !== parsedMinimum[key]) return parsed[key] > parsedMinimum[key];
  }
  if (parsed.prerelease === parsedMinimum.prerelease) return true;
  if (!parsedMinimum.prerelease) return !parsed.prerelease;
  if (!parsed.prerelease) return true;
  return comparePrerelease(parsed.prerelease, parsedMinimum.prerelease) >= 0;
}

function comparePrerelease(left: string, right: string): number {
  const leftParts = left.split('.');
  const rightParts = right.split('.');
  const length = Math.max(leftParts.length, rightParts.length);
  for (let index = 0; index < length; index++) {
    const leftPart = leftParts[index];
    const rightPart = rightParts[index];
    if (leftPart === undefined) return -1;
    if (rightPart === undefined) return 1;
    if (leftPart === rightPart) continue;
    const leftNumber = /^\d+$/.test(leftPart) ? Number(leftPart) : undefined;
    const rightNumber = /^\d+$/.test(rightPart) ? Number(rightPart) : undefined;
    if (leftNumber !== undefined && rightNumber !== undefined) return leftNumber - rightNumber;
    if (leftNumber !== undefined) return -1;
    if (rightNumber !== undefined) return 1;
    return leftPart < rightPart ? -1 : 1;
  }
  return 0;
}

function normalizeSemver(value: unknown): string | undefined {
  if (typeof value !== 'string') return undefined;
  const parsed = parseSemver(value.trim());
  if (!parsed) return undefined;
  const prerelease = parsed.prerelease ? `-${parsed.prerelease}` : '';
  return `${parsed.major}.${parsed.minor}.${parsed.patch}${prerelease}`;
}

function parseSemver(value: string): {
  readonly major: number;
  readonly minor: number;
  readonly patch: number;
  readonly prerelease?: string;
} | undefined {
  const match = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$/.exec(value);
  if (!match) return undefined;
  const major = Number(match[1]);
  const minor = Number(match[2]);
  const patch = Number(match[3]);
  if (![major, minor, patch].every(Number.isSafeInteger)) return undefined;
  return {
    major,
    minor,
    patch,
    ...(match[4] ? { prerelease: match[4] } : {}),
  };
}

function isBase64Url(value: string): boolean {
  return value.length > 0 && value.length <= 16_384 && /^[A-Za-z0-9_-]+$/.test(value);
}

function isRpId(value: string): boolean {
  if (!value || value.length > 253 || value.trim() !== value) return false;
  if (value.includes('/') || value.includes(':') || value.includes('@')) return false;
  return value === 'localhost' || value.split('.').every((label) => (
    label.length > 0
    && label.length <= 63
    && /^[A-Za-z0-9-]+$/.test(label)
    && !label.startsWith('-')
    && !label.endsWith('-')
  ));
}

function isRecord(value: unknown): value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value) as unknown;
  return prototype === Object.prototype || prototype === null;
}

function ownDataProperty(value: Record<string, unknown>, key: string): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(value, key);
  return descriptor && 'value' in descriptor ? descriptor.value : undefined;
}
