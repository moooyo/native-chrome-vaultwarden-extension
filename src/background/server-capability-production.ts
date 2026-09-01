import {
  BITWARDEN_CLIENT_VERSION,
  type ServerConfigResponse,
} from '../core/api/client.js';
import {
  canonicalizeServerCapabilityUrl,
  type ClientCapabilityDeclaration,
} from '../core/api/server-capabilities.js';
import type { ServerConfigFetchRequest } from './server-capability-manager.js';

interface ServerConfigApi {
  getServerConfig(maxResponseBytes: number): PromiseLike<ServerConfigResponse>;
}

export interface ServerCapabilityProductionApi {
  forServer(serverUrl: string): ServerConfigApi;
}

const CONFIG_REQUEST_ERROR = 'The server capability request is invalid';

/**
 * Keep the advertised protocol and complete cipher support in one production declaration. Type 5
 * must be added here only when every read, write, import, export, and UI path is ready to expose it.
 */
export const PRODUCTION_SERVER_CAPABILITY_DECLARATION: ClientCapabilityDeclaration = Object.freeze({
  advertisedProtocolVersion: BITWARDEN_CLIENT_VERSION,
  supportedCipherTypes: Object.freeze([1, 2, 3, 4, 5]),
});

/**
 * Keep the capability transport fixed to the manager's canonical, credential-free request. The
 * ApiClient clone pins every underlying request to that exact full server base path.
 */
export async function fetchFixedServerConfig(
  api: ServerCapabilityProductionApi,
  request: Readonly<ServerConfigFetchRequest>,
): Promise<ServerConfigResponse> {
  let canonicalServerUrl: string;
  try {
    canonicalServerUrl = canonicalizeServerCapabilityUrl(request.serverUrl);
  } catch {
    throw new Error(CONFIG_REQUEST_ERROR);
  }
  if (
    canonicalServerUrl !== request.serverUrl
    || request.configUrl !== new URL('api/config', canonicalServerUrl).toString()
    || request.credentials !== 'omit'
    || !Number.isSafeInteger(request.maxResponseBytes)
    || request.maxResponseBytes < 1
  ) {
    throw new Error(CONFIG_REQUEST_ERROR);
  }
  return api.forServer(request.serverUrl).getServerConfig(request.maxResponseBytes);
}
