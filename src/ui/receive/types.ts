import type {
  ParsedSendUrl,
  AccessedSend,
  SendAccessAuthorization,
  SendEmailAuthProof,
} from '../../core/vault/send-access.js';

/**
 * The narrow dependency seam the dormant Lit Receive root is constructed with. Every side effect
 * it needs (network access, host-permission leases, and saving decrypted file bytes) is injected
 * here so tests can supply fakes instead of touching real browser APIs.
 */
export interface ReceiveDeps {
  fetch: typeof fetch;
  requestOrigins(originPatterns: readonly string[]): Promise<OriginPermissionGrant>;
  removeOrigin(originPattern: string): Promise<boolean>;
  download(bytes: Uint8Array, fileName: string): void;
  writeClipboard?(text: string): Promise<void>;
}

export interface OriginPermissionGrant {
  granted: boolean;
  /** Exact permissions added by this Receive page rather than reused from an existing grant. */
  newlyGranted: readonly string[];
}

export interface ReceiveAuthProof {
  parsed: ParsedSendUrl;
  linkGeneration: number;
}

export interface ReceivePasswordRequiredState extends ReceiveAuthProof {
  status: 'passwordRequired';
  message: string;
}

export interface ReceiveEmailRequiredState extends ReceiveAuthProof {
  status: 'emailRequired';
  proof: SendEmailAuthProof;
  message: string;
}

export interface ReceiveOtpRequiredState extends ReceiveAuthProof {
  status: 'otpRequired';
  email: string;
  proof: SendEmailAuthProof;
  resendAvailableAt: number;
  resending: boolean;
  message: string;
}

export interface ReceiveFileReadyState {
  status: 'fileReady';
  parsed: ParsedSendUrl;
  linkGeneration: number;
  send: AccessedSend;
  authorization: SendAccessAuthorization;
  /** A validated cross-origin URL waiting for a fresh user gesture to request host permission. */
  pendingDownloadUrl?: string;
  message?: string;
  messageTone?: 'info' | 'danger' | 'success';
}

export interface ReceiveTextReadyState {
  status: 'textReady';
  send: AccessedSend;
  linkGeneration: number;
  /** A hidden Send starts false and changes only after a deliberate recipient action. */
  revealed: boolean;
}

/**
 * The Receive flow's state machine, driven entirely by the root. Ready states retain the complete
 * accessed Send so protocol metadata survives local UI transitions and retry paths. `downloading`
 * retains the settled file state as well, ensuring failures return to the same decrypted context.
 */
export type ReceiveState =
  | { status: 'idle' }
  | { status: 'accessing'; linkGeneration: number }
  | ReceivePasswordRequiredState
  | ReceiveEmailRequiredState
  | ReceiveOtpRequiredState
  | ReceiveTextReadyState
  | ReceiveFileReadyState
  | { status: 'downloading'; ready: ReceiveFileReadyState }
  | { status: 'error'; message: string };
