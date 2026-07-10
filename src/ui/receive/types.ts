import type { ParsedSendUrl, AccessedSend } from '../../core/vault/send-access.js';

/**
 * The narrow dependency seam the dormant Lit Receive root is constructed with. Every side effect
 * it needs (network access, the host-permission prompt, and saving decrypted file bytes) is
 * injected here so tests can supply fakes instead of touching real browser APIs.
 */
export interface ReceiveDeps {
  fetch: typeof fetch;
  requestOrigin(originPattern: string): Promise<boolean>;
  download(bytes: Uint8Array, fileName: string): void;
}

/**
 * The Receive flow's state machine, driven entirely by the root. `fileReady` carries everything
 * needed to start (or repeat) a download; `downloading` and `error` are deliberately narrower —
 * the download handler closes over the `parsed`/`send`/`passwordHash` it needs directly from the
 * `fileReady` render, rather than threading them through every later state.
 */
export type ReceiveState =
  | { status: 'idle' }
  | { status: 'accessing' }
  | { status: 'passwordRequired'; message: string }
  | { status: 'textReady'; name: string; text: string }
  | { status: 'fileReady'; parsed: ParsedSendUrl; send: AccessedSend; passwordHash?: string }
  | { status: 'downloading' }
  | { status: 'error'; message: string };
