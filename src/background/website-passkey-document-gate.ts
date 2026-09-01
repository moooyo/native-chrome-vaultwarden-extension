import { AppError } from '../core/errors.js';
import type { WebsitePasskeyDocumentContext } from './website-passkey-coordinator.js';
import { websitePasskeyOriginMatchPattern } from './website-passkey-browser.js';
import type {
  WebsitePasskeyOperation,
} from './website-passkey-permissions-policy-parser.js';
import type {
  WebsitePasskeyPolicyCommittedNavigation,
  WebsitePasskeyPermissionsPolicyBoundary,
  WebsitePasskeyPermissionsPolicyProof,
} from './website-passkey-permissions-policy.js';

const DOCUMENT_ERROR_MESSAGE = 'Website passkey document authorization is unavailable.';
const MAX_DOCUMENT_ID_LENGTH = 4_096;

export interface WebsitePasskeyBrowserFrameRecord {
  readonly frameId?: number;
  readonly parentFrameId?: number;
  readonly documentId?: string;
  readonly url?: string;
}

export interface WebsitePasskeyDocumentGateDeps {
  readonly getAllFrames: (
    tabId: number,
  ) => PromiseLike<readonly WebsitePasskeyBrowserFrameRecord[] | null | undefined>;
  /** Optional strict cross-origin authorizer. Without it, the legacy same-origin proof remains active. */
  readonly permissionsPolicy?: WebsitePasskeyPermissionsPolicyBoundary;
}

interface AuthorizedFrame {
  readonly frameId: number;
  readonly parentFrameId: number;
  readonly documentId: string;
  readonly url: string;
  readonly origin: string;
}

interface FrameEpoch {
  readonly key: string;
  readonly value: number;
}

export interface WebsitePasskeyDocumentLease {
  readonly tabId: number;
  readonly frameId: number;
  readonly documentId: string;
  readonly url: string;
  readonly origin: string;
  readonly operation: WebsitePasskeyOperation;
  readonly topOrigin: string;
  readonly crossOrigin: boolean;
  readonly lineage: readonly AuthorizedFrame[];
  readonly epochs: readonly FrameEpoch[];
  readonly permissionsPolicyProof?: WebsitePasskeyPermissionsPolicyProof;
}

/** Browser-owned proof for one exact frame and its policy-authorized complete ancestor chain. */
export class WebsitePasskeyDocumentGate {
  readonly #getAllFrames: WebsitePasskeyDocumentGateDeps['getAllFrames'];
  readonly #permissionsPolicy: WebsitePasskeyPermissionsPolicyBoundary | undefined;
  readonly #issued = new WeakSet<object>();
  readonly #epochs = new Map<string, number>();
  #eventRevision = 0;

  constructor(deps: WebsitePasskeyDocumentGateDeps) {
    this.#getAllFrames = deps.getAllFrames;
    this.#permissionsPolicy = deps.permissionsPolicy;
  }

  async capture(
    context: WebsitePasskeyDocumentContext,
    operation: WebsitePasskeyOperation = 'get',
  ): Promise<WebsitePasskeyDocumentLease> {
    const eventRevision = this.#eventRevision;
    const policyProof = this.#permissionsPolicy
      ? await this.#permissionsPolicy.capture(context, operation)
      : undefined;
    const lineage = policyProof
      ? Object.freeze(policyProof.lineage.map((frame) => Object.freeze({ ...frame })))
      : await this.#readLineage(context, true);
    if (eventRevision !== this.#eventRevision) throw documentError();
    const epochs = Object.freeze([
      this.#epoch(tabKey(context.tabId)),
      ...lineage.map((frame) => this.#epoch(frameKey(context.tabId, frame.frameId))),
    ]);
    const lease = Object.freeze({
      tabId: context.tabId,
      frameId: context.frameId,
      documentId: context.documentId,
      url: context.url,
      origin: context.origin,
      operation,
      topOrigin: policyProof?.topOrigin ?? context.origin,
      crossOrigin: policyProof?.crossOrigin ?? false,
      lineage,
      epochs,
      ...(policyProof ? { permissionsPolicyProof: policyProof } : {}),
    });
    this.#issued.add(lease);
    return lease;
  }

  assert(lease: WebsitePasskeyDocumentLease, context: WebsitePasskeyDocumentContext): void {
    if (!this.#issued.has(lease)
      || lease.tabId !== context.tabId
      || lease.frameId !== context.frameId
      || lease.documentId !== context.documentId
      || lease.url !== context.url
      || lease.origin !== context.origin
      || lease.epochs.some((epoch) => this.#epochValue(epoch.key) !== epoch.value)) {
      throw documentError();
    }
    if (lease.permissionsPolicyProof) {
      if (!this.#permissionsPolicy) throw documentError();
      try {
        this.#permissionsPolicy.assert(
          lease.permissionsPolicyProof,
          context,
          lease.operation,
        );
      } catch {
        throw documentError();
      }
    }
  }

  async assertCurrent(
    lease: WebsitePasskeyDocumentLease,
    context: WebsitePasskeyDocumentContext,
  ): Promise<void> {
    this.assert(lease, context);
    if (lease.permissionsPolicyProof) {
      try {
        await this.#permissionsPolicy!.assertCurrent(
          lease.permissionsPolicyProof,
          context,
          lease.operation,
        );
      } catch {
        throw documentError();
      }
      this.assert(lease, context);
      return;
    }
    const eventRevision = this.#eventRevision;
    const lineage = await this.#readLineage(context, true);
    if (eventRevision !== this.#eventRevision) throw documentError();
    this.assert(lease, context);
    if (lineageFingerprint(lineage) !== lineageFingerprint(lease.lineage)) throw documentError();
  }

  async isCurrent(context: WebsitePasskeyDocumentContext): Promise<boolean> {
    const eventRevision = this.#eventRevision;
    try {
      await this.#readLineage(context, this.#permissionsPolicy === undefined);
      return eventRevision === this.#eventRevision;
    } catch {
      return false;
    }
  }

  invalidateFrame(tabId: number, frameId: number): void {
    if (!nonNegativeInteger(tabId) || !nonNegativeInteger(frameId)) return;
    this.#bump(frameKey(tabId, frameId));
    this.#permissionsPolicy?.invalidateFrame?.(tabId, frameId);
  }

  recordCommittedNavigation(navigation: WebsitePasskeyPolicyCommittedNavigation): boolean {
    if (!nonNegativeInteger(navigation?.tabId) || !nonNegativeInteger(navigation?.frameId)) return false;
    this.#bump(frameKey(navigation.tabId, navigation.frameId));
    return this.#permissionsPolicy?.recordCommittedNavigation?.(navigation) ?? false;
  }

  recordSameDocumentNavigation(navigation: WebsitePasskeyPolicyCommittedNavigation): boolean {
    if (!nonNegativeInteger(navigation?.tabId) || !nonNegativeInteger(navigation?.frameId)) return false;
    this.#bump(frameKey(navigation.tabId, navigation.frameId));
    return this.#permissionsPolicy?.recordSameDocumentNavigation?.(navigation) ?? false;
  }

  invalidateTab(tabId: number): void {
    if (!nonNegativeInteger(tabId)) return;
    this.#bump(tabKey(tabId));
    this.#permissionsPolicy?.invalidateTab?.(tabId);
  }

  async #readLineage(
    context: WebsitePasskeyDocumentContext,
    requireSameOrigin: boolean,
  ): Promise<readonly AuthorizedFrame[]> {
    validateContext(context);
    let rawFrames: readonly WebsitePasskeyBrowserFrameRecord[] | null | undefined;
    try {
      rawFrames = await this.#getAllFrames(context.tabId);
    } catch {
      throw documentError();
    }
    if (!Array.isArray(rawFrames)) throw documentError();

    const frames = new Map<number, AuthorizedFrame>();
    const seenFrameIds = new Set<number>();
    for (const raw of rawFrames) {
      if (!nonNegativeInteger(raw?.frameId)) continue;
      if (seenFrameIds.has(raw.frameId)) throw documentError();
      seenFrameIds.add(raw.frameId);
      const frame = parseFrame(raw);
      if (frame) frames.set(frame.frameId, frame);
    }
    const target = frames.get(context.frameId);
    const top = frames.get(0);
    if (!target || !top
      || target.documentId !== context.documentId
      || target.url !== context.url
      || target.origin !== context.origin
      || (requireSameOrigin && top.origin !== context.origin)) {
      throw documentError();
    }

    const lineage: AuthorizedFrame[] = [];
    const seen = new Set<number>();
    let current = target;
    for (;;) {
      if (seen.has(current.frameId) || (requireSameOrigin && current.origin !== context.origin)) {
        throw documentError();
      }
      seen.add(current.frameId);
      lineage.push(current);
      if (current.frameId === 0) break;
      if (!nonNegativeInteger(current.parentFrameId)) throw documentError();
      const parent = frames.get(current.parentFrameId);
      if (!parent) throw documentError();
      current = parent;
    }
    return Object.freeze(lineage.map((frame) => Object.freeze({ ...frame })));
  }

  #epoch(key: string): FrameEpoch {
    return Object.freeze({ key, value: this.#epochValue(key) });
  }

  #epochValue(key: string): number {
    return this.#epochs.get(key) ?? 0;
  }

  #bump(key: string): void {
    this.#epochs.set(key, this.#epochValue(key) + 1);
    this.#eventRevision += 1;
  }
}

function parseFrame(value: WebsitePasskeyBrowserFrameRecord): AuthorizedFrame | undefined {
  if (!value || !nonNegativeInteger(value.frameId)
    || !Number.isSafeInteger(value.parentFrameId)
    || (value.parentFrameId as number) < -1
    || !validDocumentId(value.documentId)
    || typeof value.url !== 'string'
    || !websitePasskeyOriginMatchPattern(value.url)) return undefined;
  let url: URL;
  try { url = new URL(value.url); } catch { return undefined; }
  if (url.username || url.password) return undefined;
  return Object.freeze({
    frameId: value.frameId,
    parentFrameId: value.parentFrameId as number,
    documentId: value.documentId,
    url: value.url,
    origin: url.origin,
  });
}

function validateContext(context: WebsitePasskeyDocumentContext): void {
  if (!context || !nonNegativeInteger(context.tabId) || !nonNegativeInteger(context.frameId)
    || !validDocumentId(context.documentId)
    || typeof context.url !== 'string'
    || typeof context.origin !== 'string') throw documentError();
  let url: URL;
  try { url = new URL(context.url); } catch { throw documentError(); }
  if (url.origin !== context.origin || !websitePasskeyOriginMatchPattern(context.url)) {
    throw documentError();
  }
}

function validDocumentId(value: unknown): value is string {
  if (typeof value !== 'string' || value.length === 0
    || value.length > MAX_DOCUMENT_ID_LENGTH || value.trim() !== value) return false;
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code <= 0x1f || code === 0x7f) return false;
  }
  return true;
}

function lineageFingerprint(lineage: readonly AuthorizedFrame[]): string {
  return JSON.stringify(lineage.map((frame) => [
    frame.frameId,
    frame.parentFrameId,
    frame.documentId,
    frame.url,
    frame.origin,
  ]));
}

function tabKey(tabId: number): string {
  return `tab:${tabId}`;
}

function frameKey(tabId: number, frameId: number): string {
  return `frame:${tabId}:${frameId}`;
}

function nonNegativeInteger(value: unknown): value is number {
  return Number.isSafeInteger(value) && (value as number) >= 0 && !Object.is(value, -0);
}

function documentError(): AppError {
  return new AppError('denied', DOCUMENT_ERROR_MESSAGE);
}
