import { AppError } from '../core/errors.js';
import type { WebsitePasskeyDocumentContext } from './website-passkey-coordinator.js';
import { websitePasskeyOriginMatchPattern } from './website-passkey-browser.js';
import type {
  WebsitePasskeyFeaturePolicyProbeBoundary,
  WebsitePasskeyFeaturePolicyProbeResult,
} from './website-passkey-feature-policy-probe.js';
import {
  parseWebsitePasskeyIframeAllowAttribute,
  parseWebsitePasskeyPermissionsPolicyHeader,
  WEBSITE_PASSKEY_PERMISSIONS_POLICY_FEATURES,
  type WebsitePasskeyContainerPolicy,
  type WebsitePasskeyHeaderPolicy,
  type WebsitePasskeyOperation,
  type WebsitePasskeyPermissionsPolicyFeature,
  type WebsitePasskeyPolicyAllowlistItem,
  type WebsitePasskeyResolvedPolicyAllowlistItem,
} from './website-passkey-permissions-policy-parser.js';

const POLICY_ERROR_MESSAGE = 'Website passkey Permissions Policy authorization is unavailable.';
const DEFAULT_CACHE_TTL_MS = 30 * 60_000;
const DEFAULT_MAX_CACHE_ENTRIES = 512;
const DEFAULT_MAX_EPOCH_ENTRIES = 4_096;
const MAX_DOCUMENT_ID_LENGTH = 4_096;
const MAX_URL_LENGTH = 8_192;
const MAX_RESPONSE_HEADERS = 256;
const MAX_IFRAMES_PER_REPORT = 128;

export interface WebsitePasskeyPolicyBrowserFrame {
  readonly frameId?: number;
  readonly parentFrameId?: number;
  readonly documentId?: string;
  readonly url?: string;
}

export interface WebsitePasskeyPolicyFrame extends Required<WebsitePasskeyPolicyBrowserFrame> {
  readonly origin: string;
}

export interface WebsitePasskeyPolicyResponseHeader {
  readonly name?: string;
  readonly value?: string;
}

export interface WebsitePasskeyPolicyResponseObservation {
  readonly tabId: number;
  readonly frameId: number;
  readonly documentId: string;
  readonly url: string;
  readonly type: 'main_frame' | 'sub_frame';
  readonly responseHeaders: readonly WebsitePasskeyPolicyResponseHeader[];
}

export interface WebsitePasskeyIframeAllowReportSender {
  readonly tabId: number;
  readonly frameId: number;
  readonly documentId: string;
  readonly url: string;
}

export interface WebsitePasskeyIframeAllowReportEntry {
  readonly src: string;
  readonly allow: string;
  readonly srcdoc: boolean;
}

export interface WebsitePasskeyPolicyCommittedNavigation {
  readonly tabId: number;
  readonly frameId: number;
  readonly documentId: string;
  readonly url: string;
}

export interface WebsitePasskeyPermissionsPolicyProof {
  readonly tabId: number;
  readonly frameId: number;
  readonly documentId: string;
  readonly url: string;
  readonly origin: string;
  readonly operation: WebsitePasskeyOperation;
  readonly topOrigin: string;
  readonly crossOrigin: boolean;
  readonly lineage: readonly WebsitePasskeyPolicyFrame[];
}

export interface WebsitePasskeyPermissionsPolicyBoundary {
  capture(
    context: WebsitePasskeyDocumentContext,
    operation: WebsitePasskeyOperation,
  ): PromiseLike<WebsitePasskeyPermissionsPolicyProof>;
  assert(
    proof: WebsitePasskeyPermissionsPolicyProof,
    context: WebsitePasskeyDocumentContext,
    operation: WebsitePasskeyOperation,
  ): void;
  assertCurrent(
    proof: WebsitePasskeyPermissionsPolicyProof,
    context: WebsitePasskeyDocumentContext,
    operation: WebsitePasskeyOperation,
  ): PromiseLike<void>;
  invalidateFrame?(tabId: number, frameId: number): void;
  invalidateTab?(tabId: number): void;
  recordCommittedNavigation?(navigation: WebsitePasskeyPolicyCommittedNavigation): boolean;
  recordSameDocumentNavigation?(navigation: WebsitePasskeyPolicyCommittedNavigation): boolean;
}

export interface WebsitePasskeyPermissionsPolicyResolverDeps {
  readonly getAllFrames: (
    tabId: number,
  ) => PromiseLike<readonly WebsitePasskeyPolicyBrowserFrame[] | null | undefined>;
  readonly now?: () => number;
  readonly cacheTtlMs?: number;
  readonly maxHeaderEntries?: number;
  readonly maxReportEntries?: number;
  readonly maxEpochEntries?: number;
  readonly featurePolicyProbe?: WebsitePasskeyFeaturePolicyProbeBoundary;
}

interface HeaderEntry {
  readonly key: string;
  readonly tabId: number;
  readonly frameId: number;
  readonly documentId: string;
  readonly url: string;
  readonly policy: WebsitePasskeyHeaderPolicy;
  readonly expiresAt: number;
}

interface ReportEntry {
  readonly key: string;
  readonly tabId: number;
  readonly frameId: number;
  readonly documentId: string;
  readonly url: string;
  readonly iframes: readonly WebsitePasskeyIframeAllowReportEntry[];
  readonly expiresAt: number;
}

interface ProofState {
  readonly authority: 'browser' | 'reconstructed';
  readonly epochEra: number;
  readonly lineageFingerprint: string;
  readonly headerEntries: readonly HeaderEntry[];
  readonly reportEntries: readonly ReportEntry[];
  readonly epochs: readonly Readonly<{ key: string; value: number }>[];
  readonly expiresAt?: number;
}

/** Owns strict response/container caches and issues revocable browser-lineage policy proofs. */
export class WebsitePasskeyPermissionsPolicyResolver implements WebsitePasskeyPermissionsPolicyBoundary {
  readonly #getAllFrames: WebsitePasskeyPermissionsPolicyResolverDeps['getAllFrames'];
  readonly #featurePolicyProbe: WebsitePasskeyFeaturePolicyProbeBoundary | undefined;
  readonly #now: () => number;
  readonly #ttlMs: number;
  readonly #maxHeaderEntries: number;
  readonly #maxReportEntries: number;
  readonly #maxEpochEntries: number;
  readonly #headers = new Map<string, HeaderEntry>();
  readonly #reports = new Map<string, ReportEntry>();
  readonly #epochs = new Map<string, number>();
  readonly #proofs = new WeakMap<object, ProofState>();
  #epochEra = 0;
  #nextEpoch = 0;
  #lastTime = 0;

  constructor(deps: WebsitePasskeyPermissionsPolicyResolverDeps) {
    if (!deps || typeof deps.getAllFrames !== 'function') throw new TypeError('getAllFrames is required');
    this.#getAllFrames = deps.getAllFrames;
    if (deps.featurePolicyProbe !== undefined
        && typeof deps.featurePolicyProbe?.probe !== 'function') {
      throw new TypeError('featurePolicyProbe is invalid');
    }
    this.#featurePolicyProbe = deps.featurePolicyProbe;
    this.#now = deps.now ?? Date.now;
    this.#ttlMs = boundedPositiveInteger(deps.cacheTtlMs, DEFAULT_CACHE_TTL_MS, 24 * 60 * 60_000);
    this.#maxHeaderEntries = boundedPositiveInteger(
      deps.maxHeaderEntries,
      DEFAULT_MAX_CACHE_ENTRIES,
      4_096,
    );
    this.#maxReportEntries = boundedPositiveInteger(
      deps.maxReportEntries,
      DEFAULT_MAX_CACHE_ENTRIES,
      4_096,
    );
    this.#maxEpochEntries = boundedPositiveInteger(
      deps.maxEpochEntries,
      DEFAULT_MAX_EPOCH_ENTRIES,
      32_768,
    );
  }

  /** Record one browser-owned document response, including a known absence of the header. */
  recordResponse(observation: WebsitePasskeyPolicyResponseObservation): boolean {
    const key = tentativeFrameKey(observation);
    const parsed = parseResponseObservation(observation, this.#deadline());
    if (!parsed) {
      if (key) this.#deleteHeader(key);
      return false;
    }
    this.#deleteHeader(parsed.key, false);
    this.#headers.set(parsed.key, parsed);
    this.#bump(frameEpochKey(parsed.tabId, parsed.frameId));
    this.#trim(this.#headers, this.#maxHeaderEntries, (entry) => {
      this.#bump(frameEpochKey(entry.tabId, entry.frameId));
    });
    return true;
  }

  /** Revoke the previous document while retaining an exact pre-commit response observation. */
  recordCommittedNavigation(navigation: WebsitePasskeyPolicyCommittedNavigation): boolean {
    const key = tentativeFrameKey(navigation);
    const parsed = parseCommittedNavigation(navigation);
    if (!key || !parsed) {
      if (key) this.invalidateFrame(navigation.tabId, navigation.frameId);
      return false;
    }
    const header = this.#headers.get(key);
    const retained = header !== undefined
      && header.documentId === parsed.documentId
      && header.url === parsed.url;
    if (!retained) this.#headers.delete(key);
    // A committed document never inherits the prior document's descendant inventory.
    this.#reports.delete(key);
    this.#bump(frameEpochKey(parsed.tabId, parsed.frameId));
    return retained;
  }

  /** Rebind policy evidence after a browser-owned History API or fragment URL transition. */
  recordSameDocumentNavigation(navigation: WebsitePasskeyPolicyCommittedNavigation): boolean {
    const key = tentativeFrameKey(navigation);
    const parsed = parseCommittedNavigation(navigation);
    if (!key || !parsed) {
      if (key) this.invalidateFrame(navigation.tabId, navigation.frameId);
      return false;
    }
    const header = this.#headers.get(key);
    const retained = header !== undefined && header.documentId === parsed.documentId;
    if (retained) {
      this.#headers.set(key, Object.freeze({ ...header, url: parsed.url }));
    } else {
      this.#headers.delete(key);
    }
    const report = this.#reports.get(key);
    if (report?.documentId === parsed.documentId) {
      this.#reports.set(key, Object.freeze({ ...report, url: parsed.url }));
    } else {
      this.#reports.delete(key);
    }
    this.#bump(frameEpochKey(parsed.tabId, parsed.frameId));
    return retained;
  }

  /** Accept iframe attributes only from the exact browser-bound parent document that reported them. */
  async recordIframeAllowReport(
    sender: WebsitePasskeyIframeAllowReportSender,
    report: unknown,
  ): Promise<boolean> {
    const key = tentativeFrameKey(sender);
    const parsedSender = parseReportSender(sender);
    const parsedReport = parseIframeReport(report);
    if (!parsedSender || !parsedReport) {
      if (key) this.#deleteReport(key);
      return false;
    }

    // A report is a full snapshot. Revoke the previous snapshot before browser validation so a
    // delayed or abandoned refresh can never leave stale container policy authoritative.
    this.#deleteReport(parsedSender.key);

    const epochEra = this.#epochEra;
    const tabEpoch = this.#epochValue(tabEpochKey(sender.tabId));
    const frameEpoch = this.#epochValue(frameEpochKey(sender.tabId, sender.frameId));
    let frames: ReadonlyMap<number, WebsitePasskeyPolicyFrame>;
    try {
      frames = await this.#readFrameMap(sender.tabId);
    } catch {
      this.#deleteReport(parsedSender.key);
      return false;
    }
    if (epochEra !== this.#epochEra
      || tabEpoch !== this.#epochValue(tabEpochKey(sender.tabId))
      || frameEpoch !== this.#epochValue(frameEpochKey(sender.tabId, sender.frameId))) return false;
    const browserFrame = frames.get(sender.frameId);
    if (!browserFrame
      || browserFrame.documentId !== sender.documentId
      || browserFrame.url !== sender.url) {
      this.#deleteReport(parsedSender.key);
      return false;
    }

    const entry: ReportEntry = Object.freeze({
      ...parsedSender,
      iframes: parsedReport,
      expiresAt: this.#deadline(),
    });
    this.#reports.set(entry.key, entry);
    this.#bump(frameEpochKey(entry.tabId, entry.frameId));
    this.#trim(this.#reports, this.#maxReportEntries, (removed) => {
      this.#bump(frameEpochKey(removed.tabId, removed.frameId));
    });
    return true;
  }

  async capture(
    context: WebsitePasskeyDocumentContext,
    operation: WebsitePasskeyOperation,
  ): Promise<WebsitePasskeyPermissionsPolicyProof> {
    assertOperation(operation);
    validateContext(context);
    const initialBrowserLineage = await this.#readLineage(context, false);
    const probeEpochEra = this.#epochEra;
    const probeEpochs = this.#captureEpochs(context.tabId, initialBrowserLineage);
    const probed = await this.#probe(context);
    if (probed.status === 'available') {
      if (probeEpochEra !== this.#epochEra || !this.#epochsAreCurrent(probeEpochs)) {
        throw policyError();
      }
      if (!probed[operation]) throw policyError();
      const lineage = await this.#readLineage(context, false);
      if (probeEpochEra !== this.#epochEra
        || !this.#epochsAreCurrent(probeEpochs)
        || fingerprint(lineage) !== fingerprint(initialBrowserLineage)) throw policyError();
      const proof = createProof(context, operation, lineage);
      this.#proofs.set(proof, browserProofState(
        lineage,
        this.#epochEra,
        probeEpochs,
      ));
      return proof;
    }

    const epochEra = this.#epochEra;
    const tabEpoch = this.#epochValue(tabEpochKey(context.tabId));
    const lineage = await this.#readLineage(context);
    if (epochEra !== this.#epochEra
      || tabEpoch !== this.#epochValue(tabEpochKey(context.tabId))) throw policyError();
    const authorization = this.#authorize(context.tabId, lineage, operation);
    const expiresAt = Math.min(
      ...authorization.headers.map((entry) => entry.expiresAt),
      ...authorization.reports.map((entry) => entry.expiresAt),
    );
    if (!Number.isFinite(expiresAt) || expiresAt <= this.#time()) throw policyError();
    const proof = createProof(context, operation, lineage);
    this.#proofs.set(proof, Object.freeze({
      authority: 'reconstructed' as const,
      epochEra: this.#epochEra,
      lineageFingerprint: fingerprint(lineage),
      headerEntries: authorization.headers,
      reportEntries: authorization.reports,
      epochs: this.#captureEpochs(context.tabId, lineage),
      expiresAt,
    }));
    return proof;
  }

  assert(
    proof: WebsitePasskeyPermissionsPolicyProof,
    context: WebsitePasskeyDocumentContext,
    operation: WebsitePasskeyOperation,
  ): void {
    const state = this.#proofs.get(proof);
    if (!state
      || proof.tabId !== context.tabId
      || proof.frameId !== context.frameId
      || proof.documentId !== context.documentId
      || proof.url !== context.url
      || proof.origin !== context.origin
      || proof.operation !== operation
      || state.epochEra !== this.#epochEra
      || state.epochs.some((epoch) => this.#epochValue(epoch.key) !== epoch.value)
      || (state.authority === 'reconstructed' && (
        state.expiresAt === undefined
        || state.expiresAt <= this.#time()
        || state.headerEntries.some((entry) => this.#headers.get(entry.key) !== entry)
        || state.reportEntries.some((entry) => this.#reports.get(entry.key) !== entry)
      ))) {
      throw policyError();
    }
  }

  async assertCurrent(
    proof: WebsitePasskeyPermissionsPolicyProof,
    context: WebsitePasskeyDocumentContext,
    operation: WebsitePasskeyOperation,
  ): Promise<void> {
    this.assert(proof, context, operation);
    const state = this.#proofs.get(proof)!;
    const probed = await this.#probe(context);
    if (probed.status === 'available') {
      if (!probed[operation]) throw policyError();
      const lineage = await this.#readLineage(context, false);
      if (state.epochEra !== this.#epochEra
        || !this.#epochsAreCurrent(state.epochs)
        || this.#proofs.get(proof) !== state
        || fingerprint(lineage) !== state.lineageFingerprint
        || proof.topOrigin !== lineage.at(-1)?.origin
        || proof.crossOrigin !== lineage.some((frame) => frame.origin !== context.origin)) {
        throw policyError();
      }
      this.#proofs.set(proof, browserProofState(
        lineage,
        this.#epochEra,
        this.#captureEpochs(context.tabId, lineage),
      ));
      return;
    }

    const epochEra = this.#epochEra;
    const tabEpoch = this.#epochValue(tabEpochKey(context.tabId));
    const lineage = await this.#readLineage(context);
    if (epochEra !== this.#epochEra
      || tabEpoch !== this.#epochValue(tabEpochKey(context.tabId))) throw policyError();
    const authorization = this.#authorize(context.tabId, lineage, operation);
    if (this.#proofs.get(proof) !== state
      || fingerprint(lineage) !== state.lineageFingerprint
      || proof.topOrigin !== lineage.at(-1)?.origin
      || proof.crossOrigin !== lineage.some((frame) => frame.origin !== context.origin)
    ) {
      throw policyError();
    }
    const expiresAt = Math.min(
      ...authorization.headers.map((entry) => entry.expiresAt),
      ...authorization.reports.map((entry) => entry.expiresAt),
    );
    if (!Number.isFinite(expiresAt) || expiresAt <= this.#time()) throw policyError();
    this.#proofs.set(proof, Object.freeze({
      authority: 'reconstructed' as const,
      epochEra: this.#epochEra,
      lineageFingerprint: fingerprint(lineage),
      headerEntries: authorization.headers,
      reportEntries: authorization.reports,
      epochs: this.#captureEpochs(context.tabId, lineage),
      expiresAt,
    }));
  }

  invalidateFrame(tabId: number, frameId: number): void {
    if (!nonNegativeInteger(tabId) || !nonNegativeInteger(frameId)) return;
    const key = frameKey(tabId, frameId);
    this.#headers.delete(key);
    this.#reports.delete(key);
    this.#bump(frameEpochKey(tabId, frameId));
  }

  invalidateTab(tabId: number): void {
    if (!nonNegativeInteger(tabId)) return;
    const prefix = `${tabId}:`;
    for (const key of this.#headers.keys()) if (key.startsWith(prefix)) this.#headers.delete(key);
    for (const key of this.#reports.keys()) if (key.startsWith(prefix)) this.#reports.delete(key);
    const frameEpochPrefix = `frame:${tabId}:`;
    for (const key of this.#epochs.keys()) {
      if (key.startsWith(frameEpochPrefix)) this.#epochs.delete(key);
    }
    this.#bump(tabEpochKey(tabId));
  }

  async #probe(
    context: WebsitePasskeyDocumentContext,
  ): Promise<WebsitePasskeyFeaturePolicyProbeResult> {
    if (!this.#featurePolicyProbe) return Object.freeze({ status: 'unavailable' as const });
    let result: unknown;
    try { result = await this.#featurePolicyProbe.probe(context); } catch { throw policyError(); }
    return parseFeaturePolicyProbeResult(result);
  }

  #authorize(
    tabId: number,
    lineage: readonly WebsitePasskeyPolicyFrame[],
    operation: WebsitePasskeyOperation,
  ): Readonly<{ headers: readonly HeaderEntry[]; reports: readonly ReportEntry[] }> {
    const feature = WEBSITE_PASSKEY_PERMISSIONS_POLICY_FEATURES[operation];
    const targetOrigin = lineage[0]!.origin;
    const now = this.#time();
    const headers: HeaderEntry[] = [];
    const reports: ReportEntry[] = [];

    for (let index = 0; index < lineage.length; index += 1) {
      const frame = lineage[index]!;
      const header = this.#headers.get(frameKey(tabId, frame.frameId));
      if (!header || !entryMatchesFrame(header, frame) || header.expiresAt <= now
        || !headerAllows(header.policy, feature, targetOrigin, frame.origin)) {
        throw policyError();
      }
      headers.push(header);
      if (index === lineage.length - 1) continue;

      const parent = lineage[index + 1]!;
      const report = this.#reports.get(frameKey(tabId, parent.frameId));
      if (!report || !entryMatchesFrame(report, parent) || report.expiresAt <= now) throw policyError();
      const matches = report.iframes.filter((iframe) => !iframe.srcdoc && iframe.src === frame.url);
      if (matches.length !== 1) throw policyError();
      const parsed = parseWebsitePasskeyIframeAllowAttribute(matches[0]!.allow, frame.origin, parent.origin);
      if (!parsed.ok || !containerAllows(parsed.value, feature, targetOrigin, parent.origin)) {
        throw policyError();
      }
      reports.push(report);
    }
    return Object.freeze({ headers: Object.freeze(headers), reports: Object.freeze(reports) });
  }

  async #readLineage(
    context: WebsitePasskeyDocumentContext,
    requireUniqueSource = true,
  ): Promise<readonly WebsitePasskeyPolicyFrame[]> {
    validateContext(context);
    const frames = await this.#readFrameMap(context.tabId);
    const target = frames.get(context.frameId);
    const top = frames.get(0);
    if (!target || !top
      || top.parentFrameId !== -1
      || target.documentId !== context.documentId
      || target.url !== context.url
      || target.origin !== context.origin) throw policyError();

    const lineage: WebsitePasskeyPolicyFrame[] = [];
    const seen = new Set<number>();
    let current = target;
    for (;;) {
      if (seen.has(current.frameId)) throw policyError();
      seen.add(current.frameId);
      lineage.push(current);
      if (current.frameId === 0) break;
      if (!nonNegativeInteger(current.parentFrameId)) throw policyError();
      const parent = frames.get(current.parentFrameId);
      if (!parent) throw policyError();
      if (requireUniqueSource) {
        let sameSourceSiblings = 0;
        for (const candidate of frames.values()) {
          if (candidate.parentFrameId === parent.frameId && candidate.url === current.url) {
            sameSourceSiblings += 1;
          }
        }
        if (sameSourceSiblings !== 1) throw policyError();
      }
      current = parent;
    }
    return Object.freeze(lineage);
  }

  async #readFrameMap(tabId: number): Promise<ReadonlyMap<number, WebsitePasskeyPolicyFrame>> {
    let rawFrames: readonly WebsitePasskeyPolicyBrowserFrame[] | null | undefined;
    try { rawFrames = await this.#getAllFrames(tabId); } catch { throw policyError(); }
    if (!Array.isArray(rawFrames) || rawFrames.length === 0 || rawFrames.length > 512) throw policyError();
    const frames = new Map<number, WebsitePasskeyPolicyFrame>();
    const seenFrameIds = new Set<number>();
    for (const raw of rawFrames) {
      if (!isRecord(raw) || !nonNegativeInteger(raw.frameId)) continue;
      if (seenFrameIds.has(raw.frameId)) throw policyError();
      seenFrameIds.add(raw.frameId);
      const frame = parseBrowserFrame(raw);
      if (frame) frames.set(frame.frameId, frame);
    }
    return frames;
  }

  #captureEpochs(
    tabId: number,
    lineage: readonly WebsitePasskeyPolicyFrame[],
  ): readonly Readonly<{ key: string; value: number }>[] {
    return Object.freeze([
      epochSnapshot(tabEpochKey(tabId), this.#epochValue(tabEpochKey(tabId))),
      ...lineage.map((frame) => {
        const key = frameEpochKey(tabId, frame.frameId);
        return epochSnapshot(key, this.#epochValue(key));
      }),
    ]);
  }

  #epochsAreCurrent(epochs: readonly Readonly<{ key: string; value: number }>[]): boolean {
    return epochs.every((epoch) => this.#epochValue(epoch.key) === epoch.value);
  }

  #deleteHeader(key: string, bump = true): void {
    const existing = this.#headers.get(key);
    this.#headers.delete(key);
    if (bump) {
      const ids = existing ?? parseKeyIds(key);
      if (ids) this.#bump(frameEpochKey(ids.tabId, ids.frameId));
    }
  }

  #deleteReport(key: string, bump = true): void {
    const existing = this.#reports.get(key);
    this.#reports.delete(key);
    if (bump) {
      const ids = existing ?? parseKeyIds(key);
      if (ids) this.#bump(frameEpochKey(ids.tabId, ids.frameId));
    }
  }

  #trim<Entry extends { readonly key: string }>(
    cache: Map<string, Entry>,
    maximum: number,
    onRemove: (entry: Entry) => void,
  ): void {
    while (cache.size > maximum) {
      const key = cache.keys().next().value as string | undefined;
      if (!key) break;
      const removed = cache.get(key);
      cache.delete(key);
      if (removed) onRemove(removed);
    }
  }

  #deadline(): number {
    const deadline = this.#time() + this.#ttlMs;
    if (!Number.isSafeInteger(deadline)) throw policyError();
    return deadline;
  }

  #time(): number {
    const now = this.#now();
    if (!Number.isSafeInteger(now) || now < 0) throw policyError();
    this.#lastTime = Math.max(this.#lastTime, now);
    return this.#lastTime;
  }

  #epochValue(key: string): number {
    return this.#epochs.get(key) ?? 0;
  }

  #bump(key: string): void {
    if ((!this.#epochs.has(key) && this.#epochs.size >= this.#maxEpochEntries)
      || this.#nextEpoch >= Number.MAX_SAFE_INTEGER) {
      const nextEra = this.#epochEra + 1;
      if (!Number.isSafeInteger(nextEra)) throw policyError();
      this.#epochEra = nextEra;
      this.#nextEpoch = 0;
      this.#epochs.clear();
    }
    this.#nextEpoch += 1;
    this.#epochs.set(key, this.#nextEpoch);
  }
}

function parseResponseObservation(
  value: WebsitePasskeyPolicyResponseObservation,
  expiresAt: number,
): HeaderEntry | undefined {
  if (!isRecord(value)
    || !hasExactKeys(value, ['tabId', 'frameId', 'documentId', 'url', 'type', 'responseHeaders'])
    || !nonNegativeInteger(value.tabId)
    || !nonNegativeInteger(value.frameId)
    || !validDocumentId(value.documentId)
    || (value.type !== 'main_frame' && value.type !== 'sub_frame')
    || (value.type === 'main_frame' ? value.frameId !== 0 : value.frameId === 0)
    || !validWebsiteUrl(value.url)
    || !Array.isArray(value.responseHeaders)
    || value.responseHeaders.length > MAX_RESPONSE_HEADERS) return undefined;

  const values: string[] = [];
  for (const header of value.responseHeaders) {
    if (!isRecord(header) || typeof header.name !== 'string') return undefined;
    if (header.name.toLowerCase() !== 'permissions-policy') continue;
    if (typeof header.value !== 'string') return undefined;
    values.push(header.value);
  }
  const parsed = parseWebsitePasskeyPermissionsPolicyHeader(values);
  if (!parsed.ok) return undefined;
  return Object.freeze({
    key: frameKey(value.tabId, value.frameId),
    tabId: value.tabId,
    frameId: value.frameId,
    documentId: value.documentId,
    url: value.url,
    policy: parsed.value,
    expiresAt,
  });
}

function parseCommittedNavigation(
  value: WebsitePasskeyPolicyCommittedNavigation,
): WebsitePasskeyPolicyCommittedNavigation | undefined {
  if (!isRecord(value)
    || !hasExactKeys(value, ['tabId', 'frameId', 'documentId', 'url'])
    || !nonNegativeInteger(value.tabId)
    || !nonNegativeInteger(value.frameId)
    || !validDocumentId(value.documentId)
    || !validWebsiteUrl(value.url)) return undefined;
  return Object.freeze({
    tabId: value.tabId,
    frameId: value.frameId,
    documentId: value.documentId,
    url: value.url,
  });
}

function parseReportSender(
  value: WebsitePasskeyIframeAllowReportSender,
): Omit<ReportEntry, 'iframes' | 'expiresAt'> | undefined {
  if (!isRecord(value)
    || !hasExactKeys(value, ['tabId', 'frameId', 'documentId', 'url'])
    || !nonNegativeInteger(value.tabId)
    || !nonNegativeInteger(value.frameId)
    || !validDocumentId(value.documentId)
    || !validWebsiteUrl(value.url)) return undefined;
  return Object.freeze({
    key: frameKey(value.tabId, value.frameId),
    tabId: value.tabId,
    frameId: value.frameId,
    documentId: value.documentId,
    url: value.url,
  });
}

function parseIframeReport(value: unknown): readonly WebsitePasskeyIframeAllowReportEntry[] | undefined {
  if (!isRecord(value) || !hasExactKeys(value, ['iframes'])
    || !Array.isArray(value.iframes) || value.iframes.length > MAX_IFRAMES_PER_REPORT) return undefined;
  const result: WebsitePasskeyIframeAllowReportEntry[] = [];
  for (let index = 0; index < value.iframes.length; index += 1) {
    if (!(index in value.iframes)) return undefined;
    const raw = value.iframes[index];
    if (!isRecord(raw) || !hasExactKeys(raw, ['src', 'allow', 'srcdoc'])
      || typeof raw.src !== 'string' || raw.src.length > MAX_URL_LENGTH
      || typeof raw.allow !== 'string'
      || typeof raw.srcdoc !== 'boolean'
      || /[\r\n\0]/u.test(raw.src)
      || /[\r\n\0]/u.test(raw.allow)) return undefined;
    if (!parseWebsitePasskeyIframeAllowAttribute(
      raw.allow,
      'https://child.invalid',
      'https://parent.invalid',
    ).ok) return undefined;
    let src = '';
    if (!raw.srcdoc && raw.src !== '') {
      try {
        const parsed = new URL(raw.src);
        if (parsed.username || parsed.password || parsed.href.length > MAX_URL_LENGTH) return undefined;
        src = parsed.href;
      } catch {
        return undefined;
      }
    } else if (raw.srcdoc && raw.src !== '') {
      return undefined;
    }
    result.push(Object.freeze({ src, allow: raw.allow, srcdoc: raw.srcdoc }));
  }
  return Object.freeze(result);
}

function parseBrowserFrame(value: WebsitePasskeyPolicyBrowserFrame): WebsitePasskeyPolicyFrame | undefined {
  if (!isRecord(value)
    || !nonNegativeInteger(value.frameId)
    || !Number.isSafeInteger(value.parentFrameId)
    || (value.parentFrameId as number) < -1
    || !validDocumentId(value.documentId)
    || !validWebsiteUrl(value.url)) return undefined;
  const url = new URL(value.url);
  return Object.freeze({
    frameId: value.frameId,
    parentFrameId: value.parentFrameId as number,
    documentId: value.documentId,
    url: value.url,
    origin: url.origin,
  });
}

function headerAllows(
  policy: WebsitePasskeyHeaderPolicy,
  feature: WebsitePasskeyPermissionsPolicyFeature,
  targetOrigin: string,
  ownerOrigin: string,
): boolean {
  const allowlist = policy[feature];
  return allowlist === undefined || allowlist.some((item) => headerItemMatches(item, targetOrigin, ownerOrigin));
}

function headerItemMatches(
  item: WebsitePasskeyPolicyAllowlistItem,
  targetOrigin: string,
  ownerOrigin: string,
): boolean {
  return item.type === 'wildcard'
    || (item.type === 'self' && targetOrigin === ownerOrigin)
    || (item.type === 'origin' && item.value === targetOrigin);
}

function containerAllows(
  policy: WebsitePasskeyContainerPolicy,
  feature: WebsitePasskeyPermissionsPolicyFeature,
  targetOrigin: string,
  parentOrigin: string,
): boolean {
  const allowlist = policy[feature];
  if (allowlist === undefined) return targetOrigin === parentOrigin;
  return allowlist.some((item) => resolvedItemMatches(item, targetOrigin));
}

function resolvedItemMatches(
  item: WebsitePasskeyResolvedPolicyAllowlistItem,
  targetOrigin: string,
): boolean {
  return item.type === 'wildcard' || item.value === targetOrigin;
}

function entryMatchesFrame(
  entry: Pick<HeaderEntry, 'frameId' | 'documentId' | 'url'>,
  frame: WebsitePasskeyPolicyFrame,
): boolean {
  return entry.frameId === frame.frameId
    && entry.documentId === frame.documentId
    && entry.url === frame.url;
}

function validateContext(context: WebsitePasskeyDocumentContext): void {
  if (!isRecord(context)
    || !nonNegativeInteger(context.tabId)
    || !nonNegativeInteger(context.frameId)
    || !validDocumentId(context.documentId)
    || !validWebsiteUrl(context.url)) throw policyError();
  if (new URL(context.url).origin !== context.origin) throw policyError();
}

function validWebsiteUrl(value: unknown): value is string {
  if (typeof value !== 'string' || !value || value.length > MAX_URL_LENGTH
    || value.trim() !== value || /[\r\n\0]/u.test(value)
    || !websitePasskeyOriginMatchPattern(value)) return false;
  try {
    const url = new URL(value);
    return !url.username && !url.password && url.origin !== 'null';
  } catch {
    return false;
  }
}

function validDocumentId(value: unknown): value is string {
  if (typeof value !== 'string' || !value || value.length > MAX_DOCUMENT_ID_LENGTH
    || value.trim() !== value) return false;
  return ![...value].some((character) => {
    const code = character.codePointAt(0) ?? 0;
    return code <= 0x1f || code === 0x7f;
  });
}

function assertOperation(value: unknown): asserts value is WebsitePasskeyOperation {
  if (value !== 'create' && value !== 'get') throw policyError();
}

function boundedPositiveInteger(value: number | undefined, fallback: number, maximum: number): number {
  const resolved = value ?? fallback;
  if (!Number.isSafeInteger(resolved) || resolved <= 0 || resolved > maximum) {
    throw new TypeError('Invalid Permissions Policy cache limit');
  }
  return resolved;
}

function fingerprint(lineage: readonly WebsitePasskeyPolicyFrame[]): string {
  return JSON.stringify(lineage.map((frame) => [
    frame.frameId,
    frame.parentFrameId,
    frame.documentId,
    frame.url,
    frame.origin,
  ]));
}

function createProof(
  context: WebsitePasskeyDocumentContext,
  operation: WebsitePasskeyOperation,
  lineage: readonly WebsitePasskeyPolicyFrame[],
): WebsitePasskeyPermissionsPolicyProof {
  return Object.freeze({
    tabId: context.tabId,
    frameId: context.frameId,
    documentId: context.documentId,
    url: context.url,
    origin: context.origin,
    operation,
    topOrigin: lineage.at(-1)!.origin,
    crossOrigin: lineage.some((frame) => frame.origin !== context.origin),
    lineage,
  });
}

function browserProofState(
  lineage: readonly WebsitePasskeyPolicyFrame[],
  epochEra: number,
  epochs: readonly Readonly<{ key: string; value: number }>[],
): ProofState {
  return Object.freeze({
    authority: 'browser' as const,
    epochEra,
    lineageFingerprint: fingerprint(lineage),
    headerEntries: Object.freeze([]),
    reportEntries: Object.freeze([]),
    epochs,
  });
}

function parseFeaturePolicyProbeResult(input: unknown): WebsitePasskeyFeaturePolicyProbeResult {
  if (!isRecord(input)) throw policyError();
  const keys = Reflect.ownKeys(input);
  if (keys.some((key) => typeof key !== 'string' || !isDataProperty(input, key))) {
    throw policyError();
  }
  const status = dataProperty(input, 'status');
  if (status === 'unavailable') {
    if (keys.length !== 1 || keys[0] !== 'status') throw policyError();
    return Object.freeze({ status: 'unavailable' as const });
  }
  const get = dataProperty(input, 'get');
  const create = dataProperty(input, 'create');
  if (status !== 'available'
    || keys.length !== 3
    || !['status', 'get', 'create'].every((key) => keys.includes(key))
    || !keys.every((key) => typeof key === 'string' && ['status', 'get', 'create'].includes(key))
    || typeof get !== 'boolean'
    || typeof create !== 'boolean') throw policyError();
  return Object.freeze({ status: 'available' as const, get, create });
}

function isDataProperty(value: Record<string, unknown>, key: string): boolean {
  const descriptor = Object.getOwnPropertyDescriptor(value, key);
  return Boolean(descriptor?.enumerable && 'value' in descriptor && descriptor.value !== undefined);
}

function dataProperty(value: Record<string, unknown>, key: string): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(value, key);
  return descriptor?.enumerable && 'value' in descriptor ? descriptor.value : undefined;
}

function epochSnapshot(key: string, value: number): Readonly<{ key: string; value: number }> {
  return Object.freeze({ key, value });
}

function frameKey(tabId: number, frameId: number): string {
  return `${tabId}:${frameId}`;
}

function tentativeFrameKey(value: unknown): string | undefined {
  return isRecord(value) && nonNegativeInteger(value.tabId) && nonNegativeInteger(value.frameId)
    ? frameKey(value.tabId, value.frameId)
    : undefined;
}

function parseKeyIds(key: string): Readonly<{ tabId: number; frameId: number }> | undefined {
  const match = /^(0|[1-9]\d*):(0|[1-9]\d*)$/u.exec(key);
  if (!match) return undefined;
  const tabId = Number(match[1]);
  const frameId = Number(match[2]);
  return nonNegativeInteger(tabId) && nonNegativeInteger(frameId) ? Object.freeze({ tabId, frameId }) : undefined;
}

function tabEpochKey(tabId: number): string {
  return `tab:${tabId}`;
}

function frameEpochKey(tabId: number, frameId: number): string {
  return `frame:${tabId}:${frameId}`;
}

function nonNegativeInteger(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 && !Object.is(value, -0);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function hasExactKeys(value: Record<string, unknown>, expected: readonly string[]): boolean {
  const keys = Reflect.ownKeys(value);
  return keys.length === expected.length
    && keys.every((key) => typeof key === 'string' && expected.includes(key));
}

function policyError(): AppError {
  return new AppError('denied', POLICY_ERROR_MESSAGE);
}
