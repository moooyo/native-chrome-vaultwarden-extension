import type {
  AutofillCandidate,
  AutofillCredentials,
  FrameAutofillMessage,
  FrameInspection,
  FrameLoginForm,
  TabAutofillSuggestion,
  TabFillOutcome,
  TabSuggestionsOutcome,
  TabSuggestionTarget,
} from '../messaging/protocol.js';
import { AppError } from '../core/errors.js';

/** A frame within a tab, as reported by the browser (`webNavigation`) — never by page content.
 *  `documentId` (Chrome-only) is used to detect a same-frameId navigation between Suggestions and
 *  Fill (the TOCTOU guard); it is omitted when the browser does not report one. */
export interface BrowserFrame {
  frameId: number;
  url: string;
  documentId?: string;
}

/** Narrow browser adapters the coordinator depends on. Every authoritative fact about the active
 *  tab, its frames, and their URLs comes from these — never from popup input. */
export interface TabAutofillDeps {
  getTab(tabId: number): Promise<{ active: boolean; url?: string }>;
  /** Permanent host-permission check (`permissions.contains`). Only consulted for frames whose
   *  origin differs from the tab's own — the tab/top-frame/same-origin case is already covered by
   *  the activeTab grant that is implied by `getTab` exposing a `url` at all, and must not be
   *  rejected just because no permanent optional host permission was granted. */
  hasHostAccess(url: string): Promise<boolean>;
  getFrames(tabId: number): Promise<BrowserFrame[]>;
  getFrame(tabId: number, frameId: number): Promise<BrowserFrame | undefined>;
  sendToFrame(tabId: number, frameId: number, message: FrameAutofillMessage): Promise<unknown>;
  findCandidates(frameUrl: string): Promise<AutofillCandidate[]>;
  getCredentials(cipherId: string, frameUrl: string): Promise<AutofillCredentials>;
  now(): number;
}

export interface TabAutofillCoordinator {
  getSuggestions(tabId: number): Promise<TabSuggestionsOutcome>;
  fill(tabId: number, cipherId: string, target: TabSuggestionTarget): Promise<TabFillOutcome>;
}

const RECENT_FOCUS_WINDOW_MS = 30_000;

interface FormRank {
  /** 0 when focused within the last 30s, 1 otherwise. Lower is better. */
  focusScore: number;
  /** 0 for the top frame, 1 otherwise. Lower is better. */
  topScore: number;
  /** Encounter order across frames/forms — earlier wins ties. Lower is better. */
  order: number;
}

export function createTabAutofillCoordinator(deps: TabAutofillDeps): TabAutofillCoordinator {
  async function getSuggestions(tabId: number): Promise<TabSuggestionsOutcome> {
    const tab = await deps.getTab(tabId);
    if (!tab.active) return { status: 'no_eligible_tab', suggestions: [] };
    if (tab.url === undefined) return { status: 'site_access_unavailable', suggestions: [] };
    if (isRestrictedUrl(tab.url)) return { status: 'restricted_page', suggestions: [] };
    const topUrl = tab.url;

    const frames = await deps.getFrames(tabId);
    const inspected: Array<{ frame: BrowserFrame; inspection: FrameInspection }> = [];
    let attempted = 0;
    for (const frame of frames) {
      const accessible = frame.frameId === 0 || sameOrigin(frame.url, topUrl) || (await deps.hasHostAccess(frame.url));
      if (!accessible) continue;
      attempted += 1;
      // A single frame's content script may be missing or unresponsive (e.g. a restricted embed);
      // skip only that frame rather than failing the whole tab.
      try {
        const response = await deps.sendToFrame(tabId, frame.frameId, { type: 'autofill.inspectFrame' });
        const inspection = parseFrameInspection(response);
        if (inspection) inspected.push({ frame, inspection });
      } catch {
        continue;
      }
    }

    if (attempted > 0 && inspected.length === 0) {
      return { status: 'content_script_unavailable', suggestions: [] };
    }

    const merged = new Map<string, TabAutofillSuggestion>();
    // Always match the top-frame URI so a row can open detail even when no form was ever found.
    for (const candidate of await deps.findCandidates(topUrl)) {
      merged.set(candidate.id, { ...candidate });
    }

    const bestRank = new Map<string, { rank: FormRank; target: TabSuggestionTarget }>();
    let order = 0;
    for (const { frame, inspection } of inspected) {
      const frameCandidates = await deps.findCandidates(inspection.frameUrl);
      for (const candidate of frameCandidates) {
        if (!merged.has(candidate.id)) merged.set(candidate.id, { ...candidate });
      }
      for (const form of inspection.forms) {
        const rank: FormRank = {
          focusScore: form.focusedAt !== undefined && deps.now() - form.focusedAt <= RECENT_FOCUS_WINDOW_MS ? 0 : 1,
          topScore: frame.frameId === 0 ? 0 : 1,
          order: order++,
        };
        const target: TabSuggestionTarget = {
          frameId: frame.frameId,
          formId: form.formId,
          ...(frame.documentId !== undefined ? { documentId: frame.documentId } : {}),
        };
        for (const candidate of frameCandidates) {
          const current = bestRank.get(candidate.id);
          if (!current || compareFormRank(rank, current.rank) < 0) {
            bestRank.set(candidate.id, { rank, target });
          }
        }
      }
    }

    for (const [cipherId, best] of bestRank) {
      const suggestion = merged.get(cipherId);
      if (suggestion) suggestion.target = best.target;
    }

    return { status: 'ready', suggestions: Array.from(merged.values()) };
  }

  async function fill(tabId: number, cipherId: string, target: TabSuggestionTarget): Promise<TabFillOutcome> {
    const tab = await deps.getTab(tabId);
    if (!tab.active) return { status: 'no_eligible_tab' };
    if (tab.url === undefined) return { status: 'site_access_unavailable' };
    if (isRestrictedUrl(tab.url)) return { status: 'restricted_page' };

    // Re-read the frame's current URL/documentId — never trust anything the popup remembered.
    const frame = await deps.getFrame(tabId, target.frameId);
    if (!frame) return { status: 'content_script_unavailable' };
    if (target.documentId !== undefined && target.documentId !== frame.documentId) {
      return { status: 'target_changed' };
    }

    let credentials: AutofillCredentials;
    try {
      // Reuses the existing URI-match + reprompt guard; a stale/mismatched URL denies here.
      credentials = await deps.getCredentials(cipherId, frame.url);
    } catch (err) {
      if (err instanceof AppError) return { status: 'no_fillable_target' };
      throw err;
    }

    const response = await deps.sendToFrame(tabId, target.frameId, {
      type: 'autofill.commitLoginFill',
      formId: target.formId,
      expectedFrameUrl: frame.url,
      credentials,
    });
    return parseTabFillOutcome(response) ?? { status: 'content_script_unavailable' };
  }

  return { getSuggestions, fill };
}

/** Reads a frame-like value returned by `webNavigation.getAllFrames`/`getFrame`, which may carry a
 *  Chrome-only `documentId` field the shared browser types don't declare. */
export function parseBrowserFrame(value: unknown): BrowserFrame | undefined {
  if (!isRecord(value)) return undefined;
  const { frameId, url, documentId } = value;
  if (typeof frameId !== 'number' || typeof url !== 'string') return undefined;
  if (documentId !== undefined && typeof documentId !== 'string') return undefined;
  return documentId !== undefined ? { frameId, url, documentId } : { frameId, url };
}

function compareFormRank(a: FormRank, b: FormRank): number {
  if (a.focusScore !== b.focusScore) return a.focusScore - b.focusScore;
  if (a.topScore !== b.topScore) return a.topScore - b.topScore;
  return a.order - b.order;
}

/** Same scheme+host+port. Falls back to an exact string match if either URL fails to parse. */
function sameOrigin(a: string, b: string): boolean {
  try {
    return new URL(a).origin === new URL(b).origin;
  } catch {
    return a === b;
  }
}

const RESTRICTED_HOSTS = /^https:\/\/(chrome\.google\.com\/webstore|chromewebstore\.google\.com)(\/|$)/i;

/** Anything that isn't http(s) (chrome://, edge://, about:, file://, view-source:, …) plus the
 *  Chrome Web Store, which stays off-limits to extensions even though it is served over https. */
function isRestrictedUrl(url: string): boolean {
  if (!/^https?:\/\//i.test(url)) return true;
  return RESTRICTED_HOSTS.test(url);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isFrameLoginForm(value: unknown): value is FrameLoginForm {
  if (!isRecord(value)) return false;
  const { formId, visible, focusedAt } = value;
  if (typeof formId !== 'string' || typeof visible !== 'boolean') return false;
  return focusedAt === undefined || typeof focusedAt === 'number';
}

function parseFrameInspection(value: unknown): FrameInspection | undefined {
  if (!isRecord(value)) return undefined;
  const { frameUrl, forms } = value;
  if (typeof frameUrl !== 'string' || !Array.isArray(forms) || !forms.every(isFrameLoginForm)) return undefined;
  return { frameUrl, forms };
}

function parseTabFillOutcome(value: unknown): TabFillOutcome | undefined {
  if (!isRecord(value)) return undefined;
  const { status } = value;
  if (typeof status !== 'string') return undefined;
  switch (status) {
    case 'filled':
    case 'no_eligible_tab':
    case 'site_access_unavailable':
    case 'no_fillable_target':
    case 'target_changed':
    case 'restricted_page':
    case 'content_script_unavailable':
      return { status };
    default:
      return undefined;
  }
}
