import {
  MAX_WEBSITE_PASSKEY_IFRAME_INVENTORY,
  WEBSITE_PASSKEY_IFRAME_INVENTORY_REQUEST,
  type WebsitePasskeyIframeInventoryEntry,
  type WebsitePasskeyIframeInventoryRequest,
} from '../messaging/website-passkey-iframe-inventory.js';

export interface WebsitePasskeyIframeReporterDependencies {
  readonly report: (request: unknown) => unknown | PromiseLike<unknown>;
  readonly document?: Document;
  readonly createObserver?: (callback: MutationCallback) => MutationObserver;
  readonly schedule?: (callback: () => void) => void;
  readonly scheduleShadowRootRescan?: (callback: () => void) => () => void;
}

const MAX_TRAVERSED_ELEMENTS = 16_384;
const SHADOW_ROOT_RESCAN_MS = 1_000;

interface InventorySnapshot {
  readonly request: WebsitePasskeyIframeInventoryRequest | unknown;
  readonly fingerprint?: string;
}

/** Reports complete iframe container-policy snapshots from the isolated world. */
export class WebsitePasskeyIframeReporter {
  readonly #document: Document;
  readonly #observer: MutationObserver;
  readonly #scheduleCallback: (callback: () => void) => void;
  readonly #scheduleShadowRootRescan: (callback: () => void) => () => void;
  readonly #observedRoots = new Set<Document | ShadowRoot>();
  readonly #onPageShow = (): void => this.forceRefresh();
  #started = false;
  #stopped = false;
  #scheduled = false;
  #inFlight = false;
  #dirty = false;
  #lastAcknowledgedFingerprint: string | undefined;
  #stopShadowRootRescan: (() => void) | undefined;

  constructor(private readonly dependencies: WebsitePasskeyIframeReporterDependencies) {
    if (!dependencies || typeof dependencies.report !== 'function') {
      throw new TypeError('Website passkey iframe reporter requires a transport');
    }
    this.#document = dependencies.document ?? document;
    const createObserver = dependencies.createObserver
      ?? ((callback: MutationCallback) => new MutationObserver(callback));
    this.#observer = createObserver(() => this.markDirty());
    this.#scheduleCallback = dependencies.schedule ?? queueMicrotask;
    this.#scheduleShadowRootRescan = dependencies.scheduleShadowRootRescan ?? ((callback) => {
      const view = this.#document.defaultView;
      if (!view) return () => {};
      const handle = view.setInterval(callback, SHADOW_ROOT_RESCAN_MS);
      return () => view.clearInterval(handle);
    });
  }

  start(): void {
    if (this.#started || this.#stopped) return;
    this.#started = true;
    this.#document.defaultView?.addEventListener('pageshow', this.#onPageShow);
    this.#observe(this.#document);
    this.#stopShadowRootRescan = this.#scheduleShadowRootRescan(() => this.markDirty());
    this.markDirty();
  }

  stop(): void {
    if (this.#stopped) return;
    this.#stopped = true;
    this.#dirty = false;
    this.#observer.disconnect();
    try { this.#stopShadowRootRescan?.(); } catch { /* Reporter teardown remains authoritative. */ }
    this.#stopShadowRootRescan = undefined;
    this.#document.defaultView?.removeEventListener('pageshow', this.#onPageShow);
    this.#observedRoots.clear();
  }

  markDirty(): void {
    if (this.#stopped) return;
    this.#dirty = true;
    if (this.#scheduled || this.#inFlight) return;
    this.#scheduled = true;
    this.#scheduleCallback(() => {
      this.#scheduled = false;
      void this.#flush();
    });
  }

  forceRefresh(): void {
    this.#lastAcknowledgedFingerprint = undefined;
    this.markDirty();
  }

  async #flush(): Promise<void> {
    if (this.#stopped || this.#inFlight || !this.#dirty) return;
    this.#dirty = false;
    this.#inFlight = true;
    try {
      const snapshot = this.#snapshot();
      if (snapshot.fingerprint === undefined
          || snapshot.fingerprint !== this.#lastAcknowledgedFingerprint) {
        const response = await this.dependencies.report(snapshot.request);
        if (snapshot.fingerprint !== undefined && isAcknowledged(response)) {
          this.#lastAcknowledgedFingerprint = snapshot.fingerprint;
        }
      }
    } catch {
      // The next DOM mutation or bridge refresh will retry a complete snapshot.
    } finally {
      this.#inFlight = false;
      if (this.#dirty) this.markDirty();
    }
  }

  #snapshot(): InventorySnapshot {
    const iframes: WebsitePasskeyIframeInventoryEntry[] = [];
    const pending: Array<Document | ShadowRoot> = [this.#document];
    const visited = new Set<Document | ShadowRoot>();
    let traversedElements = 0;
    while (pending.length > 0) {
      const root = pending.shift()!;
      if (visited.has(root)) continue;
      visited.add(root);
      this.#observe(root);
      for (const element of root.querySelectorAll('*')) {
        traversedElements += 1;
        if (traversedElements > MAX_TRAVERSED_ELEMENTS) {
          return Object.freeze({ request: overLimitRevocationSnapshot() });
        }
        if (element instanceof HTMLIFrameElement) {
          iframes.push(iframeEntry(element, this.#document));
          if (iframes.length > MAX_WEBSITE_PASSKEY_IFRAME_INVENTORY) {
            return Object.freeze({ request: overLimitRevocationSnapshot() });
          }
        }
        if (element.shadowRoot) pending.push(element.shadowRoot);
      }
    }
    const request = Object.freeze({
      type: WEBSITE_PASSKEY_IFRAME_INVENTORY_REQUEST,
      iframes: Object.freeze(iframes),
    });
    return Object.freeze({ request, fingerprint: JSON.stringify(request.iframes) });
  }

  #observe(root: Document | ShadowRoot): void {
    if (this.#observedRoots.has(root)) return;
    this.#observedRoots.add(root);
    this.#observer.observe(root, {
      attributes: true,
      attributeFilter: ['allow', 'href', 'src', 'srcdoc'],
      childList: true,
      subtree: true,
    });
  }
}

function isAcknowledged(value: unknown): boolean {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const record = value as Record<string, unknown>;
  const keys = Reflect.ownKeys(record);
  if (keys.length !== 2 || !keys.includes('ok') || !keys.includes('data')) return false;
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(record, key);
    if (!descriptor?.enumerable || !('value' in descriptor)) return false;
  }
  return record.ok === true && record.data === null;
}

function iframeEntry(
  iframe: HTMLIFrameElement,
  ownerDocument: Document,
): WebsitePasskeyIframeInventoryEntry {
  const srcdoc = iframe.hasAttribute('srcdoc');
  const hasSrc = iframe.hasAttribute('src');
  let src = '';
  if (!srcdoc && hasSrc) {
    try {
      const getter = Object.getOwnPropertyDescriptor(
        ownerDocument.defaultView?.HTMLIFrameElement.prototype
          ?? HTMLIFrameElement.prototype,
        'src',
      )?.get;
      src = typeof getter === 'function'
        ? Reflect.apply(getter, iframe, []) as string
        : new URL(iframe.getAttribute('src') ?? '', ownerDocument.baseURI).href;
    } catch {
      src = iframe.getAttribute('src') ?? '';
    }
  }
  return Object.freeze({
    src,
    allow: iframe.getAttribute('allow') ?? '',
    srcdoc,
  });
}

function overLimitRevocationSnapshot(): unknown {
  const sentinel = Object.freeze({ src: '', allow: '', srcdoc: false });
  return Object.freeze({
    type: WEBSITE_PASSKEY_IFRAME_INVENTORY_REQUEST,
    iframes: Object.freeze(Array.from(
      { length: MAX_WEBSITE_PASSKEY_IFRAME_INVENTORY + 1 },
      () => sentinel,
    )),
  });
}
