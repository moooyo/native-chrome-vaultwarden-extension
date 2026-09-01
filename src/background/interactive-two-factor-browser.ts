import {
  createInteractiveTwoFactorConnectorCaller,
  parseInteractiveTwoFactorDocumentId,
  type InteractiveTwoFactorConnectorCaller,
} from '../core/session/interactive-two-factor.js';

const DEFAULT_COMMIT_TIMEOUT_MS = 15_000;

export type InteractiveTwoFactorConnectorDocument = InteractiveTwoFactorConnectorCaller;

export interface InteractiveTwoFactorNavigationDetails {
  readonly tabId: number;
  readonly frameId: number;
  readonly documentId?: string;
  readonly url: string;
}

export interface InteractiveTwoFactorFrameDetails {
  readonly documentId?: string;
  readonly url: string;
}

export interface InteractiveTwoFactorBrowserDeps {
  readonly tabs: {
    create(input: { readonly url: string; readonly active: true }): PromiseLike<{ readonly id?: number }>;
    remove(tabId: number): PromiseLike<void>;
  };
  readonly webNavigation: {
    getFrame(input: {
      readonly tabId: number;
      readonly frameId: 0;
    }): PromiseLike<InteractiveTwoFactorFrameDetails | null>;
    onCommitted: {
      addListener(listener: (details: InteractiveTwoFactorNavigationDetails) => void): void;
      removeListener(listener: (details: InteractiveTwoFactorNavigationDetails) => void): void;
    };
  };
  readonly commitTimeoutMs?: number;
}

export class InteractiveTwoFactorBrowser {
  readonly #timeoutMs: number;

  constructor(private readonly deps: InteractiveTwoFactorBrowserDeps) {
    const timeout = deps.commitTimeoutMs ?? DEFAULT_COMMIT_TIMEOUT_MS;
    if (!Number.isSafeInteger(timeout) || timeout < 1 || timeout > 60_000) {
      throw new TypeError('Interactive connector timeout is invalid');
    }
    this.#timeoutMs = timeout;
  }

  async open(
    url: string,
    replace?: InteractiveTwoFactorConnectorCaller,
  ): Promise<InteractiveTwoFactorConnectorDocument> {
    const expectedUrl = parseConnectorUrl(url);
    if (replace) await this.close(replace);
    const tab = await this.deps.tabs.create({ url: expectedUrl, active: true });
    if (tab.id === undefined) throw new Error('Browser did not return a security-key tab id');
    assertTabId(tab.id);
    try {
      return await this.#waitForCommittedDocument(tab.id, expectedUrl);
    } catch (error) {
      try {
        await this.#closeFailedOpen(tab.id, expectedUrl);
      } catch (closeError) {
        throw new AggregateError(
          [error, closeError],
          'The security-key connector failed and its tab could not be closed.',
          { cause: closeError },
        );
      }
      throw error;
    }
  }

  async #closeFailedOpen(tabId: number, expectedUrl: string): Promise<void> {
    const frame = await this.deps.webNavigation.getFrame({ tabId, frameId: 0 });
    if (!frame || frame.url !== expectedUrl) return;
    let documentId: string;
    try {
      documentId = parseInteractiveTwoFactorDocumentId(frame.documentId);
    } catch {
      return;
    }
    const current = parseConnectorDocument({ tabId, documentId, url: expectedUrl });
    if (await this.close(current)) return;
  }

  async close(input: InteractiveTwoFactorConnectorCaller): Promise<boolean> {
    const expected = parseConnectorDocument(input);
    const frame = await this.deps.webNavigation.getFrame({ tabId: expected.tabId, frameId: 0 });
    if (!frame) return true;
    if (frame.url !== expected.url || frame.documentId !== expected.documentId) return false;
    await this.deps.tabs.remove(expected.tabId);
    return true;
  }

  async closeAfterSettlement(input: InteractiveTwoFactorConnectorCaller): Promise<boolean> {
    const expected = parseConnectorDocument(input);
    let failure: unknown;
    for (let attempt = 0; attempt < 2; attempt += 1) {
      try {
        return await this.close(expected);
      } catch (error) {
        failure = error;
      }
    }
    throw failure;
  }

  #waitForCommittedDocument(
    tabId: number,
    expectedUrl: string,
  ): Promise<InteractiveTwoFactorConnectorDocument> {
    return new Promise((resolve, reject) => {
      let settled = false;
      const finish = (
        error: Error | undefined,
        value?: InteractiveTwoFactorConnectorDocument,
      ): void => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        this.deps.webNavigation.onCommitted.removeListener(onCommitted);
        if (error) reject(error);
        else resolve(value!);
      };
      const accept = (details: InteractiveTwoFactorNavigationDetails): boolean => {
        if (details.tabId !== tabId || details.frameId !== 0) return false;
        if (details.url !== expectedUrl) {
          if (details.url !== 'about:blank') {
            finish(new Error('The security-key connector committed an unexpected URL.'));
          }
          return false;
        }
        try {
          const documentId = parseInteractiveTwoFactorDocumentId(details.documentId);
          finish(undefined, Object.freeze({ tabId, documentId, url: expectedUrl }));
        } catch (error) {
          finish(error instanceof Error ? error : new Error('Invalid connector document.'));
        }
        return true;
      };
      const onCommitted = (details: InteractiveTwoFactorNavigationDetails): void => {
        accept(details);
      };
      const timer = setTimeout(() => {
        finish(new Error('The security-key connector did not commit before the deadline.'));
      }, this.#timeoutMs);
      this.deps.webNavigation.onCommitted.addListener(onCommitted);
      void Promise.resolve(this.deps.webNavigation.getFrame({ tabId, frameId: 0 }))
        .then((frame) => {
          if (frame) accept({ tabId, frameId: 0, ...frame });
        })
        .catch((error: unknown) => {
          finish(error instanceof Error ? error : new Error('Could not inspect connector document.'));
        });
    });
  }
}

function parseConnectorDocument(
  input: InteractiveTwoFactorConnectorCaller,
): InteractiveTwoFactorConnectorDocument {
  const parsed = createInteractiveTwoFactorConnectorCaller(input);
  return Object.freeze({ ...parsed, url: parseConnectorUrl(parsed.url) });
}

function parseConnectorUrl(value: string): string {
  if (typeof value !== 'string' || value.length === 0 || value.length > 64 * 1024) {
    throw new TypeError('Interactive connector URL is invalid');
  }
  const parsed = new URL(value);
  if (parsed.protocol !== 'https:' && !(parsed.protocol === 'http:' && isLoopback(parsed.hostname))) {
    throw new TypeError('Interactive connector URL must use HTTPS or loopback HTTP');
  }
  if (parsed.username || parsed.password || parsed.href !== value) {
    throw new TypeError('Interactive connector URL is not canonical');
  }
  return value;
}

function assertTabId(value: number): void {
  if (!Number.isSafeInteger(value) || value < 0) throw new TypeError('Connector tab id is invalid');
}

function isLoopback(hostname: string): boolean {
  if (hostname === 'localhost' || hostname === '[::1]') return true;
  const octets = hostname.split('.');
  return octets.length === 4
    && octets[0] === '127'
    && octets.every((part) => /^\d{1,3}$/u.test(part) && Number(part) <= 255);
}
