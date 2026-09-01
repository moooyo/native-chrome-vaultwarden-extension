import type {
  AutofillSaveCaptureBeforeRequest,
  AutofillSaveCaptureCoordinator,
  AutofillSaveCaptureErrorRequest,
} from './autofill-save-capture-coordinator.js';

const MUTATION_METHODS = new Set(['POST', 'PUT', 'PATCH']);
const OBSERVED_TYPES = new Set(['main_frame', 'sub_frame', 'xmlhttprequest']);
const REQUEST_FILTER = Object.freeze({
  urls: Object.freeze(['http://*/*', 'https://*/*']),
  types: Object.freeze(['main_frame', 'sub_frame', 'xmlhttprequest']),
});
const MAX_REQUEST_LANES = 128;

interface SaveCaptureWebRequestDetails {
  readonly requestId?: unknown;
  readonly tabId?: unknown;
  readonly frameId?: unknown;
  readonly documentId?: unknown;
  readonly documentUrl?: unknown;
  readonly originUrl?: unknown;
  readonly initiator?: unknown;
  readonly url?: unknown;
  readonly redirectUrl?: unknown;
  readonly method?: unknown;
  readonly type?: unknown;
  readonly statusCode?: unknown;
  readonly timeStamp?: unknown;
}

interface SaveCaptureWebRequestEvent {
  addListener(
    listener: (details: SaveCaptureWebRequestDetails) => void,
    filter: typeof REQUEST_FILTER,
  ): void;
}

export interface AutofillSaveCaptureChromeApi {
  readonly webRequest: {
    readonly onBeforeRequest: SaveCaptureWebRequestEvent;
    readonly onBeforeRedirect: SaveCaptureWebRequestEvent;
    readonly onCompleted: SaveCaptureWebRequestEvent;
    readonly onErrorOccurred: SaveCaptureWebRequestEvent;
  };
  readonly webNavigation: {
    getFrame(details: { tabId: number; frameId: number }): Promise<{
      readonly documentId?: unknown;
      readonly url?: unknown;
    } | null>;
  };
}

export interface AutofillSaveCaptureBrowserLogger {
  warn(event: 'before_request' | 'redirect' | 'completed' | 'error'): void;
}

type SaveCaptureNetworkCoordinator = Pick<
  AutofillSaveCaptureCoordinator,
  | 'beginBeforeRequest'
  | 'resolveBeforeRequest'
  | 'failBeforeRequest'
  | 'observeRedirect'
  | 'observeCompleted'
  | 'observeError'
  | 'invalidateNetworkWindow'
>;

/** Register non-blocking MV3 listeners without requesting or reading request bodies. */
export function registerAutofillSaveCaptureBrowserListeners(
  chromeApi: AutofillSaveCaptureChromeApi | undefined,
  coordinator: SaveCaptureNetworkCoordinator,
  logger: AutofillSaveCaptureBrowserLogger = { warn: () => {} },
): boolean {
  const webRequest = chromeApi?.webRequest;
  const webNavigation = chromeApi?.webNavigation;
  if (!webRequest?.onBeforeRequest || !webRequest.onBeforeRedirect
      || !webRequest.onCompleted || !webRequest.onErrorOccurred
      || typeof webNavigation?.getFrame !== 'function') return false;
  const requestLanes = new Map<string, Promise<void>>();
  const enqueue = (
    requestId: string,
    task: () => void | Promise<void>,
    event: Parameters<AutofillSaveCaptureBrowserLogger['warn']>[0],
  ): void => {
    const previous = requestLanes.get(requestId);
    if (!previous && requestLanes.size >= MAX_REQUEST_LANES) {
      run(coordinator.invalidateNetworkWindow(Date.now()), logger, event);
      return;
    }
    const operation = previous?.then(task, task) ?? Promise.resolve().then(task);
    const tracked: Promise<void> = operation.finally(() => {
      if (requestLanes.get(requestId) === tracked) requestLanes.delete(requestId);
    });
    requestLanes.set(requestId, tracked);
    run(tracked, logger, event);
  };

  webRequest.onBeforeRequest.addListener((details) => {
    const common = beforeCommon(details);
    const method = requestMethod(details.method);
    const initiator = string(details.initiator);
    if (!common || !method || !initiator) return;
    const initiatorOrigin = canonicalHttpOrigin(initiator);
    const browserDocumentId = string(details.documentId);
    const documentUrl = string(details.documentUrl);
    const originUrl = string(details.originUrl);
    if (!initiatorOrigin || initiatorOrigin !== initiator
        || (common.type === 'xmlhttprequest' && !browserDocumentId)) return;
    const sourceHint = common.type === 'xmlhttprequest' ? documentUrl : originUrl;
    const canonicalSourceHint = sourceHint ? canonicalHttpUrl(sourceHint) : undefined;
    if (sourceHint !== undefined && (!canonicalSourceHint
        || canonicalHttpOrigin(canonicalSourceHint) !== initiatorOrigin)) return;
    let admission: Promise<string | undefined>;
    try {
      admission = coordinator.beginBeforeRequest({
        requestId: common.requestId,
        tabId: common.tabId,
        frameId: common.frameId,
        ...(common.type === 'xmlhttprequest' && browserDocumentId
          ? { documentId: browserDocumentId }
          : {}),
        ...(canonicalSourceHint ? { sourceDocumentUrl: canonicalSourceHint } : {}),
        timeStamp: common.timeStamp,
      });
    } catch (error) {
      run((async () => {
        await coordinator.invalidateNetworkWindow(Date.now());
        throw error;
      })(), logger, 'before_request');
      return;
    }
    void admission.catch(() => undefined);
    enqueue(common.requestId, async () => {
      const admissionId = await admission;
      if (!admissionId) return;
      try {
        const frame = await webNavigation.getFrame({
          tabId: common.tabId,
          frameId: common.frameId,
        });
        const documentId = string(frame?.documentId);
        const sourceDocumentUrl = string(frame?.url);
        const sourceUrl = sourceDocumentUrl ? canonicalHttpUrl(sourceDocumentUrl) : undefined;
        if (!documentId || !sourceDocumentUrl || !sourceUrl
            || canonicalHttpOrigin(sourceUrl) !== initiatorOrigin
            || (common.type === 'xmlhttprequest' && documentId !== browserDocumentId)
            || (common.type === 'xmlhttprequest'
              && documentUrl !== undefined
              && sourceUrl !== canonicalHttpUrl(documentUrl))
            || (common.type !== 'xmlhttprequest'
              && originUrl !== undefined
              && sourceUrl !== canonicalHttpUrl(originUrl))) {
          await coordinator.failBeforeRequest(admissionId);
          return;
        }
        await coordinator.resolveBeforeRequest(admissionId, {
          ...common,
          documentId,
          sourceDocumentUrl: sourceUrl,
          initiator,
          method,
        });
      } catch (error) {
        await coordinator.failBeforeRequest(admissionId).catch(() => undefined);
        throw error;
      }
    }, 'before_request');
  }, REQUEST_FILTER);

  webRequest.onBeforeRedirect.addListener((details) => {
    const common = terminalCommon(details);
    const redirectUrl = string(details.redirectUrl);
    const statusCode = integer(details.statusCode);
    if (!common || !redirectUrl || statusCode === undefined) return;
    enqueue(common.requestId, () => coordinator.observeRedirect({
        ...common,
        redirectUrl,
        statusCode,
      }), 'redirect');
  }, REQUEST_FILTER);

  webRequest.onCompleted.addListener((details) => {
    const common = terminalCommon(details);
    const statusCode = integer(details.statusCode);
    if (!common || statusCode === undefined) return;
    enqueue(common.requestId, () => coordinator.observeCompleted({ ...common, statusCode }), 'completed');
  }, REQUEST_FILTER);

  webRequest.onErrorOccurred.addListener((details) => {
    const common = terminalCommon(details);
    if (!common) return;
    enqueue(common.requestId, () => coordinator.observeError(common), 'error');
  }, REQUEST_FILTER);
  return true;
}

function beforeCommon(
  details: SaveCaptureWebRequestDetails,
): Omit<AutofillSaveCaptureBeforeRequest, 'documentId' | 'sourceDocumentUrl' | 'initiator'> | undefined {
  const requestId = string(details.requestId);
  const tabId = integer(details.tabId);
  const frameId = integer(details.frameId);
  const url = string(details.url);
  const method = terminalMethod(details.method);
  const type = requestType(details.type);
  const timeStamp = finiteTimestamp(details.timeStamp);
  if (!requestId || tabId === undefined || tabId < 0 || frameId === undefined || frameId < 0
      || !url || !method || !type || timeStamp === undefined) return undefined;
  return { requestId, tabId, frameId, url, method, type, timeStamp };
}

function terminalCommon(
  details: SaveCaptureWebRequestDetails,
): AutofillSaveCaptureErrorRequest | undefined {
  const requestId = string(details.requestId);
  const tabId = integer(details.tabId);
  const frameId = integer(details.frameId);
  const documentId = string(details.documentId);
  const url = string(details.url);
  const method = terminalMethod(details.method);
  const type = requestType(details.type);
  const timeStamp = finiteTimestamp(details.timeStamp);
  if (!requestId || tabId === undefined || tabId < 0 || frameId === undefined || frameId < 0
      || !documentId || !url || !method || !type || timeStamp === undefined) return undefined;
  return { requestId, tabId, frameId, documentId, url, method, type, timeStamp };
}

function requestMethod(value: unknown): 'POST' | 'PUT' | 'PATCH' | undefined {
  const method = terminalMethod(value);
  return method && MUTATION_METHODS.has(method) ? method as 'POST' | 'PUT' | 'PATCH' : undefined;
}

function terminalMethod(value: unknown): string | undefined {
  if (typeof value !== 'string' || !value || value.length > 32) return undefined;
  const method = value.toUpperCase();
  return /^[A-Z]+$/u.test(method) ? method : undefined;
}

function requestType(value: unknown): 'main_frame' | 'sub_frame' | 'xmlhttprequest' | undefined {
  return typeof value === 'string' && OBSERVED_TYPES.has(value)
    ? value as 'main_frame' | 'sub_frame' | 'xmlhttprequest'
    : undefined;
}

function string(value: unknown): string | undefined {
  return typeof value === 'string' && value.length > 0 ? value : undefined;
}

function integer(value: unknown): number | undefined {
  return Number.isSafeInteger(value) ? value as number : undefined;
}

function finiteTimestamp(value: unknown): number | undefined {
  return typeof value === 'number' && Number.isFinite(value) && value >= 0
    ? value
    : undefined;
}

function canonicalHttpUrl(value: string): string | undefined {
  try {
    const url = new URL(value);
    if ((url.protocol !== 'https:' && url.protocol !== 'http:') || url.username || url.password) return undefined;
    url.hash = '';
    return url.href;
  } catch {
    return undefined;
  }
}

function canonicalHttpOrigin(value: string): string | undefined {
  try {
    const url = new URL(value);
    if ((url.protocol !== 'https:' && url.protocol !== 'http:') || url.username || url.password) return undefined;
    return url.origin;
  } catch {
    return undefined;
  }
}

function run(
  operation: Promise<void>,
  logger: AutofillSaveCaptureBrowserLogger,
  event: Parameters<AutofillSaveCaptureBrowserLogger['warn']>[0],
): void {
  void operation.catch(() => logger.warn(event));
}
