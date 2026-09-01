import type {
  HttpAuthBlockingResponse,
  HttpAuthBroker,
  HttpAuthChallengeDetails,
} from './http-auth-broker.js';

interface ChromeRequestFilter {
  readonly urls: readonly string[];
  readonly types?: readonly string[];
}

interface ChromeEvent<Listener extends (...args: never[]) => unknown> {
  addListener(
    listener: Listener,
    filter: ChromeRequestFilter,
    extraInfoSpec?: readonly string[],
  ): void;
}

interface ChromeCompletionDetails {
  readonly requestId: string;
}

export interface HttpAuthChromeApi {
  readonly webRequest: {
    readonly onAuthRequired: ChromeEvent<(
      details: HttpAuthChallengeDetails,
      callback: (response: HttpAuthBlockingResponse) => void,
    ) => void>;
    readonly onCompleted: ChromeEvent<(details: ChromeCompletionDetails) => void>;
    readonly onErrorOccurred: ChromeEvent<(details: ChromeCompletionDetails) => void>;
  };
}

const HTTP_AUTH_FILTER: ChromeRequestFilter = Object.freeze({
  urls: Object.freeze(['<all_urls>']),
  types: Object.freeze(['main_frame']),
});

/** Register Chrome's callback-style asyncBlocking listener synchronously during worker startup. */
export function registerHttpAuthBrowserListeners(
  chromeApi: HttpAuthChromeApi | undefined,
  broker: Pick<HttpAuthBroker, 'handle' | 'finishRequest'>,
): boolean {
  const webRequest = chromeApi?.webRequest;
  if (!webRequest?.onAuthRequired || !webRequest.onCompleted || !webRequest.onErrorOccurred) {
    return false;
  }

  // Chrome supplies the second callback only with `asyncBlocking`. Returning a Promise from this
  // listener is intentionally impossible: the callback owns the request settlement.
  webRequest.onAuthRequired.addListener(
    (details, callback): void => {
      broker.handle(details, callback);
    },
    HTTP_AUTH_FILTER,
    ['asyncBlocking'],
  );
  const finish = (details: ChromeCompletionDetails): void => {
    broker.finishRequest(details.requestId);
  };
  webRequest.onCompleted.addListener(finish, HTTP_AUTH_FILTER);
  webRequest.onErrorOccurred.addListener(finish, HTTP_AUTH_FILTER);
  return true;
}
