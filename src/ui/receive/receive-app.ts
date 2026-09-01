import { LitElement, css, html, nothing, type PropertyValues } from 'lit';
import browser from 'webextension-polyfill';
import { paletteTokens, themeTokens } from '../components/tokens.js';
import { controlStyles } from '../components/styles.js';
import { uiIcon } from '../components/icon.js';
import { LocalizeController, t } from '../i18n/index.js';
import { AppearanceController } from '../theme.js';
import '../components/logo.js';
import '../components/status-message.js';
import {
  parseSendUrl,
  accessSend,
  decryptAccessedSend,
  requestFileDownloadUrl,
  resolveSendDownloadTarget,
  downloadAndDecryptFile,
  sendPasswordHash,
  normalizeSendAccessEmail,
  normalizeSendAccessOtp,
  type ParsedSendUrl,
  type AccessedSend,
  type SendAccessAuthorization,
  type SendAccessCredentials,
  type SendEmailAuthProof,
  type SendAccessError,
} from '../../core/vault/send-access.js';
import type { ReceiveDeps, ReceiveFileReadyState, ReceiveState } from './types.js';

const OTP_RESEND_COOLDOWN_MS = 30_000;
const ORIGIN_REMOVAL_ATTEMPTS = 3;

function isSendAccessErrorCode(value: string): value is SendAccessError {
  switch (value) {
    case 'invalid_link':
    case 'invalid_credentials':
    case 'password_required':
    case 'password_invalid':
    case 'email_auth_unsupported':
    case 'authorization_rejected':
    case 'unavailable':
    case 'decrypt_failed':
    case 'network_failed':
    case 'timeout':
    case 'aborted':
    case 'response_too_large':
    case 'invalid_response':
    case 'server_error':
    case 'unsafe_download':
      return true;
    default:
      return false;
  }
}

/** Localised copy for each tagged Send-access failure. `unavailable` reuses the existing
 *  `receive.expired` catalog string; the others resolve through the `receive.error.*` catalog keys.
 *  Resolved at the point the error state is set. */
function sendErrorMessage(code: SendAccessError): string {
  switch (code) {
    case 'invalid_link':
      return t('receive.error.invalidLink');
    case 'invalid_credentials':
      return t('receive.error.invalidCredentials');
    case 'password_required':
    case 'password_invalid':
      return t('receive.error.passwordRequired');
    case 'unavailable':
      return t('receive.expired');
    case 'decrypt_failed':
      return t('receive.error.decryptFailed');
    case 'email_auth_unsupported':
      return t('receive.error.emailUnsupported');
    case 'authorization_rejected':
      return t('receive.error.authorizationExpired');
    default:
      return t('common.error');
  }
}

function downloadErrorMessage(code: SendAccessError): string {
  if (code === 'decrypt_failed') return t('receive.error.decryptFailed');
  if (code === 'unavailable') return t('receive.expired');
  return t('receive.error.downloadFailed');
}

/** Narrows a caught `unknown` to the tagged error `sendAccessError` throws, without ever casting
 *  the caught value itself — both steps (`instanceof`/`in`/`typeof`, then the code allowlist) are
 *  ordinary narrowing. */
function isSendAccessError(error: unknown): error is Error & { code: SendAccessError } {
  return error instanceof Error && 'code' in error && typeof error.code === 'string' && isSendAccessErrorCode(error.code);
}

function hostOf(serverUrl: string): string {
  try {
    return new URL(serverUrl).host;
  } catch {
    return serverUrl;
  }
}

/** The real dependency seam: `fetch`, a precise host-permission request, and a
 *  DOM-backed object-URL download. The object URL is revoked right after the synchronous click —
 *  by the time `anchor.click()` returns, the browser has already grabbed the blob data. */
function createDefaultDeps(): ReceiveDeps {
  return {
    fetch,
    async requestOrigins(originPatterns) {
      const origins = [...new Set(originPatterns)];
      const requested = new Set(origins);
      const observedAdded = new Set<string>();
      const onAdded = (permissions: { origins?: string[] }) => {
        for (const origin of permissions.origins ?? []) {
          if (requested.has(origin)) observedAdded.add(origin);
        }
      };
      browser.permissions.onAdded.addListener(onAdded);
      try {
        const existingPromises = origins.map(async (origin) => browser.permissions.contains({ origins: [origin] }));
        // Start the one combined request in the click stack so split Cloud API/Identity origins are
        // covered by the same user gesture.
        const requestPromise = browser.permissions.request({ origins });
        const [existing, granted] = await Promise.all([Promise.allSettled(existingPromises), requestPromise]);
        const preflightFailed = existing.some((result) => result.status === 'rejected');
        return {
          granted: granted && !preflightFailed,
          newlyGranted: granted
            ? origins.filter((origin, index) => {
                const result = existing[index];
                return observedAdded.has(origin) || (result?.status === 'fulfilled' && !result.value);
              })
            : [],
        };
      } finally {
        browser.permissions.onAdded.removeListener(onAdded);
      }
    },
    async removeOrigin(originPattern) {
      return browser.permissions.remove({ origins: [originPattern] });
    },
    download(bytes, fileName) {
      const url = URL.createObjectURL(new Blob([bytes as BlobPart]));
      const anchor = document.createElement('a');
      anchor.href = url;
      anchor.download = fileName;
      document.body.append(anchor);
      anchor.click();
      anchor.remove();
      URL.revokeObjectURL(url);
    },
  };
}

function fileReadyState(
  parsed: ParsedSendUrl,
  send: AccessedSend,
  authorization: SendAccessAuthorization,
  linkGeneration: number,
): ReceiveFileReadyState {
  return { status: 'fileReady', parsed, send, authorization, linkGeneration };
}

function clearFileFeedback(state: ReceiveFileReadyState): ReceiveFileReadyState {
  const { message: _message, messageTone: _messageTone, ...ready } = state;
  return ready;
}

function clearPendingDownload(state: ReceiveFileReadyState): ReceiveFileReadyState {
  const { pendingDownloadUrl: _pendingDownloadUrl, message: _message, messageTone: _messageTone, ...ready } = state;
  return ready;
}

type PendingSendAccess =
  | Readonly<{ kind: 'none' }>
  | Readonly<{ kind: 'password'; password: string }>
  | Readonly<{ kind: 'email'; email: string; proof: SendEmailAuthProof }>
  | Readonly<{ kind: 'email_otp'; email: string; otp: string; proof: SendEmailAuthProof }>;

function hasAuthProof(state: ReceiveState): state is Extract<
  ReceiveState,
  { status: 'passwordRequired' | 'emailRequired' | 'otpRequired' }
> {
  return state.status === 'passwordRequired'
    || state.status === 'emailRequired'
    || state.status === 'otpRequired';
}

function isSameParsedSend(left: ParsedSendUrl, right: ParsedSendUrl): boolean {
  if (
    left.serverUrl !== right.serverUrl
    || left.accessId !== right.accessId
    || left.endpoints.binding !== right.endpoints.binding
    || left.sendKey.length !== right.sendKey.length
  ) return false;
  return left.sendKey.every((value, index) => value === right.sendKey[index]);
}

/**
 * The Lit Receive root — the live entry point for `receive.html` (mounted by `receive.ts`). It owns
 * the whole recipient-side flow — parsing the share link, requesting host permission,
 * accessing/decrypting the Send, and downloading/decrypting a file — performing every side effect
 * itself through the injectable `deps`, and reusing the existing `send-access` helpers for every
 * crypto/protocol step (no duplicated logic here).
 *
 * The Access button's click handler parses the link synchronously and then calls
 * `deps.requestOrigins` as its very first `await`, preserving the user-gesture window
 * `permissions.request` needs. Only Download reads the resulting `passwordHash`/`fetch`, and only
 * after that permission has already been granted.
 *
 * As a page root it composes `paletteTokens` (so every `--vw-*` token resolves) on top of the base
 * `themeTokens` + shared `controlStyles`, and localises through `LocalizeController` / `t`.
 */
export class VwReceiveApp extends LitElement {
  static override properties = {
    state: { attribute: false },
  };

  declare state: ReceiveState;

  /** Injectable dependency seam; defaults to the real `webextension-polyfill`/DOM implementation. */
  deps: ReceiveDeps = createDefaultDeps();

  /** Re-renders on locale change so the Appearance language switch takes effect live. */
  private i18n = new LocalizeController(this);

  /** Mirrors the theme + density prefs onto this root host so the palette re-themes at runtime. */
  private appearance = new AppearanceController(this);

  /** Exact optional host grants added by this page and therefore safe for this page to remove. */
  private temporaryOrigins = new Set<string>();

  /** Every parsed-link transition and async request gets a monotonic authority identity. */
  private linkGeneration = 0;
  private requestEpoch = 0;
  private activeRequest: AbortController | undefined;
  private resendTimer: ReturnType<typeof setTimeout> | undefined;

  constructor() {
    super();
    this.state = { status: 'idle' };
  }

  override disconnectedCallback(): void {
    this.invalidateRequest();
    this.clearResendTimer();
    super.disconnectedCallback();
    void this.releaseTemporaryOrigins();
  }

  static override styles = [
    paletteTokens,
    themeTokens,
    controlStyles,
    css`
      :host {
        display: block;
        min-height: 100vh;
      }
      .page {
        min-height: 100vh;
        display: flex;
        align-items: center;
        justify-content: center;
        padding: 32px 16px;
        background: var(--vw-options-bg);
      }
      .card {
        width: 100%;
        max-width: 420px;
        background: var(--vw-card);
        border: 1px solid var(--vw-card-border);
        border-radius: var(--vw-radius-panel);
        box-shadow: var(--vw-card-shadow);
        padding: 28px 28px 26px;
      }
      .brand {
        display: flex;
        flex-direction: column;
        align-items: center;
        text-align: center;
        gap: 4px;
        margin-bottom: 22px;
      }
      .brand h1 {
        margin: 8px 0 0;
        font-size: 20px;
        font-weight: 600;
        color: var(--vw-ink);
      }
      .brand p {
        margin: 2px 0 0;
        font-size: 12.5px;
        color: var(--vw-muted);
        line-height: 1.5;
      }
      .form {
        display: flex;
        flex-direction: column;
        gap: 14px;
      }
      .field {
        display: flex;
        flex-direction: column;
        gap: 6px;
      }
      .field-label {
        font-size: 11px;
        font-weight: 600;
        letter-spacing: 0.03em;
        color: var(--vw-faint);
      }
      .btn.block {
        width: 100%;
      }
      .result {
        display: flex;
        flex-direction: column;
        gap: 10px;
      }
      .send-name {
        font-size: 14px;
        font-weight: 600;
        color: var(--vw-ink);
      }
      .send-text {
        white-space: pre-wrap;
        word-break: break-word;
        font-family: var(--vw-font-mono);
        font-size: 12.5px;
        line-height: 1.6;
        color: var(--vw-ink);
        background: var(--vw-fill-2);
        padding: 12px 14px;
        border-radius: var(--vw-radius-card);
      }
      .send-file {
        display: flex;
        align-items: center;
        gap: 10px;
        padding: 12px 14px;
        background: var(--vw-fill-2);
        border-radius: var(--vw-radius-card);
      }
      .send-file .file-icon {
        display: grid;
        place-items: center;
        flex: none;
        color: var(--vw-teal-text);
      }
      .send-file .file-icon svg {
        width: 20px;
        height: 20px;
      }
      .send-file .file-meta {
        flex: 1;
        min-width: 0;
        font-size: 12.5px;
        color: var(--vw-ink);
        word-break: break-word;
      }
    `,
  ];

  protected override updated(changed: PropertyValues<this>): void {
    if (!changed.has('state')) return;
    if (this.state.status === 'passwordRequired') {
      this.renderRoot.querySelector<HTMLInputElement>('[data-password]')?.focus();
    } else if (this.state.status === 'emailRequired') {
      this.renderRoot.querySelector<HTMLInputElement>('[data-email]')?.focus();
    } else if (this.state.status === 'otpRequired') {
      this.renderRoot.querySelector<HTMLInputElement>('[data-otp]')?.focus();
    }
  }

  private linkValue(): string {
    return this.renderRoot.querySelector<HTMLInputElement>('[data-link]')?.value ?? '';
  }

  private passwordValue(): string {
    return this.renderRoot.querySelector<HTMLInputElement>('[data-password]')?.value ?? '';
  }

  private emailValue(): string {
    return this.renderRoot.querySelector<HTMLInputElement>('[data-email]')?.value ?? '';
  }

  private otpValue(): string {
    return this.renderRoot.querySelector<HTMLInputElement>('[data-otp]')?.value ?? '';
  }

  private async acquireOrigins(originPatterns: readonly string[]): Promise<boolean> {
    const grant = await this.deps.requestOrigins(originPatterns);
    for (const origin of grant.newlyGranted) this.temporaryOrigins.add(origin);
    return grant.granted;
  }

  private async releaseTemporaryOrigins(keepOriginPatterns: readonly string[] = []): Promise<void> {
    const keep = new Set(keepOriginPatterns);
    const releasable = [...this.temporaryOrigins].filter((pattern) => !keep.has(pattern));
    await Promise.all(releasable.map(async (pattern) => {
      for (let attempt = 0; attempt < ORIGIN_REMOVAL_ATTEMPTS; attempt += 1) {
        try {
          if (await this.deps.removeOrigin(pattern)) {
            this.temporaryOrigins.delete(pattern);
            return;
          }
        } catch {
          // A rejected cleanup is retried below and remains tracked if all attempts fail.
        }
      }
    }));
  }

  private beginRequest(): { epoch: number; controller: AbortController } {
    this.activeRequest?.abort();
    const controller = new AbortController();
    const epoch = ++this.requestEpoch;
    this.activeRequest = controller;
    return { epoch, controller };
  }

  private requestIsCurrent(linkGeneration: number, epoch: number): boolean {
    return this.isConnected
      && this.linkGeneration === linkGeneration
      && this.requestEpoch === epoch
      && this.activeRequest?.signal.aborted === false;
  }

  private finishRequest(epoch: number): void {
    if (this.requestEpoch === epoch) this.activeRequest = undefined;
  }

  private invalidateRequest(): void {
    this.activeRequest?.abort();
    this.activeRequest = undefined;
    this.requestEpoch += 1;
  }

  private clearResendTimer(): void {
    if (this.resendTimer !== undefined) clearTimeout(this.resendTimer);
    this.resendTimer = undefined;
  }

  private scheduleResendRefresh(availableAt: number, linkGeneration: number): void {
    this.clearResendTimer();
    const delay = Math.max(0, availableAt - Date.now());
    this.resendTimer = setTimeout(() => {
      this.resendTimer = undefined;
      if (this.linkGeneration === linkGeneration && this.state.status === 'otpRequired') {
        this.requestUpdate();
      }
    }, delay + 1);
  }

  private onLinkInput(): void {
    this.invalidateRequest();
    this.clearResendTimer();
    this.linkGeneration += 1;
    this.state = { status: 'idle' };
    void this.releaseTemporaryOrigins();
  }

  private onEmailInput(): void {
    if (this.state.status === 'otpRequired') {
      const otp = this.renderRoot.querySelector<HTMLInputElement>('[data-otp]');
      if (otp) otp.value = '';
    }
  }

  private async onAccess(): Promise<void> {
    if (
      this.state.status === 'accessing'
      || this.state.status === 'downloading'
      || (this.state.status === 'otpRequired' && this.state.resending)
    ) return;

    let parsed: ParsedSendUrl;
    try {
      parsed = parseSendUrl(this.linkValue());
    } catch {
      this.invalidateRequest();
      this.clearResendTimer();
      void this.releaseTemporaryOrigins();
      this.state = { status: 'error', message: sendErrorMessage('invalid_link') };
      return;
    }

    const previous = this.state;
    if (!hasAuthProof(previous) || !isSameParsedSend(previous.parsed, parsed)) {
      this.invalidateRequest();
      this.clearResendTimer();
      const generation = ++this.linkGeneration;
      await this.runAccess(parsed, generation, { kind: 'none' });
      return;
    }

    let pending: PendingSendAccess;
    try {
      if (previous.status === 'passwordRequired') {
        pending = { kind: 'password', password: this.passwordValue() };
      } else if (previous.status === 'emailRequired') {
        pending = {
          kind: 'email',
          email: normalizeSendAccessEmail(this.emailValue()),
          proof: previous.proof,
        };
      } else {
        const email = normalizeSendAccessEmail(this.emailValue());
        pending = email === previous.email
          ? { kind: 'email_otp', email, otp: normalizeSendAccessOtp(this.otpValue()), proof: previous.proof }
          : { kind: 'email', email, proof: previous.proof };
      }
    } catch (err) {
      this.state = { ...previous, message: isSendAccessError(err) ? sendErrorMessage(err.code) : t('common.error') };
      return;
    }

    await this.runAccess(parsed, previous.linkGeneration, pending, previous.status === 'otpRequired'
      ? previous.resendAvailableAt
      : undefined);
  }

  private async onResend(): Promise<void> {
    if (this.state.status !== 'otpRequired' || this.state.resending || Date.now() < this.state.resendAvailableAt) return;
    const previous = this.state;
    let current: ParsedSendUrl;
    try {
      current = parseSendUrl(this.linkValue());
    } catch {
      this.onLinkInput();
      return;
    }
    if (!isSameParsedSend(current, previous.parsed)) {
      this.onLinkInput();
      return;
    }
    let email: string;
    try {
      email = normalizeSendAccessEmail(this.emailValue());
    } catch (err) {
      this.state = { ...previous, message: isSendAccessError(err) ? sendErrorMessage(err.code) : t('common.error') };
      return;
    }
    this.state = { ...previous, email, resending: true, message: t('receive.otpSending') };
    await this.runAccess(previous.parsed, previous.linkGeneration, {
      kind: 'email',
      email,
      proof: previous.proof,
    });
  }

  private async runAccess(
    parsed: ParsedSendUrl,
    linkGeneration: number,
    pending: PendingSendAccess,
    previousResendAvailableAt?: number,
  ): Promise<void> {
    const request = this.beginRequest();
    void this.releaseTemporaryOrigins(parsed.endpoints.originPatterns);
    this.state = { status: 'accessing', linkGeneration };

    try {
      // The combined exact-origin request is deliberately the first await in every user action.
      let granted: boolean;
      try {
        granted = await this.acquireOrigins(parsed.endpoints.originPatterns);
      } catch {
        if (!this.requestIsCurrent(linkGeneration, request.epoch)) {
          await this.releaseTemporaryOrigins();
          return;
        }
        await this.releaseTemporaryOrigins();
        if (!this.requestIsCurrent(linkGeneration, request.epoch)) return;
        this.state = {
          status: 'error',
          message: t('receive.error.permissionDenied', { host: hostOf(parsed.endpoints.identityBaseUrl) }),
        };
        return;
      }
      if (!this.requestIsCurrent(linkGeneration, request.epoch)) {
        await this.releaseTemporaryOrigins();
        return;
      }
      if (!granted) {
        await this.releaseTemporaryOrigins();
        if (!this.requestIsCurrent(linkGeneration, request.epoch)) return;
        this.state = {
          status: 'error',
          message: t('receive.error.permissionDenied', { host: hostOf(parsed.endpoints.identityBaseUrl) }),
        };
        return;
      }

      let credentials: SendAccessCredentials;
      if (pending.kind === 'password') {
        const passwordHashB64 = await sendPasswordHash(pending.password, parsed.sendKey);
        if (!this.requestIsCurrent(linkGeneration, request.epoch)) return;
        credentials = { kind: 'password', passwordHashB64 };
      } else {
        credentials = pending;
      }

      const result = await accessSend(
        this.deps.fetch,
        parsed.endpoints,
        parsed.accessId,
        credentials,
        { signal: request.controller.signal },
      );
      if (!this.requestIsCurrent(linkGeneration, request.epoch)) return;

      const resultBinding = result.kind === 'accessed'
        ? result.authorization.endpointBinding
        : result.endpointBinding;
      if (resultBinding !== parsed.endpoints.binding) {
        throw Object.assign(new Error('invalid_link'), { code: 'invalid_link' as const });
      }
      if (result.kind === 'email_required') {
        this.state = {
          status: 'emailRequired',
          parsed,
          linkGeneration,
          proof: result.proof,
          message: t('receive.emailDisclosure', { origin: new URL(parsed.endpoints.identityBaseUrl).origin }),
        };
        return;
      }
      if (result.kind === 'email_otp_required') {
        if (pending.kind !== 'email' && pending.kind !== 'email_otp') {
          throw Object.assign(new Error('email_auth_unsupported'), { code: 'email_auth_unsupported' as const });
        }
        const resendAvailableAt = pending.kind === 'email'
          ? Date.now() + OTP_RESEND_COOLDOWN_MS
          : (previousResendAvailableAt ?? Date.now() + OTP_RESEND_COOLDOWN_MS);
        this.state = {
          status: 'otpRequired',
          parsed,
          linkGeneration,
          email: pending.email,
          proof: result.proof,
          resendAvailableAt,
          resending: false,
          message: pending.kind === 'email'
            ? t('receive.otpSentGeneric')
            : t('receive.error.otpInvalid'),
        };
        this.scheduleResendRefresh(resendAvailableAt, linkGeneration);
        return;
      }

      const send = await decryptAccessedSend(result.payload, parsed.sendKey);
      if (!this.requestIsCurrent(linkGeneration, request.epoch)) return;
      this.clearResendTimer();
      if (send.type === 1) {
        this.state = fileReadyState(parsed, send, result.authorization, linkGeneration);
      } else {
        await this.releaseTemporaryOrigins();
        if (!this.requestIsCurrent(linkGeneration, request.epoch)) return;
        this.state = { status: 'textReady', send, revealed: false, linkGeneration };
      }
    } catch (err) {
      if (!this.requestIsCurrent(linkGeneration, request.epoch)) return;
      if (isSendAccessError(err) && (err.code === 'password_required' || err.code === 'password_invalid')) {
        this.state = {
          status: 'passwordRequired',
          parsed,
          linkGeneration,
          message: sendErrorMessage('password_required'),
        };
      } else {
        await this.releaseTemporaryOrigins();
        if (!this.requestIsCurrent(linkGeneration, request.epoch)) return;
        this.state = {
          status: 'error',
          message: isSendAccessError(err) ? sendErrorMessage(err.code) : t('common.error'),
        };
      }
    } finally {
      this.finishRequest(request.epoch);
    }
  }

  private onRevealText(): void {
    if (this.state.status !== 'textReady' || !this.state.send.hidden || this.state.revealed) return;
    this.state = { ...this.state, revealed: true };
  }

  private async onDownload(): Promise<void> {
    if (this.state.status !== 'fileReady') return;

    const ready = clearFileFeedback(this.state);
    const { parsed, send, authorization, linkGeneration } = ready;
    if (!send.fileId || !send.id) {
      this.state = { ...ready, message: sendErrorMessage('unavailable'), messageTone: 'danger' };
      return;
    }

    const request = this.beginRequest();
    let recoveryState = ready;
    this.state = { status: 'downloading', ready };
    try {
      let target: ReturnType<typeof resolveSendDownloadTarget>;
      let allowedCrossOrigin: string | undefined;

      if (ready.pendingDownloadUrl) {
        target = resolveSendDownloadTarget(ready.pendingDownloadUrl, parsed.endpoints.downloadBaseUrl);
        let granted: boolean;
        try {
          granted = await this.acquireOrigins([target.originPattern]);
        } catch {
          if (!this.requestIsCurrent(linkGeneration, request.epoch)) return;
          this.state = {
            ...ready,
            message: t('receive.error.permissionDenied', { host: target.origin }),
            messageTone: 'danger',
          };
          return;
        }
        if (!this.requestIsCurrent(linkGeneration, request.epoch)) {
          await this.releaseTemporaryOrigins(parsed.endpoints.originPatterns);
          return;
        }
        if (!granted) {
          this.state = {
            ...ready,
            message: t('receive.error.permissionDenied', { host: target.origin }),
            messageTone: 'danger',
          };
          return;
        }
        allowedCrossOrigin = target.origin;
        recoveryState = clearPendingDownload(ready);
      } else {
        const url = await requestFileDownloadUrl(
          this.deps.fetch,
          parsed.endpoints,
          send.id,
          send.fileId,
          authorization,
          { signal: request.controller.signal },
        );
        if (!this.requestIsCurrent(linkGeneration, request.epoch)) return;
        target = resolveSendDownloadTarget(url, parsed.endpoints.downloadBaseUrl);
        if (target.isCrossOrigin) {
          recoveryState = { ...ready, pendingDownloadUrl: target.url };
          // A server-selected cross-origin target is never fetched on the same click that discovers
          // it, even when a broader permission already exists. Show the exact host first, then let
          // the next user gesture request that one origin before any request can reach it.
          this.state = {
            ...recoveryState,
            message: t('receive.error.permissionDenied', { host: target.origin }),
            messageTone: 'info',
          };
          return;
        }
      }

      const options = allowedCrossOrigin === undefined
        ? { signal: request.controller.signal }
        : { allowedCrossOrigin, signal: request.controller.signal };
      const bytes = await downloadAndDecryptFile(
        this.deps.fetch,
        target.url,
        parsed.endpoints.downloadBaseUrl,
        parsed.sendKey,
        options,
      );
      if (!this.requestIsCurrent(linkGeneration, request.epoch)) return;
      this.deps.download(bytes, send.fileName ?? 'download');
      await this.releaseTemporaryOrigins();
      if (!this.requestIsCurrent(linkGeneration, request.epoch)) return;
      this.state = clearPendingDownload(ready);
    } catch (err) {
      if (!this.requestIsCurrent(linkGeneration, request.epoch)) return;
      if (isSendAccessError(err) && err.code === 'authorization_rejected') {
        await this.releaseTemporaryOrigins();
        if (!this.requestIsCurrent(linkGeneration, request.epoch)) return;
        this.state = { status: 'error', message: sendErrorMessage('authorization_rejected') };
        return;
      }
      await this.releaseTemporaryOrigins(parsed.endpoints.originPatterns);
      if (!this.requestIsCurrent(linkGeneration, request.epoch)) return;
      const message = isSendAccessError(err) ? downloadErrorMessage(err.code) : t('receive.error.downloadFailed');
      this.state = { ...recoveryState, message, messageTone: 'danger' };
    } finally {
      this.finishRequest(request.epoch);
    }
  }

  private renderResult() {
    switch (this.state.status) {
      case 'textReady': {
        const { send, revealed } = this.state;
        const showText = !send.hidden || revealed;
        return html`
          <div class="result">
            <div class="send-name">${send.name}</div>
            ${showText
              ? html`<div class="send-text" data-send-text>${send.text ?? ''}</div>`
              : html`
                  <button
                    type="button"
                    class="btn outline block"
                    data-reveal-text
                    @click=${() => this.onRevealText()}
                  >
                    ${uiIcon('eye')}<span>${this.i18n.t('receive.revealText')}</span>
                  </button>
                `}
          </div>
        `;
      }
      case 'fileReady': {
        const { send } = this.state;
        return html`
          <div class="result">
            <div class="send-name">${send.name}</div>
            <div class="send-file">
              <span class="file-icon">${uiIcon('file')}</span>
              <span class="file-meta">${send.fileName ?? 'file'}${send.sizeName ? ` · ${send.sizeName}` : ''}</span>
            </div>
            <button
              type="button"
              class="btn primary block"
              data-download
              @click=${() => void this.onDownload()}
            >
              ${uiIcon('file')}<span>${this.i18n.t('receive.download')}</span>
            </button>
          </div>
        `;
      }
      default:
        return nothing;
    }
  }

  private renderStatus() {
    switch (this.state.status) {
      case 'passwordRequired':
        // The first access of a password-protected Send is a normal prompt, not a failure (a
        // wrong-password retry returns the same 401), so keep it a polite info message — no
        // assertive alert, no error icon.
        return html`<vw-status-message tone="info" .message=${this.state.message}></vw-status-message>`;
      case 'emailRequired':
      case 'otpRequired':
        return html`<vw-status-message tone="info" .message=${this.state.message}></vw-status-message>`;
      case 'accessing':
      case 'downloading':
        return html`<vw-status-message tone="info" .message=${this.i18n.t('receive.loading')}></vw-status-message>`;
      case 'fileReady':
        return this.state.message
          ? html`<vw-status-message
              .tone=${this.state.messageTone ?? 'danger'}
              .icon=${this.state.messageTone === 'info' ? undefined : 'alert'}
              .message=${this.state.message}
            ></vw-status-message>`
          : nothing;
      case 'error':
        return html`<vw-status-message tone="danger" .icon=${'alert'} .message=${this.state.message}></vw-status-message>`;
      default:
        return nothing;
    }
  }

  protected override render() {
    const busy = this.state.status === 'accessing' || this.state.status === 'downloading';
    const emailState = this.state.status === 'emailRequired' || this.state.status === 'otpRequired';
    const accessLabel = this.state.status === 'accessing'
      ? this.i18n.t('receive.loading')
      : this.state.status === 'emailRequired'
        ? this.i18n.t('receive.sendCode')
        : this.state.status === 'otpRequired'
          ? this.i18n.t('receive.verifyCode')
          : this.i18n.t('receive.unlock');
    return html`
      <div class="page">
        <section class="card" data-task-column>
          <header class="brand" data-page-heading>
            <vw-logo variant="hero"></vw-logo>
            <h1>${this.i18n.t('receive.title')}</h1>
            <p>${this.i18n.t('receive.subtitle')}</p>
          </header>
          <div class="form">
            <label class="field">
              <span class="field-label">${this.i18n.t('receive.linkLabel')}</span>
              <input
                class="input mono"
                data-link
                type="url"
                placeholder="https://vault.example/#/send/…/…"
                ?disabled=${busy}
                @input=${() => this.onLinkInput()}
              />
            </label>
            ${this.state.status === 'passwordRequired'
              ? html`
                  <label class="field">
                    <span class="field-label">${this.i18n.t('receive.password')}</span>
                    <input class="input" data-password type="password" autocomplete="off" />
                  </label>
                `
              : nothing}
            ${emailState
              ? html`
                  <label class="field">
                    <span class="field-label">${this.i18n.t('receive.email')}</span>
                    <input
                      class="input"
                      data-email
                      type="email"
                      maxlength="254"
                      autocomplete="email"
                      .value=${this.state.status === 'otpRequired' ? this.state.email : ''}
                      @input=${() => this.onEmailInput()}
                    />
                  </label>
                `
              : nothing}
            ${this.state.status === 'otpRequired'
              ? html`
                  <label class="field">
                    <span class="field-label">${this.i18n.t('receive.verificationCode')}</span>
                    <input
                      class="input mono"
                      data-otp
                      type="text"
                      maxlength="256"
                      inputmode="numeric"
                      autocomplete="one-time-code"
                    />
                  </label>
                `
              : nothing}
            <button type="button" class="btn primary block" data-access ?disabled=${busy} @click=${() => void this.onAccess()}>
              ${uiIcon(this.state.status === 'accessing' ? 'refresh' : emailState ? 'mail' : 'unlock')}<span>${accessLabel}</span>
            </button>
            ${this.state.status === 'otpRequired'
              ? html`
                  <button
                    type="button"
                    class="btn outline block"
                    data-resend
                    ?disabled=${this.state.resending || Date.now() < this.state.resendAvailableAt}
                    @click=${() => void this.onResend()}
                  >
                    ${uiIcon('refresh')}<span>${this.i18n.t('receive.resendCode')}</span>
                  </button>
                `
              : nothing}
            ${this.renderResult()}
            ${this.renderStatus()}
          </div>
        </section>
      </div>
    `;
  }
}

customElements.define('vw-receive-app', VwReceiveApp);

declare global {
  interface HTMLElementTagNameMap {
    'vw-receive-app': VwReceiveApp;
  }
}
