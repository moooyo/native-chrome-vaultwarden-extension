import { LitElement, css, html, nothing, type PropertyValues } from 'lit';
import browser from 'webextension-polyfill';
import { paletteTokens, themeTokens } from '../components/tokens.js';
import { controlStyles } from '../components/styles.js';
import { uiIcon } from '../components/icon.js';
import { LocalizeController, t } from '../i18n/index.js';
import '../components/logo.js';
import '../components/status-message.js';
import {
  parseSendUrl,
  accessSend,
  decryptAccessedSend,
  requestFileDownloadUrl,
  downloadAndDecryptFile,
  sendPasswordHash,
  type ParsedSendUrl,
  type AccessedSend,
  type SendAccessError,
} from '../../core/vault/send-access.js';
import type { ReceiveDeps, ReceiveState } from './types.js';

function isSendAccessErrorCode(value: string): value is SendAccessError {
  return value === 'invalid_link' || value === 'password_required' || value === 'unavailable' || value === 'decrypt_failed';
}

/** Localised copy for each tagged Send-access failure. `unavailable` reuses the existing
 *  `receive.expired` catalog string; the others have no key yet, so they are inline Chinese with a
 *  `// TODO i18n` marker. Resolved at the point the error state is set. */
function sendErrorMessage(code: SendAccessError): string {
  switch (code) {
    case 'invalid_link':
      return '无效的 Send 链接'; // TODO i18n
    case 'password_required':
      return '此 Send 需要访问密码'; // TODO i18n
    case 'unavailable':
      return t('receive.expired');
    case 'decrypt_failed':
      return '无法解密，链接或文件可能已损坏'; // TODO i18n
  }
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

/** The real dependency seam: `fetch`, a `webextension-polyfill` host-permission prompt, and a
 *  DOM-backed object-URL download. The object URL is revoked right after the synchronous click —
 *  by the time `anchor.click()` returns, the browser has already grabbed the blob data. */
function createDefaultDeps(): ReceiveDeps {
  return {
    fetch,
    async requestOrigin(originPattern) {
      return browser.permissions.request({ origins: [originPattern] });
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

/**
 * The Lit Receive root — the live entry point for `receive.html` (mounted by `receive.ts`). It owns
 * the whole recipient-side flow — parsing the share link, requesting host permission,
 * accessing/decrypting the Send, and downloading/decrypting a file — performing every side effect
 * itself through the injectable `deps`, and reusing the existing `send-access` helpers for every
 * crypto/protocol step (no duplicated logic here).
 *
 * The Access button's click handler parses the link synchronously and then calls
 * `deps.requestOrigin` as its very first `await`, preserving the user-gesture window
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

  constructor() {
    super();
    this.state = { status: 'idle' };
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
    if (changed.has('state') && this.state.status === 'passwordRequired') {
      this.renderRoot.querySelector<HTMLInputElement>('[data-password]')?.focus();
    }
  }

  private linkValue(): string {
    return this.renderRoot.querySelector<HTMLInputElement>('[data-link]')?.value ?? '';
  }

  private passwordValue(): string {
    return this.renderRoot.querySelector<HTMLInputElement>('[data-password]')?.value ?? '';
  }

  private async onAccess(): Promise<void> {
    // Double-submit guard: ignore a second Access click while one is already in flight.
    if (this.state.status === 'accessing' || this.state.status === 'downloading') {
      return;
    }
    let parsed: ParsedSendUrl;
    try {
      parsed = parseSendUrl(this.linkValue());
    } catch {
      this.state = { status: 'error', message: sendErrorMessage('invalid_link') };
      return;
    }
    // Read the password field (if any) before switching to the busy state below — that render
    // drops the password field from the DOM when it's showing.
    const password = this.passwordValue();
    // Derive the origin pattern synchronously so the permission request below is the very first
    // await — still inside the click's user-gesture window.
    const originPattern = `${new URL(parsed.serverUrl).origin}/*`;
    this.state = { status: 'accessing' };
    const granted = await this.deps.requestOrigin(originPattern);
    if (!granted) {
      // TODO i18n
      this.state = { status: 'error', message: `请授予对 ${hostOf(parsed.serverUrl)} 的访问权限以接收此 Send` };
      return;
    }
    try {
      const passwordHash = password ? await sendPasswordHash(password, parsed.sendKey) : undefined;
      const raw = await accessSend(this.deps.fetch, parsed.serverUrl, parsed.accessId, passwordHash);
      const send = await decryptAccessedSend(raw, parsed.sendKey);
      if (send.type === 1) {
        this.state = passwordHash === undefined
          ? { status: 'fileReady', parsed, send }
          : { status: 'fileReady', parsed, send, passwordHash };
      } else {
        this.state = { status: 'textReady', name: send.name, text: send.text ?? '' };
      }
    } catch (err) {
      if (isSendAccessError(err) && err.code === 'password_required') {
        this.state = { status: 'passwordRequired', message: sendErrorMessage('password_required') };
      } else {
        this.state = { status: 'error', message: isSendAccessError(err) ? sendErrorMessage(err.code) : t('common.error') };
      }
    }
  }

  private async onDownload(parsed: ParsedSendUrl, send: AccessedSend, passwordHash: string | undefined): Promise<void> {
    // Double-submit guard: only start a download from the settled fileReady state.
    if (this.state.status !== 'fileReady') {
      return;
    }
    if (!send.fileId || !send.id) {
      this.state = { status: 'error', message: sendErrorMessage('unavailable') };
      return;
    }
    this.state = { status: 'downloading' };
    try {
      const url = await requestFileDownloadUrl(this.deps.fetch, parsed.serverUrl, send.id, send.fileId, passwordHash);
      const bytes = await downloadAndDecryptFile(this.deps.fetch, url, parsed.serverUrl, parsed.sendKey);
      this.deps.download(bytes, send.fileName ?? 'download');
      this.state = passwordHash === undefined
        ? { status: 'fileReady', parsed, send }
        : { status: 'fileReady', parsed, send, passwordHash };
    } catch (err) {
      // TODO i18n
      this.state = { status: 'error', message: isSendAccessError(err) ? sendErrorMessage(err.code) : '下载失败' };
    }
  }

  private renderResult() {
    switch (this.state.status) {
      case 'textReady':
        return html`
          <div class="result">
            <div class="send-name">${this.state.name}</div>
            <div class="send-text">${this.state.text}</div>
          </div>
        `;
      case 'fileReady': {
        const { parsed, send, passwordHash } = this.state;
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
              @click=${() => void this.onDownload(parsed, send, passwordHash)}
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
        return html`<vw-status-message tone="danger" .icon=${'alert'} .message=${this.state.message}></vw-status-message>`;
      case 'downloading':
        return html`<vw-status-message tone="info" .message=${this.i18n.t('receive.loading')}></vw-status-message>`;
      case 'error':
        return html`<vw-status-message tone="danger" .icon=${'alert'} .message=${this.state.message}></vw-status-message>`;
      default:
        return nothing;
    }
  }

  protected override render() {
    const busy = this.state.status === 'accessing' || this.state.status === 'downloading';
    return html`
      <div class="page">
        <section class="card" data-task-column>
          <header class="brand" data-page-heading>
            <vw-logo variant="hero"></vw-logo>
            <h1>${this.i18n.t('receive.title')}</h1>
            <!-- TODO i18n -->
            <p>在此设备上查看安全文本或下载共享文件</p>
          </header>
          <div class="form">
            <label class="field">
              <!-- TODO i18n -->
              <span class="field-label">Send 链接</span>
              <input
                class="input mono"
                data-link
                type="url"
                placeholder="https://vault.example/#/send/…/…"
                ?disabled=${busy}
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
            <button type="button" class="btn primary block" data-access ?disabled=${busy} @click=${() => void this.onAccess()}>
              ${uiIcon('unlock')}<span>${this.i18n.t('receive.unlock')}</span>
            </button>
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
