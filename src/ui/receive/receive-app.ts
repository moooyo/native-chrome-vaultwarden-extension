import { LitElement, css, html, nothing, type PropertyValues } from 'lit';
import browser from 'webextension-polyfill';
import { themeTokens } from '../components/tokens.js';
import { controlStyles } from '../components/styles.js';
import { uiIcon } from '../components/icon.js';
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

const MESSAGES: Record<SendAccessError, string> = {
  invalid_link: 'Invalid Send link.',
  password_required: 'This Send needs a password.',
  unavailable: 'This Send is no longer available.',
  decrypt_failed: 'Could not decrypt — the link or file may be corrupted.',
};

function isSendAccessErrorCode(value: string): value is SendAccessError {
  return value === 'invalid_link' || value === 'password_required' || value === 'unavailable' || value === 'decrypt_failed';
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
 * The dormant Lit Receive root. It owns the whole recipient-side flow — parsing the share link,
 * requesting host permission, accessing/decrypting the Send, and downloading/decrypting a file —
 * performing every side effect itself through the injectable `deps`, and reusing the existing
 * `send-access` helpers for every crypto/protocol step (no duplicated logic here).
 *
 * The Access button's click handler parses the link synchronously and then calls
 * `deps.requestOrigin` as its very first `await`, preserving the user-gesture window
 * `permissions.request` needs. Only Download reads the resulting `passwordHash`/`fetch`, and only
 * after that permission has already been granted.
 *
 * Not wired into `receive.html` yet — `src/ui/receive/receive.ts` remains the live entry point
 * until a later task replaces it.
 */
export class VwReceiveApp extends LitElement {
  static override properties = {
    state: { attribute: false },
  };

  declare state: ReceiveState;

  /** Injectable dependency seam; defaults to the real `webextension-polyfill`/DOM implementation. */
  deps: ReceiveDeps = createDefaultDeps();

  constructor() {
    super();
    this.state = { status: 'idle' };
  }

  static override styles = [
    themeTokens,
    controlStyles,
    css`
      :host {
        display: block;
      }
      .receive {
        display: flex;
        flex-direction: column;
        gap: 12px;
      }
      .actions {
        display: flex;
      }
      .send-name {
        font-weight: 650;
      }
      .send-text {
        white-space: pre-wrap;
        word-break: break-word;
        font-family: var(--vw-font-mono);
        background: var(--vw-blue-50);
        padding: 10px 12px;
        border-radius: var(--vw-radius-control);
      }
      .send-file {
        display: flex;
        align-items: center;
        gap: 10px;
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
      this.state = { status: 'error', message: MESSAGES.invalid_link };
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
      this.state = { status: 'error', message: `Grant access to ${hostOf(parsed.serverUrl)} to receive this Send.` };
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
        this.state = { status: 'passwordRequired', message: MESSAGES.password_required };
      } else {
        this.state = { status: 'error', message: isSendAccessError(err) ? MESSAGES[err.code] : 'Something went wrong.' };
      }
    }
  }

  private async onDownload(parsed: ParsedSendUrl, send: AccessedSend, passwordHash: string | undefined): Promise<void> {
    // Double-submit guard: only start a download from the settled fileReady state.
    if (this.state.status !== 'fileReady') {
      return;
    }
    if (!send.fileId || !send.id) {
      this.state = { status: 'error', message: MESSAGES.unavailable };
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
      this.state = { status: 'error', message: isSendAccessError(err) ? MESSAGES[err.code] : 'Download failed.' };
    }
  }

  private renderResult() {
    switch (this.state.status) {
      case 'textReady':
        return html`
          <div class="send-name">${this.state.name}</div>
          <div class="send-text">${this.state.text}</div>
        `;
      case 'fileReady': {
        const { parsed, send, passwordHash } = this.state;
        return html`
          <div class="send-name">${send.name}</div>
          <div class="send-file">
            ${uiIcon('note')}
            <span>${send.fileName ?? 'file'}${send.sizeName ? ` · ${send.sizeName}` : ''}</span>
            <button
              type="button"
              class="button"
              data-download
              @click=${() => void this.onDownload(parsed, send, passwordHash)}
            >
              ${uiIcon('key')}<span>Download</span>
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
        return html`<vw-status-message tone="info" .message=${'Downloading and decrypting…'}></vw-status-message>`;
      case 'error':
        return html`<vw-status-message tone="danger" .icon=${'alert'} .message=${this.state.message}></vw-status-message>`;
      default:
        return nothing;
    }
  }

  protected override render() {
    const busy = this.state.status === 'accessing' || this.state.status === 'downloading';
    return html`
      <div class="receive">
        <label class="field">
          <span class="field-label">Send link</span>
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
                <span class="field-label">Password</span>
                <input class="input" data-password type="password" autocomplete="off" />
              </label>
            `
          : nothing}
        <div class="actions">
          <button type="button" class="button primary" data-access ?disabled=${busy} @click=${() => void this.onAccess()}>
            ${uiIcon('unlock')}<span>Access Send</span>
          </button>
        </div>
        ${this.renderResult()}
        ${this.renderStatus()}
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
