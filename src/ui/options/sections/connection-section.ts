import { LitElement, css, html, nothing } from 'lit';
import { themeTokens } from '../../components/tokens.js';
import { controlStyles } from '../../components/styles.js';
import { uiIcon } from '../../components/icon.js';
import '../../components/status-message.js';
import type { ConnectionSaveDetail, SectionStatus } from '../types.js';

/**
 * Connection settings: the Vaultwarden server URL. This is the only section that leads to a host
 * permission prompt, so it carries the permission notice. Validation/normalization is local and
 * synchronous — the section parses the URL with `new URL(...)` and emits an already-normalized
 * value, so the root can request host permission in the same user gesture without an intervening
 * await. The root performs the permission request and the `settings.save`; this section never does.
 */
export class VwConnectionSection extends LitElement {
  static override properties = {
    serverUrl: { type: String },
    pending: { type: Boolean },
    status: { attribute: false },
    validationError: { state: true },
  };

  declare serverUrl: string;
  declare pending: boolean;
  declare status: SectionStatus | undefined;
  declare validationError: string | undefined;

  constructor() {
    super();
    this.serverUrl = '';
    this.pending = false;
    this.status = undefined;
    this.validationError = undefined;
  }

  static override styles = [
    themeTokens,
    controlStyles,
    css`
      :host { display: block; max-width: 760px; }
      h1 { margin: 0 0 4px; font-size: 28px; color: var(--vw-ink-strong); }
      h2 { margin: 0; padding: 10px 12px; background: var(--vw-blue-weak); font-size: 14px; }
      p.lede { margin: 0 0 24px; color: var(--vw-muted); font-size: 14px; }
      form { display: flex; flex-direction: column; }
      .settings-group { overflow: hidden; border: 1px solid var(--vw-line); border-radius: var(--vw-radius-row); background: var(--vw-panel); }
      .sr-only { position:absolute; width:1px; height:1px; padding:0; margin:-1px; overflow:hidden; clip:rect(0,0,0,0); white-space:nowrap; border:0; }
      .setting-row { display: grid; grid-template-columns: minmax(180px, 1fr) minmax(210px, 320px); gap: 24px; align-items: center; padding: 16px 12px; border-top: 1px solid var(--vw-line-weak); }
      .setting-row .field { margin: 0; }
      .input { width: 100%; box-sizing: border-box; }
      .notice { display: flex; gap: 8px; margin: 0; font-size: 12px; color: var(--vw-muted); }
      .notice svg { width: 16px; height: 16px; flex: none; }
      .status { margin-top: 12px; }
      .primary-action { align-self: flex-start; margin-top: 18px; min-width: 150px; }
      @media (max-width: 640px) { .setting-row { grid-template-columns: 1fr; gap: 10px; } }
    `,
  ];

  private submit(event: Event): void {
    event.preventDefault();
    if (this.pending) return;
    this.validationError = undefined;
    const raw = this.renderRoot.querySelector<HTMLInputElement>('[data-server-url]')?.value ?? '';
    let normalized: string;
    try {
      normalized = new URL(raw).toString();
    } catch {
      this.validationError = 'Enter a valid server URL (for example http://10.0.1.20:8080).';
      return;
    }
    this.dispatchEvent(new CustomEvent<ConnectionSaveDetail>('vw-connection-save', {
      detail: { serverUrl: normalized },
      bubbles: true,
      composed: true,
    }));
  }

  private renderStatus() {
    if (this.validationError) {
      return html`<vw-status-message class="status" tone="danger" .icon=${'alert'} .message=${this.validationError}></vw-status-message>`;
    }
    if (this.status) {
      return html`<vw-status-message class="status" tone=${this.status.tone} .message=${this.status.message}></vw-status-message>`;
    }
    return nothing;
  }

  protected override render() {
    return html`
      <header><h1>Connection</h1><p class="lede">Choose the Vaultwarden or Bitwarden server used by this browser.</p></header>
      <form @submit=${(e: Event) => this.submit(e)}>
        <section class="settings-group">
          <h2>Server connection</h2>
          <div class="setting-row" data-setting-row>
            <div><strong>Server URL</strong><p class="notice">${uiIcon('shield')}<span>Chrome asks for permission when this address changes.</span></p></div>
            <label class="field"><span class="sr-only">Server URL</span><input class="input" data-server-url type="text" inputmode="url" autocomplete="off" placeholder="http://10.0.1.20:8080" .value=${this.serverUrl} /></label>
          </div>
        </section>
        <button type="submit" class="button primary primary-action" data-save data-primary-action ?disabled=${this.pending}>${uiIcon('check')}<span>Save connection</span></button>
      </form>
      ${this.renderStatus()}
    `;
  }
}

customElements.define('vw-connection-section', VwConnectionSection);

declare global {
  interface HTMLElementTagNameMap {
    'vw-connection-section': VwConnectionSection;
  }
}
