import { LitElement, css, html, nothing } from 'lit';
import { themeTokens, paletteTokens } from '../components/tokens.js';
import { LocalizeController, t } from '../i18n/index.js';
import type { MessageKey } from '../i18n/index.js';
import { AppearanceController } from '../theme.js';
import '../components/logo.js';
import { tileInitial } from '../components/tile-color.js';

export interface OptionsNavItem {
  id: string;
  labelKey: MessageKey;
}

/**
 * The MiYu options shell: a 236px sidebar (logo + version badge + nav + user card) and a content
 * column (eyebrow + section title + slotted section). It is the page ROOT's visual frame, so it
 * composes `paletteTokens` and mirrors the theme onto its host via `AppearanceController`, letting
 * the whole options tree re-theme at runtime. Emits `vw-nav-change` with `{ id }`.
 */
export class VwOptionsShell extends LitElement {
  static override properties = {
    items: { attribute: false },
    selected: { type: String },
    version: { type: String },
    accountName: { type: String },
    accountEmail: { type: String },
  };

  declare items: OptionsNavItem[];
  declare selected: string;
  declare version: string;
  declare accountName: string;
  declare accountEmail: string;

  private i18n = new LocalizeController(this);
  private appearance = new AppearanceController(this);

  constructor() {
    super();
    this.items = [];
    this.selected = '';
    this.version = '';
    this.accountName = '';
    this.accountEmail = '';
  }

  static override styles = [
    paletteTokens,
    themeTokens,
    css`
      :host { display: flex; min-height: 100vh; background: var(--vw-options-bg); color: var(--vw-ink); }

      .sidebar {
        width: 236px;
        flex: none;
        box-sizing: border-box;
        display: flex;
        flex-direction: column;
        padding: 20px 12px 14px;
        border-right: 1px solid var(--vw-line-1);
      }
      .brand { display: flex; align-items: center; gap: 9px; padding: 0 10px 16px; }
      .brand .name { font-size: 15px; font-weight: 600; color: var(--vw-ink); }
      .badge {
        margin-left: auto; font-family: var(--vw-font-mono); font-size: 10px; color: var(--vw-muted);
        background: var(--vw-icon-hover); border-radius: 5px; padding: 2px 6px;
      }
      nav { display: flex; flex-direction: column; gap: 2px; }
      .nav-item {
        display: flex; align-items: center; height: 34px; padding: 0 12px; border: none; border-radius: var(--vw-radius-input);
        background: transparent; color: var(--vw-text-2); font-family: inherit; font-size: 13px; text-align: left;
        cursor: pointer; transition: background-color var(--vw-dur-fast);
      }
      .nav-item:hover { background: var(--vw-row-hover); }
      .nav-item.on { background: var(--vw-icon-hover); color: var(--vw-ink); font-weight: 600; }
      .nav-item:focus-visible { outline: none; box-shadow: var(--vw-focus); }
      .spacer { flex: 1; }
      .user { display: flex; align-items: center; gap: 9px; padding: 12px 10px 4px; border-top: 1px solid var(--vw-line-1); }
      .avatar { width: 28px; height: 28px; border-radius: 50%; background: var(--vw-teal-solid); color: #fff; display: grid; place-items: center; font-size: 12px; font-weight: 600; flex: none; }
      .user .meta { min-width: 0; }
      .user .name { font-size: 12px; font-weight: 600; color: var(--vw-ink); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
      .user .email { font-size: 10.5px; color: var(--vw-muted); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }

      .content { flex: 1; min-width: 0; overflow-y: auto; }
      .inner { max-width: 720px; padding: 28px 40px 44px; }
      .eyebrow { font-size: 12px; color: var(--vw-muted); }
      .title { font-size: 24px; font-weight: 650; letter-spacing: -0.01em; margin: 2px 0 18px; color: var(--vw-ink); }
      .section { display: flex; flex-direction: column; gap: 8px; }
    `,
  ];

  private selectNav(id: string): void {
    if (id === this.selected) return;
    this.dispatchEvent(new CustomEvent('vw-nav-change', { detail: { id }, bubbles: true, composed: true }));
  }

  private currentLabel(): string {
    const item = this.items.find((i) => i.id === this.selected);
    return item ? t(item.labelKey) : '';
  }

  protected override render() {
    return html`
      <aside class="sidebar">
        <div class="brand">
          <vw-logo variant="sidebar"></vw-logo>
          <span class="name">${t('common.brand')}</span>
          ${this.version ? html`<span class="badge">v${this.version}</span>` : nothing}
        </div>
        <nav>
          ${this.items.map(
            (item) => html`
              <button
                type="button"
                class="nav-item ${item.id === this.selected ? 'on' : ''}"
                aria-current=${item.id === this.selected ? 'page' : 'false'}
                @click=${() => this.selectNav(item.id)}
              >
                ${t(item.labelKey)}
              </button>
            `,
          )}
        </nav>
        <div class="spacer"></div>
        ${this.accountEmail
          ? html`
              <div class="user">
                <div class="avatar">${tileInitial(this.accountName || this.accountEmail)}</div>
                <div class="meta">
                  ${this.accountName ? html`<div class="name">${this.accountName}</div>` : nothing}
                  <div class="email">${this.accountEmail}</div>
                </div>
              </div>`
          : nothing}
      </aside>
      <div class="content">
        <div class="inner">
          <div class="eyebrow">${t('options.eyebrow')}</div>
          <h1 class="title">${this.currentLabel()}</h1>
          <div class="section"><slot></slot></div>
        </div>
      </div>
    `;
  }
}

customElements.define('vw-options-shell', VwOptionsShell);

declare global {
  interface HTMLElementTagNameMap {
    'vw-options-shell': VwOptionsShell;
  }
}
