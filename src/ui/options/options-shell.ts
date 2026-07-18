import { LitElement, css, html, nothing } from 'lit';
import { keyed } from 'lit/directives/keyed.js';
import { themeTokens, paletteTokens } from '../components/tokens.js';
import { emit } from '../components/emit.js';
import { LocalizeController, t, getLocale, setLocale, type Locale } from '../i18n/index.js';
import type { MessageKey } from '../i18n/index.js';
import { AppearanceController, getTheme, setTheme } from '../theme.js';
import { uiIcon, type IconName } from '../components/icon.js';
import '../components/logo.js';

export interface OptionsNavItem {
  id: string;
  labelKey: MessageKey;
  icon?: IconName;
}

/**
 * The MiYu options shell: a 236px sidebar (logo + version badge + nav + quick controls) and a content
 * column (eyebrow + section title + slotted section). It is the page ROOT's visual frame, so it
 * composes `paletteTokens` and mirrors the theme onto its host via `AppearanceController`, letting
 * the whole options tree re-theme at runtime. The sidebar footer holds three quick controls — a
 * light/dark theme toggle, a zh/EN language toggle, and logout — instead of an account card. Emits
 * `vw-nav-change` with `{ id }` and `vw-logout`.
 */
export class VwOptionsShell extends LitElement {
  static override properties = {
    items: { attribute: false },
    selected: { type: String },
    version: { type: String },
  };

  declare items: OptionsNavItem[];
  declare selected: string;
  declare version: string;

  private i18n = new LocalizeController(this);
  private appearance = new AppearanceController(this);

  constructor() {
    super();
    this.items = [];
    this.selected = '';
    this.version = '';
  }

  static override styles = [
    paletteTokens,
    themeTokens,
    css`
      :host { display:flex; min-height:100vh; background:var(--vw-options-bg); color:var(--vw-ink); }

      .sidebar {
        width: 212px;
        flex: none;
        box-sizing: border-box;
        display: flex;
        flex-direction: column;
        padding: 18px 10px 14px;
      }
      .brand { display:flex; align-items:center; gap:9px; padding:0 10px 18px; }
      .brand .name { font-size:15px; font-weight:500; color:var(--vw-ink); }
      .badge {
        margin-left: auto; font-family: var(--vw-font-mono); font-size: 10px; color: var(--vw-muted);
        background:var(--vw-fill); border-radius:6px; padding:2px 6px;
      }
      nav { display:flex; flex-direction:column; gap:2px; }
      .nav-item {
        display:flex; align-items:center; gap:12px; height:40px; padding:0 14px; border:0; border-radius:20px;
        background:transparent; color:var(--vw-text-2); font-family:inherit; font-size:13px; text-align:left;
        cursor: pointer; transition: background-color var(--vw-dur-fast);
      }
      .nav-item:hover { background: var(--vw-row-hover); }
      .nav-item.on { background:var(--pc); color:var(--onpc); font-weight:500; }
      .nav-icon { width:18px; height:18px; display:inline-flex; flex:none; }
      .nav-icon svg { width:18px; height:18px; }
      .nav-item:focus-visible { outline: none; box-shadow: var(--vw-focus); }
      .spacer { flex: 1; }

      /* Sidebar footer — quick controls (theme toggle · language toggle · logout) */
      .foot {
        display: flex; flex-direction: column; gap: 8px;
        padding:12px 10px 4px; border-top:1px solid var(--vw-line-1);
      }
      .foot-controls { display: flex; align-items: center; gap: 8px; }
      .foot-icon {
        display: inline-flex; align-items: center; justify-content: center;
        width: 30px; height: 30px; flex: none; border: none; border-radius: var(--vw-radius-input);
        background: transparent; color: var(--vw-text-2); cursor: pointer;
        transition: background-color var(--vw-dur-fast), color var(--vw-dur-fast);
      }
      .foot-icon:hover { background: var(--vw-row-hover); color: var(--vw-ink); }
      .foot-icon:focus-visible { outline: none; box-shadow: var(--vw-focus); }
      .foot-icon svg { width: 17px; height: 17px; }

      .lang { display: inline-flex; margin-left: auto; gap: 2px; padding: 2px; background: var(--vw-icon-hover); border-radius: var(--vw-radius-input); }
      .lang-seg {
        min-width: 30px; height: 24px; padding: 0 8px; border: none; border-radius: calc(var(--vw-radius-input) - 2px);
        background: transparent; color: var(--vw-muted); font-family: inherit; font-size: 12px; font-weight: 600;
        cursor: pointer; transition: background-color var(--vw-dur-fast), color var(--vw-dur-fast);
      }
      .lang-seg:hover { color: var(--vw-ink); }
      .lang-seg.on { background: var(--vw-panel); color: var(--vw-ink); }
      .lang-seg:focus-visible { outline: none; box-shadow: var(--vw-focus); }

      .foot-logout {
        display: inline-flex; align-items: center; gap: 8px; width: 100%; height: 34px; padding: 0 12px;
        border: none; border-radius: var(--vw-radius-input); background: transparent; color: var(--vw-text-2);
        font-family: inherit; font-size: 13px; text-align: left; cursor: pointer;
        transition: background-color var(--vw-dur-fast), color var(--vw-dur-fast);
      }
      .foot-logout:hover { background: var(--vw-row-hover); color: var(--vw-danger); }
      .foot-logout:focus-visible { outline: none; box-shadow: var(--vw-focus); }
      .foot-logout svg { width: 16px; height: 16px; flex: none; }

      .content { flex:1; min-width:0; overflow-y:auto; }
      .inner { max-width:580px; margin:0; padding:28px 36px 44px; }
      .eyebrow { display:none; }
      .title { margin:0 0 18px; color:var(--vw-ink); font-size:22px; font-weight:400; letter-spacing:0; }
      .section { display:flex; flex-direction:column; gap:8px; animation:mvIn .2s ease-out; }
      @media (max-width:720px) {
        :host { display:block; }
        .sidebar { width:100%; padding-bottom:8px; }
        nav { flex-direction:row; overflow-x:auto; }
        .nav-item { flex:none; }
        .spacer, .foot { display:none; }
        .inner { padding:22px 18px 36px; }
      }
    `,
  ];

  private selectNav(id: string): void {
    if (id === this.selected) return;
    emit(this, 'vw-nav-change', { id });
  }

  private currentLabel(): string {
    const item = this.items.find((i) => i.id === this.selected);
    return item ? t(item.labelKey) : '';
  }

  /** The active light/dark theme, resolving `system` against the OS preference. */
  private effectiveTheme(): 'light' | 'dark' {
    const theme = getTheme();
    if (theme === 'system') {
      return typeof matchMedia === 'function' && matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
    }
    return theme;
  }

  private toggleTheme(): void {
    setTheme(this.effectiveTheme() === 'dark' ? 'light' : 'dark');
  }

  private selectLang(locale: Locale): void {
    setLocale(locale);
  }

  private emitLogout(): void {
    emit(this, 'vw-logout');
  }

  private renderFooter() {
    const langs: readonly Locale[] = ['zh-CN', 'en'];
    return html`
      <footer class="foot">
        <div class="foot-controls">
          <button
            type="button"
            class="foot-icon"
            data-theme-toggle
            title=${t('options.footer.toggleTheme')}
            aria-label=${t('options.footer.toggleTheme')}
            aria-pressed=${this.effectiveTheme() === 'dark' ? 'true' : 'false'}
            @click=${() => this.toggleTheme()}
          >
            ${uiIcon(this.effectiveTheme() === 'dark' ? 'moon' : 'sun')}
          </button>
          <div class="lang" role="group" aria-label=${t('options.appearance.language')}>
            ${langs.map(
              (loc) => html`
                <button
                  type="button"
                  class="lang-seg ${getLocale() === loc ? 'on' : ''}"
                  data-lang=${loc}
                  aria-pressed=${getLocale() === loc ? 'true' : 'false'}
                  aria-label=${loc === 'zh-CN' ? t('options.appearance.langZh') : t('options.appearance.langEn')}
                  @click=${() => this.selectLang(loc)}
                >
                  ${loc === 'zh-CN' ? '中' : 'EN'}
                </button>
              `,
            )}
          </div>
        </div>
        <button type="button" class="foot-logout" data-logout @click=${() => this.emitLogout()}>
          ${uiIcon('logout')}<span>${t('auth.logout')}</span>
        </button>
      </footer>
    `;
  }

  protected override render() {
    return html`
      <aside class="sidebar">
        <div class="brand">
          <vw-logo variant="sidebar"></vw-logo>
          <span class="name">${t('common.brand')} ${t('options.eyebrow')}</span>
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
                ${item.icon ? html`<span class="nav-icon">${uiIcon(item.icon)}</span>` : nothing}
                ${t(item.labelKey)}
              </button>
            `,
          )}
        </nav>
        <div class="spacer"></div>
        ${this.renderFooter()}
      </aside>
      <div class="content">
        <div class="inner">
          <div class="eyebrow">${t('options.eyebrow')}</div>
          <h1 class="title">${this.currentLabel()}</h1>
          ${keyed(this.selected, html`<div class="section"><slot></slot></div>`)}
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
