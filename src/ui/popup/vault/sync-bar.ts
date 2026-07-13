import { LitElement, css, html } from 'lit';
import { themeTokens } from '../../components/tokens.js';
import { uiIcon } from '../../components/icon.js';
import { LocalizeController, t } from '../../i18n/index.js';

/**
 * The popup's bottom sync bar: a status dot (teal synced / amber syncing), a relative "last synced"
 * label, and a manual sync button whose icon spins while a sync is in flight. Emits `vw-sync-now`.
 * `lastSync` is an epoch-ms timestamp (or undefined when never synced); the relative label is
 * computed here so it stays localized and live.
 */
export class VwSyncBar extends LitElement {
  static override properties = {
    syncing: { type: Boolean },
    lastSync: { type: Number },
  };

  declare syncing: boolean;
  declare lastSync: number | undefined;

  private i18n = new LocalizeController(this);

  constructor() {
    super();
    this.syncing = false;
    this.lastSync = undefined;
  }

  static override styles = [
    themeTokens,
    css`
      :host { display: block; flex: none; }
      .bar {
        display: flex;
        align-items: center;
        gap: 7px;
        height: 32px;
        padding: 0 14px;
        border-top: 1px solid var(--vw-line-1);
      }
      .dot { width: 6px; height: 6px; border-radius: 50%; flex: none; background: var(--vw-teal-solid); }
      .dot.syncing { background: var(--vw-sync-amber); }
      .label { font-size: 11px; color: var(--vw-muted); }
      .spacer { flex: 1; }
      button {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        width: 24px;
        height: 24px;
        border: none;
        border-radius: var(--vw-radius-small);
        background: transparent;
        color: var(--vw-text-2);
        cursor: pointer;
      }
      button:hover { background: var(--vw-icon-hover); }
      button:focus-visible { outline: none; box-shadow: var(--vw-focus); }
      button svg { width: 13px; height: 13px; }
      button.spin svg { animation: mvSpin 0.8s linear infinite; }
      @keyframes mvSpin { to { transform: rotate(360deg); } }
      @media (prefers-reduced-motion: reduce) { button.spin svg { animation: none; } }
    `,
  ];

  private label(): string {
    if (this.syncing) return t('sync.syncing');
    if (this.lastSync === undefined) return t('sync.never');
    const seconds = Math.max(0, Math.floor((Date.now() - this.lastSync) / 1000));
    if (seconds < 45) return t('sync.synced', { time: t('sync.justNow') });
    const minutes = Math.round(seconds / 60);
    if (minutes < 60) return t('sync.synced', { time: t('sync.minutesAgo', { count: minutes }) });
    const hours = Math.round(minutes / 60);
    if (hours < 24) return t('sync.synced', { time: t('sync.hoursAgo', { count: hours }) });
    return t('sync.synced', { time: t('sync.daysAgo', { count: Math.round(hours / 24) }) });
  }

  private syncNow(): void {
    if (this.syncing) return;
    this.dispatchEvent(new CustomEvent('vw-sync-now', { bubbles: true, composed: true }));
  }

  protected override render() {
    return html`
      <div class="bar">
        <span class="dot ${this.syncing ? 'syncing' : ''}"></span>
        <span class="label">${this.label()}</span>
        <span class="spacer"></span>
        <button
          type="button"
          class=${this.syncing ? 'spin' : ''}
          title=${t('sync.now')}
          aria-label=${t('sync.now')}
          @click=${this.syncNow}
        >
          ${uiIcon('refresh')}
        </button>
      </div>
    `;
  }
}

customElements.define('vw-sync-bar', VwSyncBar);

declare global {
  interface HTMLElementTagNameMap {
    'vw-sync-bar': VwSyncBar;
  }
}
