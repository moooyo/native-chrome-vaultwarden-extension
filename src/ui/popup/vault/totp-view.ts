import { LitElement, css, html, nothing, svg } from 'lit';
import { themeTokens } from '../../components/tokens.js';
import { tileColor, tileInitial } from '../../components/tile-color.js';
import { LocalizeController, t } from '../../i18n/index.js';
import type { TotpListEntry } from '../../../core/vault/models.js';

/** Ring geometry: a 26px SVG, radius 11 → this circumference drives the draining arc. */
const RING_R = 11;
const RING_C = 2 * Math.PI * RING_R;
/** Below this many seconds the ring + count warm to amber to signal an imminent refresh. */
const URGENT_S = 5;

/**
 * The 2FA view: every login carrying a TOTP secret as a live one-time code. Each row is one line —
 * item + code (mono, right-aligned so codes read down a column) + a draining ring with the seconds
 * remaining at its centre (the view's signature; warms to amber in the final seconds). The whole row
 * is the copy target. Split into a current-site group (logins matching the active tab) and an all
 * group. Display-only — the parent (`VwPopupApp`) owns the per-second tick and the periodic refetch.
 */
export class VwTotpView extends LitElement {
  static override properties = {
    entries: { attribute: false },
    currentIds: { attribute: false },
    currentDomain: { type: String },
  };

  declare entries: TotpListEntry[];
  declare currentIds: string[];
  declare currentDomain: string;

  private i18n = new LocalizeController(this);

  constructor() {
    super();
    this.entries = [];
    this.currentIds = [];
    this.currentDomain = '';
  }

  static override styles = [
    themeTokens,
    css`
      :host { display: flex; flex-direction: column; min-height: 0; flex: 1; }
      .list { flex: 1; min-height: 0; overflow-y: auto; padding: 2px 8px 8px; scrollbar-width: thin; scrollbar-color: var(--vw-scrollbar) transparent; }
      .list::-webkit-scrollbar { width: 8px; }
      .list::-webkit-scrollbar-thumb { background: var(--vw-scrollbar); border-radius: 4px; border: 2px solid transparent; background-clip: content-box; }

      .group-label { font-size: 11px; font-weight: 600; color: var(--vw-muted); padding: 10px 6px 4px; letter-spacing: 0.01em; }

      .row {
        display: flex; align-items: center; gap: 11px;
        width: 100%; padding: 9px 8px; border: none; background: transparent;
        border-radius: var(--vw-radius-control); cursor: pointer; text-align: left; font: inherit; color: inherit;
        animation: mvStag 0.3s ease-out both;
      }
      .row:hover { background: var(--vw-row-hover); }
      .row:focus-visible { outline: none; box-shadow: var(--vw-focus); }

      .tile { width: 34px; height: 34px; border-radius: var(--vw-radius-control); display: grid; place-items: center; color: #fff; font-size: 13px; font-weight: 700; flex: none; }
      .meta { flex: 1; min-width: 0; display: flex; flex-direction: column; gap: 1px; }
      .name { font-size: 13px; font-weight: 600; color: var(--vw-ink); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
      .user { font-size: 11.5px; color: var(--vw-muted); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }

      .code {
        font-family: var(--vw-font-mono); font-size: 16.5px; font-weight: 600; letter-spacing: 0.04em;
        color: var(--vw-teal-text); font-variant-numeric: tabular-nums; flex: none;
      }
      .row:hover .code { color: var(--vw-accent); }

      .ring { flex: none; width: 28px; height: 28px; transform: rotate(-90deg); }
      .ring-track { fill: none; stroke: var(--vw-track); stroke-width: 2.75; }
      .ring-arc { fill: none; stroke: var(--vw-teal-text); stroke-width: 2.75; stroke-linecap: round; transition: stroke-dashoffset 1s linear, stroke 0.3s; }
      .ring-num { font-family: var(--vw-font-mono); font-size: 9.5px; font-weight: 600; fill: var(--vw-muted); font-variant-numeric: tabular-nums; }
      .row.urgent .ring-arc { stroke: #e0a400; }
      .row.urgent .ring-num { fill: #e0a400; }

      .empty { padding: 48px 20px; text-align: center; color: var(--vw-muted); font-size: 12.5px; }
    `,
  ];

  private emit(type: string, detail?: unknown): void {
    this.dispatchEvent(new CustomEvent(type, { detail, bubbles: true, composed: true }));
  }

  private copy(entry: TotpListEntry): void {
    this.emit('vw-copy', { value: entry.code, label: t('detail.totp') });
  }

  private grouped(code: string): string {
    if (code.length === 6) return `${code.slice(0, 3)} ${code.slice(3)}`;
    if (code.length === 8) return `${code.slice(0, 4)} ${code.slice(4)}`;
    return code;
  }

  protected override render() {
    if (this.entries.length === 0) {
      return html`<div class="list"><div class="empty">${t('totp.empty')}</div></div>`;
    }
    const currentSet = new Set(this.currentIds);
    const current = this.entries.filter((e) => currentSet.has(e.id));
    return html`
      <div class="list">
        ${current.length
          ? html`
              <div class="group-label">${t('totp.currentSite')}</div>
              ${current.map((e) => this.renderRow(e))}
            `
          : nothing}
        <div class="group-label">${t('totp.all')}</div>
        ${this.entries.map((e) => this.renderRow(e))}
      </div>
    `;
  }

  private renderRow(entry: TotpListEntry) {
    const period = entry.period || 30;
    const remaining = Math.max(0, Math.min(period, entry.remaining));
    const urgent = remaining <= URGENT_S;
    // Draining arc: full ring when fresh, empties as time runs out.
    const offset = RING_C * (1 - remaining / period);
    const label = entry.username ? `${entry.name} · ${entry.username}` : entry.name;
    return html`
      <button type="button" class="row ${urgent ? 'urgent' : ''}" title=${t('detail.copyCode')} aria-label=${`${t('detail.copyCode')} — ${label}`} @click=${() => this.copy(entry)}>
        <span class="tile" style=${`background:${tileColor(entry.id)}`}>${tileInitial(entry.name)}</span>
        <span class="meta">
          <span class="name">${entry.name}</span>
          ${entry.username ? html`<span class="user">${entry.username}</span>` : nothing}
        </span>
        <span class="code">${this.grouped(entry.code)}</span>
        <svg class="ring" viewBox="0 0 26 26" aria-hidden="true">
          <circle class="ring-track" cx="13" cy="13" r=${RING_R}></circle>
          <circle class="ring-arc" cx="13" cy="13" r=${RING_R}
            stroke-dasharray=${RING_C} stroke-dashoffset=${offset}></circle>
          ${svg`<text class="ring-num" x="13" y="13" transform="rotate(90 13 13)" text-anchor="middle" dominant-baseline="central">${remaining}</text>`}
        </svg>
      </button>
    `;
  }
}

customElements.define('vw-totp-view', VwTotpView);

declare global {
  interface HTMLElementTagNameMap {
    'vw-totp-view': VwTotpView;
  }
}
