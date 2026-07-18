import { LitElement, css, html, nothing, svg } from 'lit';
import { themeTokens } from '../../components/tokens.js';
import { emit } from '../../components/emit.js';
import { tileColor, tileInitial } from '../../components/tile-color.js';
import { LocalizeController, t } from '../../i18n/index.js';
import type { TotpListEntry } from '../../../core/vault/models.js';

/** Ring geometry: a compact 20px SVG matching the handoff countdown. */
const RING_R = 8;
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
      :host { display:flex; flex-direction:column; min-height:0; flex:1; }
      .view-head { display:flex; align-items:center; min-height:44px; padding:4px 14px 0; }
      .view-title { display:flex; align-items:center; gap:7px; flex:1; color:var(--vw-ink); font-size:12.5px; font-weight:500; }
      .view-title svg { width:17px; height:17px; color:var(--p); }
      .back { height:30px; padding:0 10px; border:0; border-radius:15px; background:transparent; color:var(--p); font:500 11.5px/1 var(--vw-font-ui); cursor:pointer; }
      .back:hover { background:var(--vw-icon-hover); }
      .list { flex:1; min-height:0; overflow-y:auto; padding:0 8px 8px; scrollbar-width:thin; scrollbar-color:var(--vw-scrollbar) transparent; }
      .list::-webkit-scrollbar { width:6px; }
      .list::-webkit-scrollbar-thumb { background:var(--vw-scrollbar); border-radius:3px; }
      .group-label { font-size:11px; font-weight:500; color:var(--vw-muted); padding:8px 8px 4px; }

      .row {
        display:flex; align-items:center; gap:10px; width:100%; min-height:50px; padding:7px 8px;
        border:0; border-radius:12px; background:transparent; color:inherit;
        cursor:pointer; text-align:left; font:inherit; animation:mvStag .24s ease-out both;
      }
      .row:hover { background: var(--vw-row-hover); }
      .row:focus-visible { outline: none; box-shadow: var(--vw-focus); }

      .tile { width:32px; height:32px; border-radius:10px; display:grid; place-items:center; color:#fff; font-size:13px; font-weight:500; flex:none; }
      .meta { flex: 1; min-width: 0; display: flex; flex-direction: column; gap: 1px; }
      .name { font-size:13px; font-weight:500; color:var(--vw-ink); white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
      .user { font-size:11.5px; color:var(--vw-text-2); white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }

      .code {
        font-family:var(--vw-font-mono); font-size:17px; font-weight:500; letter-spacing:.04em;
        color:var(--p); font-variant-numeric:tabular-nums; flex:none;
      }
      .row:hover .code { color: var(--vw-accent); }

      .countdown { display:flex; align-items:center; gap:5px; flex:none; }
      .ring { flex:none; width:20px; height:20px; transform:rotate(-90deg); }
      .ring-track { fill:none; stroke:var(--vw-track); stroke-width:2.5; }
      .ring-arc { fill:none; stroke:var(--p); stroke-width:2.5; stroke-linecap:round; transition:stroke-dashoffset 1s linear, stroke .3s; }
      .seconds { width:22px; color:var(--vw-muted); font:400 10.5px/1 var(--vw-font-ui); font-variant-numeric:tabular-nums; }
      .row.urgent .ring-arc { stroke: #e0a400; }
      .row.urgent .seconds { color:#b06000; }

      .empty { padding: 48px 20px; text-align: center; color: var(--vw-muted); font-size: 12.5px; }
    `,
  ];

  private emit(type: string, detail?: unknown): void {
    emit(this, type, detail);
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
    const heading = html`
      <div class="view-head">
        <span class="view-title">${uiShield()}${t('popup.authenticator')} · ${this.entries.length}</span>
        <button type="button" class="back" @click=${() => this.emit('vw-item-back')}>← ${t('common.back')}</button>
      </div>
    `;
    if (this.entries.length === 0) {
      return html`${heading}<div class="list"><div class="empty">${t('totp.empty')}</div></div>`;
    }
    const currentSet = new Set(this.currentIds);
    const current = this.entries.filter((e) => currentSet.has(e.id));
    return html`
      ${heading}<div class="list">
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
        <span class="countdown">
          <svg class="ring" viewBox="0 0 20 20" aria-hidden="true">
            <circle class="ring-track" cx="10" cy="10" r=${RING_R}></circle>
            <circle class="ring-arc" cx="10" cy="10" r=${RING_R} stroke-dasharray=${RING_C} stroke-dashoffset=${offset}></circle>
          </svg>
          <span class="seconds">${remaining}s</span>
        </span>
      </button>
    `;
  }
}

function uiShield() {
  return svg`<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 3l7 3v5c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V6l7-3z"/><path d="M9 12l2 2 4-4"/></svg>`;
}

customElements.define('vw-totp-view', VwTotpView);

declare global {
  interface HTMLElementTagNameMap {
    'vw-totp-view': VwTotpView;
  }
}
