import { html, nothing, type TemplateResult } from 'lit';
import { uiIcon } from '../../ui/components/icon.js';
import { SIDE_PANEL_CSS, sideWrap } from './side-panel.js';

// TODO i18n: content-script surfaces are isolated from the extension i18n module, so these
// user-facing strings are hardcoded in Chinese to match the 密屿/MiYu design.

export type TotpPanelView = 'panel' | 'filled' | 'status';

/** The full render state of the 2FA panel surface. Held by the factory (see totp-fill.ts) and passed
 *  to `renderTotpPanel` on every state change — no cipher id ever reaches this state or the DOM. */
export interface TotpPanelState {
  view: TotpPanelView;
  itemName: string;
  itemUser: string;
  code: string;
  remaining: number;
  statusMessage: string;
}

/** Privileged callbacks. Every click that reaches them is gated on `Event.isTrusted` in the template,
 *  so a page script cannot synthesize a click to fill / copy / undo. */
export interface TotpPanelHandlers {
  onFill?: () => void;
  onCopy?: () => void;
  onUndo?: () => void;
}

/**
 * Styles for the 密屿/MiYu 2FA side panel (design 3a): a standalone verification-code step showing the
 * matching item, a live one-time code with a 30s meter, and a "填充验证码" action. Because the surface
 * lives in a closed shadow root on arbitrary host pages it cannot use the extension's `--vw-*` tokens,
 * so the MiYu palette is defined locally on `:host` with a `prefers-color-scheme: dark` override.
 */
export const TOTP_PANEL_STYLES = `
    :host { all: initial; }
    :host {
      --mi-panel: #fff;
      --mi-ink: #16181D;
      --mi-muted: #8A8F99;
      --mi-faint: #9AA0AA;
      --mi-teal: #0E8A72;
      --mi-teal-text: #0B7A65;
      --mi-teal-10: rgba(14,138,114,.1);
      --mi-teal-20: rgba(14,138,114,.2);
      --mi-line: rgba(22,24,29,.09);
      --mi-line-3: rgba(22,24,29,.14);
      --mi-fill-2: #F7F7F4;
      --mi-row-hover: #F2F2EF;
      --mi-track: rgba(22,24,29,.08);
      --mi-ink-btn: #16181D;
      --mi-ink-btn-fg: #fff;
      --mi-shadow: 0 16px 40px rgba(20,24,32,.16);
    }
    * { box-sizing: border-box; }
    .box {
      font: 400 14px/1.4 "Instrument Sans", "Segoe UI", system-ui, sans-serif;
      color: var(--mi-ink); background: var(--mi-panel);
      border: 1px solid var(--mi-line); border-radius: 14px; box-shadow: var(--mi-shadow);
      width: 276px; overflow: hidden; animation: mvIn .18s ease-out;
    }
    @keyframes mvIn { from { opacity: 0; transform: translateY(-5px); } to { opacity: 1; transform: none; } }
    .head { display: flex; align-items: center; gap: 7px; padding: 10px 13px 7px; }
    .brand { font-size: 11.5px; font-weight: 600; letter-spacing: .01em; color: var(--mi-teal-text); }
    .head .meta { margin-left: auto; font-size: 10.5px; color: var(--mi-faint); }
    .logo { display: grid; place-items: center; width: 16px; height: 16px; border-radius: 5px; background: #0E8A72; flex: none; }
    .glyph { position: relative; width: 8px; height: 8px; }
    .ring { position: absolute; inset: 0; border: 1.5px solid #fff; border-radius: 50%; }
    .dot { position: absolute; left: 3px; top: 3px; width: 2px; height: 2px; border-radius: 50%; background: #fff; }

    .row { display: flex; align-items: center; gap: 9px; padding: 4px 13px 8px; }
    .tile { display: grid; place-items: center; width: 30px; height: 30px; flex: none; border-radius: 9px; color: #fff; font-weight: 700; font-size: 12px; text-transform: uppercase; }
    .meta-col { min-width: 0; flex: 1; }
    .title { font-size: 12.5px; font-weight: 600; color: var(--mi-ink); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .sub { font-size: 11px; color: var(--mi-muted); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }

    .code-box { margin: 0 13px; padding: 9px 11px; background: var(--mi-fill-2); border: 1px solid var(--mi-line); border-radius: 10px; display: flex; align-items: center; gap: 9px; }
    .code { flex: 1; display: flex; align-items: baseline; font-family: "JetBrains Mono", ui-monospace, monospace; font-weight: 600; font-size: 20px; color: var(--mi-teal-text); }
    .code .grp { flex: 1; display: flex; justify-content: space-between; }
    .code .grp:first-child { margin-right: 0.7em; }
    .secs { font-size: 10.5px; color: var(--mi-faint); flex: none; }
    /* Circular countdown: an arc that drains clockwise from the top as the seconds tick down.
       (Named cd-* to avoid the logo glyph's own .ring/.dot classes.) */
    .cd-ring { width: 18px; height: 18px; flex: none; }
    .cd-ring circle { fill: none; }
    .cd-track { stroke: var(--mi-track); stroke-width: 2.5; }
    .cd-arc { stroke: var(--mi-teal); stroke-width: 2.5; stroke-linecap: round; transform: rotate(-90deg); transform-origin: center; transform-box: fill-box; transition: stroke-dashoffset 1s linear; }

    .actions { display: flex; gap: 8px; padding: 10px 13px 13px; }
    .btn-primary { flex: 1; height: 31px; border: 0; border-radius: 9px; background: var(--mi-ink-btn); color: var(--mi-ink-btn-fg); font: 600 12px/1 "Instrument Sans", system-ui, sans-serif; cursor: pointer; }
    .btn-primary:hover { background: #2A2D34; }
    .icon-btn { width: 31px; height: 31px; border: 1px solid var(--mi-line-3); border-radius: 9px; background: var(--mi-panel); color: #3F444E; display: grid; place-items: center; cursor: pointer; }
    .icon-btn:hover { background: var(--mi-row-hover); }
    .icon-btn svg { width: 14px; height: 14px; }
    button:focus-visible { outline: none; box-shadow: 0 0 0 2px var(--mi-teal); }
    svg { stroke-width: 1.8; }

    .filled { display: flex; align-items: center; gap: 8px; padding: 10px 13px 13px; }
    .badge { display: inline-flex; align-items: center; gap: 6px; height: 28px; padding: 0 12px; border-radius: 14px; background: var(--mi-teal-10); border: 1px solid var(--mi-teal-20); color: var(--mi-teal-text); font-size: 11.5px; font-weight: 600; animation: mvPop .28s ease-out both; }
    .badge svg { width: 12px; height: 12px; stroke-width: 2.4; }
    @keyframes mvPop { 0% { transform: scale(.4); opacity: 0; } 65% { transform: scale(1.12); opacity: 1; } 100% { transform: scale(1); opacity: 1; } }
    .undo { font-size: 11.5px; color: var(--mi-muted); cursor: pointer; background: none; border: 0; font-family: inherit; }
    .undo:hover { color: var(--mi-ink); text-decoration: underline; }

    .status { display: flex; align-items: center; gap: 10px; margin: 8px; padding: 11px 13px; border-radius: 12px; background: var(--mi-fill-2); }
    .status-msg { font-size: 12.5px; font-weight: 600; color: var(--mi-ink); }

    @media (prefers-color-scheme: dark) {
      :host {
        --mi-panel: #1F2229; --mi-ink: #F2F3F5; --mi-muted: #9AA0AC; --mi-faint: #7B818B;
        --mi-teal-text: #45D6B5; --mi-teal-10: rgba(69,214,181,.14); --mi-teal-20: rgba(69,214,181,.24);
        --mi-line: rgba(255,255,255,.09); --mi-line-3: rgba(255,255,255,.16); --mi-fill-2: #262A33;
        --mi-row-hover: rgba(255,255,255,.05); --mi-track: rgba(255,255,255,.12);
        --mi-ink-btn: #F2F3F5; --mi-ink-btn-fg: #16181D; --mi-shadow: 0 18px 48px rgba(0,0,0,.5);
      }
      .btn-primary:hover { background: #fff; }
    }
    @media (prefers-reduced-motion: reduce) { *, *::before, *::after { animation: none !important; } }
  ` + SIDE_PANEL_CSS;

function trusted(event: Event, fn: (() => void) | undefined): void {
  if (!event.isTrusted) return;
  fn?.();
}

/** The code laid out to fill the row: two digit groups pushed to the ends (space-between) so the code
 *  spans the width instead of bunching on the left, each digit evenly boxed. */
function codeGroups(code: string): TemplateResult {
  const c = code ?? '';
  if (c.length !== 6) {
    return html`<span class="grp">${[...c].map((d) => html`<span>${d}</span>`)}</span>`;
  }
  return html`
    <span class="grp">${[...c.slice(0, 3)].map((d) => html`<span>${d}</span>`)}</span>
    <span class="grp">${[...c.slice(3)].map((d) => html`<span>${d}</span>`)}</span>
  `;
}

/** Render the 2FA panel surface for the given state. The page cannot forge the privileged clicks: each
 *  handler bails unless `event.isTrusted`. */
export function renderTotpPanel(state: TotpPanelState, handlers: TotpPanelHandlers): TemplateResult {
  return sideWrap(html`<div class="box">${renderBody(state, handlers)}</div>`);
}

function renderBody(state: TotpPanelState, handlers: TotpPanelHandlers): TemplateResult {
  if (state.view === 'status') {
    return html`<div class="head">${logoGlyph()}<span class="brand">密屿</span></div>
      <div class="status"><span class="status-msg">${state.statusMessage}</span></div>`;
  }
  return html`
    <div class="head">
      ${logoGlyph()}<span class="brand">密屿</span>
      <span class="meta">1 个匹配项 · 2FA</span>
    </div>
    <div class="row">
      <span class="tile" style="background:${tileColor(state.itemName)}">${monogramLetter(state.itemName)}</span>
      <span class="meta-col">
        <span class="title">${state.itemName}</span>
        <span class="sub">${state.itemUser}</span>
      </span>
    </div>
    ${state.view === 'filled' ? renderFilled(handlers) : renderPanel(state, handlers)}
  `;
}

function renderPanel(state: TotpPanelState, handlers: TotpPanelHandlers): TemplateResult {
  const R = 8;
  const CIRC = 2 * Math.PI * R;
  const frac = Math.max(0, Math.min(1, state.remaining / 30));
  const offset = CIRC * (1 - frac);
  return html`
    <div class="code-box">
      <span class="code">${codeGroups(state.code)}</span>
      <span class="secs">${state.remaining}s</span>
      <svg class="cd-ring" viewBox="0 0 20 20" aria-hidden="true">
        <circle class="cd-track" cx="10" cy="10" r="8"></circle>
        <circle class="cd-arc" cx="10" cy="10" r="8" stroke-dasharray="${CIRC.toFixed(2)}" stroke-dashoffset="${offset.toFixed(2)}"></circle>
      </svg>
    </div>
    <div class="actions">
      <button type="button" class="btn-primary" @click=${(e: MouseEvent) => trusted(e, handlers.onFill)}>填充验证码</button>
      <button type="button" class="icon-btn" title="复制验证码" @click=${(e: MouseEvent) => trusted(e, handlers.onCopy)}>${uiIcon('copy')}</button>
    </div>
  `;
}

function renderFilled(handlers: TotpPanelHandlers): TemplateResult {
  return html`
    <div class="filled">
      <span class="badge">${uiIcon('check')}已填充验证码</span>
      ${handlers.onUndo ? html`<button type="button" class="undo" @click=${(e: MouseEvent) => trusted(e, handlers.onUndo)}>撤销</button>` : nothing}
    </div>
  `;
}

function logoGlyph(): TemplateResult {
  return html`<span class="logo"><span class="glyph"><span class="ring"></span><span class="dot"></span></span></span>`;
}

function monogramLetter(name: string): string {
  const match = name.match(/[\p{L}\p{N}]/u);
  return match ? match[0]!.toUpperCase() : '•';
}

function tileColor(name: string): string {
  let hash = 0;
  for (let index = 0; index < name.length; index += 1) hash = (hash * 31 + name.charCodeAt(index)) >>> 0;
  return `hsl(${hash % 360} 52% 42%)`;
}
