import { html, nothing, type TemplateResult } from 'lit';
import { uiIcon } from '../../ui/components/icon.js';
import { SIDE_PANEL_CSS, sideWrap } from './side-panel.js';
import { INLINE_SURFACE_CSS } from './surface-theme.js';

// TODO i18n: content-script surfaces are isolated from the extension i18n module, so these
// user-facing strings are hardcoded in Chinese to match the 密屿/MiYu design.

export type TotpPanelView = 'candidates' | 'panel' | 'filled' | 'status';

export interface TotpPanelCandidate {
  key: string;
  name: string;
  username: string;
  reprompt: boolean;
}

/** The full render state of the 2FA panel surface. Held by the factory (see totp-fill.ts) and passed
 *  to `renderTotpPanel` on every state change — no cipher id ever reaches this state or the DOM. */
export interface TotpPanelState {
  view: TotpPanelView;
  candidates: readonly TotpPanelCandidate[];
  overflowCount: number;
  loadingKey: string;
  itemName: string;
  itemUser: string;
  code: string;
  remaining: number;
  statusMessage: string;
  siteLabel?: string;
  period?: number;
}

/** Privileged callbacks. Every click that reaches them is gated on `Event.isTrusted` in the template,
 *  so a page script cannot synthesize a click to fill / copy / undo. */
export interface TotpPanelHandlers {
  onDismiss?: () => void;
  onSelect?: (candidateKey: string) => void;
  onChooseOther?: () => void;
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
export const TOTP_PANEL_STYLES = INLINE_SURFACE_CSS + SIDE_PANEL_CSS + `
  .row { display:flex; align-items:center; gap:10px; padding:16px 16px 12px; }
  .tile { display:grid; place-items:center; width:30px; height:30px; flex:none; border-radius:8px; color:var(--mi-muted); background:var(--mi-fill); font-weight:600; font-size:13px; }
  .meta-col { min-width:0; flex:1; display:flex; flex-direction:column; gap:3px; }
  .title { font-size:14px; font-weight:500; overflow-wrap:anywhere; }
  .sub { font-size:12px; color:var(--mi-muted); overflow-wrap:anywhere; }
  .candidate-list { display:grid; gap:2px; margin:5px; max-height:300px; overflow:auto; overscroll-behavior:contain; }
  .candidate { width:100%; display:flex; align-items:center; gap:10px; min-height:62px; padding:9px; border:0; border-radius:8px; background:transparent; text-align:left; }
  .candidate:hover { background:var(--mi-row-hover); }
  .candidate:focus-visible { background:var(--mi-teal-10); outline-offset:-2px; }
  .candidate-state { margin-left:auto; color:var(--mi-teal-text); font-size:11px; flex:none; }
  .candidate-note { margin:0; padding:8px 14px; color:var(--mi-muted); font-size:12px; }
  .candidate-error { color:var(--mi-red); }
  .change-candidate { border:0; background:transparent; color:var(--mi-teal-text); padding:5px 0; font-size:11px; white-space:nowrap; }
  .change-candidate:hover { text-decoration:underline; }
  .code-box { display:flex; align-items:center; gap:9px; margin:0 16px; padding:13px 12px; background:var(--mi-fill); border:1px solid var(--mi-line); border-radius:8px; }
  .code { flex:1; display:flex; align-items:baseline; gap:10px; font:500 25px/1.3 "Consolas", ui-monospace, monospace; color:var(--mi-ink); font-variant-numeric:tabular-nums; }
  .code .grp { display:flex; gap:2px; }
  .secs { color:var(--mi-faint); font-size:11px; font-variant-numeric:tabular-nums; }
  .cd-ring { width:20px; height:20px; }
  .cd-ring circle { fill:none; }
  .cd-track { stroke:var(--mi-track); stroke-width:2.5; }
  .cd-arc { stroke:var(--mi-teal); stroke-width:2.5; stroke-linecap:round; transform:rotate(-90deg); transform-origin:center; transform-box:fill-box; transition:stroke-dashoffset 1s linear; }
  .actions { display:flex; align-items:center; gap:8px; padding:14px 16px 16px; }
  .btn-primary { flex:1; min-height:38px; padding:8px 12px; border:1px solid var(--mi-ink-btn); border-radius:8px; background:var(--mi-ink-btn); color:var(--mi-ink-btn-fg); font-size:13px; font-weight:500; }
  .btn-primary:hover { background:var(--mi-ink-hover); border-color:var(--mi-ink-hover); }
  .icon-btn { display:grid; place-items:center; width:38px; height:38px; border:1px solid var(--mi-line-3); border-radius:8px; background:var(--mi-panel); color:var(--mi-muted); }
  .icon-btn:hover { background:var(--mi-row-hover); }
  .icon-btn svg { width:16px; height:16px; }
`;
function trusted(event: Event, fn: (() => void) | undefined): void {
  if (!event.isTrusted) return;
  fn?.();
}

/** Split six-digit codes into two readable groups without changing the actual code value. */
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
  return sideWrap(html`<div class="box" @keydown=${(event: KeyboardEvent) => {
    if (event.isTrusted && event.key === 'Escape') {
      event.preventDefault();
      event.stopPropagation();
      handlers.onDismiss?.();
    }
  }}><div class="head">${logoGlyph()}<span class="brand">${state.siteLabel || '密屿'}</span><span class="meta">验证码</span>
    <button type="button" class="panel-close" aria-label="关闭验证码建议" @click=${(event: MouseEvent) => trusted(event, handlers.onDismiss)}>${uiIcon('close')}</button>
    </div>${renderBody(state, handlers)}</div>`);
}

function renderBody(state: TotpPanelState, handlers: TotpPanelHandlers): TemplateResult {
  if (state.view === 'status') {
    return html`<div class="status" role="status" aria-live="polite" aria-atomic="true">
        <span class="status-msg">${state.statusMessage}</span>
      </div>`;
  }
  const matchCount = state.candidates.length + state.overflowCount;
  return html`
    ${state.view === 'candidates' ? renderCandidates(state, handlers) : html`
    <div class="row">
      <span class="tile" aria-hidden="true">${monogramLetter(state.itemName)}</span>
      <span class="meta-col">
        <span class="title">${state.itemUser || state.itemName}</span>
        <span class="sub">${state.itemUser ? state.itemName : ''}</span>
      </span>
      ${matchCount > 1 && state.view === 'panel'
        ? html`<button type="button" class="change-candidate" @click=${(e: MouseEvent) => trusted(e, handlers.onChooseOther)}>切换账户</button>`
        : nothing}
    </div>
    ${state.view === 'filled' ? renderFilled(handlers) : renderPanel(state, handlers)}
    `}
  `;
}

function renderCandidates(state: TotpPanelState, handlers: TotpPanelHandlers): TemplateResult {
  return html`
    <div class="candidate-list" role="listbox" aria-label="选择验证码账户" @keydown=${handleCandidateKeys}>
      ${state.candidates.map((candidate) => html`
        <button
          type="button"
          class="candidate"
          role="option"
          aria-selected="false"
          data-candidate-key=${candidate.key}
          ?disabled=${state.loadingKey === candidate.key}
          @click=${(event: MouseEvent) => trusted(event, () => handlers.onSelect?.(candidate.key))}
        >
          <span class="tile" aria-hidden="true">${monogramLetter(candidate.name)}</span>
          <span class="meta-col">
            <span class="title">${candidate.username || candidate.name}</span>
            <span class="sub">${candidate.username ? candidate.name : ''}</span>
          </span>
          <span class="candidate-state">${state.loadingKey === candidate.key
            ? '加载中…'
            : candidate.reprompt ? '需验证' : '选择'}</span>
        </button>
      `)}
    </div>
    ${state.overflowCount > 0
      ? html`<div class="candidate-note">另有 ${state.overflowCount} 个匹配项未显示</div>`
      : nothing}
    ${state.statusMessage
      ? html`<div class="candidate-note candidate-error" role="status">${state.statusMessage}</div>`
      : nothing}
    <div class="panel-footer"><span>选择后显示验证码</span><span>↑↓ 选择 · Enter 确认</span></div>
  `;
}

function renderPanel(state: TotpPanelState, handlers: TotpPanelHandlers): TemplateResult {
  const R = 8;
  const CIRC = 2 * Math.PI * R;
  const period = state.period && state.period > 0 ? state.period : 30;
  const frac = Math.max(0, Math.min(1, state.remaining / period));
  const offset = CIRC * (1 - frac);
  return html`
    <div class="code-box">
      <span class="code" aria-label=${`验证码 ${state.code}`}>${codeGroups(state.code)}</span>
      <span class="secs" aria-label=${`${state.remaining} 秒后更新`}>${state.remaining}s</span>
      <svg class="cd-ring" viewBox="0 0 20 20" aria-hidden="true">
        <circle class="cd-track" cx="10" cy="10" r="8"></circle>
        <circle class="cd-arc" cx="10" cy="10" r="8" stroke-dasharray="${CIRC.toFixed(2)}" stroke-dashoffset="${offset.toFixed(2)}"></circle>
      </svg>
    </div>
    <div class="actions">
      <button type="button" class="btn-primary" ?disabled=${!state.code || state.remaining <= 0} @click=${(e: MouseEvent) => trusted(e, handlers.onFill)}>填充验证码</button>
      <button type="button" class="icon-btn" title="复制验证码" aria-label="复制验证码" ?disabled=${!state.code || state.remaining <= 0} @click=${(e: MouseEvent) => trusted(e, handlers.onCopy)}>${uiIcon('copy')}</button>
    </div>
    <div class="panel-footer">${state.code ? '验证码到期后自动更新' : '正在获取新的验证码…'}</div>
  `;
}

function renderFilled(handlers: TotpPanelHandlers): TemplateResult {
  return html`
    <div class="filled" role="status" aria-live="polite" aria-atomic="true">
      <span class="badge">${uiIcon('check')}已填充验证码</span>
      ${handlers.onUndo ? html`<button type="button" class="undo" @click=${(e: MouseEvent) => trusted(e, handlers.onUndo)}>撤销</button>` : nothing}
    </div>
    <div class="panel-footer receipt-note">请在网站继续验证 · 此提示将自动关闭</div>
  `;
}

function logoGlyph(): TemplateResult {
  return html`<span class="logo"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M7.5 15.5a5.5 5.5 0 1 1 4.9-8H22v4h-2v2h-3v2h-4.6a5.5 5.5 0 0 1-4.9 3Zm0-3.5a2 2 0 1 0 0 4 2 2 0 0 0 0-4Z"/></svg></span>`;
}

function monogramLetter(name: string): string {
  const match = name.match(/[\p{L}\p{N}]/u);
  return match ? match[0]!.toUpperCase() : '•';
}

function handleCandidateKeys(event: KeyboardEvent): void {
  if (!event.isTrusted || event.altKey || event.ctrlKey || event.metaKey) return;
  const list = event.currentTarget as HTMLElement;
  const rows = [...list.querySelectorAll<HTMLButtonElement>('.candidate:not(:disabled)')];
  const current = rows.findIndex((row) => row === event.target || row.contains(event.target as Node));
  if (current < 0 || rows.length === 0) return;
  const next = event.key === 'ArrowDown' ? (current + 1) % rows.length
    : event.key === 'ArrowUp' ? (current - 1 + rows.length) % rows.length
      : event.key === 'Home' ? 0 : event.key === 'End' ? rows.length - 1 : -1;
  if (next < 0) return;
  event.preventDefault();
  event.stopPropagation();
  rows[next]?.focus({ preventScroll: true });
  rows[next]?.scrollIntoView?.({ block: 'nearest' });
}
