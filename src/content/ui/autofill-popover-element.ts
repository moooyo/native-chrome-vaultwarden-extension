import { html, nothing, svg, type TemplateResult } from 'lit';
import { uiIcon } from '../../ui/components/icon.js';
import { SIDE_PANEL_CSS, sideWrap } from './side-panel.js';
import { INLINE_SURFACE_CSS } from './surface-theme.js';

export interface PopoverCandidate {
  id: string;
  name: string;
  /** username / matched URI (login) or brand / full name (card / identity). */
  sub?: string;
  favorite: boolean;
  reprompt?: boolean;
}

export type PopoverKind = 'login' | 'card' | 'identity';
export type PopoverView = 'hidden' | 'trigger' | 'status' | 'list' | 'filled';

/** The full render state of the popover surface. Held by the factory (see popover.ts) and passed to
 *  `renderPopover` on every view/state change — candidate ids live only here, never in the DOM. */
export interface PopoverState {
  kind: PopoverKind;
  view: PopoverView;
  statusMessage: string;
  candidates: PopoverCandidate[];
  /** Active descendant within the non-modal listbox. Candidate ids remain closure-only. */
  activeIndex: number;
  /** Login autofill (design 2c) mounts to the RIGHT of the focused field with a connector and shows the
   *  match list directly (no click-to-open trigger). Card/identity keep the compact trigger popover. */
  sidePanel: boolean;
  /** Current frame host, displayed as plain text; never used to authorize a fill. */
  siteLabel?: string;
}

export type PopoverDismissReason = 'escape' | 'tab';

/** Privileged callbacks. Every click that reaches them is gated on `Event.isTrusted` in the template,
 *  so a page script cannot synthesize a click to open the panel or pick a candidate. */
export interface PopoverHandlers {
  onOpen?: () => void;
  onSelect?: (cipherId: string) => void;
  onActiveIndexChange?: (index: number) => void;
  onKeyboardSelect?: (index: number) => void;
  onDismiss?: (reason: PopoverDismissReason) => void;
}

// TODO i18n: content-script surfaces are isolated from the extension i18n module, so these
// user-facing strings are hardcoded in Chinese to match the 密屿/MiYu design.

/** Right-aligned header meta for the non-login kinds (login shows a live match count instead). */
const META_LABELS: Record<PopoverKind, string> = {
  login: '',
  card: '填充银行卡',
  identity: '填充身份',
};

const EMPTY_STATES: Record<PopoverKind, string> = {
  login: '没有匹配的登录项',
  card: '没有保存的银行卡',
  identity: '没有保存的身份',
};

/** Above this many rows the list scrolls locally instead of growing without bound. */
const SCROLL_THRESHOLD = 6;

const STAR = svg`<path d="M12 4l2.3 4.7 5.2.8-3.7 3.6.9 5.1L12 15.8 7.3 18.3l.9-5.1L4.5 9.5l5.2-.8z"/>`;

/**
 * Styles for the autofill popover surface. Because the surface lives in a closed shadow root on
 * arbitrary host pages it cannot use the extension's `--vw-*` tokens, so the MiYu palette is defined
 * locally on `:host` (the surface host div) with a `prefers-color-scheme: dark` override.
 */
export const POPOVER_STYLES = INLINE_SURFACE_CSS + SIDE_PANEL_CSS + `
  .trigger { display:flex; align-items:center; gap:8px; width:100%; padding:10px 14px; border:0; background:transparent; text-align:left; }
  .trigger:hover { background:var(--mi-row-hover); }
  .trigger .chev { display:grid; place-items:center; color:var(--mi-faint); margin-left:auto; }
  .list { display:block; margin:5px; padding:0; outline:none; }
  .list.scrollable { max-height:300px; overflow-y:auto; overscroll-behavior:contain; scrollbar-width:thin; }
  button.candidate { display:flex; align-items:center; gap:10px; width:100%; min-height:62px; padding:9px; border:0; border-radius:8px; background:transparent; text-align:left; }
  button.candidate:hover { background:var(--mi-row-hover); }
  button.candidate[aria-selected="true"] { background:var(--mi-teal-10); box-shadow:inset 0 0 0 1px var(--mi-teal-20); }
  .list:focus-visible { outline:2px solid var(--mi-teal); outline-offset:0; border-radius:8px; }
  .tile { display:grid; place-items:center; width:30px; height:30px; flex:none; border-radius:8px; background:var(--mi-fill); color:var(--mi-muted); font-weight:600; font-size:13px; }
  button.candidate[aria-selected="true"] .tile { color:var(--mi-teal-text); }
  .meta-col { min-width:0; flex:1; display:flex; flex-direction:column; gap:3px; }
  .title { display:flex; align-items:center; gap:5px; font-size:14px; font-weight:500; }
  .title .t { overflow-wrap:anywhere; line-height:1.4; }
  .star { width:11px; height:11px; color:#a87527; flex:none; }
  .sub { color:var(--mi-muted); font-size:12px; overflow-wrap:anywhere; }
  .fill { flex:none; padding:4px 7px; border-radius:5px; font-size:12px; color:var(--mi-muted); }
  button.candidate[aria-selected="true"] .fill { background:var(--mi-ink-btn); color:var(--mi-ink-btn-fg); }
  .verify-note { display:inline-flex; align-items:center; gap:3px; color:var(--mi-faint); font-size:11px; }
  .verify-note svg { width:12px; height:12px; }
  .keyboard-hint { white-space:nowrap; }
`;
/** Render the popover surface for the given state. The page cannot forge the privileged clicks: each
 *  handler bails unless `event.isTrusted`. Login (2c) renders as a right-mounted side panel with a
 *  connector; card/identity render as the compact trigger popover. */
export function renderPopover(state: PopoverState, handlers: PopoverHandlers): TemplateResult {
  // The login side panel rests hidden (nothing rendered, host collapses to 0×0) until focus opens it.
  if (state.view === 'hidden') return html``;
  const box = html`<div class="box" @keydown=${(event: KeyboardEvent) => {
    if (event.isTrusted && event.key === 'Escape' && !event.defaultPrevented) {
      event.preventDefault();
      event.stopPropagation();
      handlers.onDismiss?.('escape');
    }
  }}>${renderBody(state, handlers)}</div>`;
  return state.sidePanel ? sideWrap(box) : box;
}

function renderBody(state: PopoverState, handlers: PopoverHandlers): TemplateResult {
  if (state.view === 'filled') {
    return html`${renderHeader(state, handlers)}${renderFilled(state.kind)}`;
  }
  if (state.view === 'status') {
    return html`${renderHeader(state, handlers)}${renderStatus(state.statusMessage)}`;
  }
  if (state.view === 'list') {
    return renderList(state, handlers);
  }
  return html`
    <button id="vw-open" type="button" class="trigger" @click=${(event: MouseEvent) => { if (event.isTrusted) handlers.onOpen?.(); }}>
      ${logoGlyph()}
      <span class="brand">密屿</span>
      <span class="chev">${uiIcon('chevron')}</span>
    </button>
  `;
}

/** Post-fill confirmation shown in the login side panel: a 已填充 badge (design 2c). */
function renderFilled(kind: PopoverKind): TemplateResult {
  return html`
    <div class="filled" role="status" aria-live="polite" aria-atomic="true">
      <span class="badge">${uiIcon('check')}${kind === 'card' ? '银行卡信息已填入' : kind === 'identity' ? '身份资料已填入' : '登录信息已填入'}</span>
    </div>
    <div class="panel-footer receipt-note">请在网站继续操作 · 此提示将自动关闭</div>
  `;
}

function renderHeader(state: PopoverState, handlers: PopoverHandlers): TemplateResult {
  return html`
    <div class="head">
      ${logoGlyph()}
      <span class="brand">${state.siteLabel || '密屿'}</span>
      <span class="meta">${headerMeta(state)}</span>
      <button type="button" class="panel-close" aria-label="关闭密屿填充建议" @click=${(event: MouseEvent) => {
        if (event.isTrusted) handlers.onDismiss?.('escape');
      }}>${uiIcon('close')}</button>
    </div>
  `;
}

function headerMeta(state: PopoverState): string {
  if (state.kind === 'login') {
    return state.candidates.length > 0 ? `${state.candidates.length} 个匹配项` : '';
  }
  return META_LABELS[state.kind];
}

function renderStatus(message: string): TemplateResult {
  return html`
    <div class="status" role="status" aria-live="polite" aria-atomic="true">
      <span class="status-ico">${uiIcon('lock')}</span>
      <span class="status-msg">${message}</span>
    </div>
  `;
}

function renderList(state: PopoverState, handlers: PopoverHandlers): TemplateResult {
  if (state.candidates.length === 0) {
    return html`${renderHeader(state, handlers)}${renderStatus(EMPTY_STATES[state.kind])}`;
  }
  const scrollable = state.candidates.length > SCROLL_THRESHOLD;
  const activeIndex = normalizedActiveIndex(state.activeIndex, state.candidates.length);
  return html`
    ${renderHeader(state, handlers)}
    <div
      class="list ${scrollable ? 'scrollable' : ''}"
      role="listbox"
      aria-orientation="vertical"
      aria-label=${state.kind === 'login' ? '密屿' : META_LABELS[state.kind]}
      aria-activedescendant=${optionDomId(activeIndex)}
      tabindex="0"
      @keydown=${(event: KeyboardEvent) => handleListKeydown(event, state, handlers)}
    >
      ${state.candidates.map((candidate, index) => renderCandidate(candidate, index, activeIndex, handlers, state.kind))}
    </div>
    <div class="panel-footer"><span>密屿 · 选择后填入</span><span class="keyboard-hint">↑↓ 选择 · Enter 填充</span></div>
  `;
}

function renderCandidate(
  candidate: PopoverCandidate,
  index: number,
  activeIndex: number,
  handlers: PopoverHandlers,
  kind: PopoverKind,
): TemplateResult {
  return html`
    <button
      type="button"
      class="candidate"
      id=${optionDomId(index)}
      role="option"
      aria-selected=${index === activeIndex ? 'true' : 'false'}
      tabindex="-1"
      @click=${(event: MouseEvent) => { if (event.isTrusted) handlers.onSelect?.(candidate.id); }}
    >
      <span class="tile" aria-hidden="true">${monogramLetter(candidate.name)}</span>
      <span class="meta-col">
        <span class="title">
          ${candidate.favorite
            ? svg`<svg class="star" viewBox="0 0 24 24" fill="currentColor" stroke="none" aria-hidden="true">${STAR}</svg>`
            : nothing}
          <span class="t">${kind === 'login' && candidate.sub ? candidate.sub : candidate.name}</span>
        </span>
        <span class="sub">${kind === 'login' && candidate.sub ? candidate.name : candidate.sub ?? ''}</span>
        ${candidate.reprompt ? html`<span class="verify-note">${uiIcon('lock')}填充前需要验证</span>` : nothing}
      </span>
      <span class="fill">填充</span>
    </button>
  `;
}

function handleListKeydown(
  event: KeyboardEvent,
  state: PopoverState,
  handlers: PopoverHandlers,
): void {
  if (!event.isTrusted || event.altKey || event.ctrlKey || event.metaKey) return;
  const count = state.candidates.length;
  if (count === 0) return;
  const activeIndex = normalizedActiveIndex(state.activeIndex, count);

  let nextIndex: number | undefined;
  switch (event.key) {
    case 'ArrowDown':
      nextIndex = (activeIndex + 1) % count;
      break;
    case 'ArrowUp':
      nextIndex = (activeIndex - 1 + count) % count;
      break;
    case 'Home':
      nextIndex = 0;
      break;
    case 'End':
      nextIndex = count - 1;
      break;
    case 'Enter':
    case ' ':
    case 'Spacebar':
      if (event.repeat) return;
      event.preventDefault();
      event.stopPropagation();
      handlers.onKeyboardSelect?.(activeIndex);
      return;
    case 'Escape':
      event.preventDefault();
      event.stopPropagation();
      handlers.onDismiss?.('escape');
      return;
    case 'Tab':
      handlers.onDismiss?.('tab');
      return;
    default:
      return;
  }

  event.preventDefault();
  event.stopPropagation();
  handlers.onActiveIndexChange?.(nextIndex);
}

function normalizedActiveIndex(index: number, count: number): number {
  return Number.isSafeInteger(index) && index >= 0 && index < count ? index : 0;
}

function optionDomId(index: number): string {
  return `vw-autofill-option-${index}`;
}

/** The brand key glyph on a blue tile uses static markup and contains no page data. */
function logoGlyph(): TemplateResult {
  return html`<span class="logo"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M7.5 15.5a5.5 5.5 0 1 1 4.9-8H22v4h-2v2h-3v2h-4.6a5.5 5.5 0 0 1-4.9 3Zm0-3.5a2 2 0 1 0 0 4 2 2 0 0 0 0-4Z"/></svg></span>`;
}

function monogramLetter(name: string): string {
  const match = name.match(/[\p{L}\p{N}]/u);
  return match ? match[0]!.toUpperCase() : '•';
}

