import { html, nothing, svg, type TemplateResult } from 'lit';
import { uiIcon } from '../../ui/components/icon.js';

export interface PopoverCandidate {
  id: string;
  name: string;
  /** username / matched URI (login) or brand / full name (card / identity). */
  sub?: string;
  favorite: boolean;
  reprompt?: boolean;
}

export type PopoverKind = 'login' | 'card' | 'identity';
export type PopoverView = 'trigger' | 'status' | 'list';

/** The full render state of the popover surface. Held by the factory (see popover.ts) and passed to
 *  `renderPopover` on every view/state change — candidate ids live only here, never in the DOM. */
export interface PopoverState {
  kind: PopoverKind;
  view: PopoverView;
  statusMessage: string;
  candidates: PopoverCandidate[];
}

/** Privileged callbacks. Every click that reaches them is gated on `Event.isTrusted` in the template,
 *  so a page script cannot synthesize a click to open the panel or pick a candidate. */
export interface PopoverHandlers {
  onOpen?: () => void;
  onSelect?: (cipherId: string) => void;
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
export const POPOVER_STYLES = `
    :host { all: initial; }
    :host {
      --mi-panel: #fff;
      --mi-ink: #16181D;
      --mi-muted: #8A8F99;
      --mi-faint: #9AA0AA;
      --mi-teal: #0E8A72;
      --mi-teal-text: #0B7A65;
      --mi-line: rgba(22,24,29,.09);
      --mi-fill: #F1F1EE;
      --mi-row-hover: #F2F2EF;
      --mi-shadow: 0 16px 40px rgba(20,24,32,.16);
    }
    * { box-sizing: border-box; }
    .box {
      font: 400 14px/1.4 "Instrument Sans", "Segoe UI", system-ui, sans-serif;
      color: var(--mi-ink);
      background: var(--mi-panel);
      border: 1px solid var(--mi-line);
      border-radius: 14px;
      box-shadow: var(--mi-shadow);
      min-width: 248px;
      max-width: 340px;
      overflow: hidden;
      animation: mvIn .18s ease-out;
    }
    @keyframes mvIn { from { opacity: 0; transform: translateY(-5px); } to { opacity: 1; transform: none; } }

    /* Brand header row */
    .head { display: flex; align-items: center; gap: 7px; padding: 10px 13px 7px; }
    .brand { font-size: 11.5px; font-weight: 600; letter-spacing: .01em; color: var(--mi-teal-text); }
    .head .meta { margin-left: auto; font-size: 10.5px; color: var(--mi-faint); }

    /* Concentric-circle mini logo on a moss-green block (identical in light + dark). */
    .logo { display: grid; place-items: center; width: 16px; height: 16px; border-radius: 5px; background: #0E8A72; flex: none; }
    .glyph { position: relative; width: 8px; height: 8px; }
    .ring { position: absolute; inset: 0; border: 1.5px solid #fff; border-radius: 50%; }
    .dot { position: absolute; left: 3px; top: 3px; width: 2px; height: 2px; border-radius: 50%; background: #fff; }

    /* Collapsed trigger */
    .trigger { display: flex; align-items: center; gap: 7px; width: 100%; font: inherit; text-align: left; border: 0; background: transparent; padding: 9px 12px; cursor: pointer; color: inherit; }
    .trigger:hover { background: var(--mi-row-hover); }
    .trigger .chev { margin-left: auto; display: grid; place-items: center; color: var(--mi-faint); }
    .trigger .chev svg { width: 16px; height: 16px; }

    /* Candidate list */
    .list { padding: 0 6px 8px; display: block; }
    .list.scrollable { max-height: 264px; overflow-y: auto; }
    button.candidate {
      display: flex; align-items: center; gap: 9px;
      font: inherit; width: 100%; text-align: left;
      border: 0; background: transparent;
      padding: 8px; border-radius: 10px; cursor: pointer; color: inherit;
    }
    button.candidate:hover { background: var(--mi-row-hover); }
    button.candidate:focus-visible { outline: none; box-shadow: 0 0 0 2px var(--mi-teal); }
    .tile { display: grid; place-items: center; width: 30px; height: 30px; flex: none; border-radius: 9px; color: #fff; font-weight: 700; font-size: 13px; text-transform: uppercase; }
    .meta-col { min-width: 0; flex: 1; display: flex; flex-direction: column; gap: 1px; }
    .title { display: flex; align-items: center; gap: 4px; font-size: 12.5px; font-weight: 600; color: var(--mi-ink); }
    .title .t { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .star { width: 11px; height: 11px; color: #E0A400; flex: none; }
    .sub { font-size: 11px; color: var(--mi-muted); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .fill { flex: none; font-size: 11px; font-weight: 600; color: var(--mi-teal-text); }
    button.candidate:hover .fill { color: var(--mi-teal); }

    /* Status / info bar (locked hint, empty state) */
    .status { display: flex; align-items: center; gap: 10px; margin: 8px; padding: 11px 13px; border-radius: 12px; background: var(--mi-fill); }
    .status-ico { display: grid; place-items: center; width: 22px; height: 22px; border-radius: 50%; background: var(--mi-panel); color: var(--mi-teal-text); flex: none; }
    .status-ico svg { width: 14px; height: 14px; }
    .status-msg { font-size: 12.5px; font-weight: 600; color: var(--mi-ink); }
    svg { stroke-width: 1.8; }

    @media (prefers-color-scheme: dark) {
      :host {
        --mi-panel: #1F2229;
        --mi-ink: #F2F3F5;
        --mi-muted: #8A8F99;
        --mi-faint: #7B818B;
        --mi-teal-text: #45D6B5;
        --mi-line: rgba(255,255,255,.09);
        --mi-fill: #262A33;
        --mi-row-hover: rgba(255,255,255,.05);
        --mi-shadow: 0 18px 48px rgba(0,0,0,.5);
      }
    }
    @media (prefers-reduced-motion: reduce) { .box { animation: none; } }
  `;

/** Render the popover surface for the given state. The page cannot forge the privileged clicks: each
 *  handler bails unless `event.isTrusted`. */
export function renderPopover(state: PopoverState, handlers: PopoverHandlers): TemplateResult {
  return html`<div class="box">${renderBody(state, handlers)}</div>`;
}

function renderBody(state: PopoverState, handlers: PopoverHandlers): TemplateResult {
  if (state.view === 'status') {
    return renderStatus(state.statusMessage);
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

function renderHeader(state: PopoverState): TemplateResult {
  return html`
    <div class="head">
      ${logoGlyph()}
      <span class="brand">密屿</span>
      <span class="meta">${headerMeta(state)}</span>
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
    <div class="status">
      <span class="status-ico">${uiIcon('lock')}</span>
      <span class="status-msg">${message}</span>
    </div>
  `;
}

function renderList(state: PopoverState, handlers: PopoverHandlers): TemplateResult {
  if (state.candidates.length === 0) {
    return html`${renderHeader(state)}${renderStatus(EMPTY_STATES[state.kind])}`;
  }
  const scrollable = state.candidates.length > SCROLL_THRESHOLD;
  return html`
    ${renderHeader(state)}
    <div class="list ${scrollable ? 'scrollable' : ''}">
      ${state.candidates.map((candidate, index) => renderCandidate(candidate, index, handlers))}
    </div>
  `;
}

function renderCandidate(candidate: PopoverCandidate, index: number, handlers: PopoverHandlers): TemplateResult {
  return html`
    <button type="button" class="candidate" role="option" aria-selected=${index === 0 ? 'true' : 'false'} @click=${(event: MouseEvent) => { if (event.isTrusted) handlers.onSelect?.(candidate.id); }}>
      <span class="tile" style="background:${tileColor(candidate.name)}">${monogramLetter(candidate.name)}</span>
      <span class="meta-col">
        <span class="title">
          ${candidate.favorite
            ? svg`<svg class="star" viewBox="0 0 24 24" fill="currentColor" stroke="none" aria-hidden="true">${STAR}</svg>`
            : nothing}
          <span class="t">${candidate.name}</span>
        </span>
        <span class="sub">${candidate.sub ?? ''}</span>
      </span>
      <span class="fill">填充</span>
    </button>
  `;
}

/** The 密屿 concentric-circle glyph on its moss-green block — pure static markup, no page data. */
function logoGlyph(): TemplateResult {
  return html`<span class="logo"><span class="glyph"><span class="ring"></span><span class="dot"></span></span></span>`;
}

function monogramLetter(name: string): string {
  const match = name.match(/[\p{L}\p{N}]/u);
  return match ? match[0]!.toUpperCase() : '•';
}

/** Deterministic tile color derived from the item name (never from its id), so the same item
 *  always gets the same hue without leaking any identifier into the DOM. */
function tileColor(name: string): string {
  let hash = 0;
  for (let index = 0; index < name.length; index += 1) {
    hash = (hash * 31 + name.charCodeAt(index)) >>> 0;
  }
  return `hsl(${hash % 360} 52% 42%)`;
}
