import { LitElement, css, html, nothing, svg } from 'lit';
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

const HEADERS: Record<PopoverKind, string> = {
  login: 'Fill from Vaultwarden',
  card: 'Fill card',
  identity: 'Fill identity',
};

const EMPTY_STATES: Record<PopoverKind, string> = {
  login: 'No matching logins',
  card: 'No saved cards',
  identity: 'No saved identities',
};

/** Above this many rows the list scrolls locally instead of growing without bound. */
const SCROLL_THRESHOLD = 6;

const STAR = svg`<path d="M12 4l2.3 4.7 5.2.8-3.7 3.6.9 5.1L12 15.8 7.3 18.3l.9-5.1L4.5 9.5l5.2-.8z"/>`;

/**
 * Dormant Lit surface backing the autofill popover. It is mounted inside a closed root (see
 * mountClosedSurface) so the page cannot read its state or forge its callbacks. Callbacks are
 * non-reflected properties, every privileged click is gated on `Event.isTrusted`, and candidate
 * identities live only in the in-memory `candidates` array — their ids never reach the DOM.
 */
export class VwAutofillPopover extends LitElement {
  static override properties = {
    kind: { type: String },
    view: { type: String },
    statusMessage: { type: String },
    candidates: { attribute: false },
    onOpen: { attribute: false },
    onSelect: { attribute: false },
  };

  declare kind: PopoverKind;
  declare view: PopoverView;
  declare statusMessage: string;
  declare candidates: PopoverCandidate[];
  declare onOpen: (() => void) | undefined;
  declare onSelect: ((cipherId: string) => void) | undefined;

  constructor() {
    super();
    this.kind = 'login';
    this.view = 'trigger';
    this.statusMessage = '';
    this.candidates = [];
    this.onOpen = undefined;
    this.onSelect = undefined;
  }

  static override styles = css`
    :host { all: initial; }
    * { box-sizing: border-box; }
    .box {
      font: 13px/1.45 -apple-system, "Segoe UI", system-ui, Roboto, sans-serif;
      color: #181d2b;
      background: #ffffff;
      border: 1px solid #dee3ef;
      border-radius: 12px;
      box-shadow: 0 18px 48px rgba(20,27,45,.22), 0 4px 12px rgba(20,27,45,.12);
      min-width: 232px;
      max-width: 340px;
      overflow: hidden;
      animation: pop 140ms cubic-bezier(.2,.7,.2,1);
    }
    @keyframes pop { from { opacity: 0; transform: translateY(-4px) scale(.98); } to { opacity: 1; transform: none; } }
    .brandrow { display: flex; align-items: center; gap: 7px; padding: 8px 10px; border-bottom: 1px solid #eef1f8; }
    .mark { display: grid; place-items: center; width: 20px; height: 20px; border-radius: 6px; background: linear-gradient(150deg, #4f46e5, #4338ca); color: #fff; flex: none; }
    .mark svg { width: 13px; height: 13px; }
    .brandrow .label { font-weight: 650; font-size: 12px; letter-spacing: .01em; }
    .list { padding: 6px; display: block; }
    .list.scrollable { max-height: 288px; overflow-y: auto; }
    button.candidate {
      display: flex; align-items: center; gap: 10px;
      font: inherit; width: 100%; text-align: left;
      border: 1px solid transparent; background: transparent;
      padding: 8px; border-radius: 9px; cursor: pointer; color: inherit;
    }
    button.candidate:hover { background: #f3f5fb; border-color: #e7ebf5; }
    button.candidate:focus-visible { outline: none; box-shadow: 0 0 0 3px rgba(79,70,229,.32); }
    .mono-chip { display: grid; place-items: center; width: 30px; height: 30px; flex: none; border-radius: 8px; font-weight: 680; font-size: 13px; text-transform: uppercase; color: #fff; background: #4f46e5; }
    .meta { min-width: 0; flex: 1; }
    .name { display: flex; align-items: center; gap: 4px; font-weight: 600; }
    .name .t { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .star { width: 11px; height: 11px; color: #e0a400; flex: none; }
    .sub { display: block; font-family: ui-monospace, "SF Mono", Menlo, Consolas, monospace; font-size: 11px; color: #5b647a; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .open-trigger { display: flex; align-items: center; gap: 8px; width: 100%; font: inherit; text-align: left; border: 0; background: transparent; padding: 10px 12px; cursor: pointer; color: inherit; font-weight: 600; }
    .open-trigger:hover { background: #f3f5fb; }
    .open-trigger .chev { margin-left: auto; color: #8b93a7; width: 16px; height: 16px; }
    .status { display: flex; align-items: center; gap: 8px; padding: 11px 12px; color: #5b647a; }
    .status svg { width: 15px; height: 15px; flex: none; color: #8b93a7; }
    svg { stroke-width: 1.8; }
    @media (prefers-color-scheme: dark) {
      .box { color: #e9edf7; background: #151a26; border-color: #283041; box-shadow: 0 18px 48px rgba(0,0,0,.6); }
      .brandrow { border-bottom-color: #1f2636; }
      button.candidate:hover { background: #1b2230; border-color: #283041; }
      .sub { color: #9aa4b8; }
      .open-trigger:hover { background: #1b2230; }
      .status { color: #9aa4b8; }
    }
    @media (prefers-reduced-motion: reduce) { .box { animation: none; } }
  `;

  private handleOpen(event: MouseEvent): void {
    if (!event.isTrusted) {
      return;
    }
    this.onOpen?.();
  }

  private handleSelect(event: MouseEvent, index: number): void {
    if (!event.isTrusted) {
      return;
    }
    const candidate = this.candidates[index];
    if (candidate) {
      this.onSelect?.(candidate.id);
    }
  }

  protected override render() {
    return html`<div class="box">${this.renderBody()}</div>`;
  }

  private renderBody() {
    if (this.view === 'status') {
      return html`<div class="status">${uiIcon('lock')}<span>${this.statusMessage}</span></div>`;
    }
    if (this.view === 'list') {
      return this.renderList();
    }
    return html`
      <button id="vw-open" type="button" class="open-trigger" @click=${this.handleOpen}>
        <span class="mark">${uiIcon('shield')}</span>
        <span>Vaultwarden</span>
        <span class="chev">${uiIcon('chevron')}</span>
      </button>
    `;
  }

  private renderList() {
    if (this.candidates.length === 0) {
      return html`<div class="status">${uiIcon('lock')}<span>${EMPTY_STATES[this.kind]}</span></div>`;
    }
    const scrollable = this.candidates.length > SCROLL_THRESHOLD;
    return html`
      <div class="brandrow"><span class="mark">${uiIcon('shield')}</span><span class="label">${HEADERS[this.kind]}</span></div>
      <div class="list ${scrollable ? 'scrollable' : ''}">
        ${this.candidates.map((candidate, index) => this.renderCandidate(candidate, index))}
      </div>
    `;
  }

  private renderCandidate(candidate: PopoverCandidate, index: number) {
    return html`
      <button type="button" class="candidate" @click=${(event: MouseEvent) => this.handleSelect(event, index)}>
        <span class="mono-chip" style="background:hsl(${hueFor(candidate.name)} 55% 48%)">${monogramLetter(candidate.name)}</span>
        <span class="meta">
          <span class="name">
            ${candidate.favorite
              ? svg`<svg class="star" viewBox="0 0 24 24" fill="currentColor" stroke="currentColor" aria-hidden="true">${STAR}</svg>`
              : nothing}
            <span class="t">${candidate.name}</span>
          </span>
          <span class="sub">${candidate.sub ?? ''}</span>
        </span>
      </button>
    `;
  }
}

function monogramLetter(name: string): string {
  const match = name.match(/[\p{L}\p{N}]/u);
  return match ? match[0]!.toUpperCase() : '•';
}

function hueFor(name: string): number {
  let hash = 0;
  for (let i = 0; i < name.length; i++) {
    hash = (hash * 31 + name.charCodeAt(i)) >>> 0;
  }
  return hash % 360;
}

customElements.define('vw-autofill-popover', VwAutofillPopover);

declare global {
  interface HTMLElementTagNameMap {
    'vw-autofill-popover': VwAutofillPopover;
  }
}
