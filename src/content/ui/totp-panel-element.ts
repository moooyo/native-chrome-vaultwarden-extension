import { LitElement, css, html, nothing } from 'lit';
import { uiIcon } from '../../ui/components/icon.js';
import { defineContentElement } from './define.js';

// TODO i18n: content-script surfaces are isolated from the extension i18n module, so these
// user-facing strings are hardcoded in Chinese to match the 密屿/MiYu design.

export type TotpPanelView = 'panel' | 'filled' | 'status';

/**
 * The 密屿/MiYu 2FA side panel (design 3a): a standalone verification-code step shows the matching
 * item, a live one-time code with a 30s meter, and a "填充验证码" action. Lives in a CLOSED shadow
 * root on arbitrary host pages (so the MiYu palette is defined locally on `:host`), gates every
 * privileged click on `Event.isTrusted`, and exposes only imperative properties + callbacks — no
 * cipher id ever reaches the DOM.
 */
export class VwTotpPanel extends LitElement {
  static override properties = {
    view: { type: String },
    itemName: { type: String },
    itemUser: { type: String },
    code: { type: String },
    remaining: { type: Number },
    statusMessage: { type: String },
    onFill: { attribute: false },
    onCopy: { attribute: false },
    onUndo: { attribute: false },
  };

  declare view: TotpPanelView;
  declare itemName: string;
  declare itemUser: string;
  declare code: string;
  declare remaining: number;
  declare statusMessage: string;
  declare onFill: (() => void) | undefined;
  declare onCopy: (() => void) | undefined;
  declare onUndo: (() => void) | undefined;

  constructor() {
    super();
    this.view = 'panel';
    this.itemName = '';
    this.itemUser = '';
    this.code = '';
    this.remaining = 30;
    this.statusMessage = '';
    this.onFill = undefined;
    this.onCopy = undefined;
    this.onUndo = undefined;
  }

  static override styles = css`
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

    .code-box { margin: 0 13px; padding: 9px 11px; background: var(--mi-fill-2); border: 1px solid var(--mi-line); border-radius: 10px; display: flex; align-items: center; gap: 8px; }
    .code { font-family: "JetBrains Mono", ui-monospace, monospace; font-weight: 600; font-size: 18px; color: var(--mi-teal-text); letter-spacing: .08em; }
    .secs { font-size: 10.5px; color: var(--mi-faint); flex: none; }
    .track { flex: 1; height: 3px; border-radius: 2px; background: var(--mi-track); overflow: hidden; }
    .fill-bar { height: 100%; background: var(--mi-teal); transition: width 1s linear; }

    .actions { display: flex; gap: 8px; padding: 10px 13px 13px; }
    .btn-primary { flex: 1; height: 31px; border: 0; border-radius: 9px; background: var(--mi-ink-btn); color: var(--mi-ink-btn-fg); font: 600 12px/1 "Instrument Sans", system-ui, sans-serif; cursor: pointer; }
    .btn-primary:hover { background: #2A2D34; }
    .icon-btn { width: 31px; height: 31px; border: 1px solid var(--mi-line-3); border-radius: 9px; background: var(--mi-panel); color: #3F444E; display: grid; place-items: center; cursor: pointer; }
    .icon-btn:hover { background: var(--mi-row-hover); }
    .icon-btn svg { width: 14px; height: 14px; }
    button:focus-visible { outline: none; box-shadow: 0 0 0 2px var(--mi-teal); }
    svg { stroke-width: 1.8; }

    .filled { display: flex; align-items: center; gap: 8px; padding: 10px 13px 13px; }
    .badge { display: inline-flex; align-items: center; gap: 6px; height: 28px; padding: 0 12px; border-radius: 14px; background: var(--mi-teal-10); border: 1px solid var(--mi-teal-20); color: var(--mi-teal-text); font-size: 11.5px; font-weight: 600; }
    .badge svg { width: 12px; height: 12px; stroke-width: 2.4; }
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
    @media (prefers-reduced-motion: reduce) { .box { animation: none; } }
  `;

  private trusted(event: Event, fn: (() => void) | undefined): void {
    if (!event.isTrusted) return;
    fn?.();
  }

  private grouped(): string {
    const c = this.code ?? '';
    return c.length === 6 ? `${c.slice(0, 3)} ${c.slice(3)}` : c;
  }

  protected override render() {
    return html`<div class="box">${this.renderBody()}</div>`;
  }

  private renderBody() {
    if (this.view === 'status') {
      return html`<div class="head">${logoGlyph()}<span class="brand">密屿</span></div>
        <div class="status"><span class="status-msg">${this.statusMessage}</span></div>`;
    }
    return html`
      <div class="head">
        ${logoGlyph()}<span class="brand">密屿</span>
        <span class="meta">1 个匹配项 · 2FA</span>
      </div>
      <div class="row">
        <span class="tile" style="background:${tileColor(this.itemName)}">${monogramLetter(this.itemName)}</span>
        <span class="meta-col">
          <span class="title">${this.itemName}</span>
          <span class="sub">${this.itemUser}</span>
        </span>
      </div>
      ${this.view === 'filled' ? this.renderFilled() : this.renderPanel()}
    `;
  }

  private renderPanel() {
    const pct = Math.max(0, Math.min(100, Math.round((this.remaining / 30) * 100)));
    return html`
      <div class="code-box">
        <span class="code">${this.grouped()}</span>
        <span class="secs">${this.remaining}s</span>
        <span class="track"><span class="fill-bar" style="width:${pct}%"></span></span>
      </div>
      <div class="actions">
        <button type="button" class="btn-primary" @click=${(e: MouseEvent) => this.trusted(e, this.onFill)}>填充验证码</button>
        <button type="button" class="icon-btn" title="复制验证码" @click=${(e: MouseEvent) => this.trusted(e, this.onCopy)}>${uiIcon('copy')}</button>
      </div>
    `;
  }

  private renderFilled() {
    return html`
      <div class="filled">
        <span class="badge">${uiIcon('check')}已填充验证码</span>
        ${this.onUndo ? html`<button type="button" class="undo" @click=${(e: MouseEvent) => this.trusted(e, this.onUndo)}>撤销</button>` : nothing}
      </div>
    `;
  }
}

function logoGlyph() {
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

defineContentElement('vw-totp-panel', VwTotpPanel);

declare global {
  interface HTMLElementTagNameMap {
    'vw-totp-panel': VwTotpPanel;
  }
}
