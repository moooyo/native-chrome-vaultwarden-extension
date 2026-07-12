import { LitElement, css, html, nothing } from 'lit';
import { uiIcon } from '../../ui/components/icon.js';
import { defineContentElement } from './define.js';

// TODO i18n: content-script surfaces are isolated from the extension i18n module, so these
// user-facing strings are hardcoded in Chinese to match the 密屿/MiYu design.

export type GeneratePanelView = 'panel' | 'saved';

/**
 * The 密屿/MiYu inline password-generation panel (design 2e): on a registration new-password field,
 * it suggests a strong password with in-place rule tuning (length + digits/symbols), fills the field
 * on "使用此密码", and confirms the save. Closed shadow root + local MiYu palette + `Event.isTrusted`
 * gating; the generated value flows out only through the `onUse`/`onRegenerate` callbacks the
 * orchestrator owns.
 */
export class VwGeneratePanel extends LitElement {
  static override properties = {
    view: { type: String },
    password: { type: String },
    strength: { type: String },
    length: { type: Number },
    numbers: { type: Boolean },
    symbols: { type: Boolean },
    savedName: { type: String },
    savedUser: { type: String },
    onRegenerate: { attribute: false },
    onLength: { attribute: false },
    onNumbers: { attribute: false },
    onSymbols: { attribute: false },
    onUse: { attribute: false },
    onUndo: { attribute: false },
  };

  declare view: GeneratePanelView;
  declare password: string;
  declare strength: string;
  declare length: number;
  declare numbers: boolean;
  declare symbols: boolean;
  declare savedName: string;
  declare savedUser: string;
  declare onRegenerate: (() => void) | undefined;
  declare onLength: ((length: number) => void) | undefined;
  declare onNumbers: ((on: boolean) => void) | undefined;
  declare onSymbols: ((on: boolean) => void) | undefined;
  declare onUse: (() => void) | undefined;
  declare onUndo: (() => void) | undefined;

  constructor() {
    super();
    this.view = 'panel';
    this.password = '';
    this.strength = '极强';
    this.length = 18;
    this.numbers = true;
    this.symbols = true;
    this.savedName = '';
    this.savedUser = '';
    this.onRegenerate = undefined;
    this.onLength = undefined;
    this.onNumbers = undefined;
    this.onSymbols = undefined;
    this.onUse = undefined;
    this.onUndo = undefined;
  }

  static override styles = css`
    :host { all: initial; }
    :host {
      --mi-panel: #fff; --mi-ink: #16181D; --mi-muted: #8A8F99; --mi-faint: #9AA0AA; --mi-text-3: #6A6F7A;
      --mi-teal: #0E8A72; --mi-teal-text: #0B7A65; --mi-teal-12: rgba(14,138,114,.12); --mi-teal-25: rgba(14,138,114,.25);
      --mi-red: #C6453D; --mi-line: rgba(22,24,29,.09); --mi-line-3: rgba(22,24,29,.14); --mi-fill-2: #F7F7F4;
      --mi-row-hover: #F2F2EF; --mi-ink-btn: #16181D; --mi-ink-btn-fg: #fff; --mi-shadow: 0 16px 40px rgba(20,24,32,.16);
    }
    * { box-sizing: border-box; }
    .box {
      font: 400 14px/1.4 "Instrument Sans", "Segoe UI", system-ui, sans-serif;
      color: var(--mi-ink); background: var(--mi-panel);
      border: 1px solid var(--mi-line); border-radius: 14px; box-shadow: var(--mi-shadow);
      width: 300px; padding: 11px 13px 13px; animation: mvIn .16s ease-out;
    }
    @keyframes mvIn { from { opacity: 0; transform: translateY(-5px); } to { opacity: 1; transform: none; } }
    .head { display: flex; align-items: center; gap: 7px; margin-bottom: 8px; }
    .brand { font-size: 11.5px; font-weight: 600; color: var(--mi-teal-text); }
    .head .meta { margin-left: auto; font-size: 10.5px; font-weight: 600; color: var(--mi-teal-text); }
    .logo { display: grid; place-items: center; width: 16px; height: 16px; border-radius: 5px; background: #0E8A72; flex: none; }
    .glyph { position: relative; width: 8px; height: 8px; }
    .ring { position: absolute; inset: 0; border: 1.5px solid #fff; border-radius: 50%; }
    .dot { position: absolute; left: 3px; top: 3px; width: 2px; height: 2px; border-radius: 50%; background: #fff; }

    .suggest { background: var(--mi-fill-2); border: 1px solid var(--mi-line); border-radius: 10px; padding: 9px 11px; font-family: "JetBrains Mono", ui-monospace, monospace; font-size: 12.5px; line-height: 1.55; word-break: break-all; }
    .suggest .d { color: var(--mi-teal-text); }
    .suggest .s { color: var(--mi-red); }

    .len { display: flex; align-items: center; gap: 9px; margin: 10px 0 8px; }
    .len .lab { font-size: 11.5px; color: var(--mi-text-3); flex: none; }
    .len input[type=range] { flex: 1; accent-color: var(--mi-teal); }
    .len .val { font-size: 11.5px; font-weight: 600; color: var(--mi-teal-text); min-width: 20px; text-align: right; }

    .rules { display: flex; align-items: center; gap: 6px; margin-bottom: 10px; }
    .pill { height: 26px; padding: 0 11px; display: inline-flex; align-items: center; border-radius: 13px; font: 600 11.5px/1 "JetBrains Mono", ui-monospace, monospace; cursor: pointer; background: transparent; color: var(--mi-muted); border: 1px solid var(--mi-line-3); }
    .pill.on { background: var(--mi-teal-12); color: var(--mi-teal-text); border-color: var(--mi-teal-25); }
    .spacer { flex: 1; }
    .refresh { width: 28px; height: 28px; border: 1px solid var(--mi-line-3); border-radius: 8px; background: var(--mi-panel); color: #3F444E; display: grid; place-items: center; cursor: pointer; }
    .refresh:hover { background: var(--mi-row-hover); }
    .refresh svg { width: 13px; height: 13px; }
    .use { width: 100%; height: 32px; border: 0; border-radius: 9px; background: var(--mi-ink-btn); color: var(--mi-ink-btn-fg); font: 600 12px/1 "Instrument Sans", system-ui, sans-serif; cursor: pointer; }
    .use:hover { background: #2A2D34; }
    .foot { font-size: 10.5px; color: var(--mi-faint); margin-top: 8px; }
    button:focus-visible { outline: none; box-shadow: 0 0 0 2px var(--mi-teal); }
    svg { stroke-width: 1.7; }

    .saved { display: flex; align-items: center; gap: 9px; }
    .saved-ico { display: grid; place-items: center; width: 26px; height: 26px; border-radius: 50%; background: var(--mi-teal-12); color: var(--mi-teal-text); flex: none; }
    .saved-ico svg { width: 13px; height: 13px; stroke-width: 2.4; }
    .saved .col { flex: 1; min-width: 0; }
    .saved .t { font-size: 12px; font-weight: 600; color: var(--mi-ink); }
    .saved .s { font-size: 10.5px; color: var(--mi-muted); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .undo { font-size: 11.5px; font-weight: 600; color: var(--mi-teal-text); cursor: pointer; background: none; border: 0; font-family: inherit; }
    .undo:hover { text-decoration: underline; }

    @media (prefers-color-scheme: dark) {
      :host {
        --mi-panel: #1F2229; --mi-ink: #F2F3F5; --mi-muted: #9AA0AC; --mi-faint: #7B818B; --mi-text-3: #9AA0AC;
        --mi-teal-text: #45D6B5; --mi-teal-12: rgba(69,214,181,.16); --mi-teal-25: rgba(69,214,181,.3);
        --mi-red: #E5675D; --mi-line: rgba(255,255,255,.09); --mi-line-3: rgba(255,255,255,.16); --mi-fill-2: #262A33;
        --mi-row-hover: rgba(255,255,255,.05); --mi-ink-btn: #F2F3F5; --mi-ink-btn-fg: #16181D; --mi-shadow: 0 18px 48px rgba(0,0,0,.5);
      }
      .use:hover { background: #fff; }
    }
    @media (prefers-reduced-motion: reduce) { .box { animation: none; } }
  `;

  private trusted(event: Event, fn: (() => void) | undefined): void {
    if (!event.isTrusted) return;
    fn?.();
  }

  private colorize() {
    return [...(this.password ?? '')].map((ch) => {
      if (/[0-9]/.test(ch)) return html`<span class="d">${ch}</span>`;
      if (/[^A-Za-z0-9]/.test(ch)) return html`<span class="s">${ch}</span>`;
      return html`${ch}`;
    });
  }

  protected override render() {
    return html`<div class="box">${this.view === 'saved' ? this.renderSaved() : this.renderPanel()}</div>`;
  }

  private renderPanel() {
    const meta = `${this.strength} · ${this.length} 字符${this.symbols ? ' · 含符号' : ''}`;
    return html`
      <div class="head">
        ${logoGlyph()}<span class="brand">密屿 · 强密码建议</span>
        <span class="meta">${meta}</span>
      </div>
      <div class="suggest">${this.colorize()}</div>
      <div class="len">
        <span class="lab">长度</span>
        <input type="range" min="8" max="40" .value=${String(this.length)}
          @input=${(e: Event) => { if (e.isTrusted) this.onLength?.(Number((e.target as HTMLInputElement).value)); }} />
        <span class="val">${this.length}</span>
      </div>
      <div class="rules">
        <button type="button" class="pill ${this.numbers ? 'on' : ''}" title="包含数字"
          @click=${(e: MouseEvent) => { if (e.isTrusted) this.onNumbers?.(!this.numbers); }}>0–9</button>
        <button type="button" class="pill ${this.symbols ? 'on' : ''}" title="包含符号"
          @click=${(e: MouseEvent) => { if (e.isTrusted) this.onSymbols?.(!this.symbols); }}>!@#$</button>
        <span class="spacer"></span>
        <button type="button" class="refresh" title="换一个" @click=${(e: MouseEvent) => this.trusted(e, this.onRegenerate)}>${uiIcon('refresh')}</button>
      </div>
      <button type="button" class="use" @click=${(e: MouseEvent) => this.trusted(e, this.onUse)}>使用此密码</button>
      <div class="foot">使用后将自动保存到你的密钥库</div>
    `;
  }

  private renderSaved() {
    return html`
      <div class="saved">
        <span class="saved-ico">${uiIcon('check')}</span>
        <span class="col">
          <span class="t">已保存到密屿</span>
          ${this.savedUser ? html`<span class="s">${this.savedName ? this.savedName + ' · ' : ''}${this.savedUser}</span>` : nothing}
        </span>
        ${this.onUndo ? html`<button type="button" class="undo" @click=${(e: MouseEvent) => this.trusted(e, this.onUndo)}>撤销</button>` : nothing}
      </div>
    `;
  }
}

function logoGlyph() {
  return html`<span class="logo"><span class="glyph"><span class="ring"></span><span class="dot"></span></span></span>`;
}

defineContentElement('vw-generate-panel', VwGeneratePanel);

declare global {
  interface HTMLElementTagNameMap {
    'vw-generate-panel': VwGeneratePanel;
  }
}
