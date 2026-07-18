import { html, nothing, type TemplateResult } from 'lit';
import { uiIcon } from '../../ui/components/icon.js';
import { SIDE_PANEL_CSS, sideWrap } from './side-panel.js';

// TODO i18n: content-script surfaces are isolated from the extension i18n module, so these
// user-facing strings are hardcoded in Chinese to match the 密屿/MiYu design.

export type GeneratePanelView = 'panel' | 'saved';

/**
 * The full render state of the 密屿/MiYu inline password-generation panel (design 2e). Held by the
 * factory (see generate-fill.ts) and passed to `renderGeneratePanel` on every view/state change — the
 * generated value flows out only through the `onUse`/`onRegenerate` callbacks the orchestrator owns.
 */
export interface GeneratePanelViewState {
  view: GeneratePanelView;
  /** The detected registration username/email, editable in the panel; saved with the login on use. */
  username: string;
  password: string;
  strength: string;
  length: number;
  uppercase: boolean;
  lowercase: boolean;
  numbers: boolean;
  symbols: boolean;
  minNumbers: number;
  minSymbols: number;
  avoidAmbiguous: boolean;
  savedName: string;
  savedUser: string;
}

/** Privileged callbacks. Every click/input that reaches them is gated on `Event.isTrusted` in the
 *  template, so a page script cannot synthesize an event to tune, regenerate, use, edit, or save. */
export interface GeneratePanelHandlers {
  onUsername?: (value: string) => void;
  onLength?: (length: number) => void;
  onUppercase?: (on: boolean) => void;
  onLowercase?: (on: boolean) => void;
  onNumbers?: (on: boolean) => void;
  onSymbols?: (on: boolean) => void;
  onMinNumbers?: (n: number) => void;
  onMinSymbols?: (n: number) => void;
  onAvoidAmbiguous?: (on: boolean) => void;
  onRegenerate?: () => void;
  onUse?: () => void;
  onUndo?: () => void;
}

/**
 * Styles for the inline password-generation panel. Because the surface lives in a closed shadow root
 * on arbitrary host pages it cannot use the extension's `--vw-*` tokens, so the MiYu palette is defined
 * locally on `:host` (the surface host div) with a `prefers-color-scheme: dark` override.
 */
export const GENERATE_PANEL_STYLES = `
    :host { all: initial; }
    :host {
      --mi-panel:#fff; --mi-ink:#1f1f1f; --mi-muted:#747775; --mi-faint:#80868b; --mi-text-3:#474747;
      --mi-teal:#0b57d0; --mi-teal-text:#0b57d0; --mi-teal-12:rgba(11,87,208,.12); --mi-teal-25:rgba(11,87,208,.25);
      --mi-red:#c2185b; --mi-line:#e9eef6; --mi-line-3:#c4c7c5; --mi-fill-2:#f0f4f9;
      --mi-row-hover:rgba(31,31,31,.07); --mi-ink-btn:#0b57d0; --mi-ink-btn-fg:#fff; --mi-shadow:0 8px 28px rgba(0,0,0,.2);
    }
    * { box-sizing: border-box; }
    .box {
      font:400 14px/1.4 "Roboto", "Segoe UI", system-ui, sans-serif;
      color: var(--mi-ink); background: var(--mi-panel);
      border: 1px solid var(--mi-line); border-radius: 14px; box-shadow: var(--mi-shadow);
      width:236px; padding:11px 13px 13px; animation:mvFly .22s cubic-bezier(.2,.9,.3,1); transform-origin:left center;
    }
    @keyframes mvFly { from { opacity:0; transform:translateX(-12px); } to { opacity:1; transform:translateX(0); } }
    .head { display: flex; align-items: center; gap: 7px; margin-bottom: 8px; }
    .brand { font-size: 11.5px; font-weight: 600; color: var(--mi-teal-text); }
    .head .meta { margin-left: auto; font-size: 10.5px; font-weight: 600; color: var(--mi-teal-text); }
    .logo { display:grid; place-items:center; width:16px; height:16px; border-radius:5px; background:#0b57d0; flex:none; }
    .logo svg { width:11px; height:11px; fill:#fff; stroke:none; }
    .glyph { position: relative; width: 8px; height: 8px; }
    .ring { position: absolute; inset: 0; border: 1.5px solid #fff; border-radius: 50%; }
    .dot { position: absolute; left: 3px; top: 3px; width: 2px; height: 2px; border-radius: 50%; background: #fff; }

    .user { display: flex; align-items: center; gap: 8px; margin-bottom: 8px; }
    .user .lab { font-size: 11.5px; color: var(--mi-text-3); flex: none; }
    .user input { flex:1; min-width:0; height:30px; padding:0 9px; border:1px solid var(--mi-line-3); border-radius:8px; background:var(--mi-panel); color:var(--mi-ink); font:400 12px/1 "Roboto", "Segoe UI", system-ui, sans-serif; }
    .user input:focus { outline: none; border-color: var(--mi-teal); box-shadow: 0 0 0 2px var(--mi-teal-12); }

    .suggest { background:var(--mi-fill-2); border:1px solid var(--mi-line); border-radius:10px; padding:9px 11px; font-family:"Roboto Mono", ui-monospace, monospace; font-size:12.5px; line-height:1.55; word-break:break-all; }
    .suggest .d { color: var(--mi-teal-text); }
    .suggest .s { color: var(--mi-red); }

    .len { display: flex; align-items: center; gap: 9px; margin: 10px 0 10px; }
    .len .lab { font-size: 11.5px; color: var(--mi-text-3); flex: none; }
    .len input[type=range] { flex: 1; accent-color: var(--mi-teal); }
    .len .val { font-size: 11.5px; font-weight: 600; color: var(--mi-teal-text); min-width: 20px; text-align: right; }

    /* Character sets — one pill per class, spread to fill the row, with regenerate at the end. */
    .pills { display: flex; align-items: center; gap: 6px; margin-bottom: 10px; }
    .pill { height:26px; padding:0 8px; display:inline-flex; align-items:center; border-radius:13px; font:500 10.5px/1 "Roboto Mono", ui-monospace, monospace; cursor:pointer; background:transparent; color:var(--mi-muted); border:1px solid var(--mi-line-3); }
    .pill.on { background: var(--mi-teal-12); color: var(--mi-teal-text); border-color: var(--mi-teal-25); }
    .spacer { flex: 1; }
    .refresh { width: 28px; height: 28px; flex: none; border: 1px solid var(--mi-line-3); border-radius: 8px; background: var(--mi-panel); color: #3F444E; display: grid; place-items: center; cursor: pointer; }
    .refresh:hover { background: var(--mi-row-hover); }
    .refresh svg { width: 13px; height: 13px; }

    /* Per-class minimums — compact −/value/+ steppers. */
    .mins { display: flex; gap: 10px; margin-bottom: 10px; }
    .min { flex: 1; display: flex; align-items: center; justify-content: space-between; gap: 6px; }
    .min .lab { font-size: 11px; color: var(--mi-text-3); }
    .step { display: inline-flex; align-items: center; border: 1px solid var(--mi-line-3); border-radius: 8px; overflow: hidden; }
    .step button { width:22px; height:24px; border:0; background:transparent; color:var(--mi-text-3); font:400 15px/1 "Roboto", system-ui, sans-serif; cursor:pointer; }
    .step button:hover { background: var(--mi-row-hover); color: var(--mi-ink); }
    .step .val { min-width: 18px; text-align: center; font-size: 12px; font-weight: 600; color: var(--mi-ink); font-variant-numeric: tabular-nums; }

    /* Avoid-ambiguous — a full-width checkbox pill. */
    .ambig { width:100%; display:flex; align-items:center; gap:8px; height:30px; padding:0 10px; margin-bottom:10px; border:1px solid var(--mi-line-3); border-radius:9px; background:transparent; color:var(--mi-text-3); font:500 11.5px/1 "Roboto", "Segoe UI", system-ui, sans-serif; cursor:pointer; }
    .ambig.on { background: var(--mi-teal-12); color: var(--mi-teal-text); border-color: var(--mi-teal-25); }
    .ambig .check { display: inline-grid; place-items: center; width: 15px; height: 15px; border: 1.5px solid currentColor; border-radius: 4px; flex: none; }
    .ambig .check svg { width: 11px; height: 11px; stroke-width: 2.6; }

    .use { width:100%; height:38px; border:0; border-radius:19px; background:var(--mi-ink-btn); color:var(--mi-ink-btn-fg); font:500 12px/1 "Roboto", system-ui, sans-serif; cursor:pointer; }
    .use:hover { background:#0842a0; }
    .foot { font-size: 10.5px; color: var(--mi-faint); margin-top: 8px; }
    button:focus-visible { outline: none; box-shadow: 0 0 0 2px var(--mi-teal); }
    svg { stroke-width: 1.7; }

    .saved { display: flex; align-items: center; gap: 9px; }
    .saved-ico { display: grid; place-items: center; width: 26px; height: 26px; border-radius: 50%; background: var(--mi-teal-12); color: var(--mi-teal-text); flex: none; animation: mvPop .3s ease-out both; }
    .saved-ico svg { width: 13px; height: 13px; stroke-width: 2.4; }
    @keyframes mvPop { 0% { transform: scale(.4); opacity: 0; } 65% { transform: scale(1.12); opacity: 1; } 100% { transform: scale(1); opacity: 1; } }
    .saved .col { flex: 1; min-width: 0; }
    .saved .t { font-size: 12px; font-weight: 600; color: var(--mi-ink); }
    .saved .s { font-size: 10.5px; color: var(--mi-muted); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .undo { font-size: 11.5px; font-weight: 600; color: var(--mi-teal-text); cursor: pointer; background: none; border: 0; font-family: inherit; }
    .undo:hover { text-decoration: underline; }

    @media (prefers-color-scheme: dark) {
      :host {
        --mi-panel:#1f1f1f; --mi-ink:#e3e3e3; --mi-muted:#c4c7c5; --mi-faint:#8e918f; --mi-text-3:#c4c7c5;
        --mi-teal:#a8c7fa; --mi-teal-text:#a8c7fa; --mi-teal-12:rgba(168,199,250,.16); --mi-teal-25:rgba(168,199,250,.3);
        --mi-red:#ff8ab5; --mi-line:#2b2c2e; --mi-line-3:#47494c; --mi-fill-2:#242526;
        --mi-row-hover:rgba(227,227,227,.09); --mi-ink-btn:#a8c7fa; --mi-ink-btn-fg:#062e6f; --mi-shadow:0 8px 28px rgba(0,0,0,.5);
      }
      .use:hover { background:#d3e3fd; }
    }
    @media (prefers-reduced-motion: reduce) { *, *::before, *::after { animation: none !important; } }
  ` + SIDE_PANEL_CSS;

/** Render the generation panel for the given state. The page cannot forge the privileged events: each
 *  handler bails unless `event.isTrusted`. Mounts as a right-side panel (design 2c/3a-consistent). */
export function renderGeneratePanel(state: GeneratePanelViewState, handlers: GeneratePanelHandlers): TemplateResult {
  return sideWrap(html`<div class="box">${state.view === 'saved' ? renderSaved(state, handlers) : renderPanel(state, handlers)}</div>`);
}

function colorize(password: string) {
  return [...(password ?? '')].map((ch) => {
    if (/[0-9]/.test(ch)) return html`<span class="d">${ch}</span>`;
    if (/[^A-Za-z0-9]/.test(ch)) return html`<span class="s">${ch}</span>`;
    return html`${ch}`;
  });
}

function pill(label: string, on: boolean, toggle: (on: boolean) => void): TemplateResult {
  return html`<button type="button" class="pill ${on ? 'on' : ''}" aria-pressed=${on ? 'true' : 'false'}
    @click=${(e: MouseEvent) => { if (e.isTrusted) toggle(!on); }}>${label}</button>`;
}

function stepper(label: string, value: number, set: (n: number) => void): TemplateResult {
  return html`
    <div class="min">
      <span class="lab">${label}</span>
      <span class="step">
        <button type="button" aria-label="${label} 减少" @click=${(e: MouseEvent) => { if (e.isTrusted) set(value - 1); }}>−</button>
        <span class="val">${value}</span>
        <button type="button" aria-label="${label} 增加" @click=${(e: MouseEvent) => { if (e.isTrusted) set(value + 1); }}>+</button>
      </span>
    </div>
  `;
}

function renderPanel(state: GeneratePanelViewState, handlers: GeneratePanelHandlers): TemplateResult {
  const meta = `${state.strength} · ${state.length} 字符${state.symbols ? ' · 含符号' : ''}`;
  return html`
    <div class="head">
      ${logoGlyph()}<span class="brand">密屿 · 强密码建议</span>
      <span class="meta">${meta}</span>
    </div>
    <div class="user">
      <span class="lab">用户名</span>
      <input type="text" .value=${state.username} placeholder="用户名（可编辑）"
        @input=${(e: Event) => { if (e.isTrusted) handlers.onUsername?.((e.target as HTMLInputElement).value); }} />
    </div>
    <div class="suggest">${colorize(state.password)}</div>
    <div class="len">
      <span class="lab">长度</span>
      <input type="range" min="8" max="40" .value=${String(state.length)}
        @input=${(e: Event) => { if (e.isTrusted) handlers.onLength?.(Number((e.target as HTMLInputElement).value)); }} />
      <span class="val">${state.length}</span>
    </div>
    <div class="pills">
      ${pill('A-Z', state.uppercase, (on) => handlers.onUppercase?.(on))}
      ${pill('a-z', state.lowercase, (on) => handlers.onLowercase?.(on))}
      ${pill('0-9', state.numbers, (on) => handlers.onNumbers?.(on))}
      ${pill('!@#$', state.symbols, (on) => handlers.onSymbols?.(on))}
      <span class="spacer"></span>
      <button type="button" class="refresh" title="换一个" @click=${(e: MouseEvent) => { if (e.isTrusted) handlers.onRegenerate?.(); }}>${uiIcon('refresh')}</button>
    </div>
    <div class="mins">
      ${stepper('最少数字', state.minNumbers, (n) => handlers.onMinNumbers?.(n))}
      ${stepper('最少符号', state.minSymbols, (n) => handlers.onMinSymbols?.(n))}
    </div>
    <button type="button" class="ambig ${state.avoidAmbiguous ? 'on' : ''}" aria-pressed=${state.avoidAmbiguous ? 'true' : 'false'}
      @click=${(e: MouseEvent) => { if (e.isTrusted) handlers.onAvoidAmbiguous?.(!state.avoidAmbiguous); }}>
      <span class="check">${state.avoidAmbiguous ? uiIcon('check') : nothing}</span>避免易混淆字符
    </button>
    <button type="button" class="use" @click=${(e: MouseEvent) => { if (e.isTrusted) handlers.onUse?.(); }}>使用此密码</button>
    <div class="foot">使用后将自动保存到你的密钥库</div>
  `;
}

function renderSaved(state: GeneratePanelViewState, handlers: GeneratePanelHandlers): TemplateResult {
  return html`
    <div class="saved">
      <span class="saved-ico">${uiIcon('check')}</span>
      <span class="col">
        <span class="t">已保存到密屿</span>
        ${state.savedUser ? html`<span class="s">${state.savedName ? state.savedName + ' · ' : ''}${state.savedUser}</span>` : nothing}
      </span>
      ${handlers.onUndo ? html`<button type="button" class="undo" @click=${(e: MouseEvent) => { if (e.isTrusted) handlers.onUndo?.(); }}>撤销</button>` : nothing}
    </div>
  `;
}

function logoGlyph() {
  return html`<span class="logo"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M7.5 15.5a5.5 5.5 0 1 1 4.9-8H22v4h-2v2h-3v2h-4.6a5.5 5.5 0 0 1-4.9 3Zm0-3.5a2 2 0 1 0 0 4 2 2 0 0 0 0-4Z"/></svg></span>`;
}
