import { html, nothing, type TemplateResult } from 'lit';
import { uiIcon } from '../../ui/components/icon.js';
import { SIDE_PANEL_CSS, sideWrap } from './side-panel.js';
import { INLINE_SURFACE_CSS } from './surface-theme.js';

// TODO i18n: content-script surfaces are isolated from the extension i18n module, so these
// user-facing strings are hardcoded in Chinese to match the 密屿/MiYu design.

export type GeneratePanelView = 'panel' | 'filled';

/**
 * The full render state of the 密屿/MiYu inline password-generation panel (design 2e). Held by the
 * factory (see generate-fill.ts) and passed to `renderGeneratePanel` on every view/state change — the
 * generated value flows out only through the `onUse`/`onRegenerate` callbacks the orchestrator owns.
 */
export interface GeneratePanelViewState {
  view: GeneratePanelView;
  mode: 'password' | 'passphrase';
  /** The detected registration username/email, editable in the panel and filled on use. */
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
  words: number;
  capitalize: boolean;
  includeNumber: boolean;
  managed: boolean;
  disabledReason: string;
  filledUser: string;
  siteLabel?: string;
}

/** Privileged callbacks. Every click/input that reaches them is gated on `Event.isTrusted` in the
 *  template, so a page script cannot synthesize an event to tune, regenerate, use, edit, or save. */
export interface GeneratePanelHandlers {
  onMode?: (mode: 'password' | 'passphrase') => void;
  onDismiss?: () => void;
  onUsername?: (value: string) => void;
  onLength?: (length: number) => void;
  onUppercase?: (on: boolean) => void;
  onLowercase?: (on: boolean) => void;
  onNumbers?: (on: boolean) => void;
  onSymbols?: (on: boolean) => void;
  onMinNumbers?: (n: number) => void;
  onMinSymbols?: (n: number) => void;
  onAvoidAmbiguous?: (on: boolean) => void;
  onWords?: (words: number) => void;
  onCapitalize?: (on: boolean) => void;
  onIncludeNumber?: (on: boolean) => void;
  onRegenerate?: () => void;
  onUse?: () => void;
}

/**
 * Styles for the inline password-generation panel. Because the surface lives in a closed shadow root
 * on arbitrary host pages it cannot use the extension's `--vw-*` tokens, so the MiYu palette is defined
 * locally on `:host` (the surface host div) with a `prefers-color-scheme: dark` override.
 */
export const GENERATE_PANEL_STYLES = INLINE_SURFACE_CSS + SIDE_PANEL_CSS + `
  .content { padding:16px; }
  .mode-switch { display:flex; gap:3px; padding:3px; background:var(--mi-fill); border-radius:8px; margin-bottom:14px; }
  .mode-switch button { flex:1; min-height:32px; border:0; border-radius:6px; background:transparent; color:var(--mi-muted); font-size:12px; }
  .mode-switch button[aria-pressed="true"] { background:var(--mi-panel); color:var(--mi-teal-text); box-shadow:0 1px 4px #233c5212; font-weight:600; }
  .user { display:flex; flex-direction:column; gap:7px; margin-bottom:14px; }
  .lab { font-size:12px; color:var(--mi-muted); }
  .user input { width:100%; min-width:0; height:38px; padding:0 11px; border:1px solid var(--mi-line-3); border-radius:8px; background:var(--mi-panel); color:var(--mi-ink); }
  .suggest { display:block; background:var(--mi-fill); border:1px solid var(--mi-line); border-radius:8px; padding:13px 12px; font:400 16px/1.7 "Cascadia Code", "Consolas", ui-monospace, monospace; overflow-wrap:anywhere; }
  .suggest .d { color:var(--mi-teal-text); }
  .suggest .s { color:var(--mi-muted); }
  .meta { color:var(--mi-faint); font-size:12px; margin:9px 0 14px; }
  .value-actions { display:flex; gap:8px; }
  .use, .refresh { min-height:38px; padding:8px 12px; border-radius:8px; font-size:13px; font-weight:500; }
  .use { flex:1; border:1px solid var(--mi-ink-btn); background:var(--mi-ink-btn); color:var(--mi-ink-btn-fg); }
  .use:hover { background:var(--mi-ink-hover); border-color:var(--mi-ink-hover); }
  .refresh { display:flex; align-items:center; gap:6px; border:1px solid var(--mi-line-3); background:var(--mi-panel); color:var(--mi-muted); }
  .refresh:hover { background:var(--mi-row-hover); }
  .refresh svg { width:15px; height:15px; }
  .len { display:flex; align-items:center; gap:10px; margin:17px 0 12px; }
  .len input { flex:1; min-width:0; accent-color:var(--mi-teal); }
  .len .val { min-width:24px; text-align:right; color:var(--mi-teal-text); font-variant-numeric:tabular-nums; }
  .rules { margin-top:10px; border-top:1px solid var(--mi-inner); }
  .rules summary { color:var(--mi-muted); cursor:pointer; padding:13px 0 3px; font-size:12px; }
  .rules[open] summary { padding-bottom:13px; }
  .pills { display:flex; gap:6px; margin-bottom:14px; }
  .pill { flex:1; min-height:32px; padding:4px 6px; border:1px solid var(--mi-line-3); border-radius:6px; background:var(--mi-panel); color:var(--mi-muted); font:500 12px/1.4 "Consolas", ui-monospace, monospace; }
  .pill.on { background:var(--mi-teal-12); color:var(--mi-teal-text); border-color:var(--mi-teal-25); }
  .mins { display:grid; grid-template-columns:1fr 1fr; gap:12px; margin-bottom:14px; }
  .min { display:grid; gap:7px; }
  .step { display:flex; align-items:center; justify-content:space-between; border:1px solid var(--mi-line-3); border-radius:7px; }
  .step button { border:0; width:34px; height:32px; background:transparent; font-size:16px; }
  .step button:hover { background:var(--mi-row-hover); }
  .step .val { font-variant-numeric:tabular-nums; font-size:12px; }
  .ambig { display:flex; align-items:center; gap:8px; width:100%; min-height:34px; border:0; background:transparent; color:var(--mi-muted); padding:0; text-align:left; font-size:12px; }
  .check { display:grid; place-items:center; width:16px; height:16px; border:1px solid var(--mi-line-3); border-radius:4px; }
  .check svg { width:12px; height:12px; }
  .ambig.on .check { background:var(--mi-ink-btn); color:var(--mi-ink-btn-fg); border-color:var(--mi-ink-btn); }
  .save-alert { margin:0 0 12px; color:var(--mi-red); font-size:12px; line-height:1.65; }
  .managed-note { margin:0 0 12px; color:var(--mi-muted); font-size:12px; }
  .foot { border-top:1px solid var(--mi-inner); padding:10px 16px; font-size:11px; line-height:1.7; color:var(--mi-faint); }
  .saved { display:flex; align-items:flex-start; gap:10px; padding:16px; }
  .saved-ico { display:grid; place-items:center; flex:none; width:26px; height:26px; border-radius:8px; background:var(--mi-teal-12); color:var(--mi-success); animation:mi-receipt-enter 160ms var(--mi-ease); }
  .saved-ico svg { width:16px; height:16px; }
  .saved .col { display:flex; flex-direction:column; min-width:0; gap:5px; }
  .saved .t { font-size:14px; font-weight:500; }
  .saved .s { font-size:12px; color:var(--mi-muted); overflow-wrap:anywhere; line-height:1.65; }
`;
/** Render the generation panel for the given state. The page cannot forge the privileged events: each
 *  handler bails unless `event.isTrusted`. Mounts as a right-side panel (design 2c/3a-consistent). */
export function renderGeneratePanel(state: GeneratePanelViewState, handlers: GeneratePanelHandlers): TemplateResult {
  return sideWrap(html`<div class="box" @keydown=${(event: KeyboardEvent) => {
    if (event.isTrusted && event.key === 'Escape') {
      event.preventDefault();
      event.stopPropagation();
      handlers.onDismiss?.();
    }
  }}><div class="head">${logoGlyph()}<span class="brand">${state.siteLabel || '密屿 · 强密码建议'}</span>
    <button type="button" class="panel-close" aria-label="关闭密码生成建议" @click=${(event: MouseEvent) => {
      if (event.isTrusted) handlers.onDismiss?.();
    }}>${uiIcon('close')}</button></div>
    ${state.view === 'filled' ? renderFilled(state) : renderPanel(state, handlers)}</div>`);
}

function colorize(password: string) {
  return [...(password ?? '')].map((ch) => {
    if (/[0-9]/.test(ch)) return html`<span class="d">${ch}</span>`;
    if (/[^A-Za-z0-9]/.test(ch)) return html`<span class="s">${ch}</span>`;
    return html`${ch}`;
  });
}

function pill(label: string, on: boolean, disabled: boolean, toggle: (on: boolean) => void): TemplateResult {
  return html`<button type="button" class="pill ${on ? 'on' : ''}" aria-pressed=${on ? 'true' : 'false'}
    ?disabled=${disabled} @click=${(e: MouseEvent) => { if (e.isTrusted) toggle(!on); }}>${label}</button>`;
}

function stepper(label: string, value: number, disabled: boolean, set: (n: number) => void): TemplateResult {
  return html`
    <div class="min">
      <span class="lab">${label}</span>
      <span class="step">
        <button type="button" aria-label="${label} 减少" ?disabled=${disabled} @click=${(e: MouseEvent) => { if (e.isTrusted) set(value - 1); }}>−</button>
        <span class="val">${value}</span>
        <button type="button" aria-label="${label} 增加" ?disabled=${disabled} @click=${(e: MouseEvent) => { if (e.isTrusted) set(value + 1); }}>+</button>
      </span>
    </div>
  `;
}

function renderPanel(state: GeneratePanelViewState, handlers: GeneratePanelHandlers): TemplateResult {
  const meta = state.mode === 'passphrase'
    ? `${state.strength} · ${state.words} 个词`
    : `${state.strength} · ${state.length} 字符${state.symbols ? ' · 含符号' : ''}`;
  const controlsDisabled = state.managed || Boolean(state.disabledReason);
  return html`
    <div class="content">
    ${handlers.onMode ? html`<div class="mode-switch" aria-label="生成类型">
      <button type="button" aria-pressed=${state.mode === 'password' ? 'true' : 'false'} ?disabled=${controlsDisabled}
        @click=${(event: MouseEvent) => { if (event.isTrusted && !controlsDisabled) handlers.onMode?.('password'); }}>随机密码</button>
      <button type="button" aria-pressed=${state.mode === 'passphrase' ? 'true' : 'false'} ?disabled=${controlsDisabled}
        @click=${(event: MouseEvent) => { if (event.isTrusted && !controlsDisabled) handlers.onMode?.('passphrase'); }}>易记短语</button>
    </div>` : nothing}
    <div class="user">
      <label class="lab" for="mi-generated-username">用户名</label>
      <input id="mi-generated-username" type="text" .value=${state.username} placeholder="用户名（可编辑）" autocomplete="off"
        @input=${(e: Event) => { if (e.isTrusted) handlers.onUsername?.((e.target as HTMLInputElement).value); }} />
    </div>
    ${state.disabledReason
      ? html`<p class="save-alert" data-generator-disabled>${state.disabledReason}</p>`
      : state.managed
        ? html`<p class="managed-note" data-generator-managed>生成规则由组织管理</p>`
        : nothing}
    <output class="suggest" aria-label="生成的密码">${colorize(state.password)}</output>
    <div class="meta">${meta}</div>
    <div class="value-actions">
      <button type="button" class="use" ?disabled=${Boolean(state.disabledReason) || !state.password}
        @click=${(e: MouseEvent) => { if (e.isTrusted) handlers.onUse?.(); }}>使用此密码</button>
      <button type="button" class="refresh" title="重新生成密码" ?disabled=${Boolean(state.disabledReason)}
        @click=${(e: MouseEvent) => { if (e.isTrusted) handlers.onRegenerate?.(); }}>${uiIcon('refresh')}换一个</button>
    </div>
    <div class="len">
      <label class="lab" for="mi-generated-length">${state.mode === 'passphrase' ? '词数' : '长度'}</label>
      <input id="mi-generated-length" type="range" min=${state.mode === 'passphrase' ? 3 : 8} max=${state.mode === 'passphrase' ? 20 : 128}
        .value=${String(state.mode === 'passphrase' ? state.words : state.length)} ?disabled=${controlsDisabled}
        @input=${(e: Event) => {
          if (!e.isTrusted) return;
          const value = Number((e.target as HTMLInputElement).value);
          if (state.mode === 'passphrase') handlers.onWords?.(value);
          else handlers.onLength?.(value);
        }} />
      <span class="val">${state.mode === 'passphrase' ? state.words : state.length}</span>
    </div>
    <details class="rules"><summary>字符与高级规则</summary><div class="pills">
      ${state.mode === 'passphrase'
        ? html`
            ${pill('A-Z', state.capitalize, controlsDisabled, (on) => handlers.onCapitalize?.(on))}
            ${pill('0-9', state.includeNumber, controlsDisabled, (on) => handlers.onIncludeNumber?.(on))}
          `
        : html`
            ${pill('A-Z', state.uppercase, controlsDisabled, (on) => handlers.onUppercase?.(on))}
            ${pill('a-z', state.lowercase, controlsDisabled, (on) => handlers.onLowercase?.(on))}
            ${pill('0-9', state.numbers, controlsDisabled, (on) => handlers.onNumbers?.(on))}
            ${pill('!@#$', state.symbols, controlsDisabled, (on) => handlers.onSymbols?.(on))}
          `}
    </div>
    ${state.mode === 'password'
      ? html`
          <div class="mins">
            ${stepper('最少数字', state.minNumbers, controlsDisabled, (n) => handlers.onMinNumbers?.(n))}
            ${stepper('最少符号', state.minSymbols, controlsDisabled, (n) => handlers.onMinSymbols?.(n))}
          </div>
          <button type="button" class="ambig ${state.avoidAmbiguous ? 'on' : ''}" aria-pressed=${state.avoidAmbiguous ? 'true' : 'false'}
            ?disabled=${controlsDisabled}
            @click=${(e: MouseEvent) => { if (e.isTrusted) handlers.onAvoidAmbiguous?.(!state.avoidAmbiguous); }}>
            <span class="check">${state.avoidAmbiguous ? uiIcon('check') : nothing}</span>避免易混淆字符
          </button>
        `
      : nothing}
    </details></div>
    <div class="foot">填写后，将在网站提交时询问是否保存</div>
  `;
}

function renderFilled(state: GeneratePanelViewState): TemplateResult {
  return html`
    <div class="saved" role="status" aria-live="polite" aria-atomic="true">
      <span class="saved-ico">${uiIcon('check')}</span>
      <span class="col">
        <span class="t">密码已填入</span>
        <span class="s">${state.filledUser ? `${state.filledUser} · ` : ''}提交后可保存到密屿</span>
      </span>
    </div>
  `;
}

function logoGlyph() {
  return html`<span class="logo"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M7.5 15.5a5.5 5.5 0 1 1 4.9-8H22v4h-2v2h-3v2h-4.6a5.5 5.5 0 0 1-4.9 3Zm0-3.5a2 2 0 1 0 0 4 2 2 0 0 0 0-4Z"/></svg></span>`;
}
