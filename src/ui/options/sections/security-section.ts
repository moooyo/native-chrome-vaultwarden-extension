import { LitElement, css, html, nothing } from 'lit';
import { themeTokens } from '../../components/tokens.js';
import { controlStyles } from '../../components/styles.js';
import { uiIcon } from '../../components/icon.js';
import '../../components/status-message.js';
import {
  LOCK_TIMEOUT_VALUES,
  CLIPBOARD_CLEAR_VALUES,
  isLockTimeoutSetting,
  isOnIdleAction,
  isClipboardClearSetting,
  type LockTimeoutSetting,
  type OnIdleAction,
  type ClipboardClearSetting,
} from '../../../background/settings.js';
import type { LockTimeoutSaveDetail, SecuritySaveDetail, SectionStatus } from '../types.js';

const LOCK_TIMEOUT_LABELS: Record<LockTimeoutSetting, string> = {
  '1': 'After 1 minute',
  '5': 'After 5 minutes',
  '15': 'After 15 minutes',
  '30': 'After 30 minutes',
  onClose: 'When the browser closes',
  never: 'Never',
};

const CLIPBOARD_CLEAR_LABELS: Record<ClipboardClearSetting, string> = {
  never: 'Never',
  '30': 'After 30 seconds',
  '60': 'After 1 minute',
  '120': 'After 2 minutes',
  '300': 'After 5 minutes',
};

/**
 * Security settings: the automatic lock timeout (an explicit Save, persisted through
 * `settings.save` by the root), plus the idle action and clipboard-clear window which save on
 * change through `settings.saveSecurity`. This section only emits already-typed values; the root
 * performs every request and drives the section-local status.
 */
export class VwSecuritySection extends LitElement {
  static override properties = {
    lockTimeout: { attribute: false },
    onIdleAction: { attribute: false },
    clipboardClearSeconds: { attribute: false },
    pending: { type: Boolean },
    status: { attribute: false },
  };

  declare lockTimeout: LockTimeoutSetting;
  declare onIdleAction: OnIdleAction;
  declare clipboardClearSeconds: ClipboardClearSetting;
  declare pending: boolean;
  declare status: SectionStatus | undefined;

  constructor() {
    super();
    this.lockTimeout = '15';
    this.onIdleAction = 'lock';
    this.clipboardClearSeconds = '60';
    this.pending = false;
    this.status = undefined;
  }

  static override styles = [
    themeTokens,
    controlStyles,
    css`
      :host { display: block; max-width: 760px; }
      h1 { margin: 0 0 4px; font-size: 28px; color: var(--vw-ink-strong); }
      p.lede { margin: 0 0 24px; color: var(--vw-muted); font-size: 14px; }
      .card { display: grid; grid-template-columns: minmax(180px,1fr) minmax(210px,320px); gap: 12px 24px; align-items: center; margin-bottom: 16px; border: 1px solid var(--vw-line); border-radius: var(--vw-radius-row); padding: 16px 12px; background: var(--vw-panel); }
      .card h2 { grid-column: 1 / -1; margin: -16px -12px 4px; padding: 10px 12px; background: var(--vw-blue-weak); font-size: 14px; }
      .select { width: 100%; box-sizing: border-box; }
      .warning { display: flex; gap: 8px; font-size: 12px; color: var(--vw-danger); }
      .warning svg { width: 16px; height: 16px; flex: none; }
      .status { margin-top: 8px; }
      @media (max-width:640px) { .card { grid-template-columns:1fr; } }
    `,
  ];

  private saveLockTimeout(): void {
    if (this.pending) return;
    const value = this.renderRoot.querySelector<HTMLSelectElement>('[data-lock-timeout]')?.value ?? '';
    if (!isLockTimeoutSetting(value)) return;
    this.dispatchEvent(new CustomEvent<LockTimeoutSaveDetail>('vw-lock-timeout-save', {
      detail: { lockTimeout: value },
      bubbles: true,
      composed: true,
    }));
  }

  private saveSecurity(): void {
    const idle = this.renderRoot.querySelector<HTMLSelectElement>('[data-idle]')?.value ?? '';
    const clip = this.renderRoot.querySelector<HTMLSelectElement>('[data-clipboard]')?.value ?? '';
    if (!isOnIdleAction(idle) || !isClipboardClearSetting(clip)) return;
    this.onIdleAction = idle;
    this.clipboardClearSeconds = clip;
    this.dispatchEvent(new CustomEvent<SecuritySaveDetail>('vw-security-save', {
      detail: { onIdleAction: idle, clipboardClearSeconds: clip },
      bubbles: true,
      composed: true,
    }));
  }

  // Native <select>s need their value set after their <option>s are in the DOM; a `.value`
  // binding can commit before the options do. Sync each select here so reads are reliable.
  protected override updated(): void {
    const lock = this.renderRoot.querySelector<HTMLSelectElement>('[data-lock-timeout]');
    if (lock) lock.value = this.lockTimeout;
    const idle = this.renderRoot.querySelector<HTMLSelectElement>('[data-idle]');
    if (idle) idle.value = this.onIdleAction;
    const clip = this.renderRoot.querySelector<HTMLSelectElement>('[data-clipboard]');
    if (clip) clip.value = this.clipboardClearSeconds;
  }

  private renderStatus() {
    return this.status
      ? html`<vw-status-message class="status" tone=${this.status.tone} .message=${this.status.message}></vw-status-message>`
      : nothing;
  }

  protected override render() {
    return html`
      <h1>Security</h1>
      <p class="lede">Control how and when the vault locks.</p>
      <div class="card">
        <h2>Automatic lock</h2>
        <label class="field">
          <span>Lock the vault</span>
          <select class="select" data-lock-timeout>
            ${LOCK_TIMEOUT_VALUES.map((v) => html`<option value=${v} ?selected=${v === this.lockTimeout}>${LOCK_TIMEOUT_LABELS[v]}</option>`)}
          </select>
        </label>
        <button type="button" class="button primary" data-lock-save ?disabled=${this.pending} @click=${() => this.saveLockTimeout()}>${uiIcon('lock')}<span>Save lock timeout</span></button>
      </div>
      <div class="card">
        <h2>On idle or system lock</h2>
        <label class="field">
          <span>When idle times out</span>
          <select class="select" data-idle @change=${() => this.saveSecurity()}>
            <option value="lock" ?selected=${this.onIdleAction === 'lock'}>Lock the vault</option>
            <option value="logout" ?selected=${this.onIdleAction === 'logout'}>Log out</option>
          </select>
        </label>
        ${this.onIdleAction === 'logout'
          ? html`<p class="warning">${uiIcon('alert')}<span>Log out will end your session (and disable PIN unlock) on every idle timeout and system lock.</span></p>`
          : nothing}
        <label class="field">
          <span>Clear copied secrets</span>
          <select class="select" data-clipboard @change=${() => this.saveSecurity()}>
            ${CLIPBOARD_CLEAR_VALUES.map((v) => html`<option value=${v} ?selected=${v === this.clipboardClearSeconds}>${CLIPBOARD_CLEAR_LABELS[v]}</option>`)}
          </select>
        </label>
      </div>
      ${this.renderStatus()}
    `;
  }
}

customElements.define('vw-security-section', VwSecuritySection);

declare global {
  interface HTMLElementTagNameMap {
    'vw-security-section': VwSecuritySection;
  }
}
