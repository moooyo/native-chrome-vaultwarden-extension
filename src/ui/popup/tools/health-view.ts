import { LitElement, css, html, nothing } from 'lit';
import { themeTokens } from '../../components/tokens.js';
import { controlStyles } from '../../components/styles.js';
import { uiIcon } from '../../components/icon.js';
import '../../components/status-message.js';
import { LocalizeController, t } from '../../i18n/index.js';
import type { AsyncState } from '../../components/async-state.js';
import type { HealthEntry, ItemOpenDetail, PwnedState } from '../types.js';

/**
 * The password-health report (MiYu design). It renders only from typed props — the root loads the
 * local report (`vault.getPasswordHealth`) and, on the explicit `vw-health-check`, the HIBP breach
 * counts (`vault.checkPwned`). Every secret stays in the worker; this view shows names and non-secret
 * weak/reused/breach markers only, and opening a row emits `vw-item-open`.
 */
export class VwHealthView extends LitElement {
  static override properties = {
    report: { attribute: false },
    pwned: { attribute: false },
  };

  declare report: AsyncState<HealthEntry[]>;
  declare pwned: PwnedState;

  private i18n = new LocalizeController(this);

  constructor() {
    super();
    this.report = { status: 'idle' };
    this.pwned = { status: 'idle' };
  }

  static override styles = [
    themeTokens,
    controlStyles,
    css`
      :host {
        display: flex;
        flex-direction: column;
        min-height: 0;
        flex: 1;
      }
      .head {
        display: flex;
        align-items: center;
        gap: 8px;
        padding: 10px 14px;
        flex: none;
      }
      .head h1 {
        margin: 0;
        font-size: 14px;
        font-weight: 600;
        color: var(--vw-ink);
      }
      .content {
        flex: 1;
        min-height: 0;
        overflow-y: auto;
        display: flex;
        flex-direction: column;
        gap: 8px;
        padding: 2px 14px 14px;
        scrollbar-width: thin;
        scrollbar-color: var(--vw-scrollbar) transparent;
      }
      .content::-webkit-scrollbar {
        width: 8px;
      }
      .content::-webkit-scrollbar-thumb {
        background: var(--vw-scrollbar);
        border-radius: 4px;
        border: 2px solid transparent;
        background-clip: content-box;
      }

      .row {
        display: flex;
        align-items: center;
        gap: 10px;
        width: 100%;
        padding: 10px 12px;
        border: 1px solid var(--vw-line-1);
        border-radius: var(--vw-radius-card);
        background: var(--vw-card);
        color: var(--vw-ink);
        font-family: inherit;
        text-align: left;
        cursor: pointer;
        transition: background-color var(--vw-dur-fast), border-color var(--vw-dur-fast);
      }
      .row:hover {
        background: var(--vw-row-hover);
      }
      .row-icon {
        width: 30px;
        height: 30px;
        border-radius: var(--vw-radius-control);
        display: grid;
        place-items: center;
        flex: none;
      }
      .row-icon.warn {
        color: var(--vw-strength-mid);
        background: var(--vw-fill);
      }
      .row-icon.danger {
        color: var(--vw-danger);
        background: var(--vw-danger-10);
      }
      .row-icon svg {
        width: 16px;
        height: 16px;
      }
      .meta {
        flex: 1;
        min-width: 0;
        display: flex;
        flex-direction: column;
        gap: 4px;
      }
      .name {
        font-size: 13px;
        font-weight: 600;
        color: var(--vw-ink);
        white-space: nowrap;
        overflow: hidden;
        text-overflow: ellipsis;
      }
      .chips {
        display: flex;
        flex-wrap: wrap;
        gap: 4px;
      }
      .chip {
        display: inline-flex;
        align-items: center;
        font-size: 11px;
        font-weight: 600;
        padding: 1px 8px;
        border-radius: var(--vw-radius-chip);
        border: 1px solid transparent;
      }
      .chip.warn {
        color: var(--vw-strength-mid);
        border-color: var(--vw-strength-mid);
      }
      .chip.danger {
        color: var(--vw-danger);
        border-color: var(--vw-danger-border);
        background: var(--vw-danger-10);
      }
      .chip.ok {
        color: var(--vw-teal-text);
        border-color: var(--vw-teal-25);
        background: var(--vw-teal-10);
      }
      .chev {
        width: 14px;
        height: 14px;
        color: var(--vw-chevron);
        flex: none;
        display: inline-flex;
      }
      .chev svg {
        width: 14px;
        height: 14px;
      }

      .check {
        width: 100%;
        margin-top: 4px;
      }
      .check svg {
        width: 16px;
        height: 16px;
      }

      .empty {
        flex: 1;
        display: flex;
        flex-direction: column;
        align-items: center;
        justify-content: center;
        gap: 12px;
        padding: 44px 20px;
        text-align: center;
      }
      .empty-icon {
        color: var(--vw-teal-text);
        display: inline-flex;
      }
      .empty-icon svg {
        width: 44px;
        height: 44px;
      }
      .empty-text {
        font-size: 13px;
        font-weight: 600;
        color: var(--vw-text-2);
      }
    `,
  ];

  private back(): void {
    this.dispatchEvent(new CustomEvent('vw-item-back', { bubbles: true, composed: true }));
  }

  private check(): void {
    if (this.pwned.status === 'loading') return;
    this.dispatchEvent(new CustomEvent('vw-health-check', { bubbles: true, composed: true }));
  }

  private open(cipherId: string): void {
    this.dispatchEvent(
      new CustomEvent<ItemOpenDetail>('vw-item-open', { detail: { cipherId }, bubbles: true, composed: true }),
    );
  }

  private renderChips(entry: HealthEntry) {
    const pwnedCount = this.pwned.status === 'ready' ? this.pwned.data.get(entry.id) : undefined;
    return html`
      <span class="chips">
        ${entry.weak ? html`<span class="chip warn">${t('health.weak')}</span>` : nothing}
        ${entry.reuseCount > 1
          ? html`<span class="chip warn">${t('health.reused')} ×${entry.reuseCount}</span>`
          : nothing}
        ${pwnedCount === undefined
          ? nothing
          : pwnedCount > 0
            ? html`<span class="chip danger">${t('health.pwned')} · ${pwnedCount}</span>`
            : html`<span class="chip ok">未泄露</span>` /* TODO i18n */}
      </span>
    `;
  }

  private renderRow(entry: HealthEntry) {
    const pwnedCount = this.pwned.status === 'ready' ? this.pwned.data.get(entry.id) : undefined;
    const severity = pwnedCount && pwnedCount > 0 ? 'danger' : 'warn';
    return html`
      <button type="button" class="row" data-entry=${entry.id} @click=${() => this.open(entry.id)}>
        <span class="row-icon ${severity}">${uiIcon('alert')}</span>
        <span class="meta">
          <span class="name">${entry.name}</span>
          ${this.renderChips(entry)}
        </span>
        <span class="chev">${uiIcon('chevron')}</span>
      </button>
    `;
  }

  private renderReport() {
    const report = this.report;
    switch (report.status) {
      case 'idle':
      case 'loading':
        return html`<vw-status-message tone="info" .icon=${'refresh'} .message=${t('common.loading')}></vw-status-message>`;
      case 'error':
        return html`<vw-status-message tone="danger" .icon=${'alert'} .message=${report.message}></vw-status-message>`;
      case 'empty':
        return html`
          <div class="empty" data-empty>
            <span class="empty-icon">${uiIcon('checkCircle')}</span>
            <span class="empty-text">${t('health.healthy')}</span>
          </div>
        `;
      case 'ready':
        return html`
          ${report.data.map((entry) => this.renderRow(entry))}
          <button
            type="button"
            class="btn primary check"
            data-check
            ?disabled=${this.pwned.status === 'loading'}
            @click=${() => this.check()}
          >
            ${uiIcon('shield')}<span>${this.pwned.status === 'loading' ? t('common.loading') : '检查是否泄露' /* TODO i18n */}</span>
          </button>
          ${this.pwned.status === 'error'
            ? html`<vw-status-message tone="danger" .icon=${'alert'} .message=${this.pwned.message}></vw-status-message>`
            : nothing}
        `;
    }
  }

  protected override render() {
    return html`
      <div class="head">
        <button type="button" class="icon-btn" data-back title=${t('common.back')} aria-label=${t('common.back')} @click=${() => this.back()}>
          ${uiIcon('back')}
        </button>
        <h1>${t('health.title')}</h1>
      </div>
      <div class="content">${this.renderReport()}</div>
    `;
  }
}

customElements.define('vw-health-view', VwHealthView);

declare global {
  interface HTMLElementTagNameMap {
    'vw-health-view': VwHealthView;
  }
}
