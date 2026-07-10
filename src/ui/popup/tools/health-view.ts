import { LitElement, css, html, nothing } from 'lit';
import { themeTokens } from '../../components/tokens.js';
import { controlStyles } from '../../components/styles.js';
import { uiIcon } from '../../components/icon.js';
import '../../components/status-message.js';
import type { AsyncState } from '../../components/async-state.js';
import type { HealthEntry, ItemOpenDetail, PwnedState } from '../types.js';

/**
 * The password-health report. It renders only from typed props — the root loads the local report
 * (`vault.getPasswordHealth`) and, on the explicit `vw-health-check`, the HIBP breach counts
 * (`vault.checkPwned`). Every secret stays in the worker; this view shows names and non-secret
 * weak/reused/breach markers only, and opening a row emits `vw-item-open`.
 */
export class VwHealthView extends LitElement {
  static override properties = {
    report: { attribute: false },
    pwned: { attribute: false },
  };

  declare report: AsyncState<HealthEntry[]>;
  declare pwned: PwnedState;

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
        display: block;
      }
      .head {
        display: flex;
        align-items: center;
        gap: 8px;
        padding: 6px 0 12px;
      }
      .head h1 {
        margin: 0;
        font-size: 15px;
      }
      .list {
        display: flex;
        flex-direction: column;
        gap: 4px;
      }
      .item {
        display: flex;
        align-items: center;
        gap: 8px;
        width: 100%;
        padding: 8px 10px;
        border: none;
        border-radius: var(--vw-radius-control);
        background: transparent;
        color: var(--vw-ink);
        font-family: var(--vw-font-ui);
        text-align: left;
        cursor: pointer;
      }
      .item:hover {
        background: var(--vw-blue-50);
      }
      .body {
        display: flex;
        flex-direction: column;
        gap: 3px;
        flex: 1;
        min-width: 0;
      }
      .name {
        font-size: 13px;
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
      }
      .tags {
        display: flex;
        flex-wrap: wrap;
        gap: 4px;
      }
      .tag {
        font-size: 11px;
        padding: 1px 6px;
        border-radius: 999px;
        border: 1px solid var(--vw-line);
        color: var(--vw-muted);
      }
      .tag.warn {
        border-color: var(--vw-blue-600);
        color: var(--vw-blue-600);
      }
      .tag.danger {
        border-color: var(--vw-danger);
        color: var(--vw-danger);
      }
      .tag.ok {
        border-color: var(--vw-ok);
        color: var(--vw-ok);
      }
      .actions {
        margin-top: 12px;
      }
      .block {
        width: 100%;
      }
      .check-status {
        margin-top: 10px;
      }
      svg {
        width: 16px;
        height: 16px;
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
    this.dispatchEvent(new CustomEvent<ItemOpenDetail>('vw-item-open', { detail: { cipherId }, bubbles: true, composed: true }));
  }

  private renderTags(entry: HealthEntry) {
    const pwnedCount = this.pwned.status === 'ready' ? this.pwned.data.get(entry.id) : undefined;
    return html`
      <span class="tags">
        ${entry.weak ? html`<span class="tag warn">Weak</span>` : nothing}
        ${entry.reuseCount > 1 ? html`<span class="tag warn">Reused ×${entry.reuseCount}</span>` : nothing}
        ${pwnedCount === undefined
          ? nothing
          : pwnedCount > 0
            ? html`<span class="tag danger">Found in ${pwnedCount} breaches</span>`
            : html`<span class="tag ok">Not found</span>`}
      </span>
    `;
  }

  private renderReport() {
    const report = this.report;
    switch (report.status) {
      case 'idle':
      case 'loading':
        return html`<vw-status-message tone="info" .icon=${'refresh'} message="Checking your passwords…"></vw-status-message>`;
      case 'error':
        return html`<vw-status-message tone="danger" .icon=${'alert'} .message=${report.message}></vw-status-message>`;
      case 'empty':
        return html`<vw-status-message tone="success" .icon=${'checkCircle'} message="No weak or reused passwords found."></vw-status-message>`;
      case 'ready':
        return html`
          <div class="list">
            ${report.data.map((entry) => html`
              <button type="button" class="item" data-entry=${entry.id} @click=${() => this.open(entry.id)}>
                <span class="body">
                  <span class="name">${entry.name}</span>
                  ${this.renderTags(entry)}
                </span>
                <span>${uiIcon('chevron')}</span>
              </button>
            `)}
          </div>
          <div class="actions">
            <button type="button" class="button block" data-check ?disabled=${this.pwned.status === 'loading'} @click=${() => this.check()}>
              ${uiIcon('shield')}<span>${this.pwned.status === 'loading' ? 'Checking…' : 'Check for breaches'}</span>
            </button>
          </div>
          ${this.pwned.status === 'error'
            ? html`<vw-status-message class="check-status" tone="danger" .icon=${'alert'} .message=${this.pwned.message}></vw-status-message>`
            : nothing}
        `;
    }
  }

  protected override render() {
    return html`
      <div class="head">
        <button type="button" class="icon-button" data-back title="Back" aria-label="Back" @click=${() => this.back()}>${uiIcon('back')}</button>
        <h1>Password health</h1>
      </div>
      ${this.renderReport()}
    `;
  }
}

customElements.define('vw-health-view', VwHealthView);

declare global {
  interface HTMLElementTagNameMap {
    'vw-health-view': VwHealthView;
  }
}
