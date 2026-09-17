import { LitElement, css, html, nothing } from 'lit';
import { themeTokens } from '../../components/tokens.js';
import { emit } from '../../components/emit.js';
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
      :host { display:flex; flex-direction:column; min-height:0; flex:1; }
      .head { display:flex; align-items:center; gap:8px; padding:12px 16px; flex:none; }
      .head h1 { margin:0; font-size:18px; font-weight:600; color:var(--vw-ink); }
      .content { display:flex; flex-direction:column; flex:1; min-height:0; overflow-y:auto; gap:16px; padding:4px 16px 18px; overscroll-behavior:contain; scrollbar-width:thin; scrollbar-color:var(--vw-scrollbar) transparent; }
      .summary { padding:4px 0 8px; }
      .summary-title { color:var(--vw-ink); font-size:15px; font-weight:600; }
      .summary-desc { margin-top:7px; color:var(--vw-text-2); font-size:12px; line-height:1.7; }
      .rows { border-top:1px solid var(--vw-line-1); }
      .row { appearance:none; display:flex; align-items:center; gap:12px; width:100%; padding:14px 6px; border:0; border-bottom:1px solid var(--vw-line-1); border-radius:0; background:var(--vw-card); color:var(--vw-ink); font-family:inherit; text-align:left; cursor:pointer; transition:background-color var(--vw-dur-fast); }
      .row:hover { background:var(--vw-row-hover); }
      .row:focus-visible { outline-offset:-2px; }
      .row-icon { display:grid; place-items:center; width:32px; height:32px; border-radius:var(--vw-radius-control); flex:none; }
      .row-icon.warn { color:var(--vw-strength-mid); background:var(--vw-fill-2); }
      .row-icon.danger { color:var(--vw-danger); background:var(--vw-danger-10); }
      .row-icon.unknown { color:var(--vw-text-3); background:var(--vw-fill); }
      .row-icon svg { width:16px; height:16px; }
      .meta { display:flex; flex-direction:column; flex:1; min-width:0; gap:5px; }
      .name { font-size:13px; font-weight:500; color:var(--vw-ink); white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
      .chips { display:flex; flex-wrap:wrap; gap:5px; }
      .chip { display:inline-flex; align-items:center; font-size:11px; font-weight:500; padding:2px 7px; border-radius:var(--vw-radius-chip); border:1px solid transparent; }
      .chip.warn { color:var(--vw-strength-mid); background:var(--vw-fill-2); }
      .chip.danger { color:var(--vw-danger); border-color:var(--vw-danger-border); background:var(--vw-danger-10); }
      .chip.ok { color:var(--vw-strength-strong); background:var(--vw-fill-2); }
      .chip.unknown { color:var(--vw-text-2); background:var(--vw-fill); }
      .chev { display:inline-flex; width:14px; height:14px; color:var(--vw-chevron); flex:none; }
      .chev svg { width:14px; height:14px; }
      .check { width:100%; margin-top:4px; }
      .check svg { width:16px; height:16px; }
      .empty { display:flex; flex-direction:column; align-items:center; justify-content:center; flex:1; gap:14px; padding:40px 20px; text-align:center; }
      .empty-icon { color:var(--vw-teal-text); display:inline-flex; }
      .empty-icon svg { width:38px; height:38px; }
      .empty-text { font-size:14px; font-weight:500; line-height:1.7; color:var(--vw-text-2); }
      @media(prefers-reduced-motion:reduce) { .row { transition:none; } }
    `,
  ];

  private back(): void {
    emit(this, 'vw-item-back');
  }

  private check(): void {
    if (this.pwned.status === 'loading') return;
    emit(this, 'vw-health-check');
  }

  private open(cipherId: string): void {
    emit<ItemOpenDetail>(this, 'vw-item-open', { cipherId });
  }

  private renderBreachChip(entryId: string) {
    const pwned = this.pwned;
    if (pwned.status === 'idle' || pwned.status === 'loading' || pwned.status === 'empty') return nothing;
    if (pwned.status === 'error') {
      return html`<span class="chip unknown">${t('health.unknown')}</span>`;
    }
    const pwnedCount = pwned.data.get(entryId);
    if (pwnedCount === undefined) {
      return html`<span class="chip unknown">${t('health.unknown')}</span>`;
    }
    return pwnedCount > 0
      ? html`<span class="chip danger">${t('health.pwned')} · ${pwnedCount}</span>`
      : html`<span class="chip ok">${t('health.notPwned')}</span>`;
  }

  private renderChips(entry: HealthEntry) {
    return html`
      <span class="chips">
        ${entry.weak ? html`<span class="chip warn">${t('health.weak')}</span>` : nothing}
        ${entry.reuseCount > 1
          ? html`<span class="chip warn">${t('health.reused')} ×${entry.reuseCount}</span>`
          : nothing}
        ${this.renderBreachChip(entry.id)}
      </span>
    `;
  }

  private renderRow(entry: HealthEntry) {
    const pwnedCount = this.pwned.status === 'ready' ? this.pwned.data.get(entry.id) : undefined;
    const breached = (pwnedCount ?? 0) > 0;
    const severity = breached ? 'danger' : entry.weak || entry.reuseCount > 1 ? 'warn' : 'unknown';
    return html`
      <button type="button" class="row" data-entry=${entry.id} @click=${() => this.open(entry.id)}>
        <span class="row-icon ${severity}">${uiIcon(severity === 'unknown' ? 'shield' : 'alert')}</span>
        <span class="meta">
          <span class="name">${entry.name}</span>
          ${this.renderChips(entry)}
        </span>
        <span class="chev">${uiIcon('chevron')}</span>
      </button>
    `;
  }

  private renderReady(entries: HealthEntry[]) {
    const pwned = this.pwned;
    const priority = (entry: HealthEntry): number => {
      const exposed = pwned.status === 'ready' && (pwned.data.get(entry.id) ?? 0) > 0;
      return exposed ? 3 : entry.weak || entry.reuseCount > 1 ? 2 : 1;
    };
    const visibleEntries = entries.filter((entry) => {
      const breachUnknown = pwned.status === 'error'
        || (pwned.status === 'ready' && !pwned.data.has(entry.id));
      const breachCount = pwned.status === 'ready' ? pwned.data.get(entry.id) : undefined;
      return entry.weak || entry.reuseCount > 1 || breachUnknown || (breachCount ?? 0) > 0;
    }).sort((a, b) => priority(b) - priority(a));
    const unknownCount = pwned.status === 'error'
      ? entries.length
      : pwned.status === 'ready'
        ? entries.filter((entry) => !pwned.data.has(entry.id)).length
        : 0;
    const emptyMessage = pwned.status === 'ready' ? t('health.healthy') : t('health.localHealthy');
    const summaryDescription = pwned.status === 'ready' || pwned.status === 'error'
      ? t('health.summaryDesc', { count: visibleEntries.length })
      : t('health.localSummaryDesc', { count: visibleEntries.length });

    return html`
      <div class="summary">
        <div class="summary-title">${t('health.summaryTitle')}</div>
        <div class="summary-desc">${summaryDescription}</div>
      </div>
      ${visibleEntries.length > 0
        ? html`<div class="rows">${visibleEntries.map((entry) => this.renderRow(entry))}</div>`
        : html`
          <div class="empty" data-empty>
            <span class="empty-icon">${uiIcon('checkCircle')}</span>
            <span class="empty-text">${emptyMessage}</span>
          </div>
        `}
      <button
        type="button"
        class="btn primary check"
        data-check
        ?disabled=${pwned.status === 'loading'}
        @click=${() => this.check()}
      >
        ${uiIcon('shield')}<span>${pwned.status === 'loading' ? t('common.loading') : t('health.checkBreaches')}</span>
      </button>
      ${pwned.status === 'error'
        ? html`<vw-status-message tone="danger" .icon=${'alert'} .message=${pwned.message}></vw-status-message>`
        : unknownCount > 0
          ? html`<vw-status-message
              tone="warning"
              .icon=${'alert'}
              .message=${t('health.incomplete', { count: unknownCount })}
            ></vw-status-message>`
          : nothing}
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
            <span class="empty-icon">${uiIcon('shield')}</span>
            <span class="empty-text">${t('health.noCheckable')}</span>
          </div>
        `;
      case 'ready':
        return this.renderReady(report.data);
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
