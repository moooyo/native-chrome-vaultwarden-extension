import { LitElement, css, html, nothing, type TemplateResult } from 'lit';
import { emit } from '../../components/emit.js';
import { uiIcon, type IconName } from '../../components/icon.js';
import { controlStyles } from '../../components/styles.js';
import { themeTokens } from '../../components/tokens.js';
import { LocalizeController, t } from '../../i18n/index.js';
import '../../components/status-message.js';

export type ImportPreviewFormat =
  | 'bitwarden-json'
  | 'bitwarden-encrypted-json'
  | 'bitwarden-csv'
  | 'bitwarden-zip';
export type ImportPreviewScope = 'personal' | 'organization';

/**
 * A deliberately narrow, display-only diagnostic. Callers must sanitize `message` and `path` before
 * constructing this model. Raw transfer records and secret fields are intentionally not accepted.
 */
export interface SanitizedImportPreviewDiagnostic {
  code: string;
  message: string;
  count?: number;
  sourceIndex?: number;
  path?: string;
}

export interface SanitizedImportPreviewViewModel {
  format: ImportPreviewFormat;
  scope: ImportPreviewScope;
  counts: {
    folders: number;
    collections: number;
    items: number;
    attachments: number;
  };
  diagnostics: {
    errors: SanitizedImportPreviewDiagnostic[];
    warnings: SanitizedImportPreviewDiagnostic[];
    unsupported: SanitizedImportPreviewDiagnostic[];
  };
  organizationTargetRequired: boolean;
  hasUnknownOutcome: boolean;
  canCommit: boolean;
}

const MAX_VISIBLE_DIAGNOSTICS_PER_GROUP = 4;
const MAX_MESSAGE_CHARS = 320;
const MAX_PATH_CHARS = 180;

const EMPTY_PREVIEW: SanitizedImportPreviewViewModel = {
  format: 'bitwarden-json',
  scope: 'personal',
  counts: { folders: 0, collections: 0, items: 0, attachments: 0 },
  diagnostics: { errors: [], warnings: [], unsupported: [] },
  organizationTargetRequired: false,
  hasUnknownOutcome: false,
  canCommit: false,
};

interface DiagnosticGroup {
  kind: 'errors' | 'warnings' | 'unsupported';
  label: string;
  icon: IconName;
  items: SanitizedImportPreviewDiagnostic[];
}

/** Standalone import-preview surface. It emits intent only and never imports or stores anything. */
export class VwImportPreview extends LitElement {
  static override properties = {
    preview: { attribute: false },
    pending: { type: Boolean },
  };

  declare preview: SanitizedImportPreviewViewModel;
  declare pending: boolean;

  private i18n = new LocalizeController(this);

  constructor() {
    super();
    this.preview = EMPTY_PREVIEW;
    this.pending = false;
  }

  static override styles = [
    themeTokens,
    controlStyles,
    css`
      :host { display: block; }
      .preview {
        display: flex;
        flex-direction: column;
        gap: 14px;
        padding: 18px;
        border: 1px solid var(--vw-line-1);
        border-radius: var(--vw-radius-small);
        background: var(--vw-card);
      }
      .header { display: flex; align-items: flex-start; gap: 10px; }
      .header-icon {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        width: 34px;
        height: 34px;
        flex: none;
        border-radius: var(--vw-radius-small);
        background: var(--vw-teal-10);
        color: var(--vw-accent);
      }
      .header-icon svg { width: 17px; height: 17px; }
      .heading { min-width: 0; }
      h2 { margin: 0; color: var(--vw-ink); font-size: 14px; font-weight: 600; line-height: 1.35; }
      .description { margin: 3px 0 0; color: var(--vw-text-2); font-size: 11.5px; line-height: 1.5; }

      .meta {
        display: grid;
        grid-template-columns: repeat(2, minmax(0, 1fr));
        gap: 8px 16px;
        margin: 0;
        padding: 10px 12px;
        border-radius: var(--vw-radius-small);
        background: var(--vw-fill-2);
      }
      .meta-row { min-width: 0; }
      dt { color: var(--vw-muted); font-size: 10.5px; }
      dd { margin: 2px 0 0; color: var(--vw-ink); font-size: 12px; font-weight: 500; overflow-wrap: anywhere; }

      .counts {
        display: grid;
        grid-template-columns: repeat(4, minmax(0, 1fr));
        border: 1px solid var(--vw-line-1);
        border-radius: var(--vw-radius-small);
        overflow: hidden;
      }
      .count { min-width: 0; padding: 10px 8px; text-align: center; }
      .count + .count { border-left: 1px solid var(--vw-line-1); }
      .count-value { display: block; color: var(--vw-ink); font-size: 17px; font-weight: 600; line-height: 1.2; }
      .count-label { display: block; margin-top: 3px; color: var(--vw-muted); font-size: 10.5px; overflow-wrap: anywhere; }

      .notices { display: flex; flex-direction: column; gap: 7px; }
      vw-status-message { display: block; }

      .diagnostics { display: flex; flex-direction: column; gap: 10px; }
      .diagnostic-group {
        padding: 10px 12px;
        border: 1px solid var(--vw-line-1);
        border-radius: var(--vw-radius-small);
        background: var(--vw-fill-2);
      }
      .diagnostic-group.errors { border-color: var(--vw-danger-border); background: var(--vw-danger-10); }
      .diagnostic-group.warnings, .diagnostic-group.unsupported { border-color: var(--vw-sync-amber); }
      .group-heading { display: flex; align-items: center; gap: 6px; margin: 0; font-size: 11.5px; font-weight: 600; }
      .group-heading svg { width: 14px; height: 14px; flex: none; }
      .errors .group-heading { color: var(--vw-danger); }
      .warnings .group-heading, .unsupported .group-heading { color: var(--vw-sync-amber); }
      ul { display: flex; flex-direction: column; gap: 7px; margin: 8px 0 0; padding: 0; list-style: none; }
      li { min-width: 0; color: var(--vw-text-2); font-size: 11.5px; line-height: 1.45; }
      .diagnostic-message { overflow-wrap: anywhere; }
      .diagnostic-count { margin-left: 5px; color: var(--vw-muted); font-variant-numeric: tabular-nums; }
      .location { display: block; margin-top: 2px; color: var(--vw-muted); font-family: var(--vw-font-mono); font-size: 10px; overflow-wrap: anywhere; }
      .omitted { color: var(--vw-muted); font-style: italic; }
      .clear { margin: 0; color: var(--vw-text-2); font-size: 11.5px; }

      .actions { display: flex; justify-content: flex-end; gap: 8px; padding-top: 2px; }
      .btn { min-height: 34px; border-radius: var(--vw-radius-input); }

      @media (max-width: 420px) {
        .meta { grid-template-columns: minmax(0, 1fr); }
        .actions { align-items: stretch; flex-direction: column-reverse; }
        .btn { width: 100%; }
      }
    `,
  ];

  private formatLabel(format: ImportPreviewFormat): string {
    switch (format) {
      case 'bitwarden-json': return t('options.data.preview.formatJson');
      case 'bitwarden-encrypted-json': return t('options.data.preview.formatEncryptedJson');
      case 'bitwarden-csv': return t('options.data.preview.formatCsv');
      case 'bitwarden-zip': return t('options.data.preview.formatZip');
    }
  }

  private scopeLabel(scope: ImportPreviewScope): string {
    return scope === 'organization'
      ? t('options.data.preview.scopeOrganization')
      : t('options.data.preview.scopePersonal');
  }

  private diagnosticGroups(preview: SanitizedImportPreviewViewModel): DiagnosticGroup[] {
    return [
      {
        kind: 'errors',
        label: t('options.data.preview.errors'),
        icon: 'alert',
        items: preview.diagnostics.errors,
      },
      {
        kind: 'warnings',
        label: t('options.data.preview.warnings'),
        icon: 'alert',
        items: preview.diagnostics.warnings,
      },
      {
        kind: 'unsupported',
        label: t('options.data.preview.unsupported'),
        icon: 'shield',
        items: preview.diagnostics.unsupported,
      },
    ];
  }

  private diagnosticLocation(diagnostic: SanitizedImportPreviewDiagnostic): string {
    const parts: string[] = [];
    const sourceIndex = diagnostic.sourceIndex;
    if (typeof sourceIndex === 'number' && Number.isSafeInteger(sourceIndex) && sourceIndex >= 0) {
      parts.push(t('options.data.preview.sourceIndex', { index: sourceIndex }));
    }
    if (diagnostic.path) {
      parts.push(t('options.data.preview.path', { path: boundedText(diagnostic.path, MAX_PATH_CHARS) }));
    }
    return parts.join(' / ');
  }

  private renderDiagnosticGroup(group: DiagnosticGroup): TemplateResult | typeof nothing {
    if (group.items.length === 0) return nothing;
    const visible = group.items.slice(0, MAX_VISIBLE_DIAGNOSTICS_PER_GROUP);
    const omitted = group.items.length - visible.length;
    const total = group.items.reduce((sum, item) => sum + safePositiveCount(item.count), 0);
    return html`
      <section class="diagnostic-group ${group.kind}" data-diagnostic-group=${group.kind}>
        <h3 class="group-heading">${uiIcon(group.icon)}<span>${group.label} (${total})</span></h3>
        <ul>
          ${visible.map((diagnostic) => {
            const location = this.diagnosticLocation(diagnostic);
            const message = fixedDiagnosticMessage(diagnostic.code) ?? diagnostic.message;
            return html`
              <li data-diagnostic data-code=${boundedText(diagnostic.code, 80)}>
                <span class="diagnostic-message">${boundedText(message, MAX_MESSAGE_CHARS)}</span>
                ${safePositiveCount(diagnostic.count) > 1
                  ? html`<span class="diagnostic-count">×${safePositiveCount(diagnostic.count)}</span>`
                  : nothing}
                ${location ? html`<span class="location">${location}</span>` : nothing}
              </li>
            `;
          })}
          ${omitted > 0
            ? html`<li class="omitted" data-diagnostics-omitted>${t('options.data.preview.more', { count: omitted })}</li>`
            : nothing}
        </ul>
      </section>
    `;
  }

  private confirm(): void {
    if (!this.preview.canCommit) return;
    emit(this, 'vw-import-preview-confirm');
  }

  private cancel(): void {
    emit(this, 'vw-import-preview-cancel');
  }

  protected override render() {
    const preview = this.preview ?? EMPTY_PREVIEW;
    const groups = this.diagnosticGroups(preview);
    const hasDiagnostics = groups.some((group) => group.items.length > 0);
    return html`
      <section class="preview" aria-labelledby="import-preview-title" aria-describedby="import-preview-description">
        <header class="header">
          <span class="header-icon" aria-hidden="true">${uiIcon('file')}</span>
          <div class="heading">
            <h2 id="import-preview-title">${t('options.data.preview.title')}</h2>
            <p id="import-preview-description" class="description">${t('options.data.preview.description')}</p>
          </div>
        </header>

        <dl class="meta">
          <div class="meta-row">
            <dt>${t('options.data.preview.format')}</dt>
            <dd data-format>${this.formatLabel(preview.format)}</dd>
          </div>
          <div class="meta-row">
            <dt>${t('options.data.preview.scope')}</dt>
            <dd data-scope>${this.scopeLabel(preview.scope)}</dd>
          </div>
        </dl>

        <div class="counts" aria-label=${t('options.data.preview.plan')}>
          <div class="count">
            <span class="count-value" data-folder-count>${safeCount(preview.counts.folders)}</span>
            <span class="count-label">${t('options.data.preview.folders')}</span>
          </div>
          <div class="count">
            <span class="count-value" data-collection-count>${safeCount(preview.counts.collections)}</span>
            <span class="count-label">${t('options.data.preview.collections')}</span>
          </div>
          <div class="count">
            <span class="count-value" data-item-count>${safeCount(preview.counts.items)}</span>
            <span class="count-label">${t('options.data.preview.items')}</span>
          </div>
          <div class="count">
            <span class="count-value" data-attachment-count>${safeCount(preview.counts.attachments)}</span>
            <span class="count-label">${t('options.data.preview.attachments')}</span>
          </div>
        </div>

        <div class="notices">
          ${preview.organizationTargetRequired
            ? html`<vw-status-message data-organization-required tone="warning" .icon=${'alert'} .message=${t('options.data.preview.organizationTargetRequired')}></vw-status-message>`
            : nothing}
          ${preview.hasUnknownOutcome
            ? html`<vw-status-message data-unknown-outcome tone="danger" .icon=${'alert'} .message=${t('options.data.preview.unknownOutcome')}></vw-status-message>`
            : nothing}
          <vw-status-message data-retry-policy tone="info" .icon=${'shield'} .message=${t('options.data.preview.noWholeRetry')}></vw-status-message>
        </div>

        <div class="diagnostics" aria-label=${t('options.data.preview.diagnostics')}>
          ${hasDiagnostics
            ? groups.map((group) => this.renderDiagnosticGroup(group))
            : html`<p class="clear" data-no-diagnostics>${t('options.data.preview.noDiagnostics')}</p>`}
        </div>

        <vw-status-message
          data-readiness
          .tone=${preview.canCommit ? 'success' : 'warning'}
          .icon=${preview.canCommit ? 'checkCircle' : 'alert'}
          .message=${preview.canCommit ? t('options.data.preview.ready') : t('options.data.preview.blocked')}
        ></vw-status-message>

        <div class="actions">
          <button type="button" class="btn outline" data-cancel ?disabled=${this.pending} @click=${() => this.cancel()}>
            ${t('common.cancel')}
          </button>
          <button type="button" class="btn primary" data-confirm ?disabled=${this.pending || !preview.canCommit} @click=${() => this.confirm()}>
            ${uiIcon('check')}<span>${t('options.data.preview.confirm')}</span>
          </button>
        </div>
      </section>
    `;
  }
}

function safeCount(value: number): number {
  return Number.isSafeInteger(value) && value >= 0 ? value : 0;
}

function safePositiveCount(value: number | undefined): number {
  return Number.isSafeInteger(value) && value !== undefined && value > 0 ? value : 1;
}

function boundedText(value: string, limit: number): string {
  if (value.length <= limit) return value;
  return `${value.slice(0, Math.max(0, limit - 3))}...`;
}

function fixedDiagnosticMessage(code: string): string | undefined {
  switch (code) {
    case 'malformed_input': return t('options.data.preview.code.malformedInput');
    case 'unsupported_format': return t('options.data.preview.code.unsupportedFormat');
    case 'unsupported_data': return t('options.data.preview.code.unsupportedData');
    case 'unknown_data': return t('options.data.preview.code.unknownData');
    case 'limit_exceeded': return t('options.data.preview.code.limitExceeded');
    case 'missing_reference': return t('options.data.preview.code.missingReference');
    case 'unavailable_resource': return t('options.data.preview.code.unavailableResource');
    case 'policy_blocked': return t('options.data.preview.code.policyBlocked');
    case 'organization_target_required': return t('options.data.preview.code.organizationTargetRequired');
    case 'capability_blocked': return t('options.data.preview.code.capabilityBlocked');
    case 'attachment_unavailable': return t('options.data.preview.code.attachmentUnavailable');
    case 'partial_result': return t('options.data.preview.code.partialResult');
    case 'outcome_unknown': return t('options.data.preview.code.outcomeUnknown');
    case 'diagnostics_omitted': return t('options.data.preview.code.diagnosticsOmitted');
    case 'other': return t('options.data.preview.code.other');
    default: return undefined;
  }
}

customElements.define('vw-import-preview', VwImportPreview);

declare global {
  interface HTMLElementTagNameMap {
    'vw-import-preview': VwImportPreview;
  }
}
