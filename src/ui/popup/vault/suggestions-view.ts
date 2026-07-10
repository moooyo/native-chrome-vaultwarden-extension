import { LitElement, css, html, nothing } from 'lit';
import { themeTokens } from '../../components/tokens.js';
import { controlStyles } from '../../components/styles.js';
import { uiIcon } from '../../components/icon.js';
import '../../components/status-message.js';
import type { StatusTone } from '../../components/status-message.js';
import type { TabAutofillSuggestion, TabFillOutcome } from '../../../messaging/protocol.js';
import type {
  FillResult,
  ItemOpenDetail,
  SuggestionFillDetail,
  SuggestionsUnavailableReason,
  SuggestionsViewState,
} from '../types.js';

/** Neutral, non-blaming guidance for each reason Suggestions cannot be shown. */
export function unavailableMessage(reason: SuggestionsUnavailableReason): string {
  switch (reason) {
    case 'no_eligible_tab':
      return 'Open a website tab to see logins suggested for it.';
    case 'site_access_unavailable':
      return "This page's address isn't available to the extension.";
    case 'restricted_page':
      return "Suggestions aren't available on this browser page.";
    case 'content_script_unavailable':
      return 'This page is still loading the extension helper. Reopen to try again.';
  }
}

/** A user-facing message and tone for each Fill outcome. */
export function fillOutcomeMessage(status: TabFillOutcome['status']): { tone: StatusTone; message: string } {
  switch (status) {
    case 'filled':
      return { tone: 'success', message: 'Filled the login on this page.' };
    case 'no_eligible_tab':
      return { tone: 'info', message: 'No active website tab to fill.' };
    case 'site_access_unavailable':
      return { tone: 'info', message: "This page's address isn't available to the extension." };
    case 'no_fillable_target':
      return { tone: 'warning', message: 'No login field to fill on this page.' };
    case 'reprompt_required':
      return { tone: 'warning', message: 'This item needs master-password verification. Open it here first, then fill.' };
    case 'vault_locked':
      return { tone: 'info', message: 'Your vault locked. Unlock it and try again.' };
    case 'sync_required':
      return { tone: 'info', message: 'Sync your vault, then try again.' };
    case 'no_longer_matched':
      return { tone: 'warning', message: 'This item no longer matches this page.' };
    case 'target_changed':
      return { tone: 'warning', message: 'The page changed before filling. Reopen and try again.' };
    case 'restricted_page':
      return { tone: 'info', message: "Filling isn't available on this browser page." };
    case 'content_script_unavailable':
      return { tone: 'info', message: 'This page is still loading the extension helper. Reopen to try again.' };
  }
}

/**
 * Renders the current tab's login candidates and Fill results from props only. The root owns every
 * request; this view merely dispatches `vw-suggestion-fill` (ids + target, never credentials) and
 * `vw-item-open`, and maps the typed `state`/`fill` props to neutral guidance. `TabAutofillSuggestion`
 * carries no secret fields, so no password/TOTP can reach the DOM here.
 */
export class VwSuggestionsView extends LitElement {
  static override properties = {
    state: { attribute: false },
    fill: { attribute: false },
    selectedCipherId: { attribute: false },
  };

  declare state: SuggestionsViewState;
  declare fill: FillResult;
  declare selectedCipherId: string | null;

  constructor() {
    super();
    this.state = { status: 'loading' };
    this.fill = {};
    this.selectedCipherId = null;
  }

  static override styles = [
    themeTokens,
    controlStyles,
    css`
      :host {
        display: block;
      }
      .list {
        display: flex;
        flex-direction: column;
        gap: 4px;
        padding: 4px 0;
      }
      .suggestion {
        display: flex;
        align-items: center;
        gap: 8px;
        min-height: 54px;
        border-radius: var(--vw-radius-row);
      }
      .suggestion[data-selected] {
        background: var(--vw-blue);
        color: #fff;
      }
      .open {
        display: flex;
        align-items: center;
        gap: 10px;
        flex: 1;
        min-width: 0;
        padding: 8px 10px;
        border: none;
        border-radius: var(--vw-radius-control);
        background: transparent;
        color: var(--vw-ink);
        font-family: var(--vw-font-ui);
        text-align: left;
        cursor: pointer;
      }
      .open:hover {
        background: var(--vw-blue-weak);
      }
      .suggestion[data-selected] .open,
      .suggestion[data-selected] .sub,
      .suggestion[data-selected] .glyph {
        color: #fff;
      }
      .suggestion[data-selected] .open:hover {
        background: transparent;
      }
      .body {
        display: flex;
        flex-direction: column;
        gap: 2px;
        min-width: 0;
      }
      .name {
        font-size: var(--vw-font-size-body);
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
      }
      .sub {
        font-size: 12px;
        color: var(--vw-muted);
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
      }
      .glyph {
        color: var(--vw-muted);
        display: inline-flex;
      }
      .glyph svg {
        width: 16px;
        height: 16px;
      }
    `,
  ];

  private emitFill(suggestion: TabAutofillSuggestion): void {
    if (!suggestion.target) return;
    this.dispatchEvent(
      new CustomEvent<SuggestionFillDetail>('vw-suggestion-fill', {
        detail: { cipherId: suggestion.id, target: suggestion.target },
        bubbles: true,
        composed: true,
      }),
    );
  }

  private emitOpen(cipherId: string): void {
    this.dispatchEvent(
      new CustomEvent<ItemOpenDetail>('vw-item-open', {
        detail: { cipherId },
        bubbles: true,
        composed: true,
      }),
    );
  }

  private renderFillBanner() {
    const { error, outcome } = this.fill;
    if (error !== undefined) {
      return html`<vw-status-message tone="danger" .icon=${'alert'} message=${error}></vw-status-message>`;
    }
    if (outcome !== undefined) {
      const { tone, message } = fillOutcomeMessage(outcome);
      return html`<vw-status-message tone=${tone} .icon=${tone === 'success' ? 'checkCircle' : 'alert'} message=${message}></vw-status-message>`;
    }
    return nothing;
  }

  private renderRow(suggestion: TabAutofillSuggestion) {
    const canFill = suggestion.target !== undefined && suggestion.reprompt !== true;
    const selected = suggestion.id === this.selectedCipherId;
    return html`
      <div class="suggestion" ?data-selected=${selected}>
        <button type="button" class="open" role="option" aria-selected=${selected ? 'true' : 'false'} data-open @click=${() => this.emitOpen(suggestion.id)}>
          <span class="glyph">${uiIcon('globe')}</span>
          <span class="body">
            <span class="name">${suggestion.name}</span>
            ${suggestion.username ? html`<span class="sub">${suggestion.username}</span>` : nothing}
            <span class="sub">${suggestion.matchedUri}</span>
          </span>
        </button>
        ${canFill
          ? html`<button type="button" class="button primary" data-fill @click=${() => this.emitFill(suggestion)}>${uiIcon('key')}<span>Fill</span></button>`
          : nothing}
      </div>
    `;
  }

  private renderState() {
    const state = this.state;
    switch (state.status) {
      case 'loading':
        return html`<vw-status-message tone="info" .icon=${'refresh'} message="Checking this page for logins…"></vw-status-message>`;
      case 'error':
        return html`<vw-status-message tone="danger" .icon=${'alert'} message=${state.message}></vw-status-message>`;
      case 'unavailable':
        return html`<vw-status-message tone="info" .icon=${'globe'} message=${unavailableMessage(state.reason)}></vw-status-message>`;
      case 'ready':
        return state.suggestions.length === 0
          ? html`<vw-status-message tone="info" .icon=${'search'} message="No matching logins for this page. Use All items to search your vault."></vw-status-message>`
          : html`<div class="list" role="listbox">${state.suggestions.map((s) => this.renderRow(s))}</div>`;
    }
  }

  protected override render() {
    return html`${this.renderFillBanner()}${this.renderState()}`;
  }
}

customElements.define('vw-suggestions-view', VwSuggestionsView);

declare global {
  interface HTMLElementTagNameMap {
    'vw-suggestions-view': VwSuggestionsView;
  }
}
