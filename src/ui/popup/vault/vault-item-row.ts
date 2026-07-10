import { LitElement, css, html, nothing } from 'lit';
import { themeTokens } from '../../components/tokens.js';
import { controlStyles } from '../../components/styles.js';
import { uiIcon, type IconName } from '../../components/icon.js';
import type { CipherSummary } from '../../../core/vault/models.js';
import type { ItemOpenDetail } from '../types.js';

/** Human labels for each cipher type. Non-secret, static mapping. */
const TYPE_LABELS: Record<1 | 2 | 3 | 4 | 5, string> = {
  1: 'Login',
  2: 'Secure note',
  3: 'Card',
  4: 'Identity',
  5: 'SSH key',
};

const TYPE_ICONS: Record<1 | 2 | 3 | 4 | 5, IconName> = {
  1: 'key',
  2: 'note',
  3: 'card',
  4: 'idcard',
  5: 'key',
};

/**
 * A shared, presentational vault row. It renders only the non-secret fields of a `CipherSummary`
 * (name, a subtitle drawn from username/URI/subtitle, favorite/type markers) and emits
 * `vw-item-open` with the cipher id when activated. It never receives or renders passwords, TOTP,
 * or any secret; the id is passed only through the typed event, never into an HTML attribute.
 */
export class VwVaultItemRow extends LitElement {
  static override properties = {
    item: { attribute: false },
    selected: { type: Boolean },
  };

  declare item: CipherSummary;
  declare selected: boolean;

  constructor() {
    super();
    this.selected = false;
  }

  static override styles = [
    themeTokens,
    controlStyles,
    css`
      :host {
        display: block;
      }
      .row {
        display: flex;
        align-items: center;
        gap: 10px;
        width: 100%;
        min-height: 52px;
        padding: 4px 8px;
        border: none;
        border-radius: var(--vw-radius-control);
        background: transparent;
        color: var(--vw-ink);
        font-family: var(--vw-font-ui);
        text-align: left;
        cursor: pointer;
      }
      .row:hover {
        background: var(--vw-blue-weak);
      }
      .row[data-selected] {
        background: var(--vw-blue);
        color: #fff;
      }
      .row[data-selected] .sub,
      .row[data-selected] .type,
      .row[data-selected] .chevron,
      .row[data-selected] .type-glyph {
        color: rgb(255 255 255 / 85%);
      }
      .body {
        display: flex;
        flex-direction: column;
        gap: 2px;
        min-width: 0;
        flex: 1;
      }
      .name {
        display: flex;
        align-items: center;
        gap: 6px;
        font-size: var(--vw-font-size-body);
      }
      .title {
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
      }
      .fav {
        color: var(--vw-blue-600);
        display: inline-flex;
      }
      .fav svg {
        width: 14px;
        height: 14px;
      }
      .sub {
        font-size: var(--vw-font-size-meta);
        color: var(--vw-muted);
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
      }
      .type {
        font-size: 11px;
        color: var(--vw-muted);
      }
      .tag {
        font-size: 11px;
        color: var(--vw-danger);
      }
      .chevron {
        color: var(--vw-muted);
        display: inline-flex;
      }
      .chevron svg,
      .type-glyph svg {
        width: 16px;
        height: 16px;
      }
      .type-glyph {
        color: var(--vw-muted);
        display: inline-flex;
      }
    `,
  ];

  private open(): void {
    this.dispatchEvent(
      new CustomEvent<ItemOpenDetail>('vw-item-open', {
        detail: { cipherId: this.item.id },
        bubbles: true,
        composed: true,
      }),
    );
  }

  private onKeyDown(event: KeyboardEvent): void {
    if (event.key !== 'Enter' && event.key !== ' ') return;
    event.preventDefault();
    this.open();
  }

  protected override render() {
    const item = this.item;
    const subtitle = item.username ?? item.uris[0] ?? item.subtitle ?? '';
    const label = TYPE_LABELS[item.type];
    return html`
      <button
        type="button"
        class="row"
        role="option"
        aria-selected=${this.selected ? 'true' : 'false'}
        ?data-selected=${this.selected}
        @click=${() => this.open()}
        @keydown=${(event: KeyboardEvent) => this.onKeyDown(event)}
      >
        <span class="type-glyph">${uiIcon(TYPE_ICONS[item.type])}</span>
        <span class="body">
          <span class="name">
            ${item.favorite ? html`<span class="fav" data-favorite title="Favorite">${uiIcon('star')}</span>` : nothing}
            <span class="title">${item.name}</span>
            ${item.undecryptable ? html`<span class="tag">Undecryptable</span>` : nothing}
          </span>
          <span class="sub">
            <span class="type">${label}</span>${subtitle ? html` · ${subtitle}` : nothing}
          </span>
        </span>
        <span class="chevron">${uiIcon('chevron')}</span>
      </button>
    `;
  }
}

customElements.define('vw-vault-item-row', VwVaultItemRow);

declare global {
  interface HTMLElementTagNameMap {
    'vw-vault-item-row': VwVaultItemRow;
  }
}
