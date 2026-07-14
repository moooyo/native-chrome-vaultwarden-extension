import { LitElement, css, html, nothing, type PropertyValues } from 'lit';
import { themeTokens } from './tokens.js';
import { controlStyles } from './styles.js';
import { emit } from './emit.js';

export type DialogCloseReason = 'escape' | 'backdrop' | 'dismiss' | string;

/**
 * A dormant modal wrapper around the native <dialog> element.
 *
 * - `cancelable` (default true) controls whether Escape, a backdrop click,
 *   or the built-in dismiss button can close the dialog implicitly. In
 *   "destructive" (non-cancelable) mode those implicit paths are blocked,
 *   but callers can still close it explicitly via `requestClose(reason)`
 *   from their own slotted action buttons.
 * - Initial focus goes to the slotted `[autofocus]` element, falling back
 *   to the built-in dismiss button, then the dialog surface itself.
 * - The previously focused element is restored when the dialog closes.
 */
export class VwDialog extends LitElement {
  static override properties = {
    open: { type: Boolean },
    heading: { type: String },
    cancelable: { type: Boolean },
  };

  declare open: boolean;
  declare heading: string;
  declare cancelable: boolean;

  private previouslyFocused: HTMLElement | null = null;
  private pendingCloseReason: DialogCloseReason | null = null;

  constructor() {
    super();
    this.open = false;
    this.heading = '';
    this.cancelable = true;
  }

  static override styles = [
    themeTokens,
    controlStyles,
    css`
      dialog {
        border: none;
        border-radius: var(--vw-radius-shell);
        padding: 0;
        background: var(--vw-panel);
        color: var(--vw-ink);
        max-width: min(90vw, 420px);
      }
      dialog::backdrop {
        background: rgb(15 20 32 / 45%);
      }
      .surface {
        display: flex;
        flex-direction: column;
        gap: 12px;
        padding: 16px;
      }
      .dialog-header {
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 12px;
      }
      .dialog-header h2 {
        margin: 0;
        font-size: 15px;
      }
      .dialog-actions {
        display: flex;
        justify-content: flex-end;
        gap: 8px;
      }
    `,
  ];

  private readonly handleDocumentFocusIn = (event: FocusEvent): void => {
    if (!this.open) {
      return;
    }
    const target = event.target;
    if (target instanceof Node && !this.contains(target)) {
      this.focusInitialTarget();
    }
  };

  private readonly handleKeydown = (event: KeyboardEvent): void => {
    if (event.key === 'Escape') {
      event.preventDefault();
      this.requestClose('escape');
    }
  };

  private readonly handleNativeCancel = (event: Event): void => {
    event.preventDefault();
    this.requestClose('escape');
  };

  private readonly handleNativeClose = (): void => {
    document.removeEventListener('focusin', this.handleDocumentFocusIn);
    this.open = false;
    this.restoreFocus();
    const reason = this.pendingCloseReason ?? 'dismiss';
    this.pendingCloseReason = null;
    emit(this, 'vw-dialog-close', { reason });
  };

  private readonly handleBackdropClick = (event: MouseEvent): void => {
    if (event.target === this.dialogElement) {
      this.requestClose('backdrop');
    }
  };

  override connectedCallback(): void {
    super.connectedCallback();
    this.addEventListener('keydown', this.handleKeydown);
  }

  override disconnectedCallback(): void {
    super.disconnectedCallback();
    this.removeEventListener('keydown', this.handleKeydown);
    document.removeEventListener('focusin', this.handleDocumentFocusIn);
  }

  private get dialogElement(): HTMLDialogElement | null {
    return this.renderRoot.querySelector('dialog');
  }

  /**
   * Requests that the dialog close for the given reason. Implicit reasons
   * (escape/backdrop/dismiss) are ignored while `cancelable` is false;
   * any other caller-supplied reason (e.g. 'confirm') always closes it.
   */
  requestClose(reason: DialogCloseReason): void {
    const implicit = reason === 'escape' || reason === 'backdrop' || reason === 'dismiss';
    if (implicit && !this.cancelable) {
      return;
    }
    const dialogEl = this.dialogElement;
    if (!dialogEl || !dialogEl.open) {
      return;
    }
    this.pendingCloseReason = reason;
    dialogEl.close();
  }

  private focusInitialTarget(): void {
    const autofocusTarget = this.querySelector<HTMLElement>('[autofocus]');
    const dismissButton = this.renderRoot.querySelector<HTMLElement>('.dialog-dismiss');
    const target = autofocusTarget ?? dismissButton ?? this.dialogElement;
    target?.focus();
  }

  private restoreFocus(): void {
    const target = this.previouslyFocused;
    this.previouslyFocused = null;
    if (target && document.contains(target)) {
      target.focus();
    }
  }

  protected override updated(changed: PropertyValues<this>): void {
    if (!changed.has('open')) {
      return;
    }
    const dialogEl = this.dialogElement;
    if (this.open) {
      this.previouslyFocused = document.activeElement instanceof HTMLElement ? document.activeElement : null;
      if (dialogEl && !dialogEl.open) {
        dialogEl.showModal();
      }
      this.focusInitialTarget();
      document.addEventListener('focusin', this.handleDocumentFocusIn);
    } else {
      if (dialogEl?.open) {
        dialogEl.close();
      }
      document.removeEventListener('focusin', this.handleDocumentFocusIn);
    }
  }

  protected override render() {
    return html`
      <dialog
        tabindex="-1"
        aria-labelledby="vw-dialog-heading"
        @cancel=${this.handleNativeCancel}
        @close=${this.handleNativeClose}
        @click=${this.handleBackdropClick}
      >
        <div class="surface">
          <div class="dialog-header">
            <h2 id="vw-dialog-heading">${this.heading}</h2>
            ${this.cancelable
              ? html`
                  <button
                    type="button"
                    class="icon-button dialog-dismiss"
                    aria-label="Close"
                    @click=${() => this.requestClose('dismiss')}
                  >
                    ×
                  </button>
                `
              : nothing}
          </div>
          <div class="dialog-body"><slot></slot></div>
          <div class="dialog-actions"><slot name="actions"></slot></div>
        </div>
      </dialog>
    `;
  }
}

customElements.define('vw-dialog', VwDialog);

declare global {
  interface HTMLElementTagNameMap {
    'vw-dialog': VwDialog;
  }
}
