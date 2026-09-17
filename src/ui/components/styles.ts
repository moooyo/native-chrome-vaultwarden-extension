import { css } from 'lit';

/**
 * Shared MiYu control styling, built only on the palette custom properties. Components compose this
 * alongside `themeTokens` and add their own pixel-level layout on top. Provides the recurring
 * patterns: ink/outline/ghost buttons, inputs, icon buttons, cards, the focus ring, and the themed
 * scrollbar. Bespoke, per-screen geometry stays in each component.
 */
export const controlStyles = css`
  /* Buttons -------------------------------------------------------------------------------- */
  .btn {
    appearance: none;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: 6px;
    min-height: 38px;
    max-width: 100%;
    padding: 8px 14px;
    border: 1px solid transparent;
    border-radius: var(--vw-radius-control);
    background: transparent;
    color: var(--vw-ink);
    font-family: var(--vw-font-ui);
    font-size: 13px;
    font-weight: 600;
    line-height: 1.4;
    text-align: center;
    cursor: pointer;
    transition: background-color var(--vw-dur-fast), border-color var(--vw-dur-fast), color var(--vw-dur-fast);
  }
  .btn:disabled {
    opacity: 1;
    color: var(--vw-disabled-fg);
    border-color: var(--vw-disabled-border);
    background: var(--vw-disabled-bg);
    box-shadow: none;
    cursor: default;
  }

  .btn.primary:not(:disabled) {
    background: var(--vw-primary-bg);
    color: var(--vw-primary-fg);
  }
  .btn.primary:hover:not(:disabled) { background: var(--vw-primary-bg-hover); }

  .btn.outline:not(:disabled) {
    border-color: var(--vw-line-3);
    background: var(--vw-card);
    color: var(--vw-text-2);
  }
  .btn.outline:hover:not(:disabled) { background: var(--vw-row-hover); }

  .btn.ghost:not(:disabled) { color: var(--vw-text-2); }
  .btn.ghost:hover:not(:disabled) { background: var(--vw-icon-hover); }

  .btn.danger:not(:disabled) {
    border-color: var(--vw-danger-border);
    background: var(--vw-card);
    color: var(--vw-danger);
  }
  .btn.danger:hover:not(:disabled) { background: var(--vw-danger-10); }

  /* Icon buttons --------------------------------------------------------------------------- */
  .icon-btn {
    appearance: none;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
    width: 34px;
    height: 34px;
    padding: 0;
    border: none;
    border-radius: var(--vw-radius-control);
    background: transparent;
    color: var(--vw-text-2);
    cursor: pointer;
    transition: background-color var(--vw-dur-fast), color var(--vw-dur-fast);
  }
  .icon-btn:hover:not(:disabled) { background: var(--vw-icon-hover); }
  .icon-btn:disabled { color: var(--vw-disabled-fg); cursor: default; }
  .icon-btn.sm { width: 26px; height: 26px; border-radius: var(--vw-radius-small); color: var(--vw-muted); }
  .icon-btn.xs { width: 24px; height: 24px; border-radius: var(--vw-radius-small); }
  .icon-btn svg { width: 15px; height: 15px; }
  .icon-btn.sm svg { width: 13px; height: 13px; }
  .icon-btn.xs svg { width: 13px; height: 13px; }

  /* Inputs --------------------------------------------------------------------------------- */
  .input {
    width: 100%;
    min-width: 0;
    height: 40px;
    padding: 9px 11px;
    border: 1px solid var(--vw-line-3);
    border-radius: var(--vw-radius-input);
    background: var(--vw-card);
    color: var(--vw-ink);
    font-family: var(--vw-font-ui);
    font-size: 14px;
    line-height: 1.5;
    transition: border-color var(--vw-dur-fast), box-shadow var(--vw-dur-fast);
  }
  .input::placeholder { color: var(--vw-placeholder); }
  .input:focus { outline: none; border-color: var(--vw-accent); box-shadow: var(--vw-focus); }
  .input:disabled { color: var(--vw-disabled-fg); background: var(--vw-disabled-bg); cursor: default; }
  .input[readonly] { background: var(--vw-fill-2); color: var(--vw-text-2); }
  .input[aria-invalid='true'] { border-color: var(--vw-danger); }
  textarea.input { height: auto; min-height: 96px; resize: vertical; }

  .input.bordered {
    background: var(--vw-card);
    border-color: var(--vw-line-3);
  }

  /* Surfaces ------------------------------------------------------------------------------- */
  .card {
    background: var(--vw-card);
    border: 1px solid var(--vw-line-1);
    border-radius: var(--vw-radius-card);
  }
  .mono { font-family: var(--vw-font-mono); }

  /* Focus ---------------------------------------------------------------------------------- */
  :focus-visible {
    outline: 2px solid var(--vw-accent);
    outline-offset: 2px;
  }

  /* Scrollbar ------------------------------------------------------------------------------ */
  .scroll { overflow-y: auto; overscroll-behavior: contain; scrollbar-width: thin; scrollbar-color: var(--vw-scrollbar) transparent; }
  .scroll::-webkit-scrollbar { width: 6px; }
  .scroll::-webkit-scrollbar-thumb {
    background: var(--vw-scrollbar);
    border-radius: 4px;
    border: 2px solid transparent;
    background-clip: content-box;
  }
  .scroll::-webkit-scrollbar-track { background: transparent; }

  @media (prefers-reduced-motion: no-preference) {
    .btn:active:not(:disabled) { transform: translateY(1px); }
  }
  @media (prefers-reduced-motion: reduce) {
    .btn, .icon-btn, .input { transition: none; }
  }
`;
