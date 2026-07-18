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
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: 6px;
    min-height: 40px;
    padding: 0 18px;
    border: 1px solid transparent;
    border-radius: 20px;
    background: transparent;
    color: var(--vw-ink);
    font-family: var(--vw-font-ui);
    font-size: 13px;
    font-weight: 500;
    white-space: nowrap;
    cursor: pointer;
    transition: background-color var(--vw-dur-fast), border-color var(--vw-dur-fast), color var(--vw-dur-fast);
  }
  .btn:disabled { opacity: 0.5; cursor: default; }

  .btn.primary {
    background: var(--vw-primary-bg);
    color: var(--vw-primary-fg);
  }
  .btn.primary:hover:not(:disabled) { background: var(--vw-primary-bg-hover); }

  .btn.outline {
    border-color: var(--vw-line-3);
    background: var(--vw-card);
    color: var(--vw-text-4);
  }
  .btn.outline:hover:not(:disabled) { background: var(--vw-row-hover); }

  .btn.ghost { color: var(--vw-text-2); }
  .btn.ghost:hover:not(:disabled) { background: var(--vw-icon-hover); }

  .btn.danger {
    border-color: var(--vw-danger-border);
    background: var(--vw-card);
    color: var(--vw-danger);
  }
  .btn.danger:hover:not(:disabled) { background: var(--vw-danger-10); }

  /* Icon buttons --------------------------------------------------------------------------- */
  .icon-btn {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 40px;
    height: 40px;
    border: none;
    border-radius: 20px;
    background: transparent;
    color: var(--vw-text-2);
    cursor: pointer;
    transition: background-color var(--vw-dur-fast), color var(--vw-dur-fast);
  }
  .icon-btn:hover { background: var(--vw-icon-hover); }
  .icon-btn.sm { width: 26px; height: 26px; border-radius: var(--vw-radius-small); color: var(--vw-muted); }
  .icon-btn.xs { width: 24px; height: 24px; border-radius: var(--vw-radius-small); }
  .icon-btn svg { width: 15px; height: 15px; }
  .icon-btn.sm svg { width: 13px; height: 13px; }
  .icon-btn.xs svg { width: 13px; height: 13px; }

  /* Inputs --------------------------------------------------------------------------------- */
  .input {
    width: 100%;
    height: 44px;
    padding: 0 14px;
    border: 1px solid var(--vw-line-3);
    border-radius: 10px;
    background: var(--vw-card);
    color: var(--vw-ink);
    font-family: var(--vw-font-ui);
    font-size: 13px;
  }
  .input::placeholder { color: var(--vw-placeholder); }
  .input:focus { outline: none; border-color: var(--vw-accent); box-shadow: var(--vw-focus); }

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
    outline: none;
    box-shadow: var(--vw-focus);
  }

  /* Scrollbar ------------------------------------------------------------------------------ */
  .scroll { overflow-y: auto; scrollbar-width: thin; scrollbar-color: var(--vw-scrollbar) transparent; }
  .scroll::-webkit-scrollbar { width: 6px; }
  .scroll::-webkit-scrollbar-thumb {
    background: var(--vw-scrollbar);
    border-radius: 4px;
    border: 2px solid transparent;
    background-clip: content-box;
  }
  .scroll::-webkit-scrollbar-track { background: transparent; }
`;
