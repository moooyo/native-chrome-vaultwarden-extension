import { css } from 'lit';

/**
 * Shared control styling built only on the custom properties defined by
 * `themeTokens`. Components compose this alongside `themeTokens` in their
 * `static styles` array.
 */
export const controlStyles = css`
  .button {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: 6px;
    min-height: 34px;
    padding: 0 12px;
    border: 1px solid var(--vw-line);
    border-radius: var(--vw-radius-row);
    background: var(--vw-panel);
    color: var(--vw-ink);
    font-family: var(--vw-font-ui);
    font-size: var(--vw-font-size-body);
    font-weight: 600;
    letter-spacing: 0;
    white-space: nowrap;
    transition: background-color var(--vw-duration-fast), border-color var(--vw-duration-fast);
    cursor: pointer;
  }
  .button:hover {
    border-color: var(--vw-blue-200);
    background: var(--vw-blue-50);
  }
  .button.primary {
    border-color: var(--vw-blue);
    background: var(--vw-blue);
    color: #fff;
  }
  .button.primary:hover {
    border-color: var(--vw-blue-hover);
    background: var(--vw-blue-hover);
  }

  .icon-button {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 32px;
    height: 32px;
    border: none;
    border-radius: var(--vw-radius-row);
    background: transparent;
    color: var(--vw-muted);
    cursor: pointer;
  }
  .icon-button:hover {
    background: var(--vw-blue-50);
    color: var(--vw-blue-600);
  }

  .field {
    display: flex;
    flex-direction: column;
    gap: 4px;
  }

  .input,
  .select {
    min-height: 36px;
    padding: 0 8px;
    border: 1px solid var(--vw-line);
    border-radius: var(--vw-radius-row);
    background: var(--vw-panel);
    color: var(--vw-ink);
    font-family: var(--vw-font-ui);
    font-size: var(--vw-font-size-body);
    letter-spacing: 0;
  }
  .input:hover,
  .select:hover {
    border-color: var(--vw-blue-200);
  }

  .mono {
    font-family: var(--vw-font-mono);
  }

  .field-group {
    overflow: hidden;
    border: 1px solid var(--vw-line);
    border-radius: var(--vw-radius-row);
    background: var(--vw-panel);
  }

  .field-row {
    min-height: 52px;
    padding: var(--vw-space-xs) var(--vw-space-small);
    border-top: 1px solid var(--vw-line-weak);
  }

  .field-row:first-child {
    border-top: 0;
  }

  :focus-visible {
    outline: none;
    box-shadow: var(--vw-focus);
    border-radius: var(--vw-radius-row);
  }
`;
