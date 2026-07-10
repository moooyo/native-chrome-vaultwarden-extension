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
    height: 32px;
    padding: 0 12px;
    border: 1px solid var(--vw-line);
    border-radius: var(--vw-radius-control);
    background: var(--vw-panel);
    color: var(--vw-ink);
    font-family: var(--vw-font-ui);
    font-size: 13px;
    cursor: pointer;
  }
  .button:hover {
    border-color: var(--vw-blue-200);
    background: var(--vw-blue-50);
  }
  .button.primary {
    border-color: var(--vw-blue-600);
    background: var(--vw-blue-600);
    color: #fff;
  }
  .button.primary:hover {
    border-color: var(--vw-blue-700);
    background: var(--vw-blue-700);
  }

  .icon-button {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 28px;
    height: 28px;
    border: none;
    border-radius: var(--vw-radius-control);
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
    height: 32px;
    padding: 0 8px;
    border: 1px solid var(--vw-line);
    border-radius: var(--vw-radius-control);
    background: var(--vw-panel);
    color: var(--vw-ink);
    font-family: var(--vw-font-ui);
    font-size: 13px;
  }
  .input:hover,
  .select:hover {
    border-color: var(--vw-blue-200);
  }

  .mono {
    font-family: var(--vw-font-mono);
  }

  :focus-visible {
    outline: none;
    box-shadow: var(--vw-focus);
    border-radius: var(--vw-radius-control);
  }
`;
