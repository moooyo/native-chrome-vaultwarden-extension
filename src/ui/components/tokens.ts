import { css } from 'lit';

export const themeTokens = css`
  :host {
    --vw-blue-800:#193f9e;
    --vw-blue-700:#2454c6;
    --vw-blue-600:#3267e3;
    --vw-blue-200:#cddaff;
    --vw-blue-100:#e7eeff;
    --vw-blue-50:#f4f7ff;
    --vw-canvas:#f6f8fb;
    --vw-panel:#fff;
    --vw-ink:#172033;
    --vw-muted:#677286;
    --vw-line:#dce2eb;
    --vw-ok:#187a59;
    --vw-danger:#b33b46;
    --vw-radius-control:8px;
    --vw-radius-group:10px;
    --vw-radius-shell:14px;
    --vw-focus:0 0 0 3px rgb(50 103 227 / 28%);
    --vw-font-ui:"Segoe UI Variable", -apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, sans-serif;
    --vw-font-mono:ui-monospace, "Cascadia Code", "SF Mono", Consolas, monospace;
    color: var(--vw-ink);
    font-family: var(--vw-font-ui);
  }
  @media (prefers-color-scheme:dark) {
    :host {
      --vw-canvas:#0f1420;
      --vw-panel:#171e2b;
      --vw-ink:#edf2fb;
      --vw-muted:#a9b3c4;
      --vw-line:#303a4c;
      --vw-blue-50:#182544;
      --vw-blue-100:#21345f;
      --vw-blue-200:#395a9e;
      --vw-blue-600:#79a2ff;
      --vw-blue-700:#9ab9ff;
      --vw-focus:0 0 0 3px rgb(121 162 255 / 38%);
    }
  }
  @media (prefers-reduced-motion:reduce) {
    :host { --vw-duration: 0ms; }
  }
`;
