import { css } from 'lit';

export const themeTokens = css`
  :host {
    --vw-popup-double-width:600px;
    --vw-popup-single-width:350px;
    --vw-popup-height:450px;
    --vw-pane-list-width:260px;
    --vw-pane-detail-width:340px;
    --vw-ink-strong:#090a0c;
    --vw-ink:rgb(0 0 0 / 82%);
    --vw-muted:rgb(0 0 0 / 62%);
    --vw-disabled:rgb(0 0 0 / 36%);
    --vw-panel:#fff;
    --vw-canvas:#fafafa;
    --vw-blue:hsl(212 96% 47%);
    --vw-blue-hover:hsl(216 100% 39%);
    --vw-blue-pressed:hsl(224 100% 33%);
    --vw-blue-text:hsl(212 100% 35%);
    --vw-blue-weak:hsl(214 100% 96%);
    --vw-row-selected:hsl(215 100% 94%);
    --vw-line:rgb(0 0 0 / 13%);
    --vw-line-weak:rgb(0 0 0 / 7%);
    --vw-ok:hsl(116 100% 20%);
    --vw-warning:hsl(42 100% 22%);
    --vw-danger:hsl(14 100% 32%);
    --vw-radius-small:4px;
    --vw-radius-row:8px;
    --vw-radius-large:12px;
    --vw-space-2xs:4px;
    --vw-space-xs:8px;
    --vw-space-small:12px;
    --vw-space-medium:16px;
    --vw-space-large:24px;
    --vw-space-xl:32px;
    --vw-font-size-title:20px;
    --vw-font-size-view:16px;
    --vw-font-size-body:14px;
    --vw-font-size-meta:12px;
    --vw-duration-fast:75ms;
    --vw-duration-normal:175ms;
    --vw-focus:0 0 0 2px hsl(215 63% 53%);
    --vw-font-ui:"Segoe UI Variable Text", "Segoe UI Variable", "Segoe UI", system-ui, sans-serif;
    --vw-font-mono:"Cascadia Code", Consolas, ui-monospace, monospace;

    /* Transitional aliases keep existing components coherent while they migrate. */
    --vw-blue-800:var(--vw-blue-pressed);
    --vw-blue-700:var(--vw-blue-hover);
    --vw-blue-600:var(--vw-blue);
    --vw-blue-200:hsl(215 84% 76%);
    --vw-blue-100:var(--vw-row-selected);
    --vw-blue-50:var(--vw-blue-weak);
    --vw-radius-control:var(--vw-radius-row);
    --vw-radius-group:var(--vw-radius-row);
    --vw-radius-shell:var(--vw-radius-large);
    --vw-duration:var(--vw-duration-normal);
    color:var(--vw-ink);
    font-family:var(--vw-font-ui);
    font-size:var(--vw-font-size-body);
  }
  @media (prefers-color-scheme:dark) {
    :host {
      --vw-ink-strong:#fff;
      --vw-ink:rgb(255 255 255 / 89%);
      --vw-muted:rgb(255 255 255 / 78.5%);
      --vw-disabled:rgb(255 255 255 / 56%);
      --vw-panel:hsl(0 0% 13%);
      --vw-canvas:hsl(0 0% 8%);
      --vw-blue-text:hsl(215 100% 85%);
      --vw-blue-weak:hsl(227 40% 16%);
      --vw-row-selected:hsl(214 100% 16%);
      --vw-line:rgb(255 255 255 / 28%);
      --vw-line-weak:rgb(255 255 255 / 9%);
      --vw-blue-200:hsl(215 63% 53%);
      --vw-focus:0 0 0 2px hsl(215 84% 76%);
    }
  }
  @media (prefers-reduced-motion:reduce) {
    :host {
      --vw-duration-fast:0ms;
      --vw-duration-normal:0ms;
      --vw-duration:0ms;
    }
  }
`;
