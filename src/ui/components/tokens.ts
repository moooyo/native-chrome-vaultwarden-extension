import { css } from 'lit';

/**
 * Chrome-native Material 3 tokens from the new design handoff.
 *
 * The `--vw-*` aliases remain the component contract, while the canonical short names preserve the
 * exact handoff values. Page roots own these values and child shadow trees inherit them.
 */
export const paletteTokens = css`
  :host {
    color-scheme: light;
    --p:#0b57d0;
    --onp:#ffffff;
    --pc:#d3e3fd;
    --onpc:#041e49;
    --bg:#e8eef7;
    --sf:#ffffff;
    --sfcl:#f8fafd;
    --sfc:#f0f4f9;
    --sfch:#e9eef6;
    --sfhi:#dde3ea;
    --txt:#1f1f1f;
    --txt2:#474747;
    --otl:#747775;
    --otlv:#c4c7c5;
    --hov:rgba(31,31,31,.07);
    --err:#b3261e;
    --grn:#146c2e;
    --inv:#322f35;
    --oninv:#f5eff7;
    --veil:rgba(248,250,253,.55);

    --vw-ink:var(--txt);
    --vw-ink-hover:#303030;
    --vw-text-2:var(--txt2);
    --vw-text-3:#5f6368;
    --vw-text-4:var(--txt);
    --vw-muted:#747775;
    --vw-faint:#80868b;
    --vw-teal-solid:var(--p);
    --vw-accent:var(--p);
    --vw-teal-text:var(--p);
    --vw-teal-10:rgba(11,87,208,.10);
    --vw-teal-12:rgba(11,87,208,.12);
    --vw-teal-18:rgba(11,87,208,.18);
    --vw-teal-25:rgba(11,87,208,.25);
    --vw-panel:var(--sf);
    --vw-options-bg:var(--sfcl);
    --vw-card:var(--sf);
    --vw-fill:var(--sfc);
    --vw-fill-2:var(--sfcl);
    --vw-row-hover:var(--hov);
    --vw-icon-hover:var(--hov);
    --vw-line-1:var(--sfch);
    --vw-line-2:#dde3ea;
    --vw-line-3:var(--otlv);
    --vw-card-border:var(--sfch);
    --vw-primary-bg:var(--p);
    --vw-primary-bg-hover:#0842a0;
    --vw-primary-fg:var(--onp);
    --vw-danger:var(--err);
    --vw-danger-border:rgba(179,38,30,.32);
    --vw-danger-10:rgba(179,38,30,.08);
    --vw-sync-amber:#b06000;
    --vw-chevron:var(--otl);
    --vw-toggle-on:var(--p);
    --vw-toggle-off:var(--sfhi);
    --vw-track:var(--sfhi);
    --vw-scrollbar:rgba(71,71,71,.30);
    --vw-placeholder:#747775;
    --vw-strength-strong:var(--grn);
    --vw-strength-good:#3c7d23;
    --vw-strength-mid:#b06000;
    --vw-strength-weak:var(--err);
    --vw-gen-digit:var(--p);
    --vw-gen-symbol:#c2185b;
    --vw-font-ui:'Roboto','Segoe UI',system-ui,sans-serif;
    --vw-font-mono:'Roboto Mono','Cascadia Mono',ui-monospace,monospace;
    --vw-radius-dialog:20px;
    --vw-radius-panel:16px;
    --vw-radius-pill:999px;
    --vw-radius-card:16px;
    --vw-radius-control:12px;
    --vw-radius-input:10px;
    --vw-radius-chip:8px;
    --vw-radius-small:8px;
    --vw-radius-xs:6px;
    --vw-popup-shadow:0 6px 20px rgba(0,0,0,.14);
    --vw-panel-shadow:0 8px 28px rgba(0,0,0,.20);
    --vw-dialog-shadow:0 -4px 24px rgba(0,0,0,.18);
    --vw-card-shadow:none;
    --vw-knob-shadow:0 1px 2px rgba(0,0,0,.24);
    --vw-seg-shadow:0 1px 2px rgba(0,0,0,.16);
    --vw-dur-fast:150ms;
    --vw-dur:220ms;
    --vw-focus:0 0 0 3px rgba(11,87,208,.28);
  }

  :host([data-theme='dark']) {
    color-scheme:dark;
    --p:#a8c7fa;
    --onp:#062e6f;
    --pc:#0842a0;
    --onpc:#d3e3fd;
    --bg:#131314;
    --sf:#1f1f1f;
    --sfcl:#1a1a1a;
    --sfc:#242526;
    --sfch:#2b2c2e;
    --sfhi:#37393b;
    --txt:#e3e3e3;
    --txt2:#c4c7c5;
    --otl:#8e918f;
    --otlv:#47494c;
    --hov:rgba(227,227,227,.09);
    --err:#f2b8b5;
    --grn:#6dd58c;
    --inv:#e3e3e3;
    --oninv:#1f1f1f;
    --veil:rgba(19,19,20,.55);
    --vw-ink-hover:#ffffff;
    --vw-text-3:#aeb1b0;
    --vw-muted:#aeb1b0;
    --vw-faint:#8e918f;
    --vw-teal-10:rgba(168,199,250,.12);
    --vw-teal-12:rgba(168,199,250,.16);
    --vw-teal-18:rgba(168,199,250,.22);
    --vw-teal-25:rgba(168,199,250,.30);
    --vw-line-2:#37393b;
    --vw-primary-bg-hover:#d3e3fd;
    --vw-danger-border:rgba(242,184,181,.32);
    --vw-danger-10:rgba(242,184,181,.10);
    --vw-sync-amber:#ffb95c;
    --vw-scrollbar:rgba(227,227,227,.24);
    --vw-placeholder:#9aa0a6;
    --vw-strength-good:var(--grn);
    --vw-strength-mid:#ffb95c;
    --vw-gen-symbol:#ff8ab5;
    --vw-popup-shadow:0 6px 22px rgba(0,0,0,.50);
    --vw-focus:0 0 0 3px rgba(168,199,250,.30);
  }

  @media (prefers-color-scheme: dark) {
    :host([data-theme='system']) {
      color-scheme:dark;
      --p:#a8c7fa;
      --onp:#062e6f;
      --pc:#0842a0;
      --onpc:#d3e3fd;
      --bg:#131314;
      --sf:#1f1f1f;
      --sfcl:#1a1a1a;
      --sfc:#242526;
      --sfch:#2b2c2e;
      --sfhi:#37393b;
      --txt:#e3e3e3;
      --txt2:#c4c7c5;
      --otl:#8e918f;
      --otlv:#47494c;
      --hov:rgba(227,227,227,.09);
      --err:#f2b8b5;
      --grn:#6dd58c;
      --inv:#e3e3e3;
      --oninv:#1f1f1f;
      --veil:rgba(19,19,20,.55);
      --vw-ink-hover:#ffffff;
      --vw-text-3:#aeb1b0;
      --vw-muted:#aeb1b0;
      --vw-faint:#8e918f;
      --vw-teal-10:rgba(168,199,250,.12);
      --vw-teal-12:rgba(168,199,250,.16);
      --vw-teal-18:rgba(168,199,250,.22);
      --vw-teal-25:rgba(168,199,250,.30);
      --vw-line-2:#37393b;
      --vw-primary-bg-hover:#d3e3fd;
      --vw-danger-border:rgba(242,184,181,.32);
      --vw-danger-10:rgba(242,184,181,.10);
      --vw-sync-amber:#ffb95c;
      --vw-scrollbar:rgba(227,227,227,.24);
      --vw-placeholder:#9aa0a6;
      --vw-strength-good:var(--grn);
      --vw-strength-mid:#ffb95c;
      --vw-gen-symbol:#ff8ab5;
      --vw-popup-shadow:0 6px 22px rgba(0,0,0,.50);
      --vw-focus:0 0 0 3px rgba(168,199,250,.30);
    }
  }

  @keyframes mvIn { from { opacity:0; } to { opacity:1; } }
  @keyframes mvUp { from { opacity:0; transform:translate(-50%,10px); } to { opacity:1; transform:translate(-50%,0); } }
  @keyframes mvGrow { from { opacity:0; transform:translateY(-4px); } to { opacity:1; transform:none; } }
  @keyframes mvStag { from { opacity:0; transform:translateY(5px); } to { opacity:1; transform:none; } }
  @keyframes mvPop { 0% { transform:scale(.4); opacity:0; } 70% { transform:scale(1.12); } 100% { transform:scale(1); opacity:1; } }
  @keyframes mvPulse { 0% { box-shadow:0 0 0 0 rgba(11,87,208,.35); } 70% { box-shadow:0 0 0 12px rgba(11,87,208,0); } 100% { box-shadow:0 0 0 0 rgba(11,87,208,0); } }
  @keyframes mvSheet { from { transform:translateY(60px); opacity:0; } to { transform:translateY(0); opacity:1; } }
  @keyframes mvFly { from { transform:translateX(-12px); opacity:0; } to { transform:translateX(0); opacity:1; } }
  @keyframes mvSpin { to { transform:rotate(360deg); } }

  @media (prefers-reduced-motion: reduce) {
    :host { --vw-dur-fast:0ms; --vw-dur:0ms; }
    *, *::before, *::after { animation:none !important; scroll-behavior:auto !important; }
  }
`;

export const themeTokens = css`
  :host {
    color:var(--vw-ink);
    font-family:var(--vw-font-ui);
    font-size:13px;
    line-height:1.45;
    -webkit-font-smoothing:antialiased;
    text-rendering:optimizeLegibility;
  }
  *, *::before, *::after { box-sizing:border-box; }
`;
