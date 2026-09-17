import { css } from 'lit';

/**
 * Blue-and-white foundations from the final MiYu design handoff.
 *
 * The `--vw-*` aliases remain the component contract, while the canonical short names preserve the
 * exact handoff values. Page roots own these values and child shadow trees inherit them.
 */
export const paletteTokens = css`
  :host {
    color-scheme: light;
    --p:#155ed7;
    --onp:#ffffff;
    --pc:#edf4ff;
    --onpc:#1859b3;
    --bg:#f6f9fd;
    --sf:#ffffff;
    --sfcl:#f7faff;
    --sfc:#f1f6fd;
    --sfch:#e9eff6;
    --sfhi:#dbe4ef;
    --txt:#192d48;
    --txt2:#526780;
    --otl:#7189a5;
    --otlv:#d2deec;
    --hov:#f1f6fd;
    --err:#aa3949;
    --grn:#267451;
    --inv:#1c3555;
    --oninv:#ffffff;
    --veil:rgba(36,59,89,.18);

    --vw-ink:var(--txt);
    --vw-ink-hover:#102746;
    --vw-text-2:var(--txt2);
    --vw-text-3:#5d748f;
    --vw-text-4:var(--txt);
    --vw-muted:#657b94;
    --vw-faint:#73849b;
    --vw-teal-solid:var(--p);
    --vw-accent:var(--p);
    --vw-teal-text:var(--p);
    --vw-teal-10:rgba(21,94,215,.08);
    --vw-teal-12:rgba(21,94,215,.12);
    --vw-teal-18:rgba(21,94,215,.18);
    --vw-teal-25:rgba(21,94,215,.25);
    --vw-panel:var(--sf);
    --vw-options-bg:var(--sfcl);
    --vw-card:var(--sf);
    --vw-fill:var(--sfc);
    --vw-fill-2:var(--sfcl);
    --vw-row-hover:var(--hov);
    --vw-icon-hover:var(--hov);
    --vw-line-1:var(--sfch);
    --vw-line-2:#dbe4ef;
    --vw-line-3:var(--otlv);
    --vw-card-border:var(--sfch);
    --vw-primary-bg:var(--p);
    --vw-primary-bg-hover:#0d4faf;
    --vw-primary-fg:var(--onp);
    --vw-danger:var(--err);
    --vw-danger-border:#f0d5dc;
    --vw-danger-10:#fff4f5;
    --vw-sync-amber:#966525;
    --vw-chevron:var(--otl);
    --vw-toggle-on:var(--p);
    --vw-toggle-off:var(--otl);
    --vw-track:var(--sfhi);
    --vw-scrollbar:#c1d1e4;
    --vw-placeholder:#73849b;
    --vw-strength-strong:var(--grn);
    --vw-strength-good:#387452;
    --vw-strength-mid:#966525;
    --vw-strength-weak:var(--err);
    --vw-gen-digit:var(--p);
    --vw-gen-symbol:#9b4068;
    --vw-font-ui:'Instrument Sans','Noto Sans SC','Microsoft YaHei UI','Segoe UI',system-ui,sans-serif;
    --vw-font-mono:'JetBrains Mono','Cascadia Mono',ui-monospace,monospace;
    --vw-radius-dialog:12px;
    --vw-radius-shell:var(--vw-radius-dialog);
    --vw-radius-panel:12px;
    --vw-radius-pill:999px;
    --vw-radius-card:10px;
    --vw-radius-control:8px;
    --vw-radius-input:8px;
    --vw-radius-chip:5px;
    --vw-radius-small:8px;
    --vw-radius-xs:6px;
    --vw-popup-shadow:0 12px 32px rgba(24,56,87,.08),0 2px 6px rgba(24,56,87,.03);
    --vw-panel-shadow:0 12px 32px rgba(24,56,87,.08),0 2px 6px rgba(24,56,87,.03);
    --vw-dialog-shadow:0 16px 40px rgba(24,56,87,.12),0 2px 8px rgba(24,56,87,.06);
    --vw-card-shadow:none;
    --vw-knob-shadow:0 1px 2px rgba(24,56,87,.18);
    --vw-seg-shadow:0 1px 3px rgba(24,56,87,.08);
    --vw-dur-fast:140ms;
    --vw-dur:180ms;
    --vw-ease:cubic-bezier(.2,.8,.2,1);
    --vw-focus:0 0 0 3px rgba(21,94,215,.18);
    --vw-disabled-bg:#edf2f8;
    --vw-disabled-fg:#73849b;
    --vw-disabled-border:#e0e7f0;

    /* Density is a page-root preference. These inherited layout tokens let nested shadow trees
     * tighten repeated rows without shrinking type or the primary controls themselves. */
    --vw-list-row-min:46px;
    --vw-list-row-padding-block:5px;
    --vw-totp-row-min:50px;
    --vw-totp-row-padding-block:7px;
    --vw-command-row-min:46px;
    --vw-setting-row-min:68px;
    --vw-setting-row-padding-block:13px;
    --vw-setting-stack-gap:12px;
  }

  :host([data-density='compact']) {
    --vw-list-row-min:40px;
    --vw-list-row-padding-block:4px;
    --vw-totp-row-min:40px;
    --vw-totp-row-padding-block:4px;
    --vw-command-row-min:40px;
    --vw-setting-row-min:56px;
    --vw-setting-row-padding-block:8px;
    --vw-setting-stack-gap:8px;
  }

  :host([data-theme='dark']) {
    color-scheme:dark;
    --p:#91b9ff;
    --onp:#102746;
    --pc:#213a60;
    --onpc:#bbd3ff;
    --bg:#101923;
    --sf:#162230;
    --sfcl:#131e2b;
    --sfc:#1b2b3d;
    --sfch:#25374b;
    --sfhi:#31485f;
    --txt:#e3ecf8;
    --txt2:#b1c2d7;
    --otl:#91a7c1;
    --otlv:#405874;
    --hov:#213247;
    --err:#f0a9b3;
    --grn:#8bd0aa;
    --inv:#dce9fa;
    --oninv:#162230;
    --veil:rgba(5,14,26,.58);
    --vw-ink-hover:#ffffff;
    --vw-text-3:#a1b6ce;
    --vw-muted:#91a7c1;
    --vw-faint:#8196ae;
    --vw-teal-10:rgba(145,185,255,.12);
    --vw-teal-12:rgba(145,185,255,.16);
    --vw-teal-18:rgba(145,185,255,.22);
    --vw-teal-25:rgba(145,185,255,.30);
    --vw-line-2:#31485f;
    --vw-primary-bg-hover:#bbd3ff;
    --vw-danger-border:rgba(240,169,179,.32);
    --vw-danger-10:rgba(240,169,179,.10);
    --vw-sync-amber:#ffb95c;
    --vw-scrollbar:#405874;
    --vw-placeholder:#91a7c1;
    --vw-strength-good:var(--grn);
    --vw-strength-mid:#ffb95c;
    --vw-gen-symbol:#ff8ab5;
    --vw-popup-shadow:0 12px 32px rgba(0,0,0,.32);
    --vw-panel-shadow:0 12px 32px rgba(0,0,0,.32);
    --vw-dialog-shadow:0 16px 40px rgba(0,0,0,.42);
    --vw-focus:0 0 0 3px rgba(145,185,255,.28);
    --vw-disabled-bg:#253447;
    --vw-disabled-fg:#8196ae;
    --vw-disabled-border:#31485f;
  }

  @media (prefers-color-scheme: dark) {
    :host([data-theme='system']) {
      color-scheme:dark;
      --p:#91b9ff;
      --onp:#102746;
      --pc:#213a60;
      --onpc:#bbd3ff;
      --bg:#101923;
      --sf:#162230;
      --sfcl:#131e2b;
      --sfc:#1b2b3d;
      --sfch:#25374b;
      --sfhi:#31485f;
      --txt:#e3ecf8;
      --txt2:#b1c2d7;
      --otl:#91a7c1;
      --otlv:#405874;
      --hov:#213247;
      --err:#f0a9b3;
      --grn:#8bd0aa;
      --inv:#dce9fa;
      --oninv:#162230;
      --veil:rgba(5,14,26,.58);
      --vw-ink-hover:#ffffff;
      --vw-text-3:#a1b6ce;
      --vw-muted:#91a7c1;
      --vw-faint:#8196ae;
      --vw-teal-10:rgba(145,185,255,.12);
      --vw-teal-12:rgba(145,185,255,.16);
      --vw-teal-18:rgba(145,185,255,.22);
      --vw-teal-25:rgba(145,185,255,.30);
      --vw-line-2:#31485f;
      --vw-primary-bg-hover:#bbd3ff;
      --vw-danger-border:rgba(240,169,179,.32);
      --vw-danger-10:rgba(240,169,179,.10);
      --vw-sync-amber:#ffb95c;
      --vw-scrollbar:#405874;
      --vw-placeholder:#91a7c1;
      --vw-strength-good:var(--grn);
      --vw-strength-mid:#ffb95c;
      --vw-gen-symbol:#ff8ab5;
      --vw-popup-shadow:0 12px 32px rgba(0,0,0,.32);
      --vw-panel-shadow:0 12px 32px rgba(0,0,0,.32);
      --vw-dialog-shadow:0 16px 40px rgba(0,0,0,.42);
      --vw-focus:0 0 0 3px rgba(145,185,255,.28);
      --vw-disabled-bg:#253447;
      --vw-disabled-fg:#8196ae;
      --vw-disabled-border:#31485f;
    }
  }

  @keyframes mvIn { from { opacity:0; } to { opacity:1; } }
  @keyframes mvUp { from { opacity:0; transform:translate(-50%,10px); } to { opacity:1; transform:translate(-50%,0); } }
  @keyframes mvGrow { from { opacity:0; transform:translateY(-4px); } to { opacity:1; transform:none; } }
  @keyframes mvStag { from { opacity:0; transform:translateY(5px); } to { opacity:1; transform:none; } }
  @keyframes mvPop { from { transform:scale(.96); opacity:0; } to { transform:scale(1); opacity:1; } }
  @keyframes mvPulse { from { opacity:.7; } to { opacity:1; } }
  @keyframes mvSheet { from { transform:translateY(8px); opacity:0; } to { transform:translateY(0); opacity:1; } }
  @keyframes mvFly { from { transform:translateX(-6px); opacity:0; } to { transform:translateX(0); opacity:1; } }
  @keyframes mvSpin { to { transform:rotate(360deg); } }

  @media (prefers-reduced-motion: reduce) {
    :host { --vw-dur-fast:0ms; --vw-dur:0ms; }
    *, *::before, *::after { animation:none !important; transition:none !important; scroll-behavior:auto !important; }
  }
`;

export const themeTokens = css`
  :host {
    color:var(--vw-ink);
    font-family:var(--vw-font-ui);
    font-size:13px;
    line-height:1.5;
    -webkit-font-smoothing:antialiased;
    text-rendering:optimizeLegibility;
  }
  *, *::before, *::after { box-sizing:border-box; }
`;
