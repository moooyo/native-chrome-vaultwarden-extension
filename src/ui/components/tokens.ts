import { css } from 'lit';

/**
 * MiYu (密屿) design tokens.
 *
 * `paletteTokens` defines every token *value* on `:host`, with dark overrides gated on a
 * `data-theme` attribute (and on `prefers-color-scheme` when the theme is `system`). It is composed
 * by the three page roots (`vw-popup-app`, `vw-options-app`, `vw-receive-app`) and by the
 * self-contained content-script surfaces. Because CSS custom properties inherit across shadow
 * boundaries, child components do NOT redefine values — they inherit them from the nearest root and
 * only compose `themeTokens` (base font/color). This is what makes the Appearance theme switch work
 * at runtime: the theme controller flips `data-theme` on the root host and every descendant re-reads
 * the inherited variables.
 *
 * The moss-green block color (`--vw-teal-solid`, the logo) is identical in both themes; the themed
 * accent (`--vw-accent`) shifts lighter in dark, and the toggle-on track uses its own value
 * (`#2FBF9C` in dark, not the accent — a confirmed spec correction over the README).
 *
 * The dark declarations are intentionally written twice (for `[data-theme='dark']` and, under the
 * media query, `[data-theme='system']`) — Lit's `css` cannot interpolate a rule body into two
 * selectors, and the duplication is clearer than an `unsafeCSS` indirection.
 */
export const paletteTokens = css`
  :host {
    /* text */
    --vw-ink:#16181D;
    --vw-ink-hover:#2A2D34;
    --vw-text-2:#565B66;
    --vw-text-3:#6A6F7A;
    --vw-text-4:#3F444E;
    --vw-muted:#8A8F99;
    --vw-faint:#9AA0AA;
    /* teal / accent */
    --vw-teal-solid:#0E8A72;
    --vw-accent:#0E8A72;
    --vw-teal-text:#0B7A65;
    --vw-teal-10:rgba(14,138,114,.1);
    --vw-teal-12:rgba(14,138,114,.12);
    --vw-teal-18:rgba(14,138,114,.18);
    --vw-teal-25:rgba(14,138,114,.25);
    /* surfaces */
    --vw-panel:#FCFCFB;
    --vw-options-bg:#FAFAF8;
    --vw-card:#ffffff;
    --vw-fill:#F1F1EE;
    --vw-fill-2:#F7F7F4;
    --vw-row-hover:#F2F2EF;
    --vw-icon-hover:rgba(22,24,29,.06);
    /* lines */
    --vw-line-1:rgba(22,24,29,.07);
    --vw-line-2:rgba(22,24,29,.09);
    --vw-line-3:rgba(22,24,29,.14);
    --vw-card-border:rgba(22,24,29,.08);
    /* primary (ink) button */
    --vw-primary-bg:#16181D;
    --vw-primary-bg-hover:#2A2D34;
    --vw-primary-fg:#ffffff;
    /* status */
    --vw-danger:#C6453D;
    --vw-danger-border:rgba(198,69,61,.3);
    --vw-danger-10:rgba(198,69,61,.08);
    --vw-sync-amber:#B8860B;
    --vw-chevron:#C4C7CC;
    /* controls */
    --vw-toggle-on:#0E8A72;
    --vw-toggle-off:rgba(22,24,29,.15);
    --vw-track:rgba(22,24,29,.08);
    --vw-scrollbar:rgba(0,0,0,.16);
    --vw-placeholder:#9a9a9a;
    /* strength + generator coloring */
    --vw-strength-strong:#0E8A72;
    --vw-strength-good:#4C8A0E;
    --vw-strength-mid:#A66A00;
    --vw-strength-weak:#C6453D;
    --vw-gen-digit:#0B7A65;
    --vw-gen-symbol:#C6453D;
    /* fonts */
    --vw-font-ui:'Instrument Sans','Segoe UI',system-ui,sans-serif;
    --vw-font-mono:'JetBrains Mono',ui-monospace,monospace;
    /* radii */
    --vw-radius-dialog:16px;
    --vw-radius-panel:14px;
    --vw-radius-pill:13px;
    --vw-radius-card:12px;
    --vw-radius-control:10px;
    --vw-radius-input:9px;
    --vw-radius-chip:8px;
    --vw-radius-small:7px;
    --vw-radius-xs:6px;
    /* shadows */
    --vw-popup-shadow:0 18px 44px rgba(20,24,32,.22);
    --vw-panel-shadow:0 16px 40px rgba(20,24,32,.16);
    --vw-dialog-shadow:0 24px 56px rgba(20,24,32,.28);
    --vw-card-shadow:0 2px 10px rgba(20,24,32,.05);
    --vw-knob-shadow:0 1px 2px rgba(0,0,0,.25);
    --vw-seg-shadow:0 1px 3px rgba(0,0,0,.14);
    /* durations */
    --vw-dur-fast:150ms;
    --vw-dur:180ms;
    /* focus */
    --vw-focus:0 0 0 2px rgba(14,138,114,.55);
  }

  :host([data-theme='dark']) {
    --vw-ink:#F2F3F5;
    --vw-ink-hover:#ffffff;
    --vw-text-2:#9AA0AC;
    --vw-text-3:#9AA0AC;
    --vw-text-4:#D6D9DE;
    --vw-muted:#9AA0AC;
    --vw-faint:#7B818B;
    --vw-accent:#45D6B5;
    --vw-teal-text:#45D6B5;
    --vw-teal-10:rgba(69,214,181,.14);
    --vw-teal-12:rgba(69,214,181,.16);
    --vw-teal-18:rgba(69,214,181,.22);
    --vw-teal-25:rgba(69,214,181,.3);
    --vw-panel:#1F2229;
    --vw-options-bg:#17191E;
    --vw-card:#262A33;
    --vw-fill:#262A33;
    --vw-fill-2:#262A33;
    --vw-row-hover:rgba(255,255,255,.05);
    --vw-icon-hover:rgba(255,255,255,.07);
    --vw-line-1:rgba(255,255,255,.07);
    --vw-line-2:rgba(255,255,255,.09);
    --vw-line-3:rgba(255,255,255,.16);
    --vw-card-border:rgba(255,255,255,.07);
    --vw-primary-bg:#F2F3F5;
    --vw-primary-bg-hover:#ffffff;
    --vw-primary-fg:#16181D;
    --vw-chevron:#565B66;
    --vw-toggle-on:#2FBF9C;
    --vw-toggle-off:rgba(255,255,255,.18);
    --vw-track:rgba(255,255,255,.12);
    --vw-scrollbar:rgba(255,255,255,.2);
    --vw-placeholder:#8a8a8a;
    --vw-strength-strong:#45D6B5;
    --vw-strength-good:#45D6B5;
    --vw-strength-mid:#E0B23C;
    --vw-strength-weak:#E5675D;
    --vw-gen-digit:#45D6B5;
    --vw-gen-symbol:#E5675D;
    --vw-popup-shadow:0 18px 44px rgba(0,0,0,.5);
    --vw-knob-shadow:0 1px 2px rgba(0,0,0,.35);
    --vw-focus:0 0 0 2px rgba(69,214,181,.6);
  }

  @media (prefers-color-scheme: dark) {
    :host([data-theme='system']) {
      --vw-ink:#F2F3F5;
      --vw-ink-hover:#ffffff;
      --vw-text-2:#9AA0AC;
      --vw-text-3:#9AA0AC;
      --vw-text-4:#D6D9DE;
      --vw-muted:#9AA0AC;
      --vw-faint:#7B818B;
      --vw-accent:#45D6B5;
      --vw-teal-text:#45D6B5;
      --vw-teal-10:rgba(69,214,181,.14);
      --vw-teal-12:rgba(69,214,181,.16);
      --vw-teal-18:rgba(69,214,181,.22);
      --vw-teal-25:rgba(69,214,181,.3);
      --vw-panel:#1F2229;
      --vw-options-bg:#17191E;
      --vw-card:#262A33;
      --vw-fill:#262A33;
      --vw-fill-2:#262A33;
      --vw-row-hover:rgba(255,255,255,.05);
      --vw-icon-hover:rgba(255,255,255,.07);
      --vw-line-1:rgba(255,255,255,.07);
      --vw-line-2:rgba(255,255,255,.09);
      --vw-line-3:rgba(255,255,255,.16);
      --vw-card-border:rgba(255,255,255,.07);
      --vw-primary-bg:#F2F3F5;
      --vw-primary-bg-hover:#ffffff;
      --vw-primary-fg:#16181D;
      --vw-chevron:#565B66;
      --vw-toggle-on:#2FBF9C;
      --vw-toggle-off:rgba(255,255,255,.18);
      --vw-track:rgba(255,255,255,.12);
      --vw-scrollbar:rgba(255,255,255,.2);
      --vw-placeholder:#8a8a8a;
      --vw-strength-strong:#45D6B5;
      --vw-strength-good:#45D6B5;
      --vw-strength-mid:#E0B23C;
      --vw-strength-weak:#E5675D;
      --vw-gen-digit:#45D6B5;
      --vw-gen-symbol:#E5675D;
      --vw-popup-shadow:0 18px 44px rgba(0,0,0,.5);
      --vw-knob-shadow:0 1px 2px rgba(0,0,0,.35);
      --vw-focus:0 0 0 2px rgba(69,214,181,.6);
    }
  }

  /* Motion keyframes (animations-handoff.md) — lightweight, ease-out. Components opt in per element;
     every animation is disabled under prefers-reduced-motion below. */
  @keyframes mvIn { from { opacity: 0; transform: translateY(6px); } to { opacity: 1; transform: none; } }
  @keyframes mvUp { from { opacity: 0; transform: translate(-50%, 6px); } to { opacity: 1; transform: translate(-50%, 0); } }
  @keyframes mvGrow { from { opacity: 0; transform: translateY(-6px) scaleY(.95); } to { opacity: 1; transform: none; } }
  @keyframes mvStag { from { opacity: 0; transform: translateY(7px); } to { opacity: 1; transform: none; } }
  @keyframes mvPop { 0% { transform: scale(.4); opacity: 0; } 65% { transform: scale(1.12); opacity: 1; } 100% { transform: scale(1); opacity: 1; } }
  @keyframes mvPulse { 0% { box-shadow: 0 0 0 0 rgba(14,138,114,.45); } 70% { box-shadow: 0 0 0 6px rgba(14,138,114,0); } 100% { box-shadow: 0 0 0 0 rgba(14,138,114,0); } }
  @keyframes mvSpin { to { transform: rotate(360deg); } }

  @media (prefers-reduced-motion: reduce) {
    :host { --vw-dur-fast:0ms; --vw-dur:0ms; }
    *, *::before, *::after { animation: none !important; }
  }
`;

/**
 * Base per-component tokens: sets the inherited font + text color on every component's `:host`
 * without redefining palette *values* (so the runtime theme switch on the root host is not
 * shadowed). Every component composes this; page roots additionally compose `paletteTokens`.
 */
export const themeTokens = css`
  :host {
    color: var(--vw-ink);
    font-family: var(--vw-font-ui);
    font-size: 13px;
    line-height: 1.45;
    -webkit-font-smoothing: antialiased;
  }
  *, *::before, *::after { box-sizing: border-box; }
`;
