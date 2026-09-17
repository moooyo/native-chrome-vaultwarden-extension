import { css } from 'lit';

/** Continuous task surfaces shared by the options sections. */
export const settingsSectionStyles = css`
  :host { display:block; min-width:0; }
  .settings-sheet { background:var(--vw-card); border:1px solid var(--vw-line-1); border-radius:12px; margin-bottom:24px; }
  .settings-sheet > vw-setting-card + vw-setting-card { border-top:1px solid var(--vw-line-1); }
  .settings-sheet vw-setting-card::part(card) { border:0; border-radius:0; background:transparent; padding:22px 24px; }
  .settings-sheet vw-setting-card::part(title) { font-size:14px; font-weight:600; }
  .settings-sheet vw-setting-card::part(description) { font-size:12px; line-height:1.6; }
  .settings-sheet vw-setting-card::part(control) { min-width:0; }
  .section-note { margin:0 0 18px; color:var(--vw-muted); font-size:12px; line-height:1.6; }
  .save-feedback { display:flex; align-items:center; gap:8px; min-height:28px; margin:0 0 12px; font-size:12px; line-height:1.5; color:var(--vw-muted); }
  .save-feedback[data-state='saved'] { color:var(--vw-success, var(--grn)); }
  .save-feedback[data-state='saving'] { color:var(--vw-accent); }
  .save-feedback[data-state='error'] { color:var(--vw-danger); }
  .save-copy { flex:1; min-width:0; overflow-wrap:anywhere; }
  .save-effective { display:block; color:var(--vw-muted); margin-top:4px; }
  .save-mark { width:14px; height:14px; flex:none; display:grid; place-items:center; }
  .save-mark svg { width:14px; height:14px; }
  .save-feedback[data-state='saving'] .save-mark { border:2px solid var(--vw-line-2); border-top-color:var(--vw-accent); border-radius:50%; box-sizing:border-box; animation:settings-spin .8s linear infinite; }
  .retry-save { appearance:none; border:1px solid var(--vw-line-2); border-radius:6px; background:var(--vw-card); color:var(--vw-ink); font:inherit; min-height:30px; padding:4px 10px; cursor:pointer; flex:none; }
  .retry-save:focus-visible { outline:none; box-shadow:var(--vw-focus); }
  .control-stack { display:flex; flex-direction:column; gap:8px; width:100%; }
  .control-caption { color:var(--vw-muted); font-size:12px; line-height:1.5; }
  .section-tabs { display:flex; gap:24px; overflow-x:auto; border-bottom:1px solid var(--vw-line-1); margin-bottom:24px; }
  .section-tabs button { appearance:none; flex:none; padding:0 0 12px; border:0; border-bottom:2px solid transparent; color:var(--vw-muted); background:transparent; font:inherit; font-size:13px; cursor:pointer; }
  .section-tabs button[aria-selected='true'] { border-bottom-color:var(--vw-accent); color:var(--vw-accent); font-weight:600; }
  .section-tabs button:focus-visible { outline:none; box-shadow:var(--vw-focus); }
  .settings-panel[hidden] { display:none; }
  @keyframes settings-spin { to { transform:rotate(360deg); } }
  @media(prefers-reduced-motion:reduce) { .save-feedback[data-state='saving'] .save-mark { animation:none; } }
  @media(max-width:600px) { .settings-sheet vw-setting-card::part(card) { padding:18px; } .section-tabs { gap:18px; } }
`;
