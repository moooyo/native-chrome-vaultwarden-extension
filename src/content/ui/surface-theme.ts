/** Shared presentation tokens for isolated content surfaces. No page styles or data are inherited. */
export const INLINE_SURFACE_CSS = `
  :host { all: initial; }
  :host {
    color-scheme: light dark;
    --mi-panel:#fff; --mi-ink:#192d48; --mi-muted:#526780; --mi-faint:#63788f;
    --mi-text-2:#526780; --mi-text-3:#526780;
    --mi-teal:#155ed7; --mi-teal-text:#155ed7; --mi-teal-10:#edf4ff;
    --mi-teal-12:#edf4ff; --mi-teal-20:#c7daf7; --mi-teal-25:#c7daf7;
    --mi-line:#dbe4ef; --mi-line-3:#c6d3e3; --mi-inner:#edf1f6;
    --mi-fill:#f6f9fd; --mi-fill-2:#f6f9fd; --mi-row-hover:#f2f6fc;
    --mi-track:#dce6f2; --mi-red:#ad343e; --mi-success:#267451;
    --mi-ink-btn:#155ed7; --mi-ink-btn-fg:#fff; --mi-ink-hover:#0d4faf;
    --mi-shadow:0 12px 32px #18385714,0 2px 6px #18385708;
    --mi-ease:cubic-bezier(.2,.8,.2,1);
  }
  *, *::before, *::after { box-sizing:border-box; }
  button, input, summary { font:inherit; }
  button { appearance:none; color:inherit; cursor:pointer; -webkit-tap-highlight-color:transparent; }
  button { transition:background-color 140ms var(--mi-ease),border-color 140ms var(--mi-ease),color 140ms var(--mi-ease),box-shadow 140ms var(--mi-ease); }
  button:disabled, input:disabled { cursor:default; opacity:.6; }
  button:focus-visible, input:focus-visible, summary:focus-visible { outline:2px solid var(--mi-teal); outline-offset:2px; }
  svg { width:18px; height:18px; stroke-width:1.7; flex:none; }
  .box {
    width:min(320px,calc(100vw - 24px)); max-height:calc(100vh - 24px); overflow:auto;
    font:400 13px/1.5 "Instrument Sans", "Segoe UI", "Microsoft YaHei", system-ui, sans-serif;
    color:var(--mi-ink); background:var(--mi-panel); border:1px solid var(--mi-line);
    border-radius:12px; box-shadow:var(--mi-shadow);
    animation:mi-surface-enter 180ms var(--mi-ease);
    overscroll-behavior:contain; scrollbar-width:thin; scrollbar-color:var(--mi-line-3) transparent;
  }
  .head { display:flex; align-items:center; gap:8px; min-height:44px; padding:7px 10px 7px 14px; border-bottom:1px solid var(--mi-inner); }
  .brand { min-width:0; flex:1; overflow-wrap:anywhere; font-size:12px; font-weight:500; color:var(--mi-muted); }
  .head .meta { color:var(--mi-faint); font-size:11px; flex:none; }
  .logo { display:grid; place-items:center; width:18px; height:18px; border-radius:5px; background:#155ed7; flex:none; }
  .logo svg { width:12px; height:12px; fill:#fff; stroke:none; }
  .panel-close { display:grid; place-items:center; width:30px; height:30px; flex:none; padding:5px; border:0; border-radius:7px; background:transparent; color:var(--mi-faint); }
  .panel-close:hover { background:var(--mi-row-hover); color:var(--mi-ink); }
  .panel-close svg { width:16px; height:16px; }
  .panel-footer { display:flex; justify-content:space-between; align-items:center; gap:8px; min-height:36px; padding:8px 14px; border-top:1px solid var(--mi-inner); color:var(--mi-faint); font-size:11px; }
  .receipt-note { color:var(--mi-faint); font-size:11px; line-height:1.6; }
  .status { display:flex; align-items:flex-start; gap:10px; padding:16px; }
  .status-msg { font-size:13px; line-height:1.7; overflow-wrap:anywhere; }
  .status-ico { display:grid; place-items:center; color:var(--mi-teal-text); flex:none; }
  .filled { display:flex; align-items:center; gap:12px; padding:16px; }
  .badge { display:inline-flex; flex:1; align-items:center; gap:8px; font-size:13px; font-weight:500; color:var(--mi-ink); }
  .badge svg { width:18px; height:18px; color:var(--mi-success); animation:mi-receipt-enter 160ms var(--mi-ease); }
  .undo { border:0; background:transparent; padding:6px 0; color:var(--mi-teal-text); font-size:12px; flex:none; }
  .undo:hover { text-decoration:underline; }
  @keyframes mi-surface-enter { from { opacity:0; transform:translateY(4px); } to { opacity:1; transform:none; } }
  @keyframes mi-receipt-enter { from { opacity:0; transform:scale(.9); } to { opacity:1; transform:none; } }
  @media (prefers-color-scheme: dark) {
    :host {
      --mi-panel:#162236; --mi-ink:#e7eef8; --mi-muted:#b8c7dc; --mi-faint:#a4b6ce;
      --mi-text-2:#b8c7dc; --mi-text-3:#b8c7dc;
      --mi-teal:#8cb8ff; --mi-teal-text:#8cb8ff; --mi-teal-10:#213959;
      --mi-teal-12:#213959; --mi-teal-20:#365b87; --mi-teal-25:#365b87;
      --mi-line:#34455e; --mi-line-3:#455e7c; --mi-inner:#2a3b52;
      --mi-fill:#1e2e45; --mi-fill-2:#1e2e45; --mi-row-hover:#23364f;
      --mi-track:#344d6d; --mi-red:#ffa5a9; --mi-success:#91d6b5;
      --mi-ink-btn:#8cb8ff; --mi-ink-btn-fg:#102e58; --mi-ink-hover:#b6d1ff;
      --mi-shadow:0 12px 32px #0004,0 2px 6px #0002;
    }
  }
  @media (prefers-reduced-motion: reduce) {
    *, *::before, *::after { animation:none!important; transition:none!important; scroll-behavior:auto!important; }
  }
`;
