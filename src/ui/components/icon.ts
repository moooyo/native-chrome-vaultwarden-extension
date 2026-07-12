import { svg, type SVGTemplateResult } from 'lit';

/**
 * MiYu icon set — inline, stroke-based SVGs on a 24×24 viewBox (Lucide-style). Every path is a fixed
 * literal, so `uiIcon` never needs `unsafeSVG`. The `IconName` union and `uiIcon(name)` API are a
 * shared contract consumed by the popup, options, and content-script surfaces.
 *
 * Per-icon default stroke widths (1.6–2.6 in the design) live in `ICONS`; a caller may override with
 * `uiIcon(name, { strokeWidth })` for the few contexts where the design uses a heavier stroke (e.g.
 * the check inside a filled badge). Icons are sized by the consumer via CSS width/height.
 */
export type IconName =
  | 'lock'
  | 'unlock'
  | 'search'
  | 'copy'
  | 'user'
  | 'refresh'
  | 'logout'
  | 'chevron'
  | 'chevronDown'
  | 'back'
  | 'check'
  | 'checkCircle'
  | 'alert'
  | 'star'
  | 'mail'
  | 'key'
  | 'passkey'
  | 'wand'
  | 'sliders'
  | 'fingerprint'
  | 'eye'
  | 'eyeOff'
  | 'card'
  | 'idcard'
  | 'note'
  | 'text'
  | 'file'
  | 'folder'
  | 'link'
  | 'plus'
  | 'edit'
  | 'trash'
  | 'close'
  | 'shield'
  | 'globe';

interface IconDef {
  d: SVGTemplateResult;
  /** Default stroke-width for this glyph (design uses 1.6–2.6). */
  sw: number;
}

const ICONS: Record<IconName, IconDef> = {
  lock: { d: svg`<rect x="5" y="11" width="14" height="9" rx="2"/><path d="M8 11V8a4 4 0 0 1 8 0v3"/>`, sw: 1.6 },
  unlock: { d: svg`<rect x="5" y="11" width="14" height="9" rx="2"/><path d="M8 11V8a4 4 0 0 1 7.5-2"/>`, sw: 1.6 },
  search: { d: svg`<circle cx="11" cy="11" r="7"/><path d="M16.5 16.5L21 21"/>`, sw: 1.8 },
  copy: { d: svg`<rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15V6a2 2 0 0 1 2-2h9"/>`, sw: 1.7 },
  user: { d: svg`<circle cx="12" cy="8" r="3.5"/><path d="M5 20c0-3.5 3-5.5 7-5.5s7 2 7 5.5"/>`, sw: 1.7 },
  refresh: { d: svg`<path d="M20 12a8 8 0 1 1-2.3-5.7"/><path d="M20 4v4h-4"/>`, sw: 1.7 },
  logout: { d: svg`<path d="M14 8V6a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h6a2 2 0 0 0 2-2v-2"/><path d="M9 12h11M17 9l3 3-3 3"/>`, sw: 1.7 },
  chevron: { d: svg`<path d="M9 6l6 6-6 6"/>`, sw: 1.8 },
  chevronDown: { d: svg`<path d="M6 9l6 6 6-6"/>`, sw: 2 },
  back: { d: svg`<path d="M19 12H5M11 6l-6 6 6 6"/>`, sw: 1.8 },
  check: { d: svg`<path d="M5 12l5 5L20 7"/>`, sw: 2.4 },
  checkCircle: { d: svg`<circle cx="12" cy="12" r="9"/><path d="M8.5 12.5l2.5 2.5 4.5-5"/>`, sw: 1.8 },
  alert: { d: svg`<circle cx="12" cy="12" r="9"/><path d="M12 8v5M12 16h.01"/>`, sw: 1.8 },
  star: { d: svg`<path d="M12 4l2.3 4.7 5.2.8-3.7 3.6.9 5.1L12 15.8 7.3 18.3l.9-5.1L4.5 9.5l5.2-.8z"/>`, sw: 1.6 },
  mail: { d: svg`<rect x="3" y="5" width="18" height="14" rx="2"/><path d="M4 7l8 6 8-6"/>`, sw: 1.7 },
  key: { d: svg`<circle cx="8" cy="14" r="4"/><path d="M11 11l9-9M17 5l2 2M14 8l2 2"/>`, sw: 1.7 },
  passkey: { d: svg`<circle cx="8" cy="9" r="4"/><path d="M11 12l8 8"/><path d="M15 16l2.5-2.5"/>`, sw: 1.9 },
  wand: { d: svg`<circle cx="8" cy="14" r="4"/><path d="M11 11l8-8"/><path d="M16 6l2.5 2.5"/>`, sw: 1.7 },
  sliders: {
    d: svg`<path d="M4 7h16M4 12h16M4 17h16"/><circle cx="9" cy="7" r="2" style="fill:var(--vw-panel)"/><circle cx="15" cy="12" r="2" style="fill:var(--vw-panel)"/><circle cx="7" cy="17" r="2" style="fill:var(--vw-panel)"/>`,
    sw: 1.6,
  },
  fingerprint: { d: svg`<circle cx="12" cy="13" r="1.6"/><path d="M12 7a6 6 0 0 1 6 6c0 2-.4 3.8-1 5.4"/><path d="M6 13a6 6 0 0 1 3-5.2"/><path d="M8.5 20a12 12 0 0 0 1-4"/>`, sw: 1.6 },
  eye: { d: svg`<path d="M2 12s3.5-6 10-6 10 6 10 6-3.5 6-10 6S2 12 2 12z"/><circle cx="12" cy="12" r="3"/>`, sw: 1.6 },
  eyeOff: { d: svg`<path d="M3 3l18 18"/><path d="M10.6 6.1A10 10 0 0 1 12 5c6.5 0 10 7 10 7a17 17 0 0 1-3.3 4M6.5 7.4A17 17 0 0 0 2 12s3.5 7 10 7a10 10 0 0 0 4-.8"/><path d="M9.9 9.9a3 3 0 0 0 4.2 4.2"/>`, sw: 1.6 },
  card: { d: svg`<rect x="3" y="6" width="18" height="13" rx="2"/><path d="M3 10h18"/>`, sw: 1.7 },
  idcard: { d: svg`<rect x="3" y="5" width="18" height="14" rx="2"/><circle cx="8.5" cy="11" r="2"/><path d="M5 16c0-1.6 1.6-2.5 3.5-2.5S12 14.4 12 16M14 9h4M14 12h4M14 15h2.5"/>`, sw: 1.6 },
  note: { d: svg`<rect x="5" y="4" width="14" height="17" rx="2"/><path d="M9 9h6M9 13h6M9 17h4"/>`, sw: 1.7 },
  text: { d: svg`<rect x="5" y="4" width="14" height="17" rx="2"/><path d="M9 9h6M9 13h6"/>`, sw: 1.7 },
  file: { d: svg`<path d="M13 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V9z"/><path d="M13 3v6h6"/>`, sw: 1.7 },
  folder: { d: svg`<path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V7z"/>`, sw: 1.7 },
  link: { d: svg`<path d="M10 14a5 5 0 0 0 7 0l3-3a5 5 0 0 0-7-7l-1.5 1.5"/><path d="M14 10a5 5 0 0 0-7 0l-3 3a5 5 0 0 0 7 7l1.5-1.5"/>`, sw: 1.7 },
  plus: { d: svg`<path d="M12 5v14M5 12h14"/>`, sw: 1.8 },
  edit: { d: svg`<path d="M4 20h4L19 9l-4-4L4 16v4z"/><path d="M13.5 6.5l4 4"/>`, sw: 1.7 },
  trash: { d: svg`<path d="M4 7h16M9 7V5h6v2M6 7l1 13h10l1-13"/>`, sw: 1.7 },
  close: { d: svg`<path d="M6 6l12 12M18 6L6 18"/>`, sw: 1.8 },
  shield: { d: svg`<path d="M12 3l7 3v5c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V6l7-3z"/><path d="M9 12l2 2 4-4"/>`, sw: 1.7 },
  globe: { d: svg`<circle cx="12" cy="12" r="9"/><path d="M3 12h18"/><path d="M12 3c2.5 2.5 2.5 15 0 18M12 3c-2.5 2.5-2.5 15 0 18"/>`, sw: 1.7 },
};

/** Renders a MiYu icon. `strokeWidth` overrides the per-icon default when a heavier stroke is wanted. */
export function uiIcon(name: IconName, opts?: { strokeWidth?: number }): SVGTemplateResult {
  const def = ICONS[name];
  const sw = opts?.strokeWidth ?? def.sw;
  return svg`<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="${sw}" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false">${def.d}</svg>`;
}
