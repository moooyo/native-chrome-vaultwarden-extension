import { LitElement, css, html } from 'lit';
import { themeTokens } from './tokens.js';

/**
 * `vw-logo` — the MiYu concentric-circle mark on a moss-green rounded block. The block color is the
 * always-green `--vw-teal-solid` (identical in light/dark). Sizes match the design's hand-placed
 * instances exactly (16 / 24 / 28 / 46 px blocks); pick with the `variant` attribute.
 */
type LogoVariant = 'mini' | 'header' | 'sidebar' | 'hero';

interface LogoSpec {
  block: number;
  radius: number;
  glyph: number;
  ring: number;
  dot: number;
  dotOffset: number;
}

const SPECS: Record<LogoVariant, LogoSpec> = {
  mini: { block: 16, radius: 5, glyph: 8, ring: 1.5, dot: 2, dotOffset: 3 },
  header: { block: 24, radius: 8, glyph: 11, ring: 2, dot: 3, dotOffset: 4 },
  sidebar: { block: 28, radius: 9, glyph: 12, ring: 2, dot: 3, dotOffset: 4.5 },
  hero: { block: 46, radius: 14, glyph: 18, ring: 2.5, dot: 4, dotOffset: 7 },
};

export class VwLogo extends LitElement {
  static override properties = {
    variant: { type: String },
  };

  declare variant: LogoVariant;

  constructor() {
    super();
    this.variant = 'header';
  }

  static override styles = [
    themeTokens,
    css`
      :host { display: inline-flex; }
      .block {
        display: grid;
        place-items: center;
        background: var(--vw-teal-solid);
        flex: none;
      }
      .glyph { position: relative; }
      .ring { position: absolute; inset: 0; border-style: solid; border-color: #fff; border-radius: 50%; }
      .dot { position: absolute; border-radius: 50%; background: #fff; }
    `,
  ];

  protected override render() {
    const s = SPECS[this.variant] ?? SPECS.header;
    const blockStyle = `width:${s.block}px;height:${s.block}px;border-radius:${s.radius}px`;
    const glyphStyle = `width:${s.glyph}px;height:${s.glyph}px`;
    const ringStyle = `border-width:${s.ring}px`;
    const dotStyle = `left:${s.dotOffset}px;top:${s.dotOffset}px;width:${s.dot}px;height:${s.dot}px`;
    return html`
      <div class="block" style=${blockStyle} aria-hidden="true">
        <div class="glyph" style=${glyphStyle}>
          <div class="ring" style=${ringStyle}></div>
          <div class="dot" style=${dotStyle}></div>
        </div>
      </div>
    `;
  }
}

customElements.define('vw-logo', VwLogo);

declare global {
  interface HTMLElementTagNameMap {
    'vw-logo': VwLogo;
  }
}
