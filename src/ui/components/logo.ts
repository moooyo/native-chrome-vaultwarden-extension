import { LitElement, css, html } from 'lit';
import { themeTokens } from './tokens.js';

type LogoVariant = 'mini' | 'header' | 'sidebar' | 'hero';

const SPECS: Record<LogoVariant, { block: number; radius: number; glyph: number }> = {
  mini: { block: 16, radius: 5, glyph: 10 },
  header: { block: 24, radius: 8, glyph: 15 },
  sidebar: { block: 28, radius: 9, glyph: 17 },
  hero: { block: 60, radius: 18, glyph: 34 },
};

/** The white key on a Google-blue rounded square from the new handoff. */
export class VwLogo extends LitElement {
  static override properties = { variant: { type: String } };
  declare variant: LogoVariant;

  constructor() {
    super();
    this.variant = 'header';
  }

  static override styles = [
    themeTokens,
    css`
      :host { display:inline-flex; flex:none; }
      .block {
        display:grid;
        place-items:center;
        background:var(--p, #0b57d0);
        color:var(--onp, #fff);
        box-shadow:0 3px 8px rgba(11,87,208,.22);
      }
      svg { display:block; fill:currentColor; }
    `,
  ];

  protected override render() {
    const spec = SPECS[this.variant] ?? SPECS.header;
    return html`
      <span class="block" style=${`width:${spec.block}px;height:${spec.block}px;border-radius:${spec.radius}px`} aria-hidden="true">
        <svg style=${`width:${spec.glyph}px;height:${spec.glyph}px`} viewBox="0 0 24 24">
          <path d="M7.5 15.5a5.5 5.5 0 1 1 4.9-8H22v4h-2v2h-3v2h-4.6a5.5 5.5 0 0 1-4.9 3Zm0-3.5a2 2 0 1 0 0 4 2 2 0 0 0 0-4Z"/>
        </svg>
      </span>
    `;
  }
}

customElements.define('vw-logo', VwLogo);

declare global {
  interface HTMLElementTagNameMap {
    'vw-logo': VwLogo;
  }
}
