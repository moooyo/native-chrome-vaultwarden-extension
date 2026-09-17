import { css, html, nothing } from 'lit';
import { t } from '../../i18n/index.js';

/** Display-only identity supplied by the owner of the active authentication request. */
export interface AuthIdentityDisplay {
  readonly email?: string;
  readonly server?: string;
  readonly owner?: string;
}

export const authIdentityStyles = css`
  .auth-identity {
    display: grid;
    gap: 7px;
    width: 100%;
    min-width: 0;
    margin: 0;
    padding: 11px 12px;
    box-sizing: border-box;
    border: 1px solid var(--vw-line-1);
    border-radius: var(--vw-radius-control);
    background: var(--vw-fill-2);
    text-align: left;
  }
  .auth-identity-row {
    display: grid;
    grid-template-columns: minmax(68px, 28%) minmax(0, 1fr);
    align-items: baseline;
    gap: 12px;
    min-width: 0;
  }
  .auth-identity dt {
    margin: 0;
    color: var(--vw-muted);
    font: 400 11px/1.45 var(--vw-font-ui);
  }
  .auth-identity dd {
    min-width: 0;
    margin: 0;
    overflow-wrap: anywhere;
    color: var(--vw-ink);
    font: 500 12px/1.45 var(--vw-font-ui);
    unicode-bidi: plaintext;
  }
  .auth-identity .auth-server {
    color: var(--vw-text-2);
    font-size: 11px;
  }
`;

/** Keep the vault account distinct from a website username without exposing internal identifiers. */
export function renderAuthIdentity(identity: AuthIdentityDisplay | undefined) {
  if (!identity?.email && !identity?.server && !identity?.owner) return nothing;
  return html`
    <dl class="auth-identity" data-auth-identity>
      ${identity.email ? html`<div class="auth-identity-row"><dt>${t('auth.identity.vaultAccount')}</dt><dd>${identity.email}</dd></div>` : nothing}
      ${identity.server ? html`<div class="auth-identity-row"><dt>${t('auth.identity.server')}</dt><dd class="auth-server">${identity.server}</dd></div>` : nothing}
      ${identity.owner ? html`<div class="auth-identity-row"><dt>${t('auth.identity.owner')}</dt><dd>${identity.owner}</dd></div>` : nothing}
    </dl>
  `;
}
