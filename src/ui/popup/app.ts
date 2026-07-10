import { LitElement, css, html, nothing } from 'lit';
import browser from 'webextension-polyfill';
import { sendRequest, type ResponseMessage } from '../../messaging/protocol.js';
import type { AuthResult } from '../../core/session/auth-service.js';
import type { SessionState } from '../../core/session/session-manager.js';
import { themeTokens } from '../components/tokens.js';
import '../components/status-message.js';
import './auth/auth-views.js';
import type {
  EmailChangeDetail,
  LoginSubmitDetail,
  PinUnlockSubmitDetail,
  RegisterSubmitDetail,
  TwoFactorSubmitDetail,
  UnlockSubmitDetail,
} from './auth/auth-views.js';
import type { PopupBrowser, PopupRequest, PopupRoute } from './types.js';

/** The auth-related route names `VwAuthViews` renders; everything else is out of this task's scope. */
type AuthRoute = Extract<PopupRoute, { name: 'login' | 'register' | 'twoFactor' | 'unlock' }>;

function loginRoute(error?: string): PopupRoute {
  return error === undefined ? { name: 'login' } : { name: 'login', error };
}

function registerRoute(error?: string): PopupRoute {
  return error === undefined ? { name: 'register' } : { name: 'register', error };
}

function unlockRoute(error?: string): PopupRoute {
  return error === undefined ? { name: 'unlock' } : { name: 'unlock', error };
}

function twoFactorRoute(providers: number[], error?: string): PopupRoute {
  return error === undefined ? { name: 'twoFactor', providers } : { name: 'twoFactor', providers, error };
}

/** The real `PopupBrowser`, backed by `webextension-polyfill`. */
function createDefaultBrowser(): PopupBrowser {
  return {
    async getActiveTabId() {
      const tabs = await browser.tabs.query({ active: true, currentWindow: true });
      return tabs[0]?.id;
    },
    async openOptions() {
      await browser.runtime.openOptionsPage();
    },
    async openReceive() {
      await browser.tabs.create({ url: browser.runtime.getURL('ui/receive/receive.html') });
    },
  };
}

/**
 * The dormant Lit popup root. It owns the current `route`, the single in-flight `pending` flag,
 * and the small pieces of ephemeral auth UI state (PIN availability, remembered-device banner).
 * It performs every worker request itself (via the injectable `request`) and only ever hands
 * plain props down to `vw-auth-views`, reacting to that component's typed submit/action events.
 *
 * Not wired into `popup.html` yet — `src/ui/popup/popup.ts` remains the live entry point until a
 * later task replaces it.
 */
export class VwPopupApp extends LitElement {
  static override properties = {
    route: { attribute: false },
    pending: { type: Boolean },
    pinEnabled: { type: Boolean },
    deviceRemembered: { type: Boolean },
    deviceForgotten: { type: Boolean },
  };

  declare route: PopupRoute;
  declare pending: boolean;
  declare pinEnabled: boolean;
  declare deviceRemembered: boolean;
  declare deviceForgotten: boolean;

  /** Injectable worker request function; defaults to the real messaging channel. */
  request: PopupRequest = sendRequest;

  /** Injectable browser seam; defaults to the real `webextension-polyfill`-backed implementation. */
  browser: PopupBrowser = createDefaultBrowser();

  /** The email last checked/shown by the login screen's remembered-device banner. */
  private deviceCheckEmail = '';

  /** Active TOTP countdown interval for an open login detail. Dormant in this task (no detail
   *  view exists yet) — reserved for the task that adds it; `navigate()` always clears it. */
  private totpTimer: number | undefined;

  /** Master-password reprompt credential, held only for the duration of a reprompt-gated item's
   *  detail/editor view. Dormant in this task (no detail view sets it yet) — reserved for the
   *  task that adds it; `navigate()` and `disconnectedCallback()` always clear it. */
  private repromptCredential: { cipherId: string; masterPassword: string } | null = null;

  constructor() {
    super();
    this.route = { name: 'loading' };
    this.pending = false;
    this.pinEnabled = false;
    this.deviceRemembered = false;
    this.deviceForgotten = false;
  }

  static override styles = [
    themeTokens,
    css`
      :host {
        display: block;
        min-width: 320px;
      }
    `,
  ];

  override connectedCallback(): void {
    super.connectedCallback();
    void this.init();
  }

  override disconnectedCallback(): void {
    super.disconnectedCallback();
    this.clearEphemeralDetailState();
  }

  private clearEphemeralDetailState(): void {
    if (this.totpTimer !== undefined) {
      clearInterval(this.totpTimer);
      this.totpTimer = undefined;
    }
    this.repromptCredential = null;
  }

  /** Assigns the next route, clearing per-view ephemeral state that must not survive a
   *  navigation: the TOTP timer, the reprompt credential, and (when leaving their owning view)
   *  the remembered-device banner and PIN availability flag. */
  navigate(route: PopupRoute): void {
    this.clearEphemeralDetailState();
    this.route = route;
    if (route.name !== 'login') {
      this.deviceRemembered = false;
      this.deviceForgotten = false;
      this.deviceCheckEmail = '';
    }
    if (route.name === 'unlock') {
      void this.refreshPinStatus();
    } else {
      this.pinEnabled = false;
    }
  }

  private async init(): Promise<void> {
    const response = await this.request({ type: 'auth.getState' });
    if (!response.ok) {
      this.navigate(loginRoute(response.error.message));
      return;
    }
    const { state } = response.data as { state: SessionState };
    if (state === 'loggedOut') {
      this.navigate(loginRoute());
    } else if (state === 'locked') {
      this.navigate(unlockRoute());
    } else {
      this.navigate({ name: 'vault', scope: 'suggestions' });
    }
  }

  private async refreshPinStatus(): Promise<void> {
    const response = await this.request({ type: 'auth.pinStatus' });
    if (this.route.name !== 'unlock') return; // navigated away while the request was in flight
    this.pinEnabled = response.ok && (response.data as { enabled: boolean }).enabled;
  }

  /** Routes an `AuthResult`/error exactly like the live popup's `handleAuthResult`: 2FA challenges
   *  go to the two-factor screen, failures stay on whichever auth screen raised them, and any
   *  other success goes to the vault's default (suggestions) scope. */
  private async routeAuthResult(response: ResponseMessage): Promise<void> {
    if (!response.ok) {
      if (this.route.name === 'twoFactor') {
        this.navigate(twoFactorRoute(this.route.providers, response.error.message));
      } else if (this.route.name === 'register') {
        this.navigate(registerRoute(response.error.message));
      } else {
        this.navigate(loginRoute(response.error.message));
      }
      return;
    }
    const data = response.data as AuthResult;
    if (data.kind === 'twoFactor') {
      this.navigate(twoFactorRoute(data.providers));
    } else {
      this.navigate({ name: 'vault', scope: 'suggestions' });
    }
  }

  private async handleLoginSubmit(detail: LoginSubmitDetail): Promise<void> {
    if (this.pending) return;
    this.pending = true;
    try {
      const result = await this.request({ type: 'auth.login', email: detail.email, masterPassword: detail.masterPassword });
      await this.routeAuthResult(result);
    } finally {
      this.pending = false;
    }
  }

  private async handleRegisterSubmit(detail: RegisterSubmitDetail): Promise<void> {
    if (detail.masterPassword.length < 8) {
      this.navigate(registerRoute('Master password must be at least 8 characters'));
      return;
    }
    if (detail.masterPassword !== detail.confirm) {
      this.navigate(registerRoute('Passwords do not match'));
      return;
    }
    if (this.pending) return;
    this.pending = true;
    try {
      const result = await this.request(
        detail.name !== undefined
          ? { type: 'auth.register', email: detail.email, masterPassword: detail.masterPassword, name: detail.name }
          : { type: 'auth.register', email: detail.email, masterPassword: detail.masterPassword },
      );
      await this.routeAuthResult(result);
    } finally {
      this.pending = false;
    }
  }

  private async handleTwoFactorSubmit(detail: TwoFactorSubmitDetail): Promise<void> {
    if (this.pending) return;
    this.pending = true;
    try {
      const result = await this.request({ type: 'auth.submitTwoFactor', provider: detail.provider, code: detail.code, remember: detail.remember });
      await this.routeAuthResult(result);
    } finally {
      this.pending = false;
    }
  }

  private async handleSendEmailCode(): Promise<void> {
    if (this.pending) return;
    this.pending = true;
    try {
      const response = await this.request({ type: 'auth.sendEmailCode' });
      if (!response.ok && this.route.name === 'twoFactor') {
        this.navigate(twoFactorRoute(this.route.providers, response.error.message));
      }
    } finally {
      this.pending = false;
    }
  }

  private async handleUnlockSubmit(detail: UnlockSubmitDetail): Promise<void> {
    if (this.pending) return;
    this.pending = true;
    try {
      const response = await this.request({ type: 'auth.unlock', masterPassword: detail.masterPassword });
      this.navigate(response.ok ? { name: 'vault', scope: 'suggestions' } : unlockRoute(response.error.message));
    } finally {
      this.pending = false;
    }
  }

  private async handlePinUnlockSubmit(detail: PinUnlockSubmitDetail): Promise<void> {
    if (this.pending) return;
    this.pending = true;
    try {
      const response = await this.request({ type: 'auth.unlockWithPin', pin: detail.pin });
      this.navigate(response.ok ? { name: 'vault', scope: 'suggestions' } : unlockRoute(response.error.message));
    } finally {
      this.pending = false;
    }
  }

  private async handleLogout(): Promise<void> {
    if (this.pending) return;
    this.pending = true;
    try {
      await this.request({ type: 'auth.logout' });
      this.navigate(loginRoute());
    } finally {
      this.pending = false;
    }
  }

  private async handleEmailChange(email: string): Promise<void> {
    this.deviceCheckEmail = email;
    this.deviceForgotten = false;
    if (!email) {
      this.deviceRemembered = false;
      return;
    }
    const response = await this.request({ type: 'auth.isDeviceRemembered', email });
    if (this.deviceCheckEmail !== email) return; // superseded by a newer change
    this.deviceRemembered = response.ok && (response.data as { remembered: boolean }).remembered;
  }

  private async handleForgetDevice(): Promise<void> {
    const email = this.deviceCheckEmail;
    if (!email) return;
    const response = await this.request({ type: 'auth.forgetDevice', email });
    if (response.ok) {
      this.deviceRemembered = false;
      this.deviceForgotten = true;
    }
  }

  private renderLoading() {
    return html`<vw-status-message tone="info" .icon=${'refresh'} message="Loading vault…"></vw-status-message>`;
  }

  private renderAuth(route: AuthRoute) {
    const providers = route.name === 'twoFactor' ? route.providers : [];
    const error = 'error' in route ? route.error : undefined;
    return html`
      <vw-auth-views
        .mode=${route.name}
        .error=${error}
        .pending=${this.pending}
        .providers=${providers}
        .pinEnabled=${this.pinEnabled}
        .deviceRemembered=${this.deviceRemembered}
        .deviceForgotten=${this.deviceForgotten}
        @vw-auth-login-submit=${(event: CustomEvent<LoginSubmitDetail>) => void this.handleLoginSubmit(event.detail)}
        @vw-auth-register-submit=${(event: CustomEvent<RegisterSubmitDetail>) => void this.handleRegisterSubmit(event.detail)}
        @vw-auth-two-factor-submit=${(event: CustomEvent<TwoFactorSubmitDetail>) => void this.handleTwoFactorSubmit(event.detail)}
        @vw-auth-unlock-submit=${(event: CustomEvent<UnlockSubmitDetail>) => void this.handleUnlockSubmit(event.detail)}
        @vw-auth-pin-unlock-submit=${(event: CustomEvent<PinUnlockSubmitDetail>) => void this.handlePinUnlockSubmit(event.detail)}
        @vw-auth-email-change=${(event: CustomEvent<EmailChangeDetail>) => void this.handleEmailChange(event.detail.email)}
        @vw-auth-forget-device=${() => void this.handleForgetDevice()}
        @vw-auth-send-email-code=${() => void this.handleSendEmailCode()}
        @vw-auth-go-register=${() => this.navigate({ name: 'register' })}
        @vw-auth-back-to-login=${() => this.navigate(loginRoute())}
        @vw-auth-logout=${() => void this.handleLogout()}
      ></vw-auth-views>
    `;
  }

  protected override render() {
    const route = this.route;
    switch (route.name) {
      case 'loading':
        return this.renderLoading();
      case 'login':
      case 'register':
      case 'twoFactor':
      case 'unlock':
        return this.renderAuth(route);
      default:
        // Vault/detail/editor/generator/health/sends/trash/accountSecurity/pin views are added by
        // later tasks; this root only routes to them for now.
        return nothing;
    }
  }
}

customElements.define('vw-popup-app', VwPopupApp);

declare global {
  interface HTMLElementTagNameMap {
    'vw-popup-app': VwPopupApp;
  }
}
