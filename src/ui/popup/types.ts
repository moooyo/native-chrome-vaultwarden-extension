import type { sendRequest } from '../../messaging/protocol.js';

/**
 * The dormant Lit popup's client-side router state. Every screen the popup can show is one
 * variant here; `VwPopupApp` owns the current value and hands it to feature views as props.
 */
export type PopupRoute =
  | { name: 'loading' }
  | { name: 'login'; error?: string }
  | { name: 'register'; error?: string }
  | { name: 'twoFactor'; providers: number[]; error?: string }
  | { name: 'unlock'; error?: string }
  | { name: 'vault'; scope: 'suggestions' | 'all'; error?: string }
  | { name: 'detail'; cipherId: string }
  | { name: 'editor'; mode: 'create' | 'edit'; cipherId?: string; cipherType?: 1 | 2 | 3 | 4 }
  | { name: 'generator' | 'health' | 'sends' | 'trash' | 'accountSecurity' | 'pin' };

/** The worker request function every popup surface is injected with; never called directly by
 *  feature/shared components — only `VwPopupApp` performs requests. */
export type PopupRequest = typeof sendRequest;

/** Thin seam around the few `webextension-polyfill` calls the popup root needs, so tests can
 *  inject a fake instead of touching real browser APIs. */
export interface PopupBrowser {
  getActiveTabId(): Promise<number | undefined>;
  openOptions(): Promise<void>;
  openReceive(): Promise<void>;
}
