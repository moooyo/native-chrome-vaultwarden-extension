import type { ReactiveController, ReactiveControllerHost } from 'lit';
import browser from 'webextension-polyfill';

/**
 * Appearance preferences (theme + list density) — purely local UI state, stored in
 * `browser.storage.local` and synced across contexts, never sent to the vault server. Applied as
 * `data-theme` / `data-density` attributes on each page root's host element; because the palette
 * tokens are gated on `:host([data-theme=…])` and inherit into descendants, flipping the attribute
 * re-themes the whole tree at runtime.
 *
 * Default theme is `light` (the design's default selection); `system` follows `prefers-color-scheme`.
 */
export type ThemeSetting = 'light' | 'dark' | 'system';
export type DensitySetting = 'comfortable' | 'compact';

export const THEMES: readonly ThemeSetting[] = ['light', 'dark', 'system'];
export const DEFAULT_THEME: ThemeSetting = 'light';
export const DEFAULT_DENSITY: DensitySetting = 'comfortable';

const THEME_KEY = 'miyu.theme';
const DENSITY_KEY = 'miyu.density';

let currentTheme: ThemeSetting = DEFAULT_THEME;
let currentDensity: DensitySetting = DEFAULT_DENSITY;
const listeners = new Set<() => void>();
let storageSynced = false;

function isTheme(v: unknown): v is ThemeSetting {
  return v === 'light' || v === 'dark' || v === 'system';
}
function isDensity(v: unknown): v is DensitySetting {
  return v === 'comfortable' || v === 'compact';
}

export function getTheme(): ThemeSetting {
  return currentTheme;
}
export function getDensity(): DensitySetting {
  return currentDensity;
}

export function setTheme(theme: ThemeSetting, persist = true): void {
  if (!isTheme(theme) || theme === currentTheme) return;
  currentTheme = theme;
  if (persist) void safeSet(THEME_KEY, theme);
  notify();
}
export function setDensity(density: DensitySetting, persist = true): void {
  if (!isDensity(density) || density === currentDensity) return;
  currentDensity = density;
  if (persist) void safeSet(DENSITY_KEY, density);
  notify();
}

async function safeSet(key: string, value: string): Promise<void> {
  try {
    await browser.storage.local.set({ [key]: value });
  } catch {
    /* storage unavailable */
  }
}

function notify(): void {
  for (const listener of listeners) listener();
}

export function subscribeAppearance(fn: () => void): () => void {
  listeners.add(fn);
  return () => listeners.delete(fn);
}

/** Loads persisted appearance prefs (once) and installs cross-context sync. */
export async function initAppearance(): Promise<void> {
  installStorageSync();
  try {
    const got = await browser.storage.local.get([THEME_KEY, DENSITY_KEY]);
    if (isTheme(got[THEME_KEY])) currentTheme = got[THEME_KEY];
    if (isDensity(got[DENSITY_KEY])) currentDensity = got[DENSITY_KEY];
  } catch {
    /* storage unavailable */
  }
  // Re-notify so any controller that already applied the default re-reads the persisted values.
  notify();
}

function installStorageSync(): void {
  if (storageSynced) return;
  storageSynced = true;
  try {
    browser.storage.onChanged.addListener((changes, area) => {
      if (area !== 'local') return;
      let changed = false;
      const themeChange = changes[THEME_KEY];
      if (themeChange && isTheme(themeChange.newValue) && themeChange.newValue !== currentTheme) {
        currentTheme = themeChange.newValue;
        changed = true;
      }
      const densityChange = changes[DENSITY_KEY];
      if (densityChange && isDensity(densityChange.newValue) && densityChange.newValue !== currentDensity) {
        currentDensity = densityChange.newValue;
        changed = true;
      }
      if (changed) notify();
    });
  } catch {
    /* storage.onChanged unavailable (e.g. tests) */
  }
}

/**
 * Lit controller for a page ROOT host (`vw-popup-app` / `vw-options-app` / `vw-receive-app`): mirrors
 * the current theme + density onto the host's `data-theme` / `data-density` attributes and keeps them
 * in sync. Child components don't need this — they inherit the resolved tokens.
 */
export class AppearanceController implements ReactiveController {
  private unsubscribe: (() => void) | undefined = undefined;

  constructor(private readonly host: ReactiveControllerHost & HTMLElement) {
    host.addController(this);
  }

  private apply(): void {
    this.host.setAttribute('data-theme', currentTheme);
    this.host.setAttribute('data-density', currentDensity);
  }

  hostConnected(): void {
    this.apply();
    this.unsubscribe = subscribeAppearance(() => {
      this.apply();
      this.host.requestUpdate();
    });
  }

  hostDisconnected(): void {
    this.unsubscribe?.();
    this.unsubscribe = undefined;
  }
}
