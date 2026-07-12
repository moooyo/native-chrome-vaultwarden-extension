import type { ReactiveController, ReactiveControllerHost } from 'lit';
import browser from 'webextension-polyfill';
import { zhCN } from './zh-CN.js';
import { en } from './en.js';

/**
 * Runtime i18n. A tiny in-memory locale store with `t()` lookup, persisted to
 * `browser.storage.local` and synced across contexts (options → popup → content) via
 * `storage.onChanged`, so the Appearance language switch takes effect live without a reload.
 *
 * `chrome.i18n` is intentionally NOT used: it resolves messages at load time and cannot switch
 * language without reloading the page, which the design's Appearance switcher requires.
 *
 * The zh-CN catalog is the source of truth for the key set; `MessageKey` is derived from it and the
 * English catalog is typed `Record<MessageKey, string>`, so a missing translation is a type error.
 */
export type Locale = 'zh-CN' | 'en';
export type MessageKey = keyof typeof zhCN;

export const LOCALES: readonly Locale[] = ['zh-CN', 'en'];
export const DEFAULT_LOCALE: Locale = 'zh-CN';
const STORAGE_KEY = 'miyu.locale';

const CATALOGS: Record<Locale, Record<MessageKey, string>> = { 'zh-CN': zhCN, en };

let current: Locale = DEFAULT_LOCALE;
const listeners = new Set<() => void>();
let storageSynced = false;

function isLocale(value: unknown): value is Locale {
  return value === 'zh-CN' || value === 'en';
}

export function getLocale(): Locale {
  return current;
}

/** Localised lookup with optional `{name}`-style interpolation. Falls back to the default catalog,
 *  then to the raw key, so a surface never renders blank. */
export function t(key: MessageKey, vars?: Record<string, string | number>): string {
  const table = CATALOGS[current] ?? CATALOGS[DEFAULT_LOCALE];
  let str = table[key] ?? CATALOGS[DEFAULT_LOCALE][key] ?? String(key);
  if (vars) {
    for (const [name, value] of Object.entries(vars)) {
      str = str.split(`{${name}}`).join(String(value));
    }
  }
  return str;
}

/** Changes the active locale, notifies subscribers, and (by default) persists across contexts. */
export function setLocale(locale: Locale, persist = true): void {
  if (!isLocale(locale) || locale === current) return;
  current = locale;
  if (persist) {
    try {
      void browser.storage.local.set({ [STORAGE_KEY]: locale });
    } catch {
      /* storage unavailable (e.g. tests) */
    }
  }
  for (const listener of listeners) listener();
}

/** Loads the persisted locale (once) and installs the cross-context sync listener. Call from each
 *  page/content entry point before first render. */
export async function initLocale(): Promise<Locale> {
  installStorageSync();
  try {
    const got = await browser.storage.local.get(STORAGE_KEY);
    if (isLocale(got[STORAGE_KEY])) current = got[STORAGE_KEY];
  } catch {
    /* storage unavailable */
  }
  for (const listener of listeners) listener();
  return current;
}

function installStorageSync(): void {
  if (storageSynced) return;
  storageSynced = true;
  try {
    browser.storage.onChanged.addListener((changes, area) => {
      if (area !== 'local') return;
      const change = changes[STORAGE_KEY];
      if (change && isLocale(change.newValue) && change.newValue !== current) {
        current = change.newValue;
        for (const listener of listeners) listener();
      }
    });
  } catch {
    /* storage.onChanged unavailable (e.g. tests) */
  }
}

export function subscribeLocale(fn: () => void): () => void {
  listeners.add(fn);
  return () => listeners.delete(fn);
}

/**
 * Lit controller that re-renders its host whenever the locale changes. A component composes it with
 * `private i18n = new LocalizeController(this)` and reads strings via `t(...)` (or `this.i18n.t`).
 */
export class LocalizeController implements ReactiveController {
  private unsubscribe: (() => void) | undefined = undefined;

  constructor(private readonly host: ReactiveControllerHost) {
    host.addController(this);
  }

  hostConnected(): void {
    this.unsubscribe = subscribeLocale(() => this.host.requestUpdate());
  }

  hostDisconnected(): void {
    this.unsubscribe?.();
    this.unsubscribe = undefined;
  }

  t(key: MessageKey, vars?: Record<string, string | number>): string {
    return t(key, vars);
  }
}
