import browser from 'webextension-polyfill';

/**
 * UI-local preferences that don't belong to the vault-server settings protocol: generator defaults,
 * inline-autofill display toggles, and the account auto-sync / biometric toggles. Persisted to
 * `browser.storage.local`, synced across contexts, and read by the popup generator + content
 * scripts. Same shape as `theme.ts`. Behavioral toggles (auto-sync/biometric/auto-submit) are stored
 * here so the UI is functional and the value survives; deeper background/content honoring is wired
 * separately where applicable.
 */
export interface MiyuPrefs {
  genLength: number;
  genNumbers: boolean;
  genSymbols: boolean;
  genUppercase: boolean;
  inlineSuggestions: boolean;
  autoSubmit: boolean;
  autoSync: boolean;
  biometric: boolean;
}

export const DEFAULT_PREFS: MiyuPrefs = {
  genLength: 20,
  genNumbers: true,
  genSymbols: true,
  genUppercase: true,
  inlineSuggestions: true,
  autoSubmit: false,
  autoSync: true,
  biometric: true,
};

const STORAGE_KEY = 'miyu.prefs';

let current: MiyuPrefs = { ...DEFAULT_PREFS };
const listeners = new Set<() => void>();
let storageSynced = false;

function sanitize(raw: unknown): Partial<MiyuPrefs> {
  if (!raw || typeof raw !== 'object') return {};
  const r = raw as Record<string, unknown>;
  const out: Partial<MiyuPrefs> = {};
  if (typeof r.genLength === 'number' && r.genLength >= 8 && r.genLength <= 40) out.genLength = Math.round(r.genLength);
  for (const key of ['genNumbers', 'genSymbols', 'genUppercase', 'inlineSuggestions', 'autoSubmit', 'autoSync', 'biometric'] as const) {
    if (typeof r[key] === 'boolean') out[key] = r[key] as boolean;
  }
  return out;
}

export function getPrefs(): MiyuPrefs {
  return current;
}

export function setPref<K extends keyof MiyuPrefs>(key: K, value: MiyuPrefs[K], persist = true): void {
  if (current[key] === value) return;
  current = { ...current, [key]: value };
  if (persist) {
    try {
      void browser.storage.local.set({ [STORAGE_KEY]: current });
    } catch {
      /* storage unavailable */
    }
  }
  for (const listener of listeners) listener();
}

export function subscribePrefs(fn: () => void): () => void {
  listeners.add(fn);
  return () => listeners.delete(fn);
}

export async function initPrefs(): Promise<MiyuPrefs> {
  installStorageSync();
  try {
    const got = await browser.storage.local.get(STORAGE_KEY);
    current = { ...DEFAULT_PREFS, ...sanitize(got[STORAGE_KEY]) };
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
      if (change) {
        current = { ...DEFAULT_PREFS, ...sanitize(change.newValue) };
        for (const listener of listeners) listener();
      }
    });
  } catch {
    /* storage.onChanged unavailable (e.g. tests) */
  }
}
