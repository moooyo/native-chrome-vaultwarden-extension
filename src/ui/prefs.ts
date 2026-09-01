import browser from 'webextension-polyfill';

/**
 * UI-local generator choices that don't belong to the vault-server settings protocol. Persisted to
 * `browser.storage.local` and synced across extension pages. Address/domain inputs are deliberately
 * excluded because they can identify an account and only need to live for the current popup view.
 */
export const MIYU_PREFS_SCHEMA_VERSION = 3 as const;

export type GeneratorPreferenceMode = 'random' | 'memorable' | 'pin' | 'username';
export type GeneratorUsernamePreferenceType = 'randomWord' | 'plusAddressed' | 'catchAll';

export interface MiyuPrefs {
  readonly schemaVersion: typeof MIYU_PREFS_SCHEMA_VERSION;
  readonly genMode: GeneratorPreferenceMode;
  readonly genLength: number;
  readonly genLowercase: boolean;
  readonly genNumbers: boolean;
  readonly genSymbols: boolean;
  readonly genUppercase: boolean;
  readonly genMinNumbers: number;
  readonly genMinSpecial: number;
  readonly genAvoidAmbiguous: boolean;
  readonly genPassphraseWords: number;
  readonly genPassphraseCapitalize: boolean;
  readonly genPassphraseNumber: boolean;
  readonly genPinLength: number;
  readonly genUsernameType: GeneratorUsernamePreferenceType;
  readonly genUsernameLength: number;
  readonly genUsernameCapitalize: boolean;
  readonly genUsernameNumber: boolean;
}

export const DEFAULT_PREFS: Readonly<MiyuPrefs> = Object.freeze({
  schemaVersion: MIYU_PREFS_SCHEMA_VERSION,
  genMode: 'random',
  genLength: 20,
  genLowercase: true,
  genNumbers: true,
  genSymbols: true,
  genUppercase: true,
  genMinNumbers: 1,
  genMinSpecial: 1,
  genAvoidAmbiguous: true,
  genPassphraseWords: 6,
  genPassphraseCapitalize: false,
  genPassphraseNumber: false,
  genPinLength: 14,
  genUsernameType: 'randomWord',
  genUsernameLength: 8,
  genUsernameCapitalize: false,
  genUsernameNumber: false,
});

const STORAGE_KEY = 'miyu.prefs';

type WritableMiyuPrefKey = Exclude<keyof MiyuPrefs, 'schemaVersion'>;
type WritableMiyuPrefs = Pick<MiyuPrefs, WritableMiyuPrefKey>;

let current: Readonly<MiyuPrefs> = DEFAULT_PREFS;
const listeners = new Set<() => void>();
let storageSynced = false;

/** Decode legacy, version 2, and current preference shapes without retaining untrusted fields. */
export function sanitizePrefs(raw: unknown): Readonly<MiyuPrefs> {
  if (!isRecord(raw)) return DEFAULT_PREFS;
  const legacy = raw.schemaVersion === undefined;
  const version2 = raw.schemaVersion === 2;
  if (!legacy && !version2 && raw.schemaVersion !== MIYU_PREFS_SCHEMA_VERSION) return DEFAULT_PREFS;

  const numbers = booleanValue(raw.genNumbers, DEFAULT_PREFS.genNumbers);
  const symbols = booleanValue(raw.genSymbols, DEFAULT_PREFS.genSymbols);

  return Object.freeze({
    schemaVersion: MIYU_PREFS_SCHEMA_VERSION,
    genMode: legacy ? DEFAULT_PREFS.genMode : enumValue(raw.genMode, GENERATOR_MODES, DEFAULT_PREFS.genMode),
    genLength: boundedInteger(raw.genLength, 5, 128, DEFAULT_PREFS.genLength),
    genLowercase: version2 || legacy
      ? DEFAULT_PREFS.genLowercase
      : booleanValue(raw.genLowercase, DEFAULT_PREFS.genLowercase),
    genNumbers: numbers,
    genSymbols: symbols,
    genUppercase: booleanValue(raw.genUppercase, DEFAULT_PREFS.genUppercase),
    genMinNumbers: version2 || legacy
      ? (numbers ? DEFAULT_PREFS.genMinNumbers : 0)
      : numbers ? boundedInteger(raw.genMinNumbers, 1, 9, DEFAULT_PREFS.genMinNumbers) : 0,
    genMinSpecial: version2 || legacy
      ? (symbols ? DEFAULT_PREFS.genMinSpecial : 0)
      : symbols ? boundedInteger(raw.genMinSpecial, 1, 9, DEFAULT_PREFS.genMinSpecial) : 0,
    genAvoidAmbiguous: version2 || legacy
      ? DEFAULT_PREFS.genAvoidAmbiguous
      : booleanValue(raw.genAvoidAmbiguous, DEFAULT_PREFS.genAvoidAmbiguous),
    genPassphraseWords: legacy
      ? DEFAULT_PREFS.genPassphraseWords
      : boundedInteger(raw.genPassphraseWords, 3, 20, DEFAULT_PREFS.genPassphraseWords),
    genPassphraseCapitalize: legacy
      ? DEFAULT_PREFS.genPassphraseCapitalize
      : booleanValue(raw.genPassphraseCapitalize, DEFAULT_PREFS.genPassphraseCapitalize),
    genPassphraseNumber: legacy
      ? DEFAULT_PREFS.genPassphraseNumber
      : booleanValue(raw.genPassphraseNumber, DEFAULT_PREFS.genPassphraseNumber),
    genPinLength: legacy
      ? DEFAULT_PREFS.genPinLength
      : boundedInteger(raw.genPinLength, 8, 40, DEFAULT_PREFS.genPinLength),
    genUsernameType: legacy
      ? DEFAULT_PREFS.genUsernameType
      : enumValue(raw.genUsernameType, USERNAME_TYPES, DEFAULT_PREFS.genUsernameType),
    genUsernameLength: legacy
      ? DEFAULT_PREFS.genUsernameLength
      : boundedInteger(raw.genUsernameLength, 4, 32, DEFAULT_PREFS.genUsernameLength),
    genUsernameCapitalize: legacy
      ? DEFAULT_PREFS.genUsernameCapitalize
      : booleanValue(raw.genUsernameCapitalize, DEFAULT_PREFS.genUsernameCapitalize),
    genUsernameNumber: legacy
      ? DEFAULT_PREFS.genUsernameNumber
      : booleanValue(raw.genUsernameNumber, DEFAULT_PREFS.genUsernameNumber),
  });
}

export function getPrefs(): Readonly<MiyuPrefs> {
  return current;
}

export function setPref<K extends WritableMiyuPrefKey>(
  key: K,
  value: MiyuPrefs[K],
  persist = true,
): void {
  const next = sanitizePrefs({ ...current, [key]: value });
  if (next[key] !== value || samePrefs(current, next)) return;
  publish(next, persist);
}

/** Atomically update coupled generator preferences, producing one storage write and one notification. */
export function setPrefs(patch: Partial<WritableMiyuPrefs>, persist = true): void {
  const next = sanitizePrefs({ ...current, ...patch });
  const accepted = (Object.entries(patch) as Array<[WritableMiyuPrefKey, MiyuPrefs[WritableMiyuPrefKey]]>)
    .every(([key, value]) => next[key] === value);
  if (!accepted || samePrefs(current, next)) return;
  publish(next, persist);
}

export function subscribePrefs(fn: () => void): () => void {
  listeners.add(fn);
  return () => listeners.delete(fn);
}

export async function initPrefs(): Promise<MiyuPrefs> {
  installStorageSync();
  try {
    const got = await browser.storage.local.get(STORAGE_KEY);
    const raw = got[STORAGE_KEY];
    current = sanitizePrefs(raw);
    if (isRecord(raw) && (raw.schemaVersion === undefined || raw.schemaVersion === 2)) persistCurrent();
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
        const next = sanitizePrefs(change.newValue);
        if (samePrefs(current, next)) return;
        current = next;
        for (const listener of listeners) listener();
      }
    });
  } catch {
    /* storage.onChanged unavailable (e.g. tests) */
  }
}

const GENERATOR_MODES: readonly GeneratorPreferenceMode[] = ['random', 'memorable', 'pin', 'username'];
const USERNAME_TYPES: readonly GeneratorUsernamePreferenceType[] = ['randomWord', 'plusAddressed', 'catchAll'];

function publish(next: Readonly<MiyuPrefs>, persist: boolean): void {
  current = next;
  if (persist) persistCurrent();
  for (const listener of listeners) listener();
}

function persistCurrent(): void {
  try {
    void browser.storage.local.set({ [STORAGE_KEY]: current }).catch(() => undefined);
  } catch {
    /* storage unavailable */
  }
}

function samePrefs(first: Readonly<MiyuPrefs>, second: Readonly<MiyuPrefs>): boolean {
  return (Object.keys(DEFAULT_PREFS) as Array<keyof MiyuPrefs>)
    .every((key) => first[key] === second[key]);
}

function boundedInteger(value: unknown, min: number, max: number, fallback: number): number {
  return Number.isSafeInteger(value) && (value as number) >= min && (value as number) <= max
    ? value as number
    : fallback;
}

function booleanValue(value: unknown, fallback: boolean): boolean {
  return typeof value === 'boolean' ? value : fallback;
}

function enumValue<T extends string>(value: unknown, allowed: readonly T[], fallback: T): T {
  return typeof value === 'string' && allowed.includes(value as T) ? value as T : fallback;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
