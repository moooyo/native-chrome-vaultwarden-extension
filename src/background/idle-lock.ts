import type { OnIdleAction } from './settings.js';

export const IDLE_LOCK_ALARM = 'idle-lock';
export type IdleState = 'active' | 'idle' | 'locked';

export interface IdleLockDeps {
  /** idleSeconds=null means idle-locking is disabled (Never/On close). */
  getConfig(): Promise<{ idleSeconds: number | null; action: OnIdleAction }>;
  isUnlocked(): Promise<boolean>;
  lock(): Promise<void>;
  logout(): Promise<void>;
  queryState(detectionSeconds: number): Promise<IdleState>;
  setDetectionInterval(seconds: number): void;
}

/** chrome.idle detection interval minimum. */
const MIN_DETECTION_SECONDS = 15;
/** When disabled, set a large interval so 'idle' rarely fires; 'locked' is ignored by the applyAction gate. */
const SENTINEL_SECONDS = 4 * 3600;

/** Clamp a requested idle detection window to chrome.idle's hard minimum. Both the detection-interval
 *  setter and the backstop `queryState` call reject values below this, so every caller must clamp. */
function clampDetection(idleSeconds: number): number {
  return Math.max(MIN_DETECTION_SECONDS, idleSeconds);
}

export function createIdleLock(deps: IdleLockDeps) {
  async function applyAction(idleSeconds: number | null, action: OnIdleAction): Promise<void> {
    if (idleSeconds === null) return;                 // disabled — ignores idle AND locked
    if (!(await deps.isUnlocked())) return;           // idempotent: no cascade on double-trigger
    await (action === 'logout' ? deps.logout() : deps.lock());
  }
  return {
    async applyDetection(): Promise<void> {
      const { idleSeconds } = await deps.getConfig();
      deps.setDetectionInterval(idleSeconds === null ? SENTINEL_SECONDS : clampDetection(idleSeconds));
    },
    async onStateChanged(state: IdleState): Promise<void> {
      if (state !== 'idle' && state !== 'locked') return;
      const { idleSeconds, action } = await deps.getConfig();
      await applyAction(idleSeconds, action);
    },
    async onBackstopAlarm(): Promise<void> {
      const { idleSeconds, action } = await deps.getConfig();
      if (idleSeconds === null) return;
      const state = await deps.queryState(clampDetection(idleSeconds));
      if (state === 'idle' || state === 'locked') await applyAction(idleSeconds, action);
    },
  };
}

/** Minimal `chrome.alarms` surface `ensureIdleLockAlarm` depends on. */
export interface AlarmScheduler {
  get(name: string): Promise<{ name: string } | undefined>;
  create(name: string, options: { periodInMinutes: number }): void;
}

/** Idempotently ensure the idle-lock backstop alarm exists. The alarm is created in `onInstalled`,
 *  but MV3 can evict the worker and, in rare cases, drop its alarms; calling this on every cold SW
 *  start (and on `onStartup`) recreates a lost alarm. Recreating a present alarm would just reset its
 *  schedule, so we only create when `get` reports it missing. */
export async function ensureIdleLockAlarm(alarms: AlarmScheduler): Promise<void> {
  const existing = await alarms.get(IDLE_LOCK_ALARM);
  if (!existing) alarms.create(IDLE_LOCK_ALARM, { periodInMinutes: 1 });
}
