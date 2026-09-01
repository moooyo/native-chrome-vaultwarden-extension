import type { OnIdleAction } from './settings.js';

export const IDLE_LOCK_ALARM = 'idle-lock';
export type IdleState = 'active' | 'idle' | 'locked';

export interface IdleLockDeps {
  /** Idle and system-lock triggers are independent so event-only policies need no fake timeout. */
  getConfig(): Promise<{
    idleSeconds: number | null;
    lockOnSystemLock: boolean;
    action: OnIdleAction;
  }>;
  isUnlocked(): Promise<boolean>;
  lock(): Promise<void>;
  logout(): Promise<void>;
  queryState(detectionSeconds: number): Promise<IdleState>;
  setDetectionInterval(seconds: number): void;
}

/** chrome.idle detection interval minimum. */
const MIN_DETECTION_SECONDS = 15;
/** When disabled, set a large interval because ordinary idle events are intentionally ignored. */
const SENTINEL_SECONDS = 4 * 3600;

export function createIdleLock(deps: IdleLockDeps) {
  async function applyAction(action: OnIdleAction): Promise<void> {
    if (!(await deps.isUnlocked())) return;           // idempotent: no cascade on double-trigger
    await (action === 'logout' ? deps.logout() : deps.lock());
  }
  return {
    async applyDetection(): Promise<void> {
      const { lockOnSystemLock } = await deps.getConfig();
      deps.setDetectionInterval(lockOnSystemLock ? MIN_DETECTION_SECONDS : SENTINEL_SECONDS);
    },
    async onStateChanged(state: IdleState): Promise<void> {
      if (state !== 'locked') return;
      const { lockOnSystemLock, action } = await deps.getConfig();
      if (state === 'locked' && lockOnSystemLock) await applyAction(action);
    },
    async onBackstopAlarm(): Promise<void> {
      const { lockOnSystemLock, action } = await deps.getConfig();
      if (!lockOnSystemLock) return;
      const state = await deps.queryState(MIN_DETECTION_SECONDS);
      if (state === 'locked' && lockOnSystemLock) await applyAction(action);
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
