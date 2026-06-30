export const IDLE_LOCK_ALARM = 'idle-lock';

export interface AlarmHandlerDeps {
  auth: { lock(): Promise<void> };
  /** Current idle window in ms, or null to disable idle-locking (read live on each tick). */
  getIdleMs(): Promise<number | null>;
  now(): number;
  getLastActivity(): Promise<number | undefined>;
  setLastActivity(value: number): Promise<void>;
}

export function createAlarmHandlers(deps: AlarmHandlerDeps) {
  return {
    async touch(): Promise<void> {
      await deps.setLastActivity(deps.now());
    },

    async handleAlarm(name: string): Promise<boolean> {
      if (name !== IDLE_LOCK_ALARM) return false;
      const idleMs = await deps.getIdleMs();
      if (idleMs === null) return false;
      const last = await deps.getLastActivity();
      if (last === undefined) return false;
      if (deps.now() - last > idleMs) {
        await deps.auth.lock();
        return true;
      }
      return false;
    },
  };
}
