export const IDLE_LOCK_ALARM = 'idle-lock';

export interface AlarmHandlerDeps {
  auth: { lock(): Promise<void> };
  idleMs: number;
  now(): number;
  getLastActivity(): Promise<number | undefined>;
  setLastActivity(value: number): Promise<void>;
}

export function createAlarmHandlers(deps: AlarmHandlerDeps) {
  return {
    async touch(): Promise<void> {
      await deps.setLastActivity(deps.now());
    },

    async handleAlarm(name: string): Promise<void> {
      if (name !== IDLE_LOCK_ALARM) return;
      const last = await deps.getLastActivity();
      if (last === undefined) return;
      if (deps.now() - last > deps.idleMs) await deps.auth.lock();
    },
  };
}
