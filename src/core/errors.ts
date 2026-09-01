export type AppErrorCode =
  | 'error'
  | 'locked'
  | 'sync_required'
  | 'no_match'
  | 'stale_form'
  | 'reprompt_required'
  | 'invalid_pin'
  | 'pin_attempts_exceeded'
  | 'session_expired'
  | 'conflict'
  | 'outcome_unknown'
  | 'committed_unsynced'
  | 'denied';

export class AppError extends Error {
  constructor(
    readonly code: AppErrorCode,
    message: string,
  ) {
    super(message);
    this.name = 'AppError';
  }
}
