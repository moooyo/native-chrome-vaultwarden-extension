export type AppErrorCode =
  | 'error'
  | 'locked'
  | 'sync_required'
  | 'no_match'
  | 'stale_form'
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
