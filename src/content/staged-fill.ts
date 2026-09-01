export type FillTargetRevalidator = () => boolean;

/**
 * Serializes synchronous DOM writes behind a fail-closed target check. Page input/change handlers
 * run during a write, so every successful write is followed by the same check before another field
 * may receive data. Once stale, a commit can never become current again.
 */
export interface StagedFillCommit {
  readonly stale: boolean;
  isCurrent(): boolean;
  write(writeValue: () => boolean): boolean;
}

export function createStagedFillCommit(
  revalidate: FillTargetRevalidator = () => true,
): StagedFillCommit {
  let stale = false;

  const isCurrent = (): boolean => {
    if (stale) return false;
    try {
      if (revalidate()) return true;
    } catch {
      // A page-controlled DOM exception invalidates the rest of the staged commit.
    }
    stale = true;
    return false;
  };

  return Object.freeze({
    get stale() { return stale; },
    isCurrent,
    write(writeValue: () => boolean): boolean {
      if (!isCurrent()) return false;
      const wrote = writeValue();
      if (wrote) isCurrent();
      return wrote;
    },
  });
}
