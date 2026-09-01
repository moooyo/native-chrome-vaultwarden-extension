import { utf8ToBytes } from '../core/crypto/encoding.js';
import { isContentTotpClipboardCode } from '../messaging/totp-clipboard-code.js';

export const CLIPBOARD_CLEAR_ALARM = 'clipboard-clear';
export const MAX_CLIPBOARD_SECRET_UTF8_BYTES = 32 * 1_024;

export type ClipboardWriteMessage =
  | { readonly type: 'offscreen.writeClipboard'; readonly value: string }
  | { readonly type: 'offscreen.writeSecretClipboard'; readonly value: string };

export interface ClipboardDeps {
  getClearSeconds(): Promise<number | null>;
  createAlarm(name: string, scheduledTime: number): void;
  clearAlarm(name: string): void;
  now(): number;
  digestValue?(value: string): Promise<Uint8Array>;
  ensureOffscreen(): Promise<void>;
  sendOffscreen(msg: { type: 'offscreen.clearClipboardIfOwned'; expectedDigest: number[] }): Promise<unknown>;
  writeOffscreen?(msg: ClipboardWriteMessage): Promise<unknown>;
  closeOffscreen(): Promise<void>;
}

interface ClipboardOwnership {
  readonly digest: Uint8Array;
  readonly scheduledTime: number;
  readonly generation: number;
}

interface PendingClipboardClaim {
  readonly generation: number;
  owner: 'schedule' | 'transition' | 'released';
  setting: 'pending' | 'enabled' | 'never' | 'error';
  readonly digestReady: Promise<Uint8Array>;
  settled: Promise<void> | undefined;
  digest: Uint8Array | undefined;
}

export function createClipboard(deps: ClipboardDeps) {
  // Clipboard ownership is deliberately a memory-only, erasable digest. Persisting plaintext or a
  // digest would leave low-entropy values such as TOTP codes open to offline enumeration. An MV3 worker
  // restart therefore forgets ownership and the surviving alarm safely becomes a no-op.
  let ownership: ClipboardOwnership | undefined;
  let pendingClaim: PendingClipboardClaim | undefined;
  let scheduleGeneration = 0;
  let lastScheduledTime = 0;
  let writeClearTail: Promise<void> = Promise.resolve();

  function serializeWriteClear<Result>(operation: () => Promise<Result>): Promise<Result> {
    const result = writeClearTail.then(operation);
    writeClearTail = result.then(() => undefined, () => undefined);
    return result;
  }

  function clearOwnership(): void {
    ownership?.digest.fill(0);
    ownership = undefined;
  }

  function cancelClear(): void {
    scheduleGeneration += 1;
    clearOwnership();
    try {
      deps.clearAlarm(CLIPBOARD_CLEAR_ALARM);
    } catch (error) {
      // A stale alarm is harmless once in-memory ownership is gone.
      console.warn('clipboard alarm cancellation failed', error);
    }
  }

  async function digestForSchedule(value: string): Promise<Uint8Array> {
    const digest = await (deps.digestValue ?? digestClipboardValue)(value);
    if (digest.length !== 32) {
      digest.fill(0);
      throw new Error('invalid clipboard digest');
    }
    return digest;
  }

  async function settlePendingClaim(claim: PendingClipboardClaim): Promise<void> {
    try {
      const digest = await claim.digestReady;
      claim.digest = digest;
      if (claim.owner !== 'schedule' || claim.generation !== scheduleGeneration) return;
      let seconds: number | null;
      try {
        seconds = await deps.getClearSeconds();
      } catch (error) {
        claim.setting = 'error';
        throw error;
      }
      claim.setting = seconds === null ? 'never' : 'enabled';
      if (claim.owner !== 'schedule' || claim.generation !== scheduleGeneration) return;
      if (seconds === null) return;
      // Use an absolute, strictly increasing timestamp as the alarm's in-memory generation token. If
      // Chrome already dispatched the replaced alarm, its older scheduledTime cannot consume this copy.
      const scheduledTime = Math.max(deps.now() + Math.max(30, seconds) * 1_000, lastScheduledTime + 1);
      try {
        deps.createAlarm(CLIPBOARD_CLEAR_ALARM, scheduledTime);
      } catch (error) {
        deps.clearAlarm(CLIPBOARD_CLEAR_ALARM);
        throw error;
      }
      lastScheduledTime = scheduledTime;
      ownership = { digest, scheduledTime, generation: claim.generation };
      claim.digest = undefined;
      claim.owner = 'released';
    } finally {
      if (claim.owner === 'schedule') {
        claim.digest?.fill(0);
        claim.digest = undefined;
        claim.owner = 'released';
      }
      if (claim.owner === 'released' && pendingClaim === claim) pendingClaim = undefined;
    }
  }

  async function clearClaimed(
    digest: Uint8Array,
    isCurrent: () => boolean = () => true,
  ): Promise<void> {
    const expectedDigest = Array.from(digest);
    try {
      await deps.ensureOffscreen();
      if (!isCurrent()) return;
      const result = await deps.sendOffscreen({
        type: 'offscreen.clearClipboardIfOwned',
        expectedDigest,
      });
      if (!isClipboardClearSuccess(result)) {
        const message = isClipboardClearFailure(result) ? result.error : 'Invalid offscreen response';
        throw new Error(message);
      }
    } catch (error) {
      // Do not re-arm (that risks a wake loop), but retain a diagnostic instead of treating a
      // rejected clipboard overwrite as success.
      console.warn('clipboard clear failed', error);
    } finally {
      digest.fill(0);
      expectedDigest.fill(0);
      await deps.closeOffscreen().catch(() => {/* ignore */});
    }
  }

  function scheduleClear(value: string): Promise<void> {
    if (typeof value !== 'string') return Promise.reject(new TypeError('clipboard value must be a string'));
    const generation = ++scheduleGeneration;
    clearOwnership();
    deps.clearAlarm(CLIPBOARD_CLEAR_ALARM);
    if (value.length === 0) return Promise.resolve();

    const claim: PendingClipboardClaim = {
      generation,
      owner: 'schedule',
      setting: 'pending',
      digestReady: digestForSchedule(value),
      settled: undefined,
      digest: undefined,
    };
    const settled = settlePendingClaim(claim);
    claim.settled = settled;
    pendingClaim = claim;
    // Plaintext is confined to the digest continuation; settings and ownership use only its result.
    return settled;
  }

  function scheduleClearDigest(digest: Uint8Array): Promise<void> {
    if (digest.length !== 32) {
      digest.fill(0);
      return Promise.reject(new TypeError('invalid clipboard digest'));
    }
    const generation = ++scheduleGeneration;
    clearOwnership();
    try {
      deps.clearAlarm(CLIPBOARD_CLEAR_ALARM);
    } catch (error) {
      digest.fill(0);
      throw error;
    }
    const claim: PendingClipboardClaim = {
      generation,
      owner: 'schedule',
      setting: 'pending',
      digestReady: Promise.resolve(digest),
      settled: undefined,
      digest: undefined,
    };
    const settled = settlePendingClaim(claim);
    claim.settled = settled;
    pendingClaim = claim;
    return settled;
  }

  function writeAndClaim(
    value: string,
    type: ClipboardWriteMessage['type'],
    accepts: (candidate: unknown) => candidate is string,
    assertCurrent: () => void,
  ): Promise<boolean> {
    if (!accepts(value) || typeof assertCurrent !== 'function') return Promise.resolve(false);
    const writeOffscreen = deps.writeOffscreen;
    if (typeof writeOffscreen !== 'function') return Promise.resolve(false);
    return serializeWriteClear(async () => {
      let writtenDigest: Uint8Array | undefined;
      try {
        assertCurrent();
        // Compute the ownership proof while the old claim is still intact. It is also the only
        // value needed to clean up if authority is revoked during the browser write.
        writtenDigest = await digestForSchedule(value);
        await deps.ensureOffscreen();
        assertCurrent();
        const result = await writeOffscreen({ type, value });
        if (!isClipboardWriteSuccess(result)) return false;

        // The clipboard changed only after this acknowledgement, so a failed write leaves the
        // previous ownership and alarm untouched.
        cancelClear();
        try {
          assertCurrent();
        } catch (error) {
          const staleDigest = writtenDigest;
          writtenDigest = undefined;
          await clearClaimed(staleDigest);
          console.warn('clipboard write authority became stale', error);
          return false;
        }

        const claimedDigest = writtenDigest;
        writtenDigest = undefined;
        try {
          await scheduleClearDigest(claimedDigest);
        } catch (error) {
          // The copy succeeded. Preserve that truthful result while recording the clear failure.
          console.warn('clipboard ownership claim failed', error);
        }
        return true;
      } catch (error) {
        console.warn('clipboard write failed', error);
        return false;
      } finally {
        writtenDigest?.fill(0);
        await deps.closeOffscreen().catch(() => {/* ignore */});
      }
    });
  }

  return {
    /** Write through the worker-owned offscreen document, then claim clear ownership only after the
     * browser confirms the write. The shared lane prevents an older clear from crossing this write. */
    writeAndScheduleClear(value: string, assertCurrent: () => void = () => {}): Promise<boolean> {
      return writeAndClaim(value, 'offscreen.writeClipboard', isContentTotpClipboardCode, assertCurrent);
    },

    /** Explicit alias used by TOTP callers so generic secret writes cannot accidentally inherit the
     * constrained content-code wire format. */
    writeTotpAndScheduleClear(value: string, assertCurrent: () => void = () => {}): Promise<boolean> {
      return writeAndClaim(value, 'offscreen.writeClipboard', isContentTotpClipboardCode, assertCurrent);
    },

    /** Write a bounded arbitrary secret through the worker-only offscreen route. */
    writeSecretAndScheduleClear(value: string, assertCurrent: () => void = () => {}): Promise<boolean> {
      return writeAndClaim(value, 'offscreen.writeSecretClipboard', isBoundedClipboardSecret, assertCurrent);
    },

    /** Schedule (or cancel) the background clipboard clear. A same-named alarm replaces the prior one,
     *  so back-to-back copies collapse to a single clear at the latest deadline. Only the newest
     *  in-flight settings lookup may claim ownership. */
    scheduleClear,

    cancelClear,

    /** Clear an owned value immediately after a successful security-sensitive session transition.
     *  The old claim is consumed before reading settings so a concurrent new copy gets an independent
     *  ownership slot and cannot be cleared by this attempt. */
    clearOwnedOnSessionTransition(): Promise<void> {
      return serializeWriteClear(async () => {
        const generation = scheduleGeneration;
        const pending = pendingClaim?.generation === generation
          && pendingClaim.owner === 'schedule'
          ? pendingClaim
          : undefined;
        if (pending) pending.owner = 'transition';
        const claimed = ownership?.generation === generation ? ownership : undefined;
        const clearGeneration = ++scheduleGeneration;
        ownership = undefined;
        try {
          deps.clearAlarm(CLIPBOARD_CLEAR_ALARM);
        } catch (error) {
          console.warn('clipboard alarm cancellation failed', error);
        }

        let digest = claimed?.digest;
        try {
          if (pending) {
            try {
              await pending.settled;
            } catch (error) {
              if (pending.setting !== 'error') {
                console.warn('clipboard ownership claim failed', error);
              }
            }
            if (pending.setting === 'never' || clearGeneration !== scheduleGeneration) return;
            digest = pending.digest;
          }
          if (!digest) return;

          try {
            if (await deps.getClearSeconds() === null) return;
          } catch (error) {
            // A transient settings read must not turn an already-owned secret into an unbounded leak.
            // A saved Never value synchronously calls cancelClear(), which changes the generation.
            console.warn('clipboard clear setting read failed', error);
          }
          if (clearGeneration !== scheduleGeneration) return;

          await clearClaimed(digest, () => clearGeneration === scheduleGeneration);
          digest = undefined;
        } finally {
          digest?.fill(0);
          if (pending) {
            pending.digest = undefined;
            pending.owner = 'released';
            if (pendingClaim === pending) pendingClaim = undefined;
          }
        }
      });
    },

    /** Fired by the alarm: conditionally clear only the value this worker still owns. */
    handleClipboardAlarm(scheduledTime: number): Promise<void> {
      return serializeWriteClear(async () => {
        const claimed = ownership;
        if (!claimed || claimed.scheduledTime !== scheduledTime) return;
        // Consume before the first await. A copy that races this clear receives a fresh ownership slot
        // and alarm; this attempt can only compare against the value it captured above.
        ownership = undefined;
        await clearClaimed(claimed.digest);
      });
    },
  };
}

export function isBoundedClipboardSecret(value: unknown): value is string {
  if (typeof value !== 'string' || value.length === 0) return false;
  const bytes = new TextEncoder().encode(value);
  try {
    return bytes.byteLength <= MAX_CLIPBOARD_SECRET_UTF8_BYTES
      && new TextDecoder('utf-8', { fatal: true }).decode(bytes) === value;
  } catch {
    return false;
  } finally {
    bytes.fill(0);
  }
}

async function digestClipboardValue(value: string): Promise<Uint8Array> {
  const bytes = utf8ToBytes(value);
  try {
    return new Uint8Array(await globalThis.crypto.subtle.digest('SHA-256', bytes as BufferSource));
  } finally {
    bytes.fill(0);
  }
}

function isClipboardClearSuccess(value: unknown): value is { ok: true; cleared: boolean } {
  return typeof value === 'object'
    && value !== null
    && (value as { ok?: unknown }).ok === true
    && typeof (value as { cleared?: unknown }).cleared === 'boolean';
}

function isClipboardClearFailure(value: unknown): value is { ok: false; error: string } {
  return typeof value === 'object'
    && value !== null
    && (value as { ok?: unknown }).ok === false
    && typeof (value as { error?: unknown }).error === 'string';
}

function isClipboardWriteSuccess(value: unknown): value is { ok: true; written: true } {
  return typeof value === 'object'
    && value !== null
    && (value as { ok?: unknown }).ok === true
    && (value as { written?: unknown }).written === true;
}
