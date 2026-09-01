export const CLIENT_EVENT_BEST_EFFORT_WAIT_MS = 500;

type Settled<Value> =
  | { readonly kind: 'value'; readonly value: Value }
  | { readonly kind: 'failed' };

/** Bound optional audit work while continuing to observe any late rejection. */
export async function bestEffortClientEvent<Value>(
  operation: () => Value | PromiseLike<Value>,
  waitMs = CLIENT_EVENT_BEST_EFFORT_WAIT_MS,
): Promise<Value | undefined> {
  if (!Number.isSafeInteger(waitMs) || waitMs < 0) {
    throw new RangeError('Client event best-effort wait must be a non-negative safe integer');
  }
  let observed: Promise<Settled<Value>>;
  try {
    observed = Promise.resolve(operation()).then(
      (value) => Object.freeze({ kind: 'value' as const, value }),
      () => Object.freeze({ kind: 'failed' as const }),
    );
  } catch {
    return undefined;
  }
  if (waitMs === 0) return undefined;

  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<Readonly<{ kind: 'timeout' }>>((resolve) => {
    timer = setTimeout(() => resolve(Object.freeze({ kind: 'timeout' as const })), waitMs);
  });
  const result = await Promise.race([observed, timeout]);
  if (timer !== undefined) clearTimeout(timer);
  return result.kind === 'value' ? result.value : undefined;
}
