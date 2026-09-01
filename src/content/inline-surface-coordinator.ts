const INLINE_SURFACE_REGISTRY = Symbol.for('miyu.inlineSurfaceRegistry.v1');

interface InlineSurfaceEntry {
  readonly owner: object;
  readonly priority: number;
  readonly revoke: () => void;
}

interface InlineSurfaceRegistry {
  readonly version: 1;
  readonly entries: WeakMap<HTMLElement, InlineSurfaceEntry>;
}

/** Return the document-wide collision scope used by every visible inline credential surface. */
export function inlineSurfaceScope(anchor: HTMLElement): HTMLElement {
  return anchor.ownerDocument.documentElement;
}

/** Claim one collision scope and synchronously revoke any previously visible surface in it. */
export function claimInlineSurface(
  scope: HTMLElement,
  owner: object,
  revoke: () => void,
  priority = 0,
): boolean {
  const entries = registry().entries;
  const current = entries.get(scope);
  if (current?.owner === owner) return true;
  if (current && current.priority > priority) return false;
  if (current) {
    entries.delete(scope);
    current.revoke();
  }
  entries.set(scope, { owner, priority, revoke });
  return true;
}

export function releaseInlineSurface(scope: HTMLElement, owner: object): void {
  const entries = registry().entries;
  if (entries.get(scope)?.owner === owner) entries.delete(scope);
}

function registry(): InlineSurfaceRegistry {
  const holder = (typeof document === 'object' ? document : globalThis) as unknown as Record<PropertyKey, unknown>;
  const existing = holder[INLINE_SURFACE_REGISTRY];
  if (isRegistry(existing)) return existing;
  const created: InlineSurfaceRegistry = Object.freeze({
    version: 1,
    entries: new WeakMap(),
  });
  try {
    Object.defineProperty(holder, INLINE_SURFACE_REGISTRY, {
      configurable: true,
      value: created,
    });
  } catch {
    return created;
  }
  return created;
}

function isRegistry(value: unknown): value is InlineSurfaceRegistry {
  if (typeof value !== 'object' || value === null) return false;
  const candidate = value as Partial<InlineSurfaceRegistry>;
  const entries = candidate.entries as Partial<WeakMap<HTMLElement, InlineSurfaceEntry>> | undefined;
  return candidate.version === 1
    && typeof entries?.get === 'function'
    && typeof entries.set === 'function'
    && typeof entries.delete === 'function';
}
