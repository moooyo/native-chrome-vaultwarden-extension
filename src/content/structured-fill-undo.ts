import type { FillFieldElement } from './field-detection.js';
import { isFillableField } from './field-detection.js';
import { captureControlOwner, hasSameControlOwner } from './form-detection.js';
import { setElementValue } from './native-set-value.js';

export const STRUCTURED_UNDO_TTL_MS = 3000;

export interface StructuredFieldWrite {
  readonly element: FillFieldElement;
  readonly before: string;
  /** The value read immediately after the native setter, before page event handlers run. */
  readonly written: string;
}

export interface StructuredFillUndo {
  readonly count: number;
  remainingMs(): number;
  undo(): number;
  dispose(): void;
}

/** Keep an ephemeral receipt in the isolated world; no values or target identifiers enter the UI. */
export function createStructuredFillUndo(
  writes: readonly StructuredFieldWrite[],
  isCurrent: () => boolean,
  now: () => number = Date.now,
): StructuredFillUndo {
  const expiresAt = now() + STRUCTURED_UNDO_TTL_MS;
  let entries = writes.filter((entry) => entry.before !== entry.written).map((entry) => {
    let edited = false;
    const trackEdit = (event: Event): void => { if (event.isTrusted) edited = true; };
    entry.element.addEventListener('input', trackEdit, true);
    entry.element.addEventListener('change', trackEdit, true);
    return {
      ...entry,
      owner: captureControlOwner(entry.element),
      root: entry.element.getRootNode(),
      wasEdited: () => edited,
      stopTracking: () => {
        entry.element.removeEventListener('input', trackEdit, true);
        entry.element.removeEventListener('change', trackEdit, true);
      },
    };
  });
  const count = entries.length;
  const view = entries[0]?.element.ownerDocument.defaultView;
  let timer: number | undefined;
  const dispose = (): void => {
    for (const entry of entries) entry.stopTracking();
    entries = [];
    if (timer !== undefined) view?.clearTimeout(timer);
    timer = undefined;
  };
  timer = view?.setTimeout(dispose, STRUCTURED_UNDO_TTL_MS);
  return {
    count,
    remainingMs: () => Math.max(0, expiresAt - now()),
    dispose,
    undo(): number {
      const pending = entries;
      dispose();
      if (now() >= expiresAt || !isCurrent()) return 0;
      let restored = 0;
      for (const entry of pending) {
        if (!isCurrent()) break;
        if (entry.wasEdited() || !isFillableField(entry.element)
            || entry.element.getRootNode() !== entry.root
            || !hasSameControlOwner(captureControlOwner(entry.element), entry.owner)
            || entry.element.value !== entry.written) continue;
        setElementValue(entry.element, entry.before);
        restored += 1;
      }
      return restored;
    },
  };
}
