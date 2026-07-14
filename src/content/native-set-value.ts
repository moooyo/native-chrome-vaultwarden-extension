// Frameworks like React attach an instance-level value tracker to inputs: it caches the last value the
// framework itself set and, on the next `input` event, compares it to decide whether to fire onChange.
// Assigning `el.value = x` directly goes through that tracked setter and updates the cache too, so the
// change looks like a no-op and the controlled component's state never updates — the field shows the
// value but the form submits blank/stale data. Writing through the native prototype setter updates the
// real DOM value WITHOUT touching the tracker's cache, so the dispatched `input` event is seen as a real
// change. Falls back to a direct assignment where a prototype setter is unavailable.

type ValuedElement = HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement;

function prototypeValueSetter(el: ValuedElement): ((value: string) => void) | undefined {
  const proto = el instanceof HTMLTextAreaElement
    ? HTMLTextAreaElement.prototype
    : el instanceof HTMLSelectElement
      ? HTMLSelectElement.prototype
      : HTMLInputElement.prototype;
  const setter = Object.getOwnPropertyDescriptor(proto, 'value')?.set;
  return setter ? (value: string) => setter.call(el, value) : undefined;
}

/** Set an element's value via the native prototype setter, bypassing framework value trackers. */
export function nativeSetValue(el: ValuedElement, value: string): void {
  const setter = prototypeValueSetter(el);
  if (setter) setter(value);
  else el.value = value;
}

/** Set the value (tracker-safe) and dispatch input + change so frameworks and listeners react. */
export function setElementValue(el: ValuedElement, value: string): void {
  nativeSetValue(el, value);
  el.dispatchEvent(new Event('input', { bubbles: true }));
  el.dispatchEvent(new Event('change', { bubbles: true }));
}
