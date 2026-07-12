// Registers a content-script custom element defensively. Content scripts run in every frame
// (`all_frames: true`), including blank/synthetic frames whose window has no custom-element registry
// (`customElements` is null). Calling `define` there throws and kills the whole content script, so
// guard it — a frame without a registry simply gets no surfaces.
export function defineContentElement(tag: string, ctor: CustomElementConstructor): void {
  try {
    const registry = (globalThis as { customElements?: CustomElementRegistry }).customElements;
    if (registry && !registry.get(tag)) registry.define(tag, ctor);
  } catch {
    /* frame without a custom-element registry */
  }
}
