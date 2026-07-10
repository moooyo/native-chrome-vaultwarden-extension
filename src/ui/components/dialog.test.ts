// @vitest-environment happy-dom
import { afterEach, describe, expect, it, vi } from 'vitest';
import './dialog.js';
import type { VwDialog } from './dialog.js';

function makeTrigger(): HTMLButtonElement {
  const trigger = document.createElement('button');
  trigger.textContent = 'Open dialog';
  document.body.append(trigger);
  return trigger;
}

async function mountDialog(cancelable = true): Promise<VwDialog> {
  const dialog = document.createElement('vw-dialog') as VwDialog;
  dialog.heading = 'Delete item';
  dialog.cancelable = cancelable;
  const confirmButton = document.createElement('button');
  confirmButton.slot = 'actions';
  confirmButton.textContent = 'Confirm';
  confirmButton.setAttribute('autofocus', '');
  dialog.append(confirmButton);
  document.body.append(dialog);
  await dialog.updateComplete;
  return dialog;
}

describe('vw-dialog', () => {
  afterEach(() => {
    document.body.replaceChildren();
  });


  it('uses a native <dialog> with a heading and slotted content', async () => {
    const dialog = await mountDialog();
    const nativeDialog = dialog.shadowRoot?.querySelector('dialog');
    expect(nativeDialog).not.toBeNull();
    expect(nativeDialog?.querySelector('h2')?.textContent).toContain('Delete item');
  });

  it('moves initial focus to the slotted autofocus target when opened', async () => {
    const trigger = makeTrigger();
    trigger.focus();
    const dialog = await mountDialog();
    const confirmButton = dialog.querySelector('[autofocus]') as HTMLButtonElement;
    dialog.open = true;
    await dialog.updateComplete;
    expect(document.activeElement).toBe(confirmButton);
  });

  it('restores focus to the previously focused element on close', async () => {
    const trigger = makeTrigger();
    trigger.focus();
    const dialog = await mountDialog();
    dialog.open = true;
    await dialog.updateComplete;
    dialog.open = false;
    await dialog.updateComplete;
    expect(document.activeElement).toBe(trigger);
  });

  it('closes and emits a composed, bubbling vw-dialog-close on Escape when cancelable', async () => {
    const dialog = await mountDialog(true);
    dialog.open = true;
    await dialog.updateComplete;
    const closed = vi.fn();
    dialog.addEventListener('vw-dialog-close', closed);
    dialog.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true }));
    await dialog.updateComplete;
    expect(dialog.open).toBe(false);
    expect(closed).toHaveBeenCalledWith(expect.objectContaining({
      detail: { reason: 'escape' },
      bubbles: true,
      composed: true,
    }));
  });

  it('ignores Escape in non-cancelable (destructive) mode', async () => {
    const dialog = await mountDialog(false);
    dialog.open = true;
    await dialog.updateComplete;
    const closed = vi.fn();
    dialog.addEventListener('vw-dialog-close', closed);
    dialog.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true }));
    await dialog.updateComplete;
    expect(dialog.open).toBe(true);
    expect(closed).not.toHaveBeenCalled();
  });

  it('closes on a backdrop click when cancelable', async () => {
    const dialog = await mountDialog(true);
    dialog.open = true;
    await dialog.updateComplete;
    const closed = vi.fn();
    dialog.addEventListener('vw-dialog-close', closed);
    const nativeDialog = dialog.shadowRoot!.querySelector('dialog')!;
    nativeDialog.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    await dialog.updateComplete;
    expect(dialog.open).toBe(false);
    expect(closed).toHaveBeenCalledWith(expect.objectContaining({ detail: { reason: 'backdrop' } }));
  });

  it('ignores a backdrop click in non-cancelable (destructive) mode', async () => {
    const dialog = await mountDialog(false);
    dialog.open = true;
    await dialog.updateComplete;
    const nativeDialog = dialog.shadowRoot!.querySelector('dialog')!;
    nativeDialog.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    await dialog.updateComplete;
    expect(dialog.open).toBe(true);
  });

  it('hides the built-in dismiss button in non-cancelable mode', async () => {
    const dialog = await mountDialog(false);
    expect(dialog.shadowRoot?.querySelector('.dialog-dismiss')).toBeNull();
  });

  it('allows an explicit requestClose reason even when non-cancelable', async () => {
    const dialog = await mountDialog(false);
    dialog.open = true;
    await dialog.updateComplete;
    const closed = vi.fn();
    dialog.addEventListener('vw-dialog-close', closed);
    dialog.requestClose('confirm');
    await dialog.updateComplete;
    expect(dialog.open).toBe(false);
    expect(closed).toHaveBeenCalledWith(expect.objectContaining({ detail: { reason: 'confirm' } }));
  });

  it('removes the document focusin listener on disconnect', async () => {
    const dialog = await mountDialog();
    dialog.open = true;
    await dialog.updateComplete;
    const removeSpy = vi.spyOn(document, 'removeEventListener');
    dialog.remove();
    expect(removeSpy).toHaveBeenCalledWith('focusin', expect.any(Function));
    removeSpy.mockRestore();
  });
});
