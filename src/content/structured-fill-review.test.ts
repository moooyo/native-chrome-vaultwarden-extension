// @vitest-environment happy-dom
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { createFrameAutofillController } from './frame-autofill.js';
import { fillCardForm } from './fill-card-identity.js';
import { detectCardForms } from './field-detection.js';
import { createStructuredFillUndo, type StructuredFieldWrite } from './structured-fill-undo.js';
import { createStructuredPreview } from './ui/structured-preview-element.js';

const URL = 'https://checkout.example.test/';

function cardReview() {
  document.body.innerHTML = '<form><input autocomplete="cc-name" value="Existing name"><input autocomplete="cc-number"><input autocomplete="cc-csc"></form>';
  const controller = createFrameAutofillController({ root: document, frameUrl: () => URL, now: () => 100 });
  const inspection = controller.inspect();
  const card = inspection.forms.find((form) => form.kind === 'card')!;
  const request = {
    kind: 'card' as const, formId: card.formId, roles: card.roles,
    expectedGeneration: inspection.generation, expectedFrameUrl: inspection.frameUrl,
  };
  return { controller, request, inspection, card };
}

describe('reviewed structured fill', () => {
  beforeEach(() => { document.body.innerHTML = ''; });

  it('requires a local review and only fills the selected fields', () => {
    const { controller, request, inspection, card } = cardReview();
    const selectedRoles = ['number'] as const;
    expect(controller.commitStructured({ ...request, selectedRoles, data: { number: '4111111111111111' } })).toEqual({ status: 'target_changed' });
    expect(controller.prepareStructuredSelection(card.formId, inspection.generation, selectedRoles)).toBe(true);
    expect(controller.commitStructured({ ...request, selectedRoles, data: { number: '4111111111111111' } })).toEqual({ status: 'filled' });
    expect(document.querySelector<HTMLInputElement>('[autocomplete="cc-name"]')!.value).toBe('Existing name');
    expect(document.querySelector<HTMLInputElement>('[autocomplete="cc-csc"]')!.value).toBe('');
    expect(controller.takeStructuredUndo()?.undo()).toBe(1);
    expect(document.querySelector<HTMLInputElement>('[autocomplete="cc-number"]')!.value).toBe('');
  });

  it('refuses a changed value after review without overwriting the user', () => {
    const { controller, request, inspection, card } = cardReview();
    expect(controller.prepareStructuredSelection(card.formId, inspection.generation, ['number'])).toBe(true);
    const field = document.querySelector<HTMLInputElement>('[autocomplete="cc-number"]')!;
    field.value = 'User entered';
    expect(controller.commitStructured({ ...request, selectedRoles: ['number'], data: { number: '4111' } })).toEqual({ status: 'target_changed' });
    expect(field.value).toBe('User entered');
    expect(controller.takeStructuredUndo()).toBeUndefined();
  });

  it('consumes the review and rejects a widened or replayed selection', () => {
    const { controller, request, inspection, card } = cardReview();
    expect(controller.prepareStructuredSelection(card.formId, inspection.generation, ['number'])).toBe(true);
    expect(controller.commitStructured({ ...request, selectedRoles: ['number', 'code'], data: { number: '4111', code: '123' } })).toEqual({ status: 'target_changed' });
    expect(controller.commitStructured({ ...request, selectedRoles: ['number'], data: { number: '4111' } })).toEqual({ status: 'target_changed' });
    expect(document.querySelector<HTMLInputElement>('[autocomplete="cc-number"]')!.value).toBe('');
  });

  it('does not undo a control rebound to a different semantic role in the same form', () => {
    const { controller, request, inspection, card } = cardReview();
    controller.prepareStructuredSelection(card.formId, inspection.generation, ['number']);
    expect(controller.commitStructured({ ...request, selectedRoles: ['number'], data: { number: '4111' } })).toEqual({ status: 'filled' });
    const receipt = controller.takeStructuredUndo()!;
    const field = document.querySelector<HTMLInputElement>('[autocomplete="cc-number"]')!;
    field.autocomplete = 'email';
    expect(receipt.undo()).toBe(0);
    expect(field.value).toBe('4111');
  });

  it('does not fill an unselected full-name alias from selected first-name data', () => {
    document.body.innerHTML = '<form><input autocomplete="given-name"><input autocomplete="name"><input autocomplete="family-name"></form>';
    const controller = createFrameAutofillController({ root: document, frameUrl: () => URL, now: () => 100 });
    const inspection = controller.inspect();
    const identity = inspection.forms.find((form) => form.kind === 'identity')!;
    expect(controller.prepareStructuredSelection(identity.formId, inspection.generation, ['firstName'])).toBe(true);
    expect(controller.commitStructured({
      kind: 'identity', formId: identity.formId, roles: identity.roles, selectedRoles: ['firstName'],
      expectedGeneration: inspection.generation, expectedFrameUrl: inspection.frameUrl, data: { firstName: 'Ada' },
    })).toEqual({ status: 'filled' });
    expect(document.querySelector<HTMLInputElement>('[autocomplete="given-name"]')!.value).toBe('Ada');
    expect(document.querySelector<HTMLInputElement>('[autocomplete="name"]')!.value).toBe('');
  });

  it('stops later fields when a page handler changes a reviewed target value', () => {
    const { controller, request, inspection, card } = cardReview();
    const code = document.querySelector<HTMLInputElement>('[autocomplete="cc-csc"]')!;
    document.querySelector<HTMLInputElement>('[autocomplete="cc-number"]')!.addEventListener('input', () => { code.value = 'Keep me'; });
    controller.prepareStructuredSelection(card.formId, inspection.generation, ['number', 'code']);
    expect(controller.commitStructured({ ...request, selectedRoles: ['number', 'code'], data: { number: '4111', code: '123' } })).toEqual({ status: 'target_changed' });
    expect(code.value).toBe('Keep me');
  });

  it('allows formatting of an already written field while preserving its formatted value on undo', () => {
    const { controller, request, inspection, card } = cardReview();
    const number = document.querySelector<HTMLInputElement>('[autocomplete="cc-number"]')!;
    const code = document.querySelector<HTMLInputElement>('[autocomplete="cc-csc"]')!;
    number.addEventListener('input', () => { number.value = '4111 1111 1111 1111'; });
    controller.prepareStructuredSelection(card.formId, inspection.generation, ['number', 'code']);
    expect(controller.commitStructured({ ...request, selectedRoles: ['number', 'code'], data: { number: '4111111111111111', code: '123' } })).toEqual({ status: 'filled' });
    expect(code.value).toBe('123');
    expect(controller.takeStructuredUndo()!.undo()).toBe(1);
    expect(number.value).toBe('4111 1111 1111 1111');
    expect(code.value).toBe('');
  });
});

describe('structured fill undo', () => {
  beforeEach(() => { document.body.innerHTML = '<form><input autocomplete="cc-number"><input autocomplete="cc-csc"></form>'; });

  it('restores only unchanged native write values and can be used once', () => {
    const writes: StructuredFieldWrite[] = [];
    fillCardForm(detectCardForms()[0]!, { number: '4111', code: '123' }, undefined, (write) => writes.push(write));
    const receipt = createStructuredFillUndo(writes, () => true, () => 0);
    const code = document.querySelector<HTMLInputElement>('[autocomplete="cc-csc"]')!;
    code.value = 'User edit';
    expect(receipt.undo()).toBe(1);
    expect(code.value).toBe('User edit');
    expect(receipt.undo()).toBe(0);
  });

  it('does not mistake page event-handler edits for the value written by autofill', () => {
    const field = document.querySelector<HTMLInputElement>('[autocomplete="cc-number"]')!;
    field.addEventListener('input', () => { field.value = 'Page replacement'; });
    const writes: StructuredFieldWrite[] = [];
    fillCardForm(detectCardForms()[0]!, { number: '4111' }, undefined, (write) => writes.push(write));
    expect(writes[0]?.written).toBe('4111');
    expect(createStructuredFillUndo(writes, () => true, () => 0).undo()).toBe(0);
    expect(field.value).toBe('Page replacement');
  });

  it('expires at three seconds and refuses moved controls or retired runtime', () => {
    const field = document.querySelector<HTMLInputElement>('[autocomplete="cc-number"]')!;
    let now = 0;
    field.value = '4111';
    const receipt = createStructuredFillUndo([{ element: field, before: '', written: '4111' }], () => true, () => now);
    now = 3000;
    expect(receipt.undo()).toBe(0);
    const moved = createStructuredFillUndo([{ element: field, before: '', written: '4111' }], () => true, () => 0);
    const other = document.createElement('form'); document.body.append(other); other.append(field);
    expect(moved.undo()).toBe(0);
    expect(createStructuredFillUndo([{ element: field, before: '', written: '4111' }], () => false, () => 0).undo()).toBe(0);
    expect(field.value).toBe('4111');
  });
});

describe('structured review surface', () => {
  it('keeps existing fields unchecked, renders inert metadata, and rejects synthetic confirmation', () => {
    const onConfirm = vi.fn();
    const preview = createStructuredPreview({ kind: 'card', itemName: '<img src=x onerror=alert(1)>', site: 'checkout.example.test',
      fields: [{ role: 'cardholderName', hasValue: true }, { role: 'number', hasValue: false }, { role: 'code', hasValue: false }], onConfirm, onDismiss: vi.fn() });
    const inputs = [...preview.root.querySelectorAll<HTMLInputElement>('input')];
    expect(inputs.map((input) => input.checked)).toEqual([false, true, true]);
    expect(preview.element.shadowRoot).toBeNull();
    expect(preview.root.querySelector('img')).toBeNull();
    preview.root.querySelector<HTMLButtonElement>('.primary')!.click();
    expect(onConfirm).not.toHaveBeenCalled();
    preview.remove();
  });
});
