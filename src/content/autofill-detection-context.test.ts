// @vitest-environment happy-dom
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  createAutofillDetectionContext,
  type AutofillDetectionSnapshot,
} from './autofill-detection-context.js';
import { detectLoginForms, isSemanticSourceAvailableInTree } from './form-detection.js';
import { collectFieldHints } from './semantic-hints.js';
import { computeFillProjection } from './focused-fill.js';

function snapshot(roots: readonly ParentNode[] = [document], truncated = false): AutofillDetectionSnapshot {
  return { roots, truncated };
}

function collect(input: HTMLInputElement, context: ReturnType<typeof createAutofillDetectionContext>) {
  return context.fieldHints(
    input,
    (budget) => collectFieldHints(input, isSemanticSourceAvailableInTree, budget),
  );
}

describe('autofill detection context', () => {
  beforeEach(() => {
    document.body.replaceChildren();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('accepts the exact control limit and fails closed at limit plus one', () => {
    document.body.innerHTML = '<input><input>';

    const exact = createAutofillDetectionContext(snapshot(), { maxControls: 2 });
    const overflow = createAutofillDetectionContext(snapshot(), { maxControls: 1 });

    expect(exact.complete).toBe(true);
    expect(exact.controls).toHaveLength(2);
    expect(overflow.complete).toBe(false);
    expect(overflow.failure).toBe('control_limit');
    expect(overflow.controls).toEqual([]);
  });

  it('shares one control limit across document and shadow roots', () => {
    document.body.innerHTML = '<input id="document-field">';
    const host = document.createElement('div');
    const shadow = host.attachShadow({ mode: 'open' });
    shadow.innerHTML = '<input id="shadow-field">';
    document.body.append(host);

    const context = createAutofillDetectionContext(snapshot([document, shadow]), { maxControls: 1 });

    expect(context.complete).toBe(false);
    expect(context.failure).toBe('control_limit');
  });

  it('rejects a truncated composed-tree snapshot before enumerating controls', () => {
    document.body.innerHTML = '<input>';

    const context = createAutofillDetectionContext(snapshot([document], true));

    expect(context.complete).toBe(false);
    expect(context.failure).toBe('snapshot_truncated');
    expect(context.controls).toEqual([]);
  });

  it('counts aggregate hint limits in UTF-8 bytes', () => {
    document.body.innerHTML = '<input name="密">';
    const input = document.querySelector('input')!;
    const exact = createAutofillDetectionContext(snapshot(), { maxHintBytes: 3 });
    const overflow = createAutofillDetectionContext(snapshot(), { maxHintBytes: 2 });

    collect(input, exact);
    collect(input, overflow);

    expect(exact.complete).toBe(true);
    expect(overflow.complete).toBe(false);
    expect(overflow.failure).toBe('hint_byte_limit');
  });

  it('shares aggregate UTF-8 hint bytes across composed roots', () => {
    document.body.innerHTML = '<input name="密">';
    const documentInput = document.querySelector('input')!;
    const host = document.createElement('div');
    const shadow = host.attachShadow({ mode: 'open' });
    shadow.innerHTML = '<input name="密">';
    document.body.append(host);
    const shadowInput = shadow.querySelector('input')!;
    const exact = createAutofillDetectionContext(snapshot([document, shadow]), { maxHintBytes: 6 });
    const overflow = createAutofillDetectionContext(snapshot([document, shadow]), { maxHintBytes: 5 });

    collect(documentInput, exact);
    collect(shadowInput, exact);
    collect(documentInput, overflow);
    collect(shadowInput, overflow);

    expect(exact.complete).toBe(true);
    expect(overflow.complete).toBe(false);
    expect(overflow.failure).toBe('hint_byte_limit');
  });

  it('shares the semantic-source limit across associated labels', () => {
    document.body.innerHTML = `
      <label for="field">First name</label>
      <label for="field">Given name</label>
      <input id="field">`;
    const input = document.getElementById('field') as HTMLInputElement;
    const exact = createAutofillDetectionContext(snapshot(), { maxSemanticSources: 2 });
    const overflow = createAutofillDetectionContext(snapshot(), { maxSemanticSources: 1 });

    collect(input, exact);
    collect(input, overflow);

    expect(exact.complete).toBe(true);
    expect(overflow.complete).toBe(false);
    expect(overflow.failure).toBe('semantic_source_limit');
  });

  it('charges each candidate-group identity only once', () => {
    const context = createAutofillDetectionContext(snapshot(), { maxForms: 2 });
    const first = document.createElement('form');
    const second = document.createElement('input');
    const overflow = document.createElement('form');

    expect(context.claimCandidateGroup(first)).toBe(true);
    expect(context.claimCandidateGroup(first)).toBe(true);
    expect(context.claimCandidateGroup(second)).toBe(true);
    expect(context.claimCandidateGroup(second)).toBe(true);
    expect(context.claimCandidateGroup(overflow)).toBe(false);
    expect(context.complete).toBe(false);
    expect(context.failure).toBe('form_limit');
  });

  it('discards every detected form when an aggregate hint budget is exceeded', () => {
    document.body.innerHTML = '<form><input autocomplete="username"><input type="password"></form>';
    const context = createAutofillDetectionContext(snapshot(), { maxHintBytes: 1 });

    const projection = computeFillProjection(snapshot(), context);

    expect(projection.complete).toBe(false);
    expect(projection.loginForms).toEqual([]);
    expect(projection.cardForms).toEqual([]);
    expect(projection.identityForms).toEqual([]);
    expect(context.failure).toBe('hint_byte_limit');
  });

  it('reuses the raw candidate-group charge in the final structured-form pass', () => {
    document.body.innerHTML = '<form><input autocomplete="cc-number"></form>';
    const context = createAutofillDetectionContext(snapshot(), { maxForms: 1 });

    const projection = computeFillProjection(snapshot(), context);

    expect(projection.complete).toBe(true);
    expect(projection.cardForms).toHaveLength(1);
    expect(context.failure).toBeUndefined();
  });

  it('detects forms from the bounded inventory without selector-based field enumeration', () => {
    const host = document.createElement('div');
    const root = host.attachShadow({ mode: 'open' });
    root.innerHTML = '<form><input autocomplete="username"><input type="password"></form>';
    document.body.append(host);
    const context = createAutofillDetectionContext(snapshot([root]));
    const querySelectorAll = vi.spyOn(root, 'querySelectorAll');

    expect(detectLoginForms(root, context)).toHaveLength(1);
    expect(context.complete).toBe(true);
    expect(querySelectorAll.mock.calls.some(([selector]) => (
      /(?:^|,)\s*(?:\*|form\b|input\b|select\b|textarea\b)/iu.test(selector)
    ))).toBe(false);
  });
});
