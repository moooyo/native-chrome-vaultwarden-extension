// @vitest-environment happy-dom
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { isSemanticSourceAvailableInTree, isVisibleInTree } from './form-detection.js';
import { collectFieldHints } from './semantic-hints.js';

describe('semantic field hints', () => {
  beforeEach(() => {
    document.body.replaceChildren();
    vi.restoreAllMocks();
  });

  it('collects explicit, wrapping, and aria-labelledby text as distinct normalized sources', () => {
    document.body.innerHTML = `
      <span id="aria">  Billing\n address </span>
      <label for="field">Card   number</label>
      <label>Account holder <input id="wrapped"></label>
      <input id="field" aria-labelledby="aria">`;
    const explicit = collectFieldHints(
      document.getElementById('field') as HTMLInputElement,
      isVisibleInTree,
    );
    const wrapped = collectFieldHints(
      document.getElementById('wrapped') as HTMLInputElement,
      isVisibleInTree,
    );

    expect(explicit.semanticLabels).toEqual(['Card number', 'Billing address']);
    expect(explicit.semanticLabelsUnsafe).toBe(false);
    expect(wrapped.semanticLabels).toEqual(['Account holder']);
  });

  it('accepts accessibility sources hidden with visual-only screen-reader techniques', () => {
    const styles = [
      'position:absolute;clip:rect(0 0 0 0);width:1px;height:1px;overflow:hidden',
      'position:absolute;clip-path:inset(50%);width:1px;height:1px;overflow:hidden',
      'position:absolute;left:-10000px;top:auto',
      'opacity:0',
      'transform:scale(0)',
    ];

    for (const style of styles) {
      document.body.innerHTML = `<label for="field" style="${style}">Username</label><input id="field">`;
      const hints = collectFieldHints(
        document.getElementById('field') as HTMLInputElement,
        isSemanticSourceAvailableInTree,
      );

      expect(hints.semanticLabels).toEqual(['Username']);
      expect(hints.semanticLabelsUnsafe).toBe(false);
    }
  });

  it.each([
    ['hidden', 'hidden'],
    ['inert', 'inert'],
    ['aria-hidden', 'aria-hidden=" TRUE "'],
    ['display none', 'style="display:none"'],
    ['visibility hidden', 'style="visibility:hidden"'],
    ['content visibility hidden', 'style="content-visibility:hidden"'],
  ])('rejects a semantic source removed by %s', (_name, sourceAttribute) => {
    document.body.innerHTML = `
      <div ${sourceAttribute}><label for="field">Username</label></div>
      <input id="field">`;
    const hints = collectFieldHints(
      document.getElementById('field') as HTMLInputElement,
      isSemanticSourceAvailableInTree,
    );

    expect(hints.semanticLabels).toEqual([]);
    expect(hints.semanticLabelsUnsafe).toBe(true);
  });

  it('resolves aria-labelledby only inside the raw shadow root', () => {
    document.body.innerHTML = '<span id="hint">Document username</span>';
    const host = document.createElement('div');
    const shadow = host.attachShadow({ mode: 'open' });
    shadow.innerHTML = '<span id="hint">Shadow username</span><input id="field" aria-labelledby="hint">';
    document.body.append(host);
    const field = shadow.getElementById('field') as HTMLInputElement;

    expect(collectFieldHints(field, isVisibleInTree).semanticLabels).toEqual(['Shadow username']);

    shadow.getElementById('hint')!.remove();
    const missing = collectFieldHints(field, isVisibleInTree);
    expect(missing.semanticLabels).toEqual([]);
    expect(missing.semanticLabelsUnsafe).toBe(true);
  });

  it('skips hidden descendant text and never treats an unassociated neighbor as a label', () => {
    document.body.innerHTML = `
      <span>Card number CVC</span>
      <label for="field">Username <span hidden>Card number</span></label>
      <input id="field">`;
    const hints = collectFieldHints(
      document.getElementById('field') as HTMLInputElement,
      isVisibleInTree,
    );

    expect(hints.semanticLabels).toEqual(['Username']);
    expect(hints.semanticLabelsUnsafe).toBe(false);
  });

  it('fails closed when an explicitly associated source is hidden', () => {
    document.body.innerHTML = '<label for="field" hidden>Username</label><input id="field">';
    const hints = collectFieldHints(
      document.getElementById('field') as HTMLInputElement,
      isVisibleInTree,
    );

    expect(hints.semanticLabels).toEqual([]);
    expect(hints.semanticLabelsUnsafe).toBe(true);
  });

  it('fails closed instead of skipping an unsupported foreign-namespace subtree', () => {
    document.body.innerHTML = `
      <label for="field">Username <svg><text>Card number</text></svg></label>
      <input id="field">`;
    const hints = collectFieldHints(
      document.getElementById('field') as HTMLInputElement,
      isVisibleInTree,
    );

    expect(hints.semanticLabels).toEqual([]);
    expect(hints.semanticLabelsUnsafe).toBe(true);
  });

  it('skips a proven-hidden foreign-namespace decoration', () => {
    document.body.innerHTML = `
      <label for="field"><svg aria-hidden="true"><text>Card number</text></svg> Username</label>
      <input id="field">`;
    const hints = collectFieldHints(
      document.getElementById('field') as HTMLInputElement,
      isVisibleInTree,
    );

    expect(hints.semanticLabels).toEqual(['Username']);
    expect(hints.semanticLabelsUnsafe).toBe(false);
  });

  it('fails closed when descendant visibility cannot be read', () => {
    document.body.innerHTML = `
      <label for="field">Username <span id="poison">Card number</span></label>
      <input id="field">`;
    const poison = document.getElementById('poison')!;
    Object.defineProperty(poison, 'hidden', {
      configurable: true,
      get: () => { throw new Error('blocked'); },
    });
    const hints = collectFieldHints(
      document.getElementById('field') as HTMLInputElement,
      isVisibleInTree,
    );

    expect(hints.semanticLabels).toEqual([]);
    expect(hints.semanticLabelsUnsafe).toBe(true);
  });

  it('uses native accessors without invoking page-defined instance getters', () => {
    document.body.innerHTML = '<label for="field">Username</label><input id="field">';
    const label = document.querySelector('label')!;
    const field = document.getElementById('field') as HTMLInputElement;
    const labelsGetter = vi.fn(() => { throw new Error('own labels getter'); });
    const textGetter = vi.fn(() => { throw new Error('own textContent getter'); });
    Object.defineProperty(field, 'labels', { configurable: true, get: labelsGetter });
    Object.defineProperty(label, 'textContent', { configurable: true, get: textGetter });

    expect(collectFieldHints(field, isVisibleInTree).semanticLabels).toEqual(['Username']);
    expect(labelsGetter).not.toHaveBeenCalled();
    expect(textGetter).not.toHaveBeenCalled();
  });

  it('rejects overlong, over-count, and over-byte-budget label sets without truncating', () => {
    const scenarios = [
      [`<label for="field">${'x'.repeat(257)} username</label><input id="field">`, 'overlong'],
      [`<input id="field" aria-label="${'x'.repeat(257)} username">`, 'overlong-aria-label'],
      [
        `${Array.from({ length: 9 }, (_, index) => `<label for="field">label ${index}</label>`).join('')}<input id="field">`,
        'over-count',
      ],
      [
        `${Array.from({ length: 8 }, (_, index) => (
          `<label for="field">${'x'.repeat(150)} ${index}</label>`
        )).join('')}<input id="field">`,
        'over-byte-budget',
      ],
    ] as const;

    for (const [markup, _name] of scenarios) {
      document.body.innerHTML = markup;
      const hints = collectFieldHints(
        document.getElementById('field') as HTMLInputElement,
        isVisibleInTree,
      );
      expect(hints.semanticLabels).toEqual([]);
      expect(hints.semanticLabelsUnsafe).toBe(true);
    }
  });

  it('rejects too many aria references and bounded descendant traversal overflow', () => {
    const references = Array.from({ length: 9 }, (_, index) => `hint-${index}`);
    document.body.innerHTML = `
      ${references.map((id) => `<span id="${id}">Username</span>`).join('')}
      <input id="field" aria-labelledby="${references.join(' ')}">`;
    let hints = collectFieldHints(
      document.getElementById('field') as HTMLInputElement,
      isVisibleInTree,
    );
    expect(hints.semanticLabelsUnsafe).toBe(true);

    document.body.innerHTML = `
      <label for="field">${'<span>x</span>'.repeat(129)}</label>
      <input id="field">`;
    hints = collectFieldHints(
      document.getElementById('field') as HTMLInputElement,
      isVisibleInTree,
    );
    expect(hints.semanticLabels).toEqual([]);
    expect(hints.semanticLabelsUnsafe).toBe(true);
  });

  it('rejects overlong base attributes and never classifies their prefixes', () => {
    const field = document.createElement('input');
    document.body.append(field);
    for (const name of ['autocomplete', 'name', 'id', 'placeholder'] as const) {
      field.removeAttribute('autocomplete');
      field.removeAttribute('name');
      field.removeAttribute('id');
      field.removeAttribute('placeholder');
      field.setAttribute(name, `username-${'x'.repeat(1_024)}`);

      const hints = collectFieldHints(field, isVisibleInTree);
      expect(hints.semanticLabelsUnsafe).toBe(true);
      expect(hints.autocomplete).toBe('');
      expect(hints.name).toBe('');
      expect(hints.id).toBe('');
      expect(hints.placeholder).toBe('');
    }
  });

  it('rejects a base-attribute set that exceeds the aggregate byte budget', () => {
    const field = document.createElement('input');
    for (const name of ['autocomplete', 'name', 'id', 'placeholder'] as const) {
      field.setAttribute(name, 'x'.repeat(1_024));
    }
    field.setAttribute('aria-label', 'x');
    document.body.append(field);

    const hints = collectFieldHints(field, isVisibleInTree);
    expect(hints.semanticLabelsUnsafe).toBe(true);
    expect(hints.semanticLabels).toEqual([]);
    expect(hints.name).toBe('');
  });
});
