// @vitest-environment happy-dom
import { beforeEach, describe, expect, it } from 'vitest';
import { detectCardForms, detectIdentityForms } from './field-detection.js';

describe('card form detection', () => {
  beforeEach(() => { document.body.innerHTML = ''; });

  it('detects a card form when a card-number field is present', () => {
    document.body.innerHTML = `
      <form>
        <input autocomplete="cc-name">
        <select autocomplete="cc-type"><option>Visa</option></select>
        <input autocomplete="cc-number">
        <input autocomplete="cc-exp">
        <input autocomplete="cc-csc">
      </form>`;
    const forms = detectCardForms();
    expect(forms).toHaveLength(1);
    expect(forms[0]?.kind).toBe('card');
    expect(forms[0]?.fields.has('brand')).toBe(true);
    expect(forms[0]?.fields.has('number')).toBe(true);
    expect(forms[0]?.fields.has('code')).toBe(true);
  });

  it('classifies a textual security code beside a card number as card code', () => {
    document.body.innerHTML = `
      <form>
        <input id="number" name="cardNumber">
        <input id="security" name="securityCode">
      </form>`;

    const form = detectCardForms()[0]!;
    expect(form.fields.get('number')).toBe(document.getElementById('number'));
    expect(form.fields.get('code')).toBe(document.getElementById('security'));
  });

  it('never claims an authoritative one-time-code field as card CVC', () => {
    document.body.innerHTML = `
      <form>
        <input id="number" autocomplete="cc-number">
        <input id="otp" autocomplete="one-time-code" name="securityCode">
      </form>`;

    const form = detectCardForms()[0]!;
    expect(form.fields.get('number')).toBe(document.getElementById('number'));
    expect(form.fields.has('code')).toBe(false);
  });

  it('never claims a semantically labeled one-time code as card CVC', () => {
    document.body.innerHTML = `
      <form>
        <input id="number" autocomplete="cc-number">
        <label for="otp">One-time code</label>
        <input id="otp" name="cvv">
      </form>`;

    const form = detectCardForms()[0]!;
    expect(form.fields.get('number')).toBe(document.getElementById('number'));
    expect(form.fields.has('code')).toBe(false);
  });

  it('classifies card fields from explicit and wrapping labels', () => {
    document.body.innerHTML = `
      <form>
        <label for="number">Card number</label>
        <input id="number">
        <label>CVV <input id="code"></label>
      </form>`;

    const form = detectCardForms()[0]!;
    expect(form.fields.get('number')).toBe(document.getElementById('number'));
    expect(form.fields.get('code')).toBe(document.getElementById('code'));
  });

  it('fails closed for conflicting or hidden card labels', () => {
    document.body.innerHTML = `
      <form>
        <label for="conflict">Card number</label>
        <label for="conflict">Card CVC</label>
        <input id="conflict">
      </form>
      <form>
        <label for="hidden" hidden>Card number</label>
        <input id="hidden">
      </form>`;

    expect(detectCardForms()).toEqual([]);
  });

  it('keeps a textual card security code inside its open shadow root', () => {
    const host = document.createElement('div');
    const shadow = host.attachShadow({ mode: 'open' });
    shadow.innerHTML = `
      <form>
        <input id="number" aria-label="Card number">
        <input id="security" aria-label="Security code">
      </form>`;
    document.body.append(host);

    const form = detectCardForms(shadow)[0]!;
    expect(form.fields.get('number')).toBe(shadow.getElementById('number'));
    expect(form.fields.get('code')).toBe(shadow.getElementById('security'));
    expect(detectCardForms(document)).toEqual([]);
  });

  it('does not detect a card form without a number field', () => {
    document.body.innerHTML = `<form><input autocomplete="cc-csc"></form>`;
    expect(detectCardForms()).toEqual([]);
  });

  it('ignores form-bound and formless card controls carrying data-bwignore', () => {
    document.body.innerHTML = `
      <form><input autocomplete="cc-number" data-bwignore><input autocomplete="cc-csc"></form>
      <section><input autocomplete="cc-number" data-bwignore><input autocomplete="cc-csc"></section>`;

    expect(detectCardForms()).toEqual([]);
  });

  it('groups external form=id card controls through form.elements', () => {
    document.body.innerHTML = `
      <form id="payment"><input autocomplete="cc-number"></form>
      <input form="payment" autocomplete="cc-csc" id="external-code">`;
    const form = detectCardForms()[0]!;
    expect(form.fields.get('code')).toBe(document.getElementById('external-code'));
  });

  it('does not attach a formless CVC from another composed slot owner', () => {
    const { host, firstSlot, secondSlot } = slottedOwners();
    const number = document.createElement('input');
    number.autocomplete = 'cc-number';
    const code = document.createElement('input');
    code.autocomplete = 'cc-csc';
    assignSlot(number, firstSlot);
    assignSlot(code, secondSlot);
    host.append(number, code);
    document.body.append(host);

    const form = detectCardForms()[0]!;
    expect(form.fields.get('number')).toBe(number);
    expect(form.fields.has('code')).toBe(false);
  });
});

describe('identity form detection (conservative)', () => {
  beforeEach(() => { document.body.innerHTML = ''; });

  it('detects an identity form when an address signal is present', () => {
    document.body.innerHTML = `
      <form>
        <input autocomplete="given-name">
        <input autocomplete="family-name">
        <input autocomplete="street-address">
        <input autocomplete="postal-code">
      </form>`;
    const forms = detectIdentityForms();
    expect(forms).toHaveLength(1);
    expect(forms[0]?.fields.has('address')).toBe(true);
  });

  it('detects street-address textareas in native, formless, and open-shadow scopes', () => {
    document.body.innerHTML = `
      <form><textarea id="native" autocomplete="street-address"></textarea></form>
      <section><textarea id="formless" name="mailing-address"></textarea></section>`;
    const host = document.createElement('div');
    const shadow = host.attachShadow({ mode: 'open' });
    shadow.innerHTML = '<form><textarea id="shadow" autocomplete="street-address"></textarea></form>';
    document.body.append(host);

    expect(detectIdentityForms(document).map((form) => form.anchor.id).sort())
      .toEqual(['formless', 'native']);
    expect(detectIdentityForms(shadow)[0]?.fields.get('address')).toBe(shadow.getElementById('shadow'));
  });

  it('rejects readonly and data-bwignore address textareas', () => {
    document.body.innerHTML = `
      <form><textarea autocomplete="street-address" readonly></textarea></form>
      <form><textarea autocomplete="street-address" data-bwignore></textarea></form>`;
    expect(detectIdentityForms()).toEqual([]);
  });

  it('never reclassifies a new-password input as a generic address target', () => {
    document.body.innerHTML = `
      <form><input type="password" autocomplete="new-password" name="mailing-address"></form>`;
    expect(detectIdentityForms()).toEqual([]);
  });

  it('detects an identity form on a first+last name pair without an address', () => {
    document.body.innerHTML = `
      <form><input autocomplete="given-name"><input autocomplete="family-name"></form>`;
    expect(detectIdentityForms()).toHaveLength(1);
  });

  it('classifies root-local aria-labelledby identity fields inside shadow DOM', () => {
    const host = document.createElement('div');
    const shadow = host.attachShadow({ mode: 'open' });
    shadow.innerHTML = `
      <form>
        <span id="first-label">First name</span>
        <input id="first" aria-labelledby="first-label">
        <span id="last-label">Last name</span>
        <input id="last" aria-labelledby="last-label">
      </form>`;
    document.body.append(host);

    const form = detectIdentityForms(shadow)[0]!;
    expect(form.fields.get('firstName')).toBe(shadow.getElementById('first'));
    expect(form.fields.get('lastName')).toBe(shadow.getElementById('last'));
  });

  it('does not fire on a lone email/subscribe field', () => {
    document.body.innerHTML = `<form><input type="email" autocomplete="email"></form>`;
    expect(detectIdentityForms()).toEqual([]);
  });

  it('skips fields in the exclude set (already claimed by login detection)', () => {
    document.body.innerHTML = `
      <form>
        <input id="u" type="email" autocomplete="email">
        <input autocomplete="given-name">
        <input autocomplete="family-name">
      </form>`;
    const email = document.getElementById('u') as HTMLInputElement;
    const forms = detectIdentityForms(document, new Set([email]));
    expect(forms[0]?.fields.has('email')).toBe(false);
    expect(forms[0]?.fields.has('firstName')).toBe(true);
  });

  it('does not fire on a lone phone field', () => {
    document.body.innerHTML = `<form><input type="tel" autocomplete="tel"></form>`;
    expect(detectIdentityForms()).toEqual([]);
  });

  it('does not fire on a lone full-name field', () => {
    document.body.innerHTML = `<form><input autocomplete="name"></form>`;
    expect(detectIdentityForms()).toEqual([]);
  });

  it('does not treat a label-only email address as a street-address threshold', () => {
    document.body.innerHTML = `
      <form><label>Email address <input id="email"></label></form>`;

    expect(detectIdentityForms()).toEqual([]);
  });

  it('ignores identity controls carrying data-bwignore', () => {
    document.body.innerHTML = `
      <form>
        <input autocomplete="given-name" data-bwignore>
        <input autocomplete="family-name" data-bwignore>
        <input autocomplete="street-address" data-bwignore>
      </form>`;
    expect(detectIdentityForms()).toEqual([]);
  });

  it('does not combine formless name fields from different composed slot owners', () => {
    const { host, firstSlot, secondSlot } = slottedOwners();
    const first = document.createElement('input');
    first.autocomplete = 'given-name';
    const last = document.createElement('input');
    last.autocomplete = 'family-name';
    assignSlot(first, firstSlot);
    assignSlot(last, secondSlot);
    host.append(first, last);
    document.body.append(host);

    expect(detectIdentityForms()).toEqual([]);
  });
});

function slottedOwners(): {
  host: HTMLDivElement;
  firstSlot: HTMLSlotElement;
  secondSlot: HTMLSlotElement;
} {
  const host = document.createElement('div');
  const shadow = host.attachShadow({ mode: 'open' });
  shadow.innerHTML = '<section><slot name="first"></slot><slot name="second"></slot></section>';
  return {
    host,
    firstSlot: shadow.querySelector<HTMLSlotElement>('slot[name=first]')!,
    secondSlot: shadow.querySelector<HTMLSlotElement>('slot[name=second]')!,
  };
}

function assignSlot(element: Element, slot: HTMLSlotElement): void {
  Object.defineProperty(element, 'assignedSlot', { configurable: true, value: slot });
}
