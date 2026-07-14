// @vitest-environment happy-dom
import { beforeEach, describe, expect, it } from 'vitest';
import { detectCardForms, detectIdentityForms } from './field-detection.js';
import { fillCardForm, fillIdentityForm } from './fill-card-identity.js';

describe('fillCardForm', () => {
  beforeEach(() => { document.body.innerHTML = ''; });

  it('fills number, cvc, and split month/year', () => {
    document.body.innerHTML = `
      <form>
        <input autocomplete="cc-number" id="num">
        <input autocomplete="cc-csc" id="csc">
        <input autocomplete="cc-exp-month" id="mm">
        <input autocomplete="cc-exp-year" id="yy">
      </form>`;
    const form = detectCardForms()[0]!;
    expect(fillCardForm(form, { number: '4111111111111111', code: '123', expMonth: '9', expYear: '2030' })).toBe(true);
    expect((document.getElementById('num') as HTMLInputElement).value).toBe('4111111111111111');
    expect((document.getElementById('csc') as HTMLInputElement).value).toBe('123');
    expect((document.getElementById('mm') as HTMLInputElement).value).toBe('9');
    expect((document.getElementById('yy') as HTMLInputElement).value).toBe('2030');
  });

  it('composes a combined MM/YY expiry field', () => {
    document.body.innerHTML = `<form><input autocomplete="cc-number"><input autocomplete="cc-exp" id="exp" placeholder="MM/YY"></form>`;
    const form = detectCardForms()[0]!;
    fillCardForm(form, { number: '4111', expMonth: '9', expYear: '2030' });
    expect((document.getElementById('exp') as HTMLInputElement).value).toBe('09/30');
  });

  it('matches a country/month <select> by value or visible text', () => {
    document.body.innerHTML = `
      <form>
        <input autocomplete="cc-number">
        <select autocomplete="cc-exp-month" id="mm"><option value="">--</option><option value="09">September</option></select>
      </form>`;
    const form = detectCardForms()[0]!;
    fillCardForm(form, { number: '4111', expMonth: '09' });
    expect((document.getElementById('mm') as HTMLSelectElement).value).toBe('09');
  });

  it('composes a four-digit MM/YYYY expiry field', () => {
    document.body.innerHTML = `<form><input autocomplete="cc-number"><input autocomplete="cc-exp" id="exp" placeholder="MM/YYYY"></form>`;
    const form = detectCardForms()[0]!;
    fillCardForm(form, { number: '4111', expMonth: '9', expYear: '2030' });
    expect((document.getElementById('exp') as HTMLInputElement).value).toBe('09/2030');
  });

  it('matches a <select> by visible option text when value differs', () => {
    document.body.innerHTML = `
      <form>
        <input autocomplete="cc-number">
        <select autocomplete="cc-exp-month" id="mm"><option value="">--</option><option value="9">September</option></select>
      </form>`;
    const form = detectCardForms()[0]!;
    fillCardForm(form, { number: '4111', expMonth: 'September' });
    expect((document.getElementById('mm') as HTMLSelectElement).value).toBe('9');
  });

  it('matches a zero-padded month <select> from an unpadded vault month', () => {
    document.body.innerHTML = `
      <form>
        <input autocomplete="cc-number">
        <select autocomplete="cc-exp-month" id="mm">
          <option value="">Month</option>
          <option value="01">01</option>
          <option value="02">02</option>
          <option value="03">03</option>
        </select>
      </form>`;
    const form = detectCardForms()[0]!;
    // Vault stores expMonth unpadded (e.g. "3"); the site's <select> uses "01".."12".
    fillCardForm(form, { number: '4111', expMonth: '3', expYear: '2027' });
    expect((document.getElementById('mm') as HTMLSelectElement).value).toBe('03');
  });

  it('matches a two-digit year <select> from a four-digit vault year', () => {
    document.body.innerHTML = `
      <form>
        <input autocomplete="cc-number">
        <select autocomplete="cc-exp-year" id="yy">
          <option value="">Year</option>
          <option value="26">26</option>
          <option value="27">27</option>
        </select>
      </form>`;
    const form = detectCardForms()[0]!;
    fillCardForm(form, { number: '4111', expMonth: '3', expYear: '2027' });
    expect((document.getElementById('yy') as HTMLSelectElement).value).toBe('27');
  });

  it('matches a four-digit year <select> from a two-digit vault year', () => {
    document.body.innerHTML = `
      <form>
        <input autocomplete="cc-number">
        <select autocomplete="cc-exp-year" id="yy">
          <option value="">Year</option>
          <option value="2026">2026</option>
          <option value="2027">2027</option>
        </select>
      </form>`;
    const form = detectCardForms()[0]!;
    fillCardForm(form, { number: '4111', expMonth: '3', expYear: '27' });
    expect((document.getElementById('yy') as HTMLSelectElement).value).toBe('2027');
  });
});

describe('fillIdentityForm', () => {
  beforeEach(() => { document.body.innerHTML = ''; });

  it('fills address fields and composes a single full-name field', () => {
    document.body.innerHTML = `
      <form>
        <input autocomplete="name" id="full">
        <input autocomplete="street-address" id="street">
        <input autocomplete="postal-code" id="zip">
      </form>`;
    // address signal present → detected; full-name composed from parts.
    const form = detectIdentityForms()[0]!;
    fillIdentityForm(form, { firstName: 'Ada', lastName: 'Lovelace', address1: '1 Analytical Way', postalCode: 'EC1' });
    expect((document.getElementById('full') as HTMLInputElement).value).toBe('Ada Lovelace');
    expect((document.getElementById('street') as HTMLInputElement).value).toBe('1 Analytical Way');
    expect((document.getElementById('zip') as HTMLInputElement).value).toBe('EC1');
  });
});
