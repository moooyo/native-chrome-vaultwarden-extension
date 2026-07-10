// @vitest-environment happy-dom
import { beforeEach, describe, expect, it } from 'vitest';
import { createFrameAutofillController } from './frame-autofill.js';

describe('frame autofill controller', () => {
  beforeEach(() => {
    document.body.innerHTML = `
      <form><input name="email" type="email"><input type="password"></form>`;
  });

  it('returns form metadata without field values', () => {
    const email = document.querySelector<HTMLInputElement>('input[type=email]')!;
    email.value = 'must-not-cross';
    const controller = createFrameAutofillController({
      root: document,
      frameUrl: () => 'https://login.example.com/',
      now: () => 1000,
    });
    controller.noteFocus(email);
    const inspection = controller.inspect();
    expect(inspection.frameUrl).toBe('https://login.example.com/');
    expect(inspection.forms).toHaveLength(1);
    expect(JSON.stringify(inspection)).not.toContain('must-not-cross');
    expect(inspection.forms[0]?.focusedAt).toBe(1000);
  });

  it('fails closed when URL or form identity changes', () => {
    let url = 'https://example.com/login';
    const controller = createFrameAutofillController({
      root: document,
      frameUrl: () => url,
      now: () => 0,
    });
    const target = controller.inspect().forms[0]!;
    url = 'https://evil.example/';
    expect(controller.commit({
      formId: target.formId,
      expectedFrameUrl: 'https://example.com/login',
      credentials: { username: 'u', password: 'p' },
    })).toEqual({ status: 'target_changed' });
  });
});
