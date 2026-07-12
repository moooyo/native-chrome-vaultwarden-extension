// @vitest-environment happy-dom
import { afterEach, describe, expect, it } from 'vitest';
import './totp-meter.js';
import type { VwTotpMeter } from './totp-meter.js';

afterEach(() => document.body.replaceChildren());

describe('vw-totp-meter', () => {
  it('groups a 6-digit code as XXX XXX and drains the progress bar', async () => {
    const el = document.createElement('vw-totp-meter') as VwTotpMeter;
    el.code = '123456';
    el.period = 30;
    el.remaining = 15;
    document.body.append(el);
    await el.updateComplete;
    expect(el.shadowRoot!.querySelector('.code')!.textContent).toBe('123 456');
    expect(el.shadowRoot!.querySelector('.secs')!.textContent).toContain('15s');
    const fill = el.shadowRoot!.querySelector('.fill') as HTMLElement;
    expect(fill.getAttribute('style')).toContain('width:50%');
  });
});
