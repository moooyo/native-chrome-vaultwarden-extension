// @vitest-environment happy-dom
import { afterEach, describe, expect, it } from 'vitest';
import './setting-card.js';
import type { VwSettingCard } from './setting-card.js';

afterEach(() => document.body.replaceChildren());

describe('vw-setting-card', () => {
  it('renders heading, description, and the slotted control', async () => {
    const el = document.createElement('vw-setting-card') as VwSettingCard;
    el.heading = 'Auto sync';
    el.description = 'Sync on unlock';
    el.innerHTML = '<button id="ctl">x</button>';
    document.body.append(el);
    await el.updateComplete;
    expect(el.shadowRoot!.querySelector('.title')!.textContent).toContain('Auto sync');
    expect(el.shadowRoot!.querySelector('.desc')!.textContent).toContain('Sync on unlock');
    expect(el.shadowRoot!.querySelector('slot')).not.toBeNull();
  });

  it('applies the danger variant', async () => {
    const el = document.createElement('vw-setting-card') as VwSettingCard;
    el.heading = 'Delete';
    el.danger = true;
    document.body.append(el);
    await el.updateComplete;
    expect(el.shadowRoot!.querySelector('.card.danger')).not.toBeNull();
  });
});
