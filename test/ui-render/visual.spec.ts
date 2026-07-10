import { test, expect } from '@playwright/test';
import { gotoFixture, type FixtureParams } from './helpers.js';

/** One approved screenshot per surface family/state, plus a single dark representative. Element
 *  screenshots keep the baselines tight and stable regardless of surrounding viewport. */
interface VisualCase {
  name: string;
  params: FixtureParams;
  selector: string;
  viewport: { width: number; height: number };
}

const CASES: VisualCase[] = [
  { name: 'popup-suggestions-light', params: { surface: 'popup', state: 'suggestions', count: 6 }, selector: '#vw-surface', viewport: { width: 404, height: 600 } },
  { name: 'popup-suggestions-dark', params: { surface: 'popup', state: 'suggestions', count: 6, theme: 'dark' }, selector: '#vw-surface', viewport: { width: 404, height: 600 } },
  { name: 'popup-list', params: { surface: 'popup', state: 'list', count: 6 }, selector: '#vw-surface', viewport: { width: 404, height: 600 } },
  { name: 'popup-detail', params: { surface: 'popup', state: 'detail' }, selector: '#vw-surface', viewport: { width: 404, height: 600 } },
  { name: 'popup-editor', params: { surface: 'popup', state: 'editor' }, selector: '#vw-surface', viewport: { width: 404, height: 600 } },
  { name: 'popup-tools', params: { surface: 'popup', state: 'tools' }, selector: '#vw-surface', viewport: { width: 404, height: 600 } },
  { name: 'popup-auth', params: { surface: 'popup', state: 'auth' }, selector: '#vw-surface', viewport: { width: 404, height: 600 } },
  { name: 'options', params: { surface: 'options' }, selector: '#vw-surface', viewport: { width: 900, height: 600 } },
  { name: 'receive', params: { surface: 'receive' }, selector: '#vw-surface', viewport: { width: 720, height: 600 } },
  { name: 'popover', params: { surface: 'popover' }, selector: 'vw-autofill-popover .box', viewport: { width: 420, height: 420 } },
  { name: 'save-bar', params: { surface: 'save' }, selector: 'vw-save-bar .bar', viewport: { width: 720, height: 240 } },
  { name: 'notice', params: { surface: 'notice' }, selector: 'vw-notice .bar', viewport: { width: 420, height: 200 } },
  { name: 'passkey-consent', params: { surface: 'consent' }, selector: 'vw-passkey-consent .card', viewport: { width: 480, height: 360 } },
  { name: 'passkey-registration', params: { surface: 'registration' }, selector: 'vw-passkey-register .card', viewport: { width: 480, height: 420 } },
];

for (const visual of CASES) {
  test(`visual: ${visual.name}`, async ({ page }) => {
    await page.setViewportSize(visual.viewport);
    await gotoFixture(page, visual.params);
    await expect(page.locator(visual.selector).first()).toHaveScreenshot(`${visual.name}.png`);
  });
}
