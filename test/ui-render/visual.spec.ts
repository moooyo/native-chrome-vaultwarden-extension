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
  { name: 'popup-double-suggestions-light', params: { surface: 'popup', state: 'suggestions', layout: 'double', count: 8 }, selector: '#vw-surface', viewport: { width: 600, height: 450 } },
  { name: 'popup-double-detail-dark', params: { surface: 'popup', state: 'detail', layout: 'double', count: 8, theme: 'dark' }, selector: '#vw-surface', viewport: { width: 600, height: 450 } },
  { name: 'popup-double-list', params: { surface: 'popup', state: 'list', layout: 'double', count: 8 }, selector: '#vw-surface', viewport: { width: 600, height: 450 } },
  { name: 'popup-double-detail', params: { surface: 'popup', state: 'detail', layout: 'double' }, selector: '#vw-surface', viewport: { width: 600, height: 450 } },
  { name: 'popup-double-editor', params: { surface: 'popup', state: 'editor', layout: 'double' }, selector: '#vw-surface', viewport: { width: 600, height: 450 } },
  { name: 'popup-double-tools', params: { surface: 'popup', state: 'tools', layout: 'double' }, selector: '#vw-surface', viewport: { width: 600, height: 450 } },
  { name: 'popup-single-auth', params: { surface: 'popup', state: 'auth', layout: 'single' }, selector: '#vw-surface', viewport: { width: 350, height: 450 } },
  { name: 'options', params: { surface: 'options' }, selector: '#vw-surface', viewport: { width: 1000, height: 700 } },
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
