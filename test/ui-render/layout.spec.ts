import { test, expect } from '@playwright/test';
import { get } from 'node:http';
import { documentWidth, gotoFixture, type FixtureParams } from './helpers.js';

/** Every surface that renders inside the fixed-width popup shell or a full page. All must avoid
 *  document-level horizontal overflow at constrained widths. */
const OVERFLOW_SURFACES: FixtureParams[] = [
  { surface: 'popup', state: 'suggestions', count: 30 },
  { surface: 'popup', state: 'list', count: 30 },
  { surface: 'popup', state: 'detail' },
  { surface: 'popup', state: 'editor' },
  { surface: 'popup', state: 'tools' },
  { surface: 'popup', state: 'auth' },
  { surface: 'options' },
  { surface: 'receive' },
];

const WIDTHS = [320, 404, 768];

test('single popup has no horizontal overflow at 320px', async ({ page }) => {
  await page.setViewportSize({ width: 320, height: 520 });
  await page.goto('/test/ui-render/fixture.html?surface=popup&state=suggestions&layout=single&count=50');
  await page.waitForSelector('body[data-ready="true"]');
  expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(320);
});

test('unlocked popup uses a 600 by 450 double-pane frame', async ({ page }) => {
  await page.setViewportSize({ width: 600, height: 450 });
  await gotoFixture(page, { surface: 'popup', state: 'detail', layout: 'double' });
  const frame = page.locator('[data-popup-frame]');
  await expect(frame).toHaveCSS('width', '600px');
  await expect(frame).toHaveCSS('height', '450px');
  await expect(page.locator('[data-list-pane]')).toHaveCSS('width', '260px');
  await expect(page.locator('[data-detail-pane]')).toHaveCSS('width', '340px');
});

test('auth popup uses a 350 by 450 single-pane frame', async ({ page }) => {
  await page.setViewportSize({ width: 350, height: 450 });
  await gotoFixture(page, { surface: 'popup', state: 'auth', layout: 'single' });
  const frame = page.locator('[data-popup-frame]');
  await expect(frame).toHaveCSS('width', '350px');
  await expect(frame).toHaveCSS('height', '450px');
  await expect(page.locator('[data-detail-pane]')).toHaveCount(0);
  const buttonIcon = await page.locator('vw-auth-views .button.primary svg').first().boundingBox();
  expect(buttonIcon).not.toBeNull();
  expect(buttonIcon!.width).toBeLessThanOrEqual(20);
  expect(buttonIcon!.height).toBeLessThanOrEqual(20);
  const statusIcon = await page.locator('vw-auth-views vw-status-message svg').first().boundingBox();
  expect(statusIcon).not.toBeNull();
  expect(statusIcon!.width).toBeLessThanOrEqual(20);
  expect(statusIcon!.height).toBeLessThanOrEqual(20);
});

test('double-pane list owns short-viewport scrolling', async ({ page }) => {
  await page.setViewportSize({ width: 600, height: 360 });
  await page.goto('/test/ui-render/fixture.html?surface=popup&state=detail&layout=double&count=50');
  await page.waitForSelector('body[data-ready="true"]');
  const geometry = await page.locator('[data-list-pane]').evaluate((element) => ({
    clientHeight: element.clientHeight,
    scrollHeight: element.scrollHeight,
  }));
  expect(geometry.scrollHeight).toBeGreaterThan(geometry.clientHeight);
  expect(await page.evaluate(() => document.documentElement.scrollHeight)).toBeLessThanOrEqual(360);
});

for (const width of WIDTHS) {
  for (const target of OVERFLOW_SURFACES) {
    test(`no horizontal overflow at ${width}px for ${target.surface}/${target.state ?? 'default'}`, async ({ page }) => {
      await page.setViewportSize({ width, height: 640 });
      await gotoFixture(page, { ...target, layout: width < 600 ? 'single' : 'double' });
      const { scrollWidth, clientWidth } = await documentWidth(page);
      expect(scrollWidth).toBeLessThanOrEqual(clientWidth);
    });
  }
}

test('long unbroken text stays contained at 320px', async ({ page }) => {
  await page.setViewportSize({ width: 320, height: 520 });
  await gotoFixture(page, { surface: 'popup', state: 'longtext', layout: 'single' });
  const { scrollWidth } = await documentWidth(page);
  expect(scrollWidth).toBeLessThanOrEqual(320);
});

test('200% zoom (halved 350px popup baseline) keeps content and primary controls reachable', async ({ page }) => {
  await page.setViewportSize({ width: 175, height: 225 });
  await gotoFixture(page, { surface: 'popup', state: 'editor', layout: 'single' });

  const { scrollWidth, clientWidth } = await documentWidth(page);
  expect(scrollWidth).toBeLessThanOrEqual(clientWidth);

  const nameField = page.locator('vw-cipher-editor input[data-field="name"]');
  const save = page.locator('vw-cipher-editor [data-save]');
  const cancel = page.locator('vw-cipher-editor [data-back]');

  await expect(nameField).toBeVisible();
  await expect(save).toBeVisible();
  await expect(cancel).toBeVisible();

  // "Reachable" means the short-viewport scroll region can bring the primary/cancel controls
  // into view without any of them being clipped by document-level horizontal overflow.
  await save.scrollIntoViewIfNeeded();
  await expect(save).toBeInViewport();
  await cancel.scrollIntoViewIfNeeded();
  await expect(cancel).toBeInViewport();

  for (const control of [nameField, save, cancel]) {
    const box = await control.boundingBox();
    expect(box).not.toBeNull();
    expect(box!.x).toBeGreaterThanOrEqual(0);
    expect(box!.x + box!.width).toBeLessThanOrEqual(clientWidth);
  }
});

test('the static server rejects encoded path traversal', async () => {
  const status = await new Promise<number>((resolve, reject) => {
    const request = get({ host: '127.0.0.1', port: 4173, path: '/..%2f..%2fetc%2fpasswd' }, (response) => {
      response.resume();
      resolve(response.statusCode ?? 0);
    });
    request.on('error', reject);
  });
  expect(status).toBe(403);
});
