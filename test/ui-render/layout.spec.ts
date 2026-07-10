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

test('popup has no horizontal overflow at 320px', async ({ page }) => {
  await page.setViewportSize({ width: 320, height: 520 });
  await page.goto('/test/ui-render/fixture.html?surface=popup&state=suggestions&count=50');
  await page.waitForSelector('body[data-ready="true"]');
  expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(320);
});

test('candidate list owns short-viewport scrolling', async ({ page }) => {
  await page.setViewportSize({ width: 404, height: 360 });
  await page.goto('/test/ui-render/fixture.html?surface=popup&state=suggestions&count=50');
  await page.waitForSelector('body[data-ready="true"]');
  const geometry = await page.locator('[data-scroll-region="suggestions"]').evaluate((element) => ({
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
      await gotoFixture(page, target);
      const { scrollWidth, clientWidth } = await documentWidth(page);
      expect(scrollWidth).toBeLessThanOrEqual(clientWidth);
    });
  }
}

test('long unbroken text stays contained at 320px', async ({ page }) => {
  await page.setViewportSize({ width: 320, height: 520 });
  await gotoFixture(page, { surface: 'popup', state: 'longtext' });
  const { scrollWidth } = await documentWidth(page);
  expect(scrollWidth).toBeLessThanOrEqual(320);
});

test('200% zoom (halved 404px popup baseline) keeps content and primary controls reachable', async ({ page }) => {
  // Chrome's 200% page zoom halves the available CSS pixels. The popup's real baseline width is
  // 404 CSS px (see OVERFLOW_SURFACES above), so emulate 200% zoom with a 202x320 layout viewport
  // (404/2 x 640/2) rather than an arbitrary halved shell width.
  await page.setViewportSize({ width: 202, height: 320 });
  await gotoFixture(page, { surface: 'popup', state: 'editor' });

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
