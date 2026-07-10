import { test, expect } from '@playwright/test';
import { gotoFixture } from './helpers.js';

test('vault tabs move selection with the arrow keys', async ({ page }) => {
  await gotoFixture(page, { surface: 'popup', state: 'suggestions', count: 10 });
  const tabs = page.locator('vw-tabs button[role="tab"]');
  const suggestions = tabs.nth(0);
  const allItems = tabs.nth(1);
  await suggestions.focus();
  await expect(suggestions).toHaveAttribute('aria-selected', 'true');
  await page.keyboard.press('ArrowRight');
  await expect(allItems).toHaveAttribute('aria-selected', 'true');
  await expect(allItems).toBeFocused();
  await page.keyboard.press('ArrowLeft');
  await expect(suggestions).toHaveAttribute('aria-selected', 'true');
});

test('account menu opens, navigates, and Escape restores trigger focus', async ({ page }) => {
  await gotoFixture(page, { surface: 'popup', state: 'suggestions', count: 10 });
  const trigger = page.locator('vw-account-menu [data-trigger]');
  await trigger.click();
  const items = page.locator('vw-account-menu vw-menu button[role="menuitem"]');
  await expect(items.first()).toBeFocused();
  await page.keyboard.press('ArrowDown');
  await expect(items.nth(1)).toBeFocused();
  await page.keyboard.press('Escape');
  await expect(page.locator('vw-account-menu vw-menu button[role="menuitem"]')).toHaveCount(0);
  await expect(trigger).toBeFocused();
});

test('dialog traps and restores focus and closes on Escape', async ({ page }) => {
  await gotoFixture(page, { surface: 'dialog' });
  const opener = page.locator('#vw-open-dialog');
  await opener.focus();
  await opener.click();
  const confirm = page.locator('vw-dialog #vw-dialog-confirm');
  await expect(confirm).toBeFocused();
  await page.keyboard.press('Escape');
  await expect(page.locator('vw-dialog dialog[open]')).toHaveCount(0);
  await expect(opener).toBeFocused();
});

test('passkey consent dialog resolves on Escape', async ({ page }) => {
  await gotoFixture(page, { surface: 'consent' });
  const status = page.locator('#vw-consent-result');
  await expect(status).toHaveText('pending');
  await page.keyboard.press('Escape');
  await expect(status).toHaveText('cancelled');
});

test('a success live region is polite and an error live region is assertive', async ({ page }) => {
  await gotoFixture(page, { surface: 'popup', state: 'filled', count: 5 });
  const status = page.locator('vw-status-message [role="status"]').first();
  await expect(status).toHaveAttribute('aria-live', 'polite');

  await gotoFixture(page, { surface: 'popup', state: 'auth', theme: 'light' });
  const alert = page.locator('vw-status-message [role="alert"]').first();
  await expect(alert).toHaveAttribute('aria-live', 'assertive');
});
