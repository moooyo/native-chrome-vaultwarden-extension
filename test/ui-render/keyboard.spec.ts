import { test, expect, type Page } from '@playwright/test';
import { gotoFixture } from './helpers.js';

/** The computed focus indicator of the actually focused element, resolved through open shadow roots. */
interface FocusIndicator {
  tag: string;
  id: string;
  outlineStyle: string;
  outlineWidth: string;
  boxShadow: string;
}

/**
 * Reads the computed outline/box-shadow of the element that keyboard focus actually landed on.
 * `document.activeElement` stops at the shadow host for open shadow roots, so this walks into
 * `shadowRoot.activeElement` (the same pattern `accessibility.spec.ts` uses for effective
 * background) to reach the real focused native control.
 */
async function focusedIndicator(page: Page): Promise<FocusIndicator | null> {
  return page.evaluate(() => {
    function deepActiveElement(root: Document | ShadowRoot): Element | null {
      const active = root.activeElement;
      if (active?.shadowRoot?.activeElement) return deepActiveElement(active.shadowRoot);
      return active;
    }
    const element = deepActiveElement(document);
    if (!element) return null;
    const style = getComputedStyle(element);
    return {
      tag: element.tagName,
      id: (element as HTMLElement).id,
      outlineStyle: style.outlineStyle,
      outlineWidth: style.outlineWidth,
      boxShadow: style.boxShadow,
    };
  });
}

test('a keyboard-navigated native control renders a visible focus indicator', async ({ page }) => {
  await gotoFixture(page, { surface: 'popup', state: 'auth', theme: 'light' });
  // The login form has no header on this surface, so the first real Tab press (not `.focus()`)
  // lands on the email input inside `vw-auth-views`' shadow root.
  await page.keyboard.press('Tab');
  const indicator = await focusedIndicator(page);
  expect(indicator).not.toBeNull();
  expect(indicator!.tag).toBe('INPUT');
  expect(indicator!.id).toBe('email');
  const hasVisibleOutline = indicator!.outlineStyle !== 'none' && Number.parseFloat(indicator!.outlineWidth) > 0;
  const hasVisibleBoxShadow = indicator!.boxShadow !== 'none';
  expect(
    hasVisibleOutline || hasVisibleBoxShadow,
    `expected a visible outline or box-shadow, got outline:${indicator!.outlineStyle} ${indicator!.outlineWidth}, box-shadow:${indicator!.boxShadow}`,
  ).toBe(true);
});

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
