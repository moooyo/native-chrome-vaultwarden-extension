import type { Page } from '@playwright/test';

/** The query parameters the deterministic fixture entry understands. */
export interface FixtureParams {
  surface: string;
  state?: string;
  theme?: 'light' | 'dark';
  count?: number;
}

/** Builds the repository-relative fixture URL the static server serves. */
export function fixturePath(params: FixtureParams): string {
  const search = new URLSearchParams();
  search.set('surface', params.surface);
  if (params.state !== undefined) search.set('state', params.state);
  if (params.theme !== undefined) search.set('theme', params.theme);
  if (params.count !== undefined) search.set('count', String(params.count));
  return `/test/ui-render/fixture.html?${search.toString()}`;
}

/**
 * Navigates to a fixture surface, emulating the requested color scheme so the token media queries
 * resolve, and waits until the fixture marks itself rendered (`body[data-ready]`).
 */
export async function gotoFixture(page: Page, params: FixtureParams): Promise<void> {
  await page.emulateMedia({ colorScheme: params.theme ?? 'light' });
  await page.goto(fixturePath(params));
  await page.waitForSelector('body[data-ready="true"]');
  await page.evaluate(() => document.fonts.ready);
}

/** The horizontal geometry of the document element. */
export interface DocumentWidth {
  scrollWidth: number;
  clientWidth: number;
}

/** Reads the document element's scroll/client widths for overflow assertions. */
export async function documentWidth(page: Page): Promise<DocumentWidth> {
  return page.evaluate(() => ({
    scrollWidth: document.documentElement.scrollWidth,
    clientWidth: document.documentElement.clientWidth,
  }));
}
