import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: 'test/ui-render',
  testMatch: '**/*.spec.ts',
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  reporter: [['line']],
  expect: {
    toHaveScreenshot: { maxDiffPixelRatio: 0.02 },
  },
  use: { baseURL: 'http://127.0.0.1:4173', colorScheme: 'light' },
  webServer: {
    command: 'node test/ui-render/server.mjs',
    port: 4173,
    reuseExistingServer: !process.env.CI,
  },
});
