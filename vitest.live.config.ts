import { defineConfig } from 'vitest/config';

if (process.env.LIVE !== '1') {
  throw new Error('Live tests are disabled. Set LIVE=1 explicitly to run them.');
}

export default defineConfig({
  test: {
    environment: 'node',
    include: ['test/live/**/*.live.test.ts'],
  },
});
