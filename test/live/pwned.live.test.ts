// Live HIBP contract check. Skipped unless LIVE=1. Run: LIVE=1 npx vitest run test/live/pwned.live.test.ts
import { describe, it, expect } from 'vitest';
import { pwnedCount } from '../../src/core/vault/pwned.js';
const LIVE = Boolean(process.env.LIVE);

(LIVE ? describe : describe.skip)('live HIBP', () => {
  it('reports a large breach count for the notorious "password"', async () => {
    const n = await pwnedCount('password');
    expect(n).toBeGreaterThan(1000);
  }, 30_000);
  it('reports 0 for a very unlikely random string', async () => {
    const n = await pwnedCount(`vw-${Date.now()}-${Math.random().toString(36).slice(2)}-unlikely`);
    expect(n).toBe(0);
  }, 30_000);
});
