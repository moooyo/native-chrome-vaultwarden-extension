import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

const page = readFileSync(new URL('../test-page/index.html', import.meta.url), 'utf8');
const guide = readFileSync(new URL('../test-page/README.md', import.meta.url), 'utf8');

describe('test-page guidance', () => {
  it('documents opt-in website passkeys and the browser fallback for required UV', () => {
    expect(guide).toContain('The feature is off by default');
    expect(guide).toContain("leaves these requests to the browser/OS authenticator");
    expect(page).toMatch(/<input type="checkbox" id="pk-uv"\s*\/>/);
  });

  it('does not infer the passkey handler from PublicKeyCredential instanceof', () => {
    expect(page).not.toContain('handledByMiyu');
    expect(page).not.toContain('duck-typed');
    expect(page).toContain("handler: 'Not inferred from the returned object");
  });

  it('matches the supported loopback hosts and deferred registration save flow', () => {
    expect(page).toContain('http://127.0.0.1');
    expect(guide).toContain('http://127.0.0.1:PORT');
    expect(page).toContain('without creating a vault item yet');
    expect(guide).toContain('submitting the website form then triggers the normal save prompt');
  });

  it('keeps every feature-table row at four columns', () => {
    const rows = guide.split(/\r?\n/).filter((line) => line.startsWith('|'));
    expect(rows.length).toBeGreaterThan(2);
    expect(rows.every((row) => (row.match(/\|/g) ?? []).length === 5)).toBe(true);
  });
});
