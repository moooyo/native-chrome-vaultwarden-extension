import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

function source(relativeUrl: string): string {
  return readFileSync(new URL(relativeUrl, import.meta.url), 'utf8');
}

describe('compact density styles', () => {
  it('defines inherited comfortable and compact row geometry at page roots', () => {
    const tokens = source('./components/tokens.ts');
    expect(tokens).toContain(":host([data-density='compact'])");
    expect(tokens).toContain('--vw-list-row-min:46px');
    expect(tokens).toContain('--vw-list-row-min:40px');
    expect(tokens).toContain('--vw-totp-row-min:40px');
    expect(tokens).toContain('--vw-command-row-min:40px');
    expect(tokens).toContain('--vw-setting-row-min:56px');
  });

  it('consumes the density tokens in the main repeated UI rows', () => {
    expect(source('./popup/vault/vault-view.ts')).toMatch(
      /--vw-list-row-min[\s\S]*--vw-command-row-min/,
    );
    expect(source('./popup/vault/totp-view.ts')).toContain('--vw-totp-row-min');
    expect(source('./components/setting-card.ts')).toContain('--vw-setting-row-min');
  });
});
