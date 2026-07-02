import { describe, it, expect } from 'vitest';
import { shouldInterceptCreate } from './page-webauthn.js';

const ES256 = [{ type: 'public-key', alg: -7 }];

describe('shouldInterceptCreate', () => {
  it('intercepts a same-origin ES256 platform request', () => {
    expect(shouldInterceptCreate({ rp: { id: 'example.com' }, pubKeyCredParams: ES256 } as any, 'app.example.com')).toBe(true);
  });
  it('falls back when rpId is not a suffix of host', () => {
    expect(shouldInterceptCreate({ rp: { id: 'evil.com' }, pubKeyCredParams: ES256 } as any, 'example.com')).toBe(false);
  });
  it('falls back when no ES256 param', () => {
    expect(shouldInterceptCreate({ rp: { id: 'example.com' }, pubKeyCredParams: [{ type: 'public-key', alg: -257 }] } as any, 'example.com')).toBe(false);
  });
  it('falls back for cross-platform attachment', () => {
    expect(shouldInterceptCreate({ rp: { id: 'example.com' }, pubKeyCredParams: ES256, authenticatorSelection: { authenticatorAttachment: 'cross-platform' } } as any, 'example.com')).toBe(false);
  });
  it('defaults rpId to host when rp.id is absent', () => {
    expect(shouldInterceptCreate({ rp: {}, pubKeyCredParams: ES256 } as any, 'example.com')).toBe(true);
  });
});
