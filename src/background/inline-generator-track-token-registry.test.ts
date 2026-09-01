import { describe, expect, it, vi } from 'vitest';
import {
  createGeneratorPolicySnapshot,
  type PasswordGeneratorOptions,
} from '../core/generator/enterprise-password-policy.js';
import {
  InlineGeneratorTrackTokenRegistry,
  type InlineGeneratorTrackOwner,
} from './inline-generator-track-token-registry.js';

const NOW = 1_800_000_000_000;
const TOKEN_A = '11111111-1111-4111-8111-111111111111';
const TOKEN_B = '22222222-2222-4222-8222-222222222222';
const OWNER: InlineGeneratorTrackOwner = Object.freeze({
  tabId: 7,
  frameId: 0,
  documentId: 'document-a',
  url: 'https://example.com/register',
});
const POLICY = createGeneratorPolicySnapshot(null, 7);
const PASSWORD_OPTIONS: PasswordGeneratorOptions = Object.freeze({
  mode: 'password',
  password: Object.freeze({
    length: 12,
    lowercase: true,
    uppercase: true,
    numbers: true,
    special: true,
    minNumbers: 1,
    minSpecial: 1,
    avoidAmbiguous: false,
  }),
  passphrase: Object.freeze({
    numWords: 3,
    separator: '-',
    capitalize: false,
    includeNumber: false,
  }),
});
const PASSPHRASE_OPTIONS: PasswordGeneratorOptions = Object.freeze({
  ...PASSWORD_OPTIONS,
  mode: 'passphrase',
  passphrase: Object.freeze({
    numWords: 3,
    separator: '-',
    capitalize: false,
    includeNumber: true,
  }),
});

function harness(options: {
  ids?: string[];
  now?: () => number;
  track?: (request: { value: string; type: string; policyRevision: number }) => Promise<{ added: boolean }>;
  maxEntries?: number;
} = {}) {
  const ids = options.ids ?? [TOKEN_A];
  const track = vi.fn(options.track ?? (async () => ({ added: true })));
  const registry = new InlineGeneratorTrackTokenRegistry({
    history: { track: track as never },
    createId: () => ids.shift()!,
    now: options.now ?? (() => NOW),
    ...(options.maxEntries === undefined ? {} : { maxEntries: options.maxEntries }),
  });
  return { registry, track };
}

describe('InlineGeneratorTrackTokenRegistry', () => {
  it('tracks an exact generated password once with the authorized policy revision', async () => {
    const h = harness();
    const token = h.registry.issue(OWNER, POLICY, PASSWORD_OPTIONS, () => {});

    await expect(h.registry.consume(token, OWNER, 'Abcdef2!ghij')).resolves.toEqual({
      kind: 'tracked', added: true,
    });
    await expect(h.registry.consume(token, OWNER, 'Abcdef2!ghij')).resolves.toEqual({ kind: 'rejected' });
    expect(h.track).toHaveBeenCalledWith({
      value: 'Abcdef2!ghij',
      type: 'password',
      policyRevision: 7,
    });
  });

  it('classifies and validates an authorized passphrase independently from password history', async () => {
    const h = harness();
    const token = h.registry.issue(OWNER, POLICY, PASSPHRASE_OPTIONS, () => {});

    await expect(h.registry.consume(token, OWNER, 'abacus-abdomen-able7')).resolves.toEqual({
      kind: 'tracked', added: true,
    });
    expect(h.track).toHaveBeenCalledWith(expect.objectContaining({
      value: 'abacus-abdomen-able7',
      type: 'passphrase',
    }));
  });

  it('consumes before rejecting a wrong document, stale authority, or policy-invalid value', async () => {
    const wrongOwner = harness();
    const wrongToken = wrongOwner.registry.issue(OWNER, POLICY, PASSWORD_OPTIONS, () => {});
    await expect(wrongOwner.registry.consume(wrongToken, {
      ...OWNER, documentId: 'document-b',
    }, 'Abcdef2!ghij')).resolves.toEqual({ kind: 'rejected' });
    await expect(wrongOwner.registry.consume(wrongToken, OWNER, 'Abcdef2!ghij'))
      .resolves.toEqual({ kind: 'rejected' });

    let current = true;
    const stale = harness();
    const staleToken = stale.registry.issue(OWNER, POLICY, PASSWORD_OPTIONS, () => {
      if (!current) throw new Error('stale');
    });
    current = false;
    await expect(stale.registry.consume(staleToken, OWNER, 'Abcdef2!ghij'))
      .resolves.toEqual({ kind: 'rejected' });

    const invalid = harness();
    const invalidToken = invalid.registry.issue(OWNER, POLICY, PASSWORD_OPTIONS, () => {});
    await expect(invalid.registry.consume(invalidToken, OWNER, 'username@example.com'))
      .resolves.toEqual({ kind: 'rejected' });
    expect(invalid.track).not.toHaveBeenCalled();
  });

  it('contains encrypted-history failure without making the consumed token replayable', async () => {
    const h = harness({ track: async () => { throw new Error('storage unavailable'); } });
    const token = h.registry.issue(OWNER, POLICY, PASSWORD_OPTIONS, () => {});

    await expect(h.registry.consume(token, OWNER, 'Abcdef2!ghij')).resolves.toEqual({ kind: 'failed' });
    await expect(h.registry.consume(token, OWNER, 'Abcdef2!ghij')).resolves.toEqual({ kind: 'rejected' });
  });

  it('expires and revokes tokens by exact document, tab, and global lifecycle', async () => {
    let now = NOW;
    const expired = harness({ now: () => now });
    const expiredToken = expired.registry.issue(OWNER, POLICY, PASSWORD_OPTIONS, () => {});
    now += 30_000;
    await expect(expired.registry.consume(expiredToken, OWNER, 'Abcdef2!ghij'))
      .resolves.toEqual({ kind: 'rejected' });

    const revoked = harness({ ids: [TOKEN_A, TOKEN_B] });
    const first = revoked.registry.issue(OWNER, POLICY, PASSWORD_OPTIONS, () => {});
    const secondOwner = { ...OWNER, tabId: 8 };
    const second = revoked.registry.issue(secondOwner, POLICY, PASSWORD_OPTIONS, () => {});
    expect(revoked.registry.revokeDocument(OWNER)).toBe(1);
    expect(revoked.registry.revokeTab(8)).toBe(1);
    expect(revoked.registry.revokeAll()).toBe(0);
    await expect(revoked.registry.consume(first, OWNER, 'Abcdef2!ghij')).resolves.toEqual({ kind: 'rejected' });
    await expect(revoked.registry.consume(second, secondOwner, 'Abcdef2!ghij')).resolves.toEqual({ kind: 'rejected' });
  });

  it('bounds capacity and retires consumed UUIDs to prevent ABA reuse', async () => {
    const h = harness({ ids: [TOKEN_A, ...Array<string>(32).fill(TOKEN_A)], maxEntries: 1 });
    const token = h.registry.issue(OWNER, POLICY, PASSWORD_OPTIONS, () => {});
    expect(() => h.registry.issue({ ...OWNER, tabId: 8 }, POLICY, PASSWORD_OPTIONS, () => {}))
      .toThrow(/capacity/);
    await h.registry.consume(token, OWNER, 'Abcdef2!ghij');
    expect(() => h.registry.issue(OWNER, POLICY, PASSWORD_OPTIONS, () => {})).toThrow(/allocate/);
  });
});
