import { describe, expect, it, vi } from 'vitest';

vi.mock('webextension-polyfill', () => ({ default: { storage: {
  local: { get: vi.fn(), set: vi.fn() },
  onChanged: { addListener: vi.fn() },
} } }));
import { createGeneratorPolicySnapshot } from '../core/generator/enterprise-password-policy.js';
import { DEFAULT_PREFS } from '../ui/prefs.js';
import { createPasswordGenerationAction } from './password-generation-action.js';

function harness(options: {
  prefs?: unknown;
  policy?: ReturnType<typeof createGeneratorPolicySnapshot>;
} = {}) {
  let generation = 1;
  const history = { track: vi.fn(async () => ({ added: true })) };
  const generate = vi.fn(() => 'generated-password');
  const action = createPasswordGenerationAction({
    readPrefs: vi.fn(async () => options.prefs ?? DEFAULT_PREFS),
    captureAuthority: () => Object.freeze({ generation }),
    assertAuthority: (authority) => {
      if (authority.generation !== generation) throw new Error('stale');
    },
    getPolicySnapshot: () => options.policy ?? createGeneratorPolicySnapshot(null, generation),
    history,
    generate,
  });
  return {
    action,
    history,
    generate,
    bump() { generation += 1; },
  };
}

describe('createPasswordGenerationAction', () => {
  it('uses saved random-password settings even when the UI mode is username', async () => {
    const h = harness({
      prefs: {
        ...DEFAULT_PREFS,
        genMode: 'username',
        genLength: 37,
        genLowercase: false,
        genUppercase: true,
        genNumbers: false,
        genSymbols: true,
        genMinNumbers: 0,
        genMinSpecial: 3,
        genAvoidAmbiguous: false,
      },
    });
    let assertFinal: (() => void) | undefined;

    await expect(h.action.generatePasswordAndTrack((assertCurrent) => {
      assertFinal = assertCurrent;
    })).resolves.toEqual({ value: 'generated-password' });

    expect(h.generate).toHaveBeenCalledWith({
      length: 37,
      lowercase: false,
      uppercase: true,
      numbers: false,
      special: true,
      minNumbers: 0,
      minSpecial: 3,
      avoidAmbiguous: false,
    });
    expect(h.history.track).toHaveBeenCalledWith({
      value: 'generated-password',
      type: 'password',
      policyRevision: 1,
    });
    expect(assertFinal).toBeTypeOf('function');
    expect(() => assertFinal?.()).not.toThrow();
    h.bump();
    expect(() => assertFinal?.()).toThrow('stale');
  });

  it('applies enterprise floors before generating and tracks that policy revision', async () => {
    const policy = createGeneratorPolicySnapshot({
      malformed: false,
      data: {
        overridePasswordType: '',
        minLength: 42,
        useUpper: true,
        useLower: true,
        useNumbers: true,
        minNumbers: 4,
        useSpecial: true,
        minSpecial: 2,
        minNumberWords: 0,
        capitalize: false,
        includeNumber: false,
      },
    }, 9);
    const h = harness({ policy, prefs: { ...DEFAULT_PREFS, genLength: 8 } });

    await h.action.generatePasswordAndTrack(() => undefined);

    expect(h.generate).toHaveBeenCalledWith(expect.objectContaining({
      length: 42,
      minNumbers: 4,
      minSpecial: 2,
    }));
    expect(h.history.track).toHaveBeenCalledWith(expect.objectContaining({ policyRevision: 9 }));
  });

  it('refuses malformed policy and policy-forced passphrase without writing history', async () => {
    const malformed = harness({
      policy: createGeneratorPolicySnapshot({
        malformed: true,
        data: {
          overridePasswordType: '', minLength: 0, useUpper: false, useLower: false,
          useNumbers: false, minNumbers: 0, useSpecial: false, minSpecial: 0,
          minNumberWords: 0, capitalize: false, includeNumber: false,
        },
      }, 4),
    });
    await expect(malformed.action.generatePasswordAndTrack(() => undefined)).resolves.toBeUndefined();
    expect(malformed.generate).not.toHaveBeenCalled();
    expect(malformed.history.track).not.toHaveBeenCalled();

    const passphrase = harness({
      policy: createGeneratorPolicySnapshot({
        malformed: false,
        data: {
          overridePasswordType: 'passphrase',
          minLength: 0,
          useUpper: false,
          useLower: false,
          useNumbers: false,
          minNumbers: 0,
          useSpecial: false,
          minSpecial: 0,
          minNumberWords: 6,
          capitalize: false,
          includeNumber: false,
        },
      }, 5),
    });
    await expect(passphrase.action.generatePasswordAndTrack(() => undefined)).resolves.toBeUndefined();
    expect(passphrase.generate).not.toHaveBeenCalled();
    expect(passphrase.history.track).not.toHaveBeenCalled();
  });

  it('does not publish a generated result after authority changes during history commit', async () => {
    const h = harness();
    h.history.track.mockImplementationOnce(async () => {
      h.bump();
      return { added: true };
    });
    const bind = vi.fn();

    await expect(h.action.generatePasswordAndTrack(bind)).rejects.toThrow('stale');
    expect(bind).not.toHaveBeenCalled();
  });

  it('keeps a current generated value when history storage alone fails', async () => {
    const h = harness();
    h.history.track.mockRejectedValueOnce(new Error('storage unavailable'));
    const bind = vi.fn();

    await expect(h.action.generatePasswordAndTrack(bind)).resolves.toEqual({
      value: 'generated-password',
    });
    expect(bind).toHaveBeenCalledOnce();
  });

  it('rejects malformed generator output before history or clipboard authority is published', async () => {
    const h = harness();
    h.generate.mockReturnValueOnce('x'.repeat(129));
    const bind = vi.fn();

    await expect(h.action.generatePasswordAndTrack(bind)).resolves.toBeUndefined();
    expect(h.history.track).not.toHaveBeenCalled();
    expect(bind).not.toHaveBeenCalled();
  });
});
