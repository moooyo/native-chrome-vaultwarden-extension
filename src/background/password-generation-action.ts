import {
  applyGeneratorPolicySnapshot,
  type GeneratorPolicySnapshot,
} from '../core/generator/enterprise-password-policy.js';
import { DEFAULT_PASSPHRASE_OPTIONS } from '../core/generator/passphrase.js';
import {
  DEFAULT_PASSWORD_OPTIONS,
  generatePassword,
  type PasswordGenOptions,
} from '../core/generator/password.js';
import { DEFAULT_PREFS, sanitizePrefs } from '../ui/prefs.js';
import type { GeneratorHistoryProductionService } from './generator-history-production.js';

export const GENERATOR_PREFS_STORAGE_KEY = 'miyu.prefs';

export interface PasswordGenerationActionDeps<Authority> {
  readonly readPrefs: () => Promise<unknown>;
  /** Captures session, account, and enterprise-policy generations synchronously. */
  readonly captureAuthority: () => Authority;
  readonly assertAuthority: (authority: Authority) => void;
  /** Must project the same policy generation held by `authority`. */
  readonly getPolicySnapshot: (authority: Authority) => GeneratorPolicySnapshot;
  readonly history: Pick<GeneratorHistoryProductionService, 'track'>;
  readonly generate?: (options: PasswordGenOptions) => string;
}

export interface GeneratedPasswordActionResult {
  readonly value: string;
}

/**
 * Generate the keyboard/context-menu random password through the same policy and encrypted-history
 * machinery as the UI. The persisted UI mode is deliberately ignored: this action always projects
 * the saved random-password settings and never turns into a username, PIN, or passphrase command.
 */
export function createPasswordGenerationAction<Authority>(
  deps: PasswordGenerationActionDeps<Authority>,
): {
  generatePasswordAndTrack(
    bindFinalAuthority: (assertCurrent: () => void) => void,
  ): Promise<GeneratedPasswordActionResult | undefined>;
} {
  const generate = deps.generate ?? generatePassword;
  return Object.freeze({
    async generatePasswordAndTrack(bindFinalAuthority) {
      if (typeof bindFinalAuthority !== 'function') return undefined;
      const authority = deps.captureAuthority();
      const assertCurrent = (): void => deps.assertAuthority(authority);
      assertCurrent();
      const rawPrefs = await deps.readPrefs();
      assertCurrent();
      const prefs = sanitizePrefs(rawPrefs);
      const snapshot = deps.getPolicySnapshot(authority);
      assertCurrent();
      const evaluation = applyGeneratorPolicySnapshot({
        mode: 'password',
        password: randomPasswordOptions(prefs),
        passphrase: DEFAULT_PASSPHRASE_OPTIONS,
      }, snapshot);
      // Enterprise policy may force a passphrase. This command is intentionally random-password
      // only, so refuse instead of silently changing the command's credential type.
      if (!evaluation.allowed || evaluation.options.mode !== 'password') return undefined;
      const value = generate(evaluation.options.password);
      if (typeof value !== 'string' || value.length === 0 || value.length > 128) return undefined;
      assertCurrent();
      try {
        await deps.history.track({ value, type: 'password', policyRevision: snapshot.revision });
      } catch {
        // History is supporting state. A storage failure must not discard a freshly generated value,
        // but a security transition observed by the failed write still revokes the result below.
        assertCurrent();
      }
      assertCurrent();
      bindFinalAuthority(assertCurrent);
      assertCurrent();
      return Object.freeze({ value });
    },
  });
}

function randomPasswordOptions(prefs: Readonly<typeof DEFAULT_PREFS>): PasswordGenOptions {
  return Object.freeze({
    ...DEFAULT_PASSWORD_OPTIONS,
    length: prefs.genLength,
    lowercase: prefs.genLowercase,
    uppercase: prefs.genUppercase,
    numbers: prefs.genNumbers,
    special: prefs.genSymbols,
    minNumbers: prefs.genNumbers ? prefs.genMinNumbers : 0,
    minSpecial: prefs.genSymbols ? prefs.genMinSpecial : 0,
    avoidAmbiguous: prefs.genAvoidAmbiguous,
  });
}
