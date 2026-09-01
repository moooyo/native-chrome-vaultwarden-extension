// @vitest-environment happy-dom
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

// The redesigned view composes the (frozen) MiYu design system, whose i18n module imports
// webextension-polyfill at the top of its graph. That polyfill throws when loaded outside an
// extension, so — like auth-views.test.ts — we stub it. LocalizeController only subscribes on
// connect; no storage call happens at mount, but the stub covers the surface it could touch.
vi.mock('webextension-polyfill', () => ({
  default: {
    storage: {
      local: { get: vi.fn(async () => ({})), set: vi.fn(async () => {}) },
      onChanged: { addListener: vi.fn() },
    },
  },
}));

import './generator-view.js';
import type { VwGeneratorView } from './generator-view.js';
import {
  createGeneratorPolicySnapshot,
  UNAVAILABLE_GENERATOR_POLICY_SNAPSHOT,
} from '../../../core/generator/enterprise-password-policy.js';
import { EMPTY_PASSWORD_GENERATOR_POLICY } from '../../../core/policy/password-generator-policy.js';
import { DEFAULT_PREFS, getPrefs, initPrefs, setPref, setPrefs } from '../../prefs.js';

function managedPolicy(
  data: Partial<typeof EMPTY_PASSWORD_GENERATOR_POLICY>,
  revision = 2,
) {
  return createGeneratorPolicySnapshot({
    malformed: false,
    data: { ...EMPTY_PASSWORD_GENERATOR_POLICY, ...data },
  }, revision);
}

beforeEach(async () => {
  await initPrefs();
});

async function mount(
  props: Partial<VwGeneratorView> = {},
  onGenerated?: (event: Event) => void,
): Promise<VwGeneratorView> {
  const el = document.createElement('vw-generator-view') as VwGeneratorView;
  Object.assign(el, { generatorPolicy: createGeneratorPolicySnapshot(null, 1) }, props);
  if (onGenerated) el.addEventListener('vw-history-add', onGenerated);
  document.body.append(el);
  await el.updateComplete;
  return el;
}

function q<T extends Element>(el: VwGeneratorView, sel: string): T {
  return el.shadowRoot!.querySelector<T>(sel)!;
}

function output(el: VwGeneratorView): string {
  return q<HTMLElement>(el, '[data-output]').textContent ?? '';
}

async function setRange(el: VwGeneratorView, value: string): Promise<void> {
  const input = q<HTMLInputElement>(el, '[data-length]');
  input.value = value;
  input.dispatchEvent(new Event('input'));
  await el.updateComplete;
}

async function setWords(el: VwGeneratorView, value: string): Promise<void> {
  const input = q<HTMLInputElement>(el, '[data-words]');
  input.value = value;
  input.dispatchEvent(new Event('input'));
  await el.updateComplete;
}

async function setMode(el: VwGeneratorView, id: string): Promise<void> {
  q(el, '[data-mode]').dispatchEvent(
    new CustomEvent('vw-segmented-change', { detail: { id }, bubbles: true, composed: true }),
  );
  await el.updateComplete;
}

async function setMinimum(el: VwGeneratorView, kind: 'numbers' | 'special', value: string): Promise<void> {
  const input = q<HTMLInputElement>(el, `[data-min-${kind}]`);
  input.value = value;
  input.dispatchEvent(new Event('change'));
  await el.updateComplete;
}

async function setUsernameType(el: VwGeneratorView, id: string): Promise<void> {
  q(el, '[data-username-type]').dispatchEvent(
    new CustomEvent('vw-segmented-change', { detail: { id }, bubbles: true, composed: true }),
  );
  await el.updateComplete;
}

async function setUsernameLength(el: VwGeneratorView, value: string): Promise<void> {
  const input = q<HTMLInputElement>(el, '[data-username-length]');
  input.value = value;
  input.dispatchEvent(new Event('input'));
  await el.updateComplete;
}

async function setUsernameToggle(el: VwGeneratorView, marker: string, checked: boolean): Promise<void> {
  const input = q<HTMLInputElement>(el, `[data-username-toggle='${marker}']`);
  input.checked = checked;
  input.dispatchEvent(new Event('change'));
  await el.updateComplete;
}

async function setPlusAddressEmail(el: VwGeneratorView, value: string): Promise<void> {
  const input = q<HTMLInputElement>(el, '[data-plus-address-email]');
  input.value = value;
  input.dispatchEvent(new Event('input'));
  await el.updateComplete;
}

async function setCatchAllDomain(el: VwGeneratorView, value: string): Promise<void> {
  const input = q<HTMLInputElement>(el, '[data-catch-all-domain]');
  input.value = value;
  input.dispatchEvent(new Event('input'));
  await el.updateComplete;
}

async function setToggle(el: VwGeneratorView, marker: string, checked: boolean): Promise<void> {
  q(el, `[data-toggle='${marker}']`).dispatchEvent(
    new CustomEvent('vw-toggle-change', { detail: { checked }, bubbles: true, composed: true }),
  );
  await el.updateComplete;
}

async function click(el: VwGeneratorView, sel: string): Promise<void> {
  q<HTMLButtonElement>(el, sel).click();
  await el.updateComplete;
}

describe('vw-generator-view modes', () => {
  afterEach(() => {
    document.body.replaceChildren();
  });

  it('starts in random mode with a value at the default length', async () => {
    const el = await mount();
    expect(q<HTMLElement & { value: string }>(el, '[data-mode]').value).toBe('random');
    expect(output(el).length).toBe(DEFAULT_PREFS.genLength);
    expect(q<HTMLElement>(el, '[data-length-value]').textContent).toBe(String(DEFAULT_PREFS.genLength));
  });

  it('seeds the initial random password from stored preferences', async () => {
    setPref('genLength', 24, false);
    setPref('genUppercase', false, false);
    setPref('genNumbers', false, false);
    setPref('genSymbols', false, false);
    const el = await mount();
    expect(output(el)).toMatch(/^[a-z]{24}$/);
    expect(q<HTMLElement>(el, '[data-length-value]').textContent).toBe('24');
    expect((q<HTMLElement & { checked: boolean }>(el, "[data-toggle='upper']")).checked).toBe(false);
    expect((q<HTMLElement & { checked: boolean }>(el, "[data-toggle='number']")).checked).toBe(false);
    expect((q<HTMLElement & { checked: boolean }>(el, "[data-toggle='symbol']")).checked).toBe(false);
  });

  it('produces a passphrase in memorable mode from a dedicated word-count control', async () => {
    const el = await mount();
    await setMode(el, 'memorable');
    // Memorable decouples from the character-length slider: it uses the official six-word default
    // within a dedicated 3–20 word-count control.
    expect(q(el, '[data-words]')).toBeTruthy();
    expect(el.shadowRoot!.querySelector('[data-length]')).toBeNull();
    expect(output(el)).toMatch(/^[a-z]+(?:-[a-z]+){5}$/);
    expect(q<HTMLElement>(el, '[data-words-value]').textContent).toBe('6');
  });

  it('produces a numeric-only value in PIN mode', async () => {
    const el = await mount();
    await setMode(el, 'pin');
    expect(output(el)).toMatch(/^[0-9]+$/);
    expect(output(el).length).toBe(14);
  });

  it('keeps password preferences isolated from passphrase and PIN defaults', async () => {
    setPref('genLength', 24, false);
    setPref('genUppercase', false, false);
    setPref('genNumbers', false, false);
    setPref('genSymbols', false, false);
    const el = await mount();
    expect(output(el)).toMatch(/^[a-z]{24}$/);

    await setMode(el, 'memorable');
    expect(output(el)).toMatch(/^[a-z]+(?:-[a-z]+){5}$/);
    expect((q<HTMLElement & { checked: boolean }>(el, "[data-toggle='upper']")).checked).toBe(false);
    expect((q<HTMLElement & { checked: boolean }>(el, "[data-toggle='number']")).checked).toBe(false);

    await setMode(el, 'pin');
    expect(output(el)).toMatch(/^[0-9]{14}$/);
    expect(q<HTMLElement>(el, '[data-length-value]').textContent).toBe('14');
  });

  it('shows every password parameter and only mode-relevant controls elsewhere', async () => {
    const el = await mount();
    expect(q(el, "[data-toggle='lower']")).toBeTruthy();
    expect(q(el, "[data-toggle='upper']")).toBeTruthy();
    expect(q(el, "[data-toggle='number']")).toBeTruthy();
    expect(q(el, "[data-toggle='symbol']")).toBeTruthy();
    expect(q(el, "[data-toggle='ambiguous']")).toBeTruthy();
    expect(q(el, '[data-min-numbers]')).toBeTruthy();
    expect(q(el, '[data-min-special]')).toBeTruthy();
    await setMode(el, 'memorable');
    expect(q(el, "[data-toggle='upper']")).toBeTruthy();
    expect(q(el, "[data-toggle='number']")).toBeTruthy();
    expect(el.shadowRoot!.querySelector("[data-toggle='symbol']")).toBeNull();
    expect(el.shadowRoot!.querySelector('[data-min-numbers]')).toBeNull();
    await setMode(el, 'pin');
    expect(el.shadowRoot!.querySelector("[data-toggle='upper']")).toBeNull();
    expect(el.shadowRoot!.querySelector("[data-toggle='number']")).toBeNull();
    expect(el.shadowRoot!.querySelector("[data-toggle='symbol']")).toBeNull();
  });

  it('does not claim an enabled but empty organization policy controls the generator', async () => {
    const el = await mount({ generatorPolicy: managedPolicy({}) });

    expect(el.shadowRoot!.querySelector('[data-generator-policy]')).toBeNull();
    expect(q<HTMLInputElement>(el, '[data-length]').disabled).toBe(false);
    expect(q<HTMLElement & { disabled: boolean }>(el, "[data-toggle='upper']").disabled).toBe(false);
    expect(q<HTMLElement & { options: Array<{ id: string }> }>(el, '[data-mode]').options.map(({ id }) => id))
      .toContain('pin');
  });

  it('forces a managed passphrase while leaving its numeric floor tunable', async () => {
    const el = await mount({
      generatorPolicy: managedPolicy({
        overridePasswordType: 'passphrase',
        minNumberWords: 8,
        capitalize: true,
        includeNumber: true,
      }),
    });

    expect(q<HTMLElement & { value: string }>(el, '[data-mode]').value).toBe('memorable');
    expect(output(el).split('-')).toHaveLength(8);
    expect(output(el)).toMatch(/[0-9]/);
    expect(output(el).split('-').every((word) => /^[A-Z]/.test(word))).toBe(true);
    expect(q<HTMLInputElement>(el, '[data-words]').disabled).toBe(false);
    expect(q<HTMLInputElement>(el, '[data-words]').min).toBe('8');
    expect(q<HTMLElement & { disabled: boolean }>(el, "[data-toggle='upper']").disabled).toBe(true);
    expect(q<HTMLElement & { disabled: boolean }>(el, "[data-toggle='number']").disabled).toBe(true);
    expect(q<HTMLElement & { message: string }>(el, '[data-generator-policy]').message)
      .toContain('组织');
    expect(q<HTMLElement & { options: Array<{ id: string }> }>(el, '[data-mode]').options.map(({ id }) => id))
      .toEqual(['memorable', 'username']);
    expect(getPrefs().genMode).toBe('random');
    expect(getPrefs().genPassphraseWords).toBe(DEFAULT_PREFS.genPassphraseWords);
  });

  it('restores saved user choices when a policy-derived state is removed', async () => {
    setPref('genLength', 12, false);
    setPref('genUppercase', false, false);
    const el = await mount({ generatorPolicy: managedPolicy({ minLength: 30, useUpper: true }) });

    expect(q<HTMLElement>(el, '[data-length-value]').textContent).toBe('30');
    expect(q<HTMLInputElement>(el, '[data-length]').disabled).toBe(false);
    expect(q<HTMLInputElement>(el, '[data-length]').min).toBe('30');
    expect(q<HTMLElement & { disabled: boolean }>(el, "[data-toggle='upper']").disabled).toBe(true);
    expect(q<HTMLElement & { disabled: boolean }>(el, "[data-toggle='lower']").disabled).toBe(false);
    expect(getPrefs().genLength).toBe(12);
    expect(getPrefs().genUppercase).toBe(false);

    el.generatorPolicy = createGeneratorPolicySnapshot(null, 3);
    await el.updateComplete;

    expect(q<HTMLElement>(el, '[data-length-value]').textContent).toBe('12');
    expect(output(el)).toMatch(/^[a-z0-9!@#$%^&*]+$/);
  });

  it('keeps policy-required character settings separate from saved user preferences', async () => {
    setPrefs({
      genLowercase: false,
      genUppercase: false,
      genNumbers: true,
      genMinNumbers: 4,
      genAvoidAmbiguous: false,
    }, false);
    const el = await mount({ generatorPolicy: managedPolicy({ useLower: true, minNumbers: 6 }) });

    expect((q<HTMLElement & { checked: boolean }>(el, "[data-toggle='lower']")).checked).toBe(true);
    expect((q<HTMLElement & { disabled: boolean }>(el, "[data-toggle='lower']")).disabled).toBe(true);
    expect(q<HTMLInputElement>(el, '[data-min-numbers]').value).toBe('6');
    expect(q<HTMLInputElement>(el, '[data-min-numbers]').min).toBe('6');
    expect((q<HTMLElement & { checked: boolean }>(el, "[data-toggle='ambiguous']")).checked).toBe(false);
    expect(getPrefs()).toMatchObject({
      genLowercase: false,
      genMinNumbers: 4,
      genAvoidAmbiguous: false,
    });

    el.generatorPolicy = createGeneratorPolicySnapshot(null, 3);
    await el.updateComplete;

    expect((q<HTMLElement & { checked: boolean }>(el, "[data-toggle='lower']")).checked).toBe(false);
    expect(q<HTMLInputElement>(el, '[data-min-numbers]').value).toBe('4');
    expect(output(el)).toMatch(/^[0-9!@#$%^&*]+$/);
  });

  it('fails a malformed managed password policy closed', async () => {
    const el = await mount({ generatorPolicy: UNAVAILABLE_GENERATOR_POLICY_SNAPSHOT });

    expect(output(el)).toBe('');
    expect(q<HTMLButtonElement>(el, '[data-copy]').disabled).toBe(true);
    expect(q<HTMLButtonElement>(el, '[data-regenerate]').disabled).toBe(true);
    const status = q<HTMLElement & { message: string; tone: string }>(el, '[data-generator-policy]');
    expect(status.tone).toBe('danger');
    expect(status.message).toContain('无效');
  });
});

describe('vw-generator-view username modes', () => {
  afterEach(() => {
    document.body.replaceChildren();
  });

  it('generates a random-word username with independent capitalization and number options', async () => {
    const el = await mount();
    await setMode(el, 'username');
    expect(q<HTMLElement & { value: string }>(el, '[data-username-type]').value).toBe('randomWord');
    expect(output(el).length).toBeGreaterThan(0);
    expect(el.shadowRoot!.querySelector('[data-strength]')).toBeNull();

    await setUsernameToggle(el, 'capitalize', true);
    expect(output(el).charAt(0)).toMatch(/[A-Z]/);
    await setUsernameToggle(el, 'number', true);
    expect(output(el)).toMatch(/[0-9]{4}$/);
    expect(q<HTMLInputElement>(el, "[data-username-toggle='capitalize']").getAttribute('aria-label')).toBe('首字母大写');
    expect(q<HTMLInputElement>(el, "[data-username-toggle='number']").getAttribute('aria-label')).toBe('末尾添加 4 位数字');
  });

  it('generates a plus-addressed username from the validated account email', async () => {
    const el = await mount({ accountEmail: ' me@example.com ' });
    await setMode(el, 'username');
    await setUsernameType(el, 'plusAddressed');
    expect(output(el)).toMatch(/^me\+[a-z0-9]{8}@example\.com$/);
    expect(q<HTMLInputElement>(el, '[data-plus-address-email]').value).toBe('me@example.com');
    expect(el.shadowRoot!.textContent).toContain('邮箱服务商必须支持加号地址');

    await setPlusAddressEmail(el, 'alias@other.example');
    expect(output(el)).toMatch(/^alias\+[a-z0-9]{8}@other\.example$/);
    await setUsernameLength(el, '12');
    expect(output(el)).toMatch(/^alias\+[a-z0-9]{12}@other\.example$/);
    expect(q<HTMLElement>(el, '[data-username-length-value]').textContent).toBe('12');
    expect(q<HTMLInputElement>(el, '[data-username-length]').getAttribute('aria-label')).toBe('随机部分长度');
  });

  it('fails closed for plus addressing until a valid account email is supplied', async () => {
    const el = await mount({ accountEmail: 'name@example.com/path' });
    await setMode(el, 'username');
    await setUsernameType(el, 'plusAddressed');
    expect(output(el)).toBe('');
    expect(q<HTMLElement>(el, '[data-username-error]').textContent).toContain('请输入有效的基础邮箱');
    expect(q<HTMLButtonElement>(el, '[data-copy]').disabled).toBe(true);
    expect(q<HTMLButtonElement>(el, '[data-regenerate]').disabled).toBe(true);

    el.accountEmail = 'valid@example.org';
    await el.updateComplete;
    expect(output(el)).toMatch(/^valid\+[a-z0-9]{8}@example\.org$/);
    expect(el.shadowRoot!.querySelector('[data-username-error]')).toBeNull();
    expect(q<HTMLButtonElement>(el, '[data-copy]').disabled).toBe(false);
  });

  it('rejects invalid dot-atoms and generated plus addresses that exceed email limits', async () => {
    const el = await mount({ accountEmail: '.name@example.com' });
    await setMode(el, 'username');
    await setUsernameType(el, 'plusAddressed');
    for (const email of ['.name@example.com', 'name.@example.com', 'name..x@example.com']) {
      await setPlusAddressEmail(el, email);
      expect(output(el)).toBe('');
      expect(q<HTMLElement>(el, '[data-username-error]').textContent).toContain('请输入有效的基础邮箱');
    }

    await setPlusAddressEmail(el, `${'a'.repeat(56)}@example.com`);
    expect(output(el)).toBe('');
    expect(q<HTMLElement>(el, '[data-username-error]').textContent).toContain('缩短随机部分长度');
    await setUsernameLength(el, '4');
    expect(output(el)).toMatch(new RegExp(`^${'a'.repeat(56)}\\+[a-z0-9]{4}@example\\.com$`));
  });

  it('requires an explicit valid domain for catch-all generation', async () => {
    const el = await mount({ accountEmail: 'me@example.com' });
    await setMode(el, 'username');
    await setUsernameType(el, 'catchAll');
    expect(output(el)).toBe('');
    expect(q<HTMLButtonElement>(el, '[data-copy]').disabled).toBe(true);
    expect(el.shadowRoot!.textContent).toContain('已配置为接收 Catch-all 邮件的域名');

    await setCatchAllDomain(el, 'example.com/path');
    expect(output(el)).toBe('');
    expect(q<HTMLElement>(el, '[data-username-error]').textContent).toContain('不含路径或端口');

    const longDomain = `${'a'.repeat(61)}.${'b'.repeat(61)}.${'c'.repeat(61)}.${'d'.repeat(60)}`;
    await setCatchAllDomain(el, longDomain);
    expect(output(el)).toBe('');
    expect(q<HTMLElement>(el, '[data-username-error]').textContent).toContain('改用更短的域名');

    await setCatchAllDomain(el, '@mail.example.com');
    expect(output(el)).toMatch(/^[a-z0-9]{8}@mail\.example\.com$/);
    expect(el.shadowRoot!.querySelector('[data-username-error]')).toBeNull();
    expect(q<HTMLButtonElement>(el, '[data-copy]').disabled).toBe(false);
  });

  it('copies usernames without retracking and tracks the next successful regenerate', async () => {
    const el = await mount();
    await setMode(el, 'username');
    const current = output(el);
    const copied = vi.fn();
    const recorded = vi.fn();
    el.addEventListener('vw-copy', (event) => copied((event as CustomEvent).detail));
    el.addEventListener('vw-history-add', (event) => recorded((event as CustomEvent).detail));

    await click(el, '[data-copy]');
    expect(copied).toHaveBeenCalledWith({ value: current, label: '用户名' });
    expect(recorded).not.toHaveBeenCalled();
    expect(q<HTMLButtonElement>(el, '[data-copy]').textContent).toContain('复制用户名');

    await click(el, '[data-regenerate]');
    expect(recorded).toHaveBeenLastCalledWith({
      value: output(el), type: 'username', policyRevision: 1,
    });
  });
});

describe('vw-generator-view length + toggles', () => {
  afterEach(() => {
    document.body.replaceChildren();
  });

  it('supports the official 5 through 128 password length range', async () => {
    const el = await mount();
    expect(q<HTMLInputElement>(el, '[data-length]').min).toBe('5');
    expect(q<HTMLInputElement>(el, '[data-length]').max).toBe('128');
    await setRange(el, '128');
    expect(output(el).length).toBe(128);
    expect(q<HTMLElement>(el, '[data-length-value]').textContent).toBe('128');
    await setRange(el, '5');
    expect(output(el).length).toBe(5);
  });

  it('clamps memorable word count to a maximum of 20', async () => {
    const el = await mount();
    await setMode(el, 'memorable');
    await setWords(el, '40');
    expect(output(el).split('-').length).toBe(20);
  });

  it('disables generation with an accessible error when every character type is off', async () => {
    const el = await mount();
    await setToggle(el, 'lower', false);
    await setToggle(el, 'upper', false);
    await setToggle(el, 'number', false);
    await setToggle(el, 'symbol', false);
    expect(output(el)).toBe('');
    expect(q<HTMLButtonElement>(el, '[data-copy]').disabled).toBe(true);
    expect(q<HTMLButtonElement>(el, '[data-regenerate]').disabled).toBe(true);
    expect(q<HTMLElement & { message: string }>(el, '[data-generator-configuration]').message)
      .toContain('至少启用一种');

    await setToggle(el, 'lower', true);
    expect(output(el)).toMatch(/^[a-z]+$/);
    expect(el.shadowRoot!.querySelector('[data-generator-configuration]')).toBeNull();
  });

  it('honors class minimums and avoid-ambiguous as independent preferences', async () => {
    const el = await mount();
    await setRange(el, '32');
    await setMinimum(el, 'numbers', '4');
    await setMinimum(el, 'special', '3');
    expect((output(el).match(/[0-9]/g) ?? []).length).toBeGreaterThanOrEqual(4);
    expect((output(el).match(/[!@#$%^&*]/g) ?? []).length).toBeGreaterThanOrEqual(3);
    expect(output(el)).not.toMatch(/[Il1O0]/);
    expect(getPrefs()).toMatchObject({
      genMinNumbers: 4,
      genMinSpecial: 3,
      genAvoidAmbiguous: true,
    });
  });

  it('disables generation when class minimums cannot fit the selected length', async () => {
    const recorded = vi.fn();
    const el = await mount({}, (event) => recorded((event as CustomEvent).detail));
    await setRange(el, '5');
    recorded.mockClear();
    await setMinimum(el, 'numbers', '4');
    await setMinimum(el, 'special', '4');

    expect(output(el)).toBe('');
    expect(recorded).not.toHaveBeenCalled();
    expect(q<HTMLButtonElement>(el, '[data-regenerate]').disabled).toBe(true);
    const status = q<HTMLElement & { message: string }>(el, '[data-generator-configuration]');
    expect(status.message).toContain('至少需要 10 个字符');
    expect(q<HTMLInputElement>(el, '[data-length]').getAttribute('aria-describedby'))
      .toBe('generator-validation-status');

    await setRange(el, '10');
    expect(output(el)).toHaveLength(10);
    expect(recorded).toHaveBeenCalledWith({
      value: output(el), type: 'password', policyRevision: 1,
    });
    expect((output(el).match(/[0-9]/g) ?? []).length).toBeGreaterThanOrEqual(4);
    expect((output(el).match(/[!@#$%^&*]/g) ?? []).length).toBeGreaterThanOrEqual(4);
  });

  it('locks only policy-required fields and raises numeric floors', async () => {
    const el = await mount({
      generatorPolicy: managedPolicy({ minLength: 24, useUpper: true, minNumbers: 3 }),
    });

    expect(q<HTMLInputElement>(el, '[data-length]').disabled).toBe(false);
    expect(q<HTMLInputElement>(el, '[data-length]').min).toBe('24');
    expect(q<HTMLElement & { disabled: boolean }>(el, "[data-toggle='upper']").disabled).toBe(true);
    expect(q<HTMLElement & { disabled: boolean }>(el, "[data-toggle='number']").disabled).toBe(true);
    expect(q<HTMLElement & { disabled: boolean }>(el, "[data-toggle='lower']").disabled).toBe(false);
    expect(q<HTMLElement & { disabled: boolean }>(el, "[data-toggle='symbol']").disabled).toBe(false);
    expect(q<HTMLElement & { disabled: boolean }>(el, "[data-toggle='ambiguous']").disabled).toBe(false);
    expect(q<HTMLInputElement>(el, '[data-min-numbers]').disabled).toBe(false);
    expect(q<HTMLInputElement>(el, '[data-min-numbers]').min).toBe('3');

    await setMinimum(el, 'numbers', '5');
    await setRange(el, '30');
    expect(output(el)).toHaveLength(30);
    expect((output(el).match(/[0-9]/g) ?? []).length).toBeGreaterThanOrEqual(5);
    expect(output(el)).toMatch(/[A-Z]/);
  });

  it('adds digits back to the random password when the numbers toggle is on', async () => {
    const el = await mount();
    await setToggle(el, 'upper', false);
    await setToggle(el, 'symbol', false);
    await setRange(el, '40');
    // lowercase + numbers only.
    expect(output(el)).toMatch(/^[a-z0-9]+$/);
    expect(output(el)).toMatch(/[0-9]/);
  });

  it('persists independent password, passphrase, PIN, and username choices across mounts', async () => {
    const first = await mount();
    await setRange(first, '28');
    await setToggle(first, 'upper', false);
    await setMode(first, 'memorable');
    await setWords(first, '9');
    await setToggle(first, 'upper', true);
    await setToggle(first, 'number', true);
    await setMode(first, 'pin');
    await setRange(first, '18');
    await setMode(first, 'username');
    await setUsernameToggle(first, 'capitalize', true);
    await setUsernameToggle(first, 'number', true);
    await setUsernameType(first, 'catchAll');
    await setUsernameLength(first, '12');

    expect(getPrefs()).toMatchObject({
      genMode: 'username',
      genLength: 28,
      genUppercase: false,
      genPassphraseWords: 9,
      genPassphraseCapitalize: true,
      genPassphraseNumber: true,
      genPinLength: 18,
      genUsernameType: 'catchAll',
      genUsernameLength: 12,
      genUsernameCapitalize: true,
      genUsernameNumber: true,
    });

    first.remove();
    const second = await mount();
    expect(q<HTMLElement & { value: string }>(second, '[data-mode]').value).toBe('username');
    expect(q<HTMLElement & { value: string }>(second, '[data-username-type]').value).toBe('catchAll');
    expect(q<HTMLElement>(second, '[data-username-length-value]').textContent).toBe('12');
  });

  it('refreshes an open view when another extension surface changes preferences', async () => {
    const el = await mount();

    setPref('genPinLength', 22, false);
    setPref('genMode', 'pin', false);
    await el.updateComplete;

    expect(q<HTMLElement & { value: string }>(el, '[data-mode]').value).toBe('pin');
    expect(q<HTMLElement>(el, '[data-length-value]').textContent).toBe('22');
    expect(output(el)).toMatch(/^[0-9]{22}$/);
  });
});

describe('vw-generator-view strength', () => {
  afterEach(() => {
    document.body.replaceChildren();
  });

  function strengthLabel(el: VwGeneratorView): string {
    return q<HTMLElement>(el, '[data-strength]').textContent?.trim() ?? '';
  }

  it('labels strength by output length', async () => {
    const el = await mount();
    // default length 14 → 强
    expect(strengthLabel(el)).toBe('强');
    await setRange(el, '40');
    expect(strengthLabel(el)).toBe('极强');
    await setRange(el, '10');
    expect(strengthLabel(el)).toBe('中等');
    await setRange(el, '8');
    expect(strengthLabel(el)).toBe('较弱');
  });

  it('rates a long digit-only PIN on entropy, not length (never "strong")', async () => {
    const el = await mount();
    await setMode(el, 'pin');
    await setRange(el, '16');
    // 16 digits ≈ 53 bits (16 × log2(10)); length alone would read "极强", but entropy caps it at 中等.
    const label = strengthLabel(el);
    expect(label).not.toBe('极强');
    expect(label).not.toBe('强');
    expect(label).toBe('中等');
  });
});

describe('vw-generator-view copy, history and back', () => {
  afterEach(() => {
    document.body.replaceChildren();
  });

  it('emits every newly generated value, including initial and explicit regenerate', async () => {
    const recorded = vi.fn();
    const el = await mount({}, (event) => recorded((event as CustomEvent).detail));
    const before = output(el);
    expect(recorded).toHaveBeenCalledTimes(1);
    expect(recorded).toHaveBeenLastCalledWith({ value: before, type: 'password', policyRevision: 1 });
    await click(el, '[data-regenerate]');
    expect(recorded).toHaveBeenCalledTimes(2);
    expect(recorded.mock.calls.at(-1)?.[0]).toEqual({
      value: output(el), type: 'password', policyRevision: 1,
    });
  });

  it('waits for policy hydration before generating a restored username', async () => {
    setPref('genMode', 'username', false);
    const recorded = vi.fn();
    const el = await mount(
      { generatorPolicy: UNAVAILABLE_GENERATOR_POLICY_SNAPSHOT },
      (event) => recorded((event as CustomEvent).detail),
    );

    expect(output(el)).toBe('');
    expect(recorded).not.toHaveBeenCalled();

    el.generatorPolicy = createGeneratorPolicySnapshot(null, 7);
    await el.updateComplete;

    expect(output(el)).not.toBe('');
    expect(recorded).toHaveBeenCalledTimes(1);
    expect(recorded).toHaveBeenCalledWith({
      value: output(el), type: 'username', policyRevision: 7,
    });
  });

  it('emits the effective passphrase and PIN types for mode and setting generations', async () => {
    const recorded = vi.fn();
    const el = await mount({}, (event) => recorded((event as CustomEvent).detail));
    recorded.mockClear();

    await setMode(el, 'memorable');
    expect(recorded.mock.calls.at(-1)?.[0]).toEqual({
      value: output(el), type: 'passphrase', policyRevision: 1,
    });
    await setWords(el, '9');
    expect(recorded.mock.calls.at(-1)?.[0]).toEqual({
      value: output(el), type: 'passphrase', policyRevision: 1,
    });
    await setMode(el, 'pin');
    expect(recorded.mock.calls.at(-1)?.[0]).toEqual({
      value: output(el), type: 'pin', policyRevision: 1,
    });
  });

  it('copies the current value without tracking it again', async () => {
    const el = await mount();
    const current = output(el);
    const copied = vi.fn();
    const recorded = vi.fn();
    el.addEventListener('vw-copy', (e) => copied((e as CustomEvent).detail));
    el.addEventListener('vw-history-add', (e) => recorded((e as CustomEvent).detail));
    await click(el, '[data-copy]');
    expect(copied).toHaveBeenCalledWith({ value: current, label: '密码' });
    expect(recorded).not.toHaveBeenCalled();
  });

  it('copies a PIN with the PIN label', async () => {
    const el = await mount();
    await setMode(el, 'pin');
    const current = output(el);
    const copied = vi.fn();
    el.addEventListener('vw-copy', (e) => copied((e as CustomEvent).detail));
    await click(el, '[data-copy]');
    expect(copied).toHaveBeenCalledWith({ value: current, label: 'PIN' });
  });

  it('emits vw-item-back from the close control', async () => {
    const el = await mount();
    const back = vi.fn();
    el.addEventListener('vw-item-back', back);
    await click(el, '[data-close]');
    expect(back).toHaveBeenCalledTimes(1);
  });

  it('uses the existing generator as a bounded password selector', async () => {
    const el = await mount({ selectionTarget: 'password' });
    const selected = vi.fn();
    const copied = vi.fn();
    el.addEventListener('vw-generator-select', (event) => selected((event as CustomEvent).detail));
    el.addEventListener('vw-copy', copied);

    const modes = q<HTMLElement & { options: Array<{ id: string }> }>(el, '[data-mode]');
    expect(modes.options.map(({ id }) => id)).toEqual(['random', 'memorable']);
    expect(el.shadowRoot?.querySelector('.history')).toBeNull();
    const current = output(el);
    await click(el, '[data-select-generated]');

    expect(selected).toHaveBeenCalledWith({ target: 'password', value: current });
    expect(copied).not.toHaveBeenCalled();
  });

  it('does not guess a catch-all username from the website URI when its prerequisite is missing', async () => {
    setPref('genUsernameType', 'catchAll', false);
    const el = await mount({
      selectionTarget: 'username',
      websiteUri: 'https://accounts.example.com/sign-in',
    });

    expect(q<HTMLElement & { value: string }>(el, '[data-mode]').value).toBe('username');
    expect(output(el)).toBe('');
    expect(q<HTMLButtonElement>(el, '[data-select-generated]').disabled).toBe(true);

    await setCatchAllDomain(el, 'example.com');
    expect(output(el)).toMatch(/@example\.com$/);
    expect(q<HTMLButtonElement>(el, '[data-select-generated]').disabled).toBe(false);
  });

  it('renders typed history values only as text and copies without reusing the current value', async () => {
    const el = await mount();
    const current = output(el);
    const copied = vi.fn();
    el.addEventListener('vw-copy', (event) => copied((event as CustomEvent).detail));
    el.history = [{ generatedAt: 1, type: 'pin', value: 'old-secret' }];
    el.accountEmail = 'me@example.com';
    await el.updateComplete;
    const historyValue = q<HTMLElement>(el, '.history-value');
    expect(historyValue.textContent).toBe('old-secret');
    expect(el.shadowRoot!.innerHTML).not.toContain('value="old-secret"');
    await click(el, '.history-copy');
    expect(copied).toHaveBeenCalledWith({ value: 'old-secret', label: 'PIN' });
    expect(output(el)).toBe(current);
  });

  it('confirms before requesting a history clear', async () => {
    const el = await mount({ history: [{ generatedAt: 1, type: 'password', value: 'old-secret' }] });
    const clear = vi.fn();
    el.addEventListener('vw-history-clear', clear);
    const confirm = vi.fn().mockReturnValueOnce(false).mockReturnValueOnce(true);
    Object.defineProperty(window, 'confirm', { value: confirm, configurable: true });

    await click(el, '[data-history-clear]');
    expect(clear).not.toHaveBeenCalled();
    await click(el, '[data-history-clear]');
    expect(clear).toHaveBeenCalledOnce();
  });
});
