// @vitest-environment happy-dom
import { describe, expect, it, vi } from 'vitest';

vi.mock('webextension-polyfill', () => ({
  default: { storage: { local: { get: vi.fn(async () => ({})), set: vi.fn(async () => {}) }, onChanged: { addListener: vi.fn() } } },
}));

import { t, setLocale, getLocale } from './index.js';

describe('i18n', () => {
  it('defaults to zh-CN', () => {
    expect(getLocale()).toBe('zh-CN');
    expect(t('common.brand')).toBe('密屿');
  });

  it('switches to English and back', () => {
    setLocale('en', false);
    expect(t('common.brand')).toBe('MiYu');
    expect(t('popup.search')).toBe('Search vault');
    expect(document.documentElement.lang).toBe('en');
    setLocale('zh-CN', false);
    expect(t('popup.search')).toBe('搜索密钥库');
    expect(document.documentElement.lang).toBe('zh-CN');
  });

  it('interpolates {name} placeholders', () => {
    expect(t('list.currentSite', { domain: 'nebula.dev' })).toBe('当前网站 · nebula.dev');
    expect(t('sync.minutesAgo', { count: 2 })).toBe('2 分钟前');
  });

  it('localizes custom-field ordering actions', () => {
    setLocale('zh-CN', false);
    expect(t('editor.moveFieldUp', { name: '服务器' })).toBe('将服务器上移');
    expect(t('editor.moveFieldDown', { name: '服务器' })).toBe('将服务器下移');
    setLocale('en', false);
    expect(t('editor.moveFieldUp', { name: 'Server' })).toBe('Move Server up');
    expect(t('editor.moveFieldDown', { name: 'Server' })).toBe('Move Server down');
    setLocale('zh-CN', false);
  });

  it('describes remembered two-step removal without claiming to forget the server device', () => {
    setLocale('zh-CN', false);
    expect(t('auth.forgetDevice')).toBe('下次要求两步验证');
    expect(t('auth.passwordMin', { min: 12 })).toBe('主密码至少需要 12 个字符');
    setLocale('en', false);
    expect(t('auth.forgetDevice')).toBe('Require two-step login next time');
    expect(t('auth.passwordMin', { min: 12 }))
      .toBe('Master password must be at least 12 characters');
    setLocale('zh-CN', false);
  });

  it('falls back to the key for an unknown message', () => {
    // @ts-expect-error unknown key
    expect(t('does.not.exist')).toBe('does.not.exist');
  });
});
