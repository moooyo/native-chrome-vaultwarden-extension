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
    setLocale('zh-CN', false);
    expect(t('popup.search')).toBe('搜索密钥库');
  });

  it('interpolates {name} placeholders', () => {
    expect(t('list.currentSite', { domain: 'nebula.dev' })).toBe('当前网站 · nebula.dev');
    expect(t('sync.minutesAgo', { count: 2 })).toBe('2 分钟前');
  });

  it('falls back to the key for an unknown message', () => {
    // @ts-expect-error unknown key
    expect(t('does.not.exist')).toBe('does.not.exist');
  });
});
