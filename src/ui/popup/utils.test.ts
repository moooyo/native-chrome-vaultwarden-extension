// @vitest-environment happy-dom
import { afterEach, describe, expect, it, vi } from 'vitest';
import { base64ToBytes, fileToBase64, formatTotp, safeWebUrl, triggerDownload } from './utils.js';

describe('safeWebUrl', () => {
  it('returns a normalized url for http and https', () => {
    expect(safeWebUrl('https://github.com')).toBe('https://github.com/');
    expect(safeWebUrl('http://example.test/login')).toBe('http://example.test/login');
  });

  it('rejects non-http(s) schemes', () => {
    expect(safeWebUrl('javascript:alert(1)')).toBeUndefined();
    expect(safeWebUrl('file:///etc/passwd')).toBeUndefined();
    expect(safeWebUrl('data:text/html,<script>')).toBeUndefined();
  });

  it('rejects values that are not URLs', () => {
    expect(safeWebUrl('not a url')).toBeUndefined();
    expect(safeWebUrl('')).toBeUndefined();
  });
});

describe('formatTotp', () => {
  it('splits a six-digit code into two groups', () => {
    expect(formatTotp('081804')).toBe('081 804');
  });

  it('leaves codes of other lengths unchanged', () => {
    expect(formatTotp('12345678')).toBe('12345678');
    expect(formatTotp('1234')).toBe('1234');
  });
});

describe('base64ToBytes', () => {
  it('round-trips ascii bytes', () => {
    const bytes = base64ToBytes(btoa('hello'));
    expect(new TextDecoder().decode(bytes)).toBe('hello');
  });
});

describe('fileToBase64', () => {
  it('reads a file into base64', async () => {
    const file = new File([new Uint8Array([104, 105])], 'greeting.txt');
    const b64 = await fileToBase64(file);
    expect(b64).toBe(btoa('hi'));
  });
});

describe('triggerDownload', () => {
  afterEach(() => {
    vi.restoreAllMocks();
    document.body.replaceChildren();
  });

  it('creates and revokes an object url and clicks an anchor', () => {
    const created = 'blob:mock-url';
    const createSpy = vi.spyOn(URL, 'createObjectURL').mockReturnValue(created);
    const revokeSpy = vi.spyOn(URL, 'revokeObjectURL').mockImplementation(() => undefined);
    const clickSpy = vi.fn();
    const realCreate = document.createElement.bind(document);
    vi.spyOn(document, 'createElement').mockImplementation((tag: string) => {
      const el = realCreate(tag) as HTMLElement;
      if (tag === 'a') el.click = clickSpy;
      return el;
    });

    triggerDownload(btoa('data'), 'notes.txt');

    expect(createSpy).toHaveBeenCalledTimes(1);
    expect(clickSpy).toHaveBeenCalledTimes(1);
    expect(revokeSpy).toHaveBeenCalledWith(created);
  });
});
