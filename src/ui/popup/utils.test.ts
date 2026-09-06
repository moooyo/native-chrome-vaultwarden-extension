// @vitest-environment happy-dom
import { afterEach, describe, expect, it, vi } from 'vitest';
import { base64ToBytes, fileToBase64, formatTotp, safeWebUrl, triggerBlobDownload, triggerDownload } from './utils.js';

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

  it.each([0, 3, 4])('allows a declared size of %i at or below an inclusive byte limit', async (size) => {
    const blob = new Blob([new Uint8Array([104, 105])]);
    Object.defineProperty(blob, 'size', { value: size });
    const read = vi.spyOn(blob, 'arrayBuffer');

    await expect(fileToBase64(blob, 4)).resolves.toBe(btoa('hi'));
    expect(read).toHaveBeenCalledOnce();
  });

  it('rejects limit + 1 before reading the blob', async () => {
    const blob = new Blob([new Uint8Array([104, 105])]);
    Object.defineProperty(blob, 'size', { value: 5 });
    const read = vi.spyOn(blob, 'arrayBuffer');

    await expect(fileToBase64(blob, 4)).rejects.toThrow(RangeError);
    expect(read).not.toHaveBeenCalled();
  });

  it.each([-1, 1.5, Number.NaN, Number.POSITIVE_INFINITY, Number.MAX_SAFE_INTEGER + 1])(
    'rejects an unsafe declared size (%s) before reading the blob',
    async (size) => {
      const blob = new Blob([new Uint8Array([104, 105])]);
      Object.defineProperty(blob, 'size', { value: size });
      const read = vi.spyOn(blob, 'arrayBuffer');

      await expect(fileToBase64(blob, 4)).rejects.toThrow(RangeError);
      expect(read).not.toHaveBeenCalled();
    },
  );

  it.each([-1, 1.5, Number.NaN, Number.POSITIVE_INFINITY])(
    'rejects an invalid byte limit (%s) before reading the blob',
    async (maxBytes) => {
      const blob = new Blob([new Uint8Array([104, 105])]);
      const read = vi.spyOn(blob, 'arrayBuffer');

      await expect(fileToBase64(blob, maxBytes)).rejects.toThrow(RangeError);
      expect(read).not.toHaveBeenCalled();
    },
  );
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

  it('uses an existing Blob and revokes its URL even if clicking fails', () => {
    const blob = new Blob(['existing']);
    const createSpy = vi.spyOn(URL, 'createObjectURL').mockReturnValue('blob:existing');
    const revokeSpy = vi.spyOn(URL, 'revokeObjectURL').mockImplementation(() => undefined);
    vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => { throw new Error('Download unavailable'); });

    expect(() => triggerBlobDownload(blob, 'file.txt')).toThrow('Download unavailable');
    expect(createSpy).toHaveBeenCalledWith(blob);
    expect(revokeSpy).toHaveBeenCalledWith('blob:existing');
    expect(document.querySelector('a')).toBeNull();
  });
});
