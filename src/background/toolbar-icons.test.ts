import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { describe, expect, it } from 'vitest';

const PNG_SIGNATURE = Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]);

describe('generated toolbar icons', () => {
  it('ships distinct nonempty PNG assets at every declared size', async () => {
    const hashes = new Set<string>();
    for (const kind of ['neutral', 'locked']) {
      for (const size of [16, 32, 48, 128]) {
        const file = path.resolve(`src/icons/icon${size}_${kind}.png`);
        const bytes = await readFile(file);
        expect(bytes.subarray(0, PNG_SIGNATURE.length)).toEqual(PNG_SIGNATURE);
        expect(bytes.readUInt32BE(16)).toBe(size);
        expect(bytes.readUInt32BE(20)).toBe(size);
        expect(bytes.byteLength).toBeGreaterThan(100);
        hashes.add(createHash('sha256').update(bytes).digest('hex'));
      }
    }
    expect(hashes.size).toBe(8);
  });
});
