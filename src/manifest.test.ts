import { describe, expect, it } from 'vitest';
import manifest from './manifest.json';

describe('manifest', () => {
  it('registers autofill content script for http and https in all frames', () => {
    expect(manifest.content_scripts).toEqual([{
      matches: ['http://*/*', 'https://*/*'],
      js: ['content/autofill.js'],
      run_at: 'document_idle',
      all_frames: true,
    }]);
  });
});
