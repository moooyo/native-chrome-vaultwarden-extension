import { describe, expect, it } from 'vitest';
import manifest from './manifest.json';

describe('manifest', () => {
  it('registers autofill content script for http and https in all frames', () => {
    expect(manifest.content_scripts[0]).toEqual({
      matches: ['http://*/*', 'https://*/*'],
      js: ['content/autofill.js'],
      run_at: 'document_idle',
      all_frames: true,
    });
  });

  it('registers the MAIN-world passkey shim and its isolated bridge at document_start', () => {
    const main = manifest.content_scripts.find((s) => s.js.includes('content/page-webauthn.js'));
    const bridge = manifest.content_scripts.find((s) => s.js.includes('content/webauthn-bridge.js'));
    expect(main).toMatchObject({ run_at: 'document_start', world: 'MAIN' });
    expect(bridge).toMatchObject({ run_at: 'document_start' });
    // The bridge runs in the default (isolated) world, where chrome.runtime is available.
    expect((bridge as { world?: string }).world).toBeUndefined();
  });

  it('declares the storage permission required for a trusted-context session store', () => {
    expect(manifest.permissions).toContain('storage');
  });

  it('requests the contextMenus permission for right-click fill', () => {
    expect(manifest.permissions).toContain('contextMenus');
  });
});
