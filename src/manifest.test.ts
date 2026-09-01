import { describe, expect, it } from 'vitest';
import manifest from './manifest.json';

describe('manifest', () => {
  it('requires the Chromium baseline that keeps MV3 WebSockets alive for notifications', () => {
    expect(manifest.minimum_chrome_version).toBe('116');
  });

  it('registers autofill content script for http and https in all frames', () => {
    expect(manifest.content_scripts[0]).toEqual({
      matches: ['http://*/*', 'https://*/*'],
      js: ['content/autofill.js'],
      run_at: 'document_idle',
      all_frames: true,
    });
  });

  it('leaves website passkey scripts to the opt-in dynamic scripting lifecycle', () => {
    const staticScripts = manifest.content_scripts.flatMap((entry) => entry.js);
    expect(staticScripts).not.toContain('content/page-webauthn.js');
    expect(staticScripts).not.toContain('content/webauthn-bridge.js');
    expect(manifest.content_scripts).toHaveLength(1);
    expect(manifest.permissions).toContain('scripting');
  });

  it('has no dormant blanket-HTTP WebAuthn injection or proxy capability', () => {
    const passkeyEntries = manifest.content_scripts.filter((entry) => (
      entry.js.some((script) => script.includes('webauthn'))
    ));
    expect(passkeyEntries).toEqual([]);
    expect(manifest.permissions).not.toContain('webAuthenticationProxy');
  });

  it('can read the clipboard only so auto-clear can verify ownership before overwriting it', () => {
    expect(manifest.permissions).toContain('clipboardRead');
    expect(manifest.permissions).toContain('clipboardWrite');
  });

  it('declares storage permissions for trusted contexts and the encrypted local vault cache', () => {
    expect(manifest.permissions).toContain('storage');
    expect(manifest.permissions).toContain('unlimitedStorage');
  });

  it('requests the contextMenus permission for right-click fill', () => {
    expect(manifest.permissions).toContain('contextMenus');
  });

  it('grants the HIBP host permission for breach checks', () => {
    expect(manifest.host_permissions).toContain('https://api.pwnedpasswords.com/*');
  });

  it('declares the focused-fill keyboard command', () => {
    const cmd = (manifest as { commands?: Record<string, { description?: string; suggested_key?: { default?: string; mac?: string } }> }).commands?.['autofill-focused'];
    expect(cmd).toBeDefined();
    expect(cmd?.description).toBeTruthy();
    expect(cmd?.suggested_key?.default).toBe('Ctrl+Shift+F');
    expect(cmd?.suggested_key?.mac).toBe('Command+Shift+F');
  });

  it('declares the complete high-value browser command set', () => {
    const commands = Object.keys(manifest.commands).sort();
    expect(commands).toEqual([
      'autofill-card',
      'autofill-focused',
      'autofill-identity',
      'autofill-login',
      'generate-password',
      'lock-vault',
      'open-popup',
    ]);
    expect(manifest.commands['autofill-login'].suggested_key.default).toBe('Ctrl+Shift+L');
    expect(manifest.commands['generate-password'].suggested_key.default).toBe('Ctrl+Shift+9');
    expect(manifest.commands['open-popup'].suggested_key.default).toBe('Ctrl+Shift+Y');
  });

  it('requests the idle and offscreen permissions', () => {
    expect(manifest.permissions).toContain('idle');
    expect(manifest.permissions).toContain('offscreen');
  });

  it('requests only the notifications capability needed for device-login approval alerts', () => {
    expect(manifest.permissions).toContain('notifications');
  });

  it('declares activeTab and webNavigation permissions', () => {
    expect(manifest.permissions).toContain('activeTab');
    expect(manifest.permissions).toContain('webNavigation');
  });

  it('declares the MV3 HTTP authentication provider permissions without proxy control', () => {
    expect(manifest.permissions).toContain('webRequest');
    expect(manifest.permissions).toContain('webRequestAuthProvider');
    expect(manifest.permissions).not.toContain('proxy');
    expect(manifest.permissions).not.toContain('webRequestBlocking');
  });

  it('allows WebAssembly compilation on extension pages for Argon2id only', () => {
    expect(manifest.content_security_policy).toEqual({
      extension_pages: "script-src 'self' 'wasm-unsafe-eval'; object-src 'self'",
    });
  });

  it('starts with the neutral signed-out toolbar icon until auth state is composed', () => {
    expect(manifest.action.default_icon).toEqual({
      16: 'icons/icon16_neutral.png',
      32: 'icons/icon32_neutral.png',
      48: 'icons/icon48_neutral.png',
      128: 'icons/icon128_neutral.png',
    });
  });
});
