// Real-Chromium check that the test page triggers every autofill detector and the passkey
// shim. Loads the unpacked dist/ extension against the locally served test page and asserts:
//   - navigator.credentials.get/create are replaced by the MAIN-world shim (vaultwardenGet/Create)
//   - focusing each section's fields makes the content script tag them with data-vw-* ids
// This needs no vault unlock (detection + shim install happen regardless), so it runs headless
// under xvfb. Full passkey ceremonies (consent dialog in a closed shadow root) stay manual.
//
// Prereq: `npm run build` and a server on the given port (default 8770).
// Usage: node test-page/verify-testpage.mjs [port]

import { chromium } from '@playwright/test';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const ext = join(root, 'dist');
const port = Number(process.argv[2] || process.env.PORT || 8770);
const url = `http://localhost:${port}/`;

const ctx = await chromium.launchPersistentContext('', {
  headless: false,
  args: [`--disable-extensions-except=${ext}`, `--load-extension=${ext}`, '--no-sandbox'],
});

let [sw] = ctx.serviceWorkers();
if (!sw) sw = await ctx.waitForEvent('serviceworker', { timeout: 15000 });

const errors = [];
const page = await ctx.newPage();
page.on('pageerror', (e) => errors.push(String(e)));
await page.goto(url, { waitUntil: 'load' });

// 1) MAIN-world passkey shim installed (independent of vault state).
const shim = await page.evaluate(() => ({
  get: navigator.credentials?.get?.name,
  create: navigator.credentials?.create?.name,
  secure: window.isSecureContext,
  rpId: location.hostname,
}));

// 2) Detection: focus each field, then read the data-vw-* id the content script writes.
async function focusAndTag(selector, attrs) {
  await page.locator(selector).first().focus();
  try {
    await page.waitForFunction(
      ({ sel, list }) => {
        const el = document.querySelector(sel);
        if (!el) return false;
        const own = list.some((a) => el.hasAttribute(a));
        const form = el.closest('form');
        const inForm = form && list.some((a) => form.querySelector(`[${a}]`));
        return own || inForm;
      },
      { sel: selector, list: attrs },
      { timeout: 6000 },
    );
    return true;
  } catch {
    return false;
  }
}

const checks = [
  ['1 login username', 'input[name="username"]', ['data-vw-autofill-id']],
  ['1 login password', 'input[name="password"]', ['data-vw-autofill-id']],
  ['2 two-step email', 'input[name="email"]', ['data-vw-autofill-id']],
  ['3 2FA one-time-code', 'input[name="otp"]', ['data-vw-autofill-id']],
  ['4 registration new-password', 'input[name="new-password"]', ['data-vw-gen-id']],
  ['5 card number (cc-*)', 'input[name="cardnumber"]', ['data-vw-fill-id']],
  ['6 identity given-name', 'input[name="fname"]', ['data-vw-fill-id']],
  ['7 hint-only card number', 'input[name="card_number"]', ['data-vw-fill-id']],
  ['7 hint-only first name', 'input[name="firstName"]', ['data-vw-fill-id']],
];

const results = [];
for (const [label, sel, attrs] of checks) {
  results.push([label, await focusAndTag(sel, attrs)]);
  await page.waitForTimeout(150);
}

// 3) Panel hosts mounted by the content script (light-DOM proof, closed shadow aside).
const panelHosts = await page.evaluate(() => document.querySelectorAll('[data-vw-popover-for]').length);

console.log('\n=== test-page verify ===');
console.log('url:', url);
console.log('secure context:', shim.secure, '| rpId:', shim.rpId);
console.log('passkey shim  get():', shim.get, '| create():', shim.create);
const shimOk = shim.get === 'vaultwardenGet' && shim.create === 'vaultwardenCreate';
console.log('passkey shim installed:', shimOk ? 'YES ✓' : 'NO ✗');
console.log('panel hosts mounted:', panelHosts);
console.log('\ndetection per section:');
let pass = 0;
for (const [label, ok] of results) { console.log(`  ${ok ? '✓' : '✗'} ${label}`); if (ok) pass++; }
console.log(`\ndetected ${pass}/${results.length} · page errors: ${errors.length}`);
for (const e of errors.slice(0, 6)) console.log('  -', e);

await ctx.close();
const allOk = shimOk && pass === results.length && errors.length === 0;
console.log(allOk ? '\nRESULT: PASS' : '\nRESULT: FAIL');
process.exit(allOk ? 0 : 1);
