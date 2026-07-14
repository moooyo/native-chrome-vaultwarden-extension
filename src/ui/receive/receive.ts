// Receive entry: a thin mount for the Lit Receive root. `VwReceiveApp` owns the whole recipient
// flow (parse, permission prompt, access/decrypt, download) through its default dependency seam.
// Load the persisted language + appearance prefs before the first paint (mirroring the popup /
// options entrypoints) so the page renders in the user's saved theme and locale rather than the
// defaults.
import { initLocale } from '../i18n/index.js';
import { initAppearance } from '../theme.js';
import { VwReceiveApp } from './receive-app.js';

async function main(): Promise<void> {
  await Promise.all([initLocale(), initAppearance()]);
  const app = document.createElement('vw-receive-app') as VwReceiveApp;
  document.getElementById('app')?.append(app);
}

void main();
