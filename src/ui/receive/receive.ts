// Receive entry: a thin mount for the Lit Receive root. `VwReceiveApp` owns the whole recipient
// flow (parse, permission prompt, access/decrypt, download) through its default dependency seam.
import { VwReceiveApp } from './receive-app.js';

const app = document.createElement('vw-receive-app') as VwReceiveApp;
document.getElementById('app')?.append(app);
