// Options entry: a thin mount for the Lit options root. `VwOptionsApp` owns the settings rail,
// every section, and all worker requests through its default dependency seam.
import { VwOptionsApp } from './options-app.js';

const app = document.createElement('vw-options-app') as VwOptionsApp;
document.getElementById('app')?.append(app);
