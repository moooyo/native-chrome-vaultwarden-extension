// @vitest-environment happy-dom
import { beforeEach, describe, expect, it } from 'vitest';
import { showNotice } from './notice.js';

describe('notice', () => {
  beforeEach(() => { document.documentElement.innerHTML = '<body></body>'; });

  it('renders the message inside a closed shadow root (not exposed)', () => {
    showNotice('Protected item — open the extension to verify');
    const host = document.querySelector('[data-vw-notice]') as HTMLElement;
    expect(host).toBeTruthy();
    expect(host.shadowRoot).toBeNull(); // closed shadow: not reachable from the page
  });
});
