// A small, self-dismissing notice bar — used to surface context-menu fill errors (e.g. a
// reprompt-protected item) without exposing anything to the page. The visible surface is the
// closed-shadow Lit element `vw-notice`; this stable factory delegates to its mount, which renders
// the message inertly inside a closed shadow root and auto-dismisses.

import { presentNotice } from './ui/notice-element.js';

export function showNotice(message: string): void {
  presentNotice(message);
}
