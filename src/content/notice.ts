// A small, self-dismissing notice bar — used to surface context-menu fill errors (e.g. a
// reprompt-protected item) without exposing anything to the page. The visible surface is a
// render-based closed-shadow notice; this stable factory delegates to its mount, which renders
// the message inertly inside a closed shadow root and auto-dismisses.

import { presentNotice, type NoticeHandle } from './ui/notice-element.js';

// Only one notice is shown at a time: each new message dismisses the previous bar first, so several
// errors in quick succession never stack into an illegible pile of bottom-center bars.
let activeNotice: NoticeHandle | null = null;

export function showNotice(message: string): NoticeHandle {
  activeNotice?.remove();
  activeNotice = presentNotice(message);
  return activeNotice;
}
