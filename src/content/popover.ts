import type { AutofillCandidate } from '../messaging/protocol.js';

export interface AutofillPopover {
  element: HTMLElement;
  root: ShadowRoot;
  showStatus(message: string): void;
  showCandidates(candidates: AutofillCandidate[]): void;
  remove(): void;
}

export interface AutofillPopoverOptions {
  anchor: HTMLElement;
  onOpen(): void;
  onSelect(cipherId: string): void;
}

export function createAutofillPopover(options: AutofillPopoverOptions): AutofillPopover {
  const host = document.createElement('div');
  host.style.position = 'absolute';
  host.style.zIndex = '2147483647';
  const shadow = host.attachShadow({ mode: 'closed' });
  document.documentElement.append(host);
  positionNearAnchor(host, options.anchor);

  const render = (body: string) => {
    shadow.innerHTML = `
      <style>
        :host { all: initial; }
        .box { font: 13px system-ui, sans-serif; color: #24292f; background: #fff; border: 1px solid #d0d7de; border-radius: 10px; box-shadow: 0 8px 24px rgba(140,149,159,.25); min-width: 220px; max-width: 320px; padding: 8px; }
        button { font: inherit; width: 100%; text-align: left; border: 0; background: transparent; padding: 8px; border-radius: 8px; cursor: pointer; }
        button:hover { background: #f6f8fa; }
        .muted { color: #57606a; font-size: 12px; }
      </style>
      <div class="box">${body}</div>
    `;
  };

  render('<button id="open" type="button">Vaultwarden</button>');
  shadow.getElementById('open')?.addEventListener('click', (event) => {
    if (!event.isTrusted) return;
    options.onOpen();
  });

  return {
    element: host,
    root: shadow,
    showStatus(message: string) {
      render(`<div>${escapeHtml(message)}</div>`);
    },
    showCandidates(candidates: AutofillCandidate[]) {
      if (candidates.length === 0) {
        render('<div>No matching logins</div>');
        return;
      }
      render(candidates.map((candidate) => `
        <button type="button" class="candidate">
          <strong>${escapeHtml(candidate.name)}</strong>
          <div class="muted">${escapeHtml(candidate.username ?? '')}</div>
          <div class="muted">${escapeHtml(candidate.matchedUri)}</div>
        </button>
      `).join(''));
      shadow.querySelectorAll<HTMLButtonElement>('button.candidate').forEach((button, index) => {
        button.addEventListener('click', (event) => {
          if (!event.isTrusted) return;
          options.onSelect(candidates[index]!.id);
        });
      });
    },
    remove() {
      host.remove();
    },
  };
}

function positionNearAnchor(host: HTMLElement, anchor: HTMLElement): void {
  const rect = anchor.getBoundingClientRect();
  host.style.left = `${Math.max(8, rect.left + window.scrollX)}px`;
  host.style.top = `${Math.max(8, rect.bottom + window.scrollY + 4)}px`;
}

function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]!));
}
