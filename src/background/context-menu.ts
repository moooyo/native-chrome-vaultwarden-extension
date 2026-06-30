import type { FillKind, FillItemCandidate, CardFillData, IdentityFillData, FillCommand, FillErrorCommand } from '../messaging/protocol.js';

type SessionState = 'loggedOut' | 'locked' | 'unlocked';

const ROOT_ID = 'vw-root';

// Four submenu groups: fill the whole detected form, or only the right-clicked field, for each kind.
const GROUPS: Array<{ id: string; title: string; scope: 'form' | 'field'; kind: FillKind }> = [
  { id: 'vw-card-form', title: 'Fill card', scope: 'form', kind: 'card' },
  { id: 'vw-identity-form', title: 'Fill identity', scope: 'form', kind: 'identity' },
  { id: 'vw-card-field', title: 'Fill this field from card', scope: 'field', kind: 'card' },
  { id: 'vw-identity-field', title: 'Fill this field from identity', scope: 'field', kind: 'identity' },
];

// Request types that change the card/identity list or lock state — refresh the menu after these.
const REFRESH_TRIGGERS = new Set<string>([
  'vault.sync', 'vault.createCipher', 'vault.updateCipher', 'vault.deleteCipher',
  'vault.softDeleteCipher', 'vault.restoreCipher', 'vault.import',
  'auth.login', 'auth.unlock', 'auth.unlockWithPin', 'auth.lock', 'auth.logout',
  'auth.switchAccount', 'auth.removeAccount',
]);

export function shouldRefreshMenu(requestType: string): boolean {
  return REFRESH_TRIGGERS.has(requestType);
}

export interface ContextMenuDeps {
  getState(): Promise<SessionState>;
  findFillItems(kind: FillKind): Promise<FillItemCandidate[]>;
  getFillData(cipherId: string, kind: FillKind): Promise<CardFillData | IdentityFillData>;
  menus: {
    removeAll(): Promise<void>;
    create(props: Record<string, unknown>): void;
  };
  tabs: {
    sendMessage(tabId: number, message: FillCommand | FillErrorCommand, options?: { frameId?: number }): Promise<unknown>;
  };
}

function itemId(scope: 'form' | 'field', kind: FillKind, cipherId: string): string {
  return `vw-fill|${scope}|${kind}|${cipherId}`;
}

function parseItemId(id: string): { scope: 'form' | 'field'; kind: FillKind; cipherId: string } | undefined {
  const parts = id.split('|');
  if (parts.length !== 4 || parts[0] !== 'vw-fill') return undefined;
  const scope = parts[1];
  const kind = parts[2];
  if ((scope !== 'form' && scope !== 'field') || (kind !== 'card' && kind !== 'identity')) return undefined;
  return { scope, kind, cipherId: parts[3]! };
}

export function createContextMenu(deps: ContextMenuDeps) {
  return {
    /** Rebuild the menu from the current vault. Hides all vault items unless the vault is unlocked. */
    async refresh(): Promise<void> {
      await deps.menus.removeAll();
      if ((await deps.getState()) !== 'unlocked') return; // never leak item names when locked / logged out
      const [cards, identities] = await Promise.all([deps.findFillItems('card'), deps.findFillItems('identity')]);
      if (cards.length === 0 && identities.length === 0) return;
      deps.menus.create({ id: ROOT_ID, title: 'Vaultwarden', contexts: ['editable'] });
      for (const group of GROUPS) {
        const items = group.kind === 'card' ? cards : identities;
        if (items.length === 0) continue;
        deps.menus.create({ id: group.id, parentId: ROOT_ID, title: group.title, contexts: ['editable'] });
        for (const item of items) {
          deps.menus.create({
            id: itemId(group.scope, group.kind, item.id),
            parentId: group.id,
            title: item.reprompt ? `${item.name} 🔒` : item.name,
            contexts: ['editable'],
          });
        }
      }
    },

    /** A menu item was clicked: fetch fill data in the worker and forward a command to the clicked frame. */
    async handleClick(menuItemId: string, tab: { id?: number } | undefined, frameId: number | undefined): Promise<void> {
      if (typeof tab?.id !== 'number') return;
      const parsed = parseItemId(menuItemId);
      if (!parsed) return;
      const options = frameId === undefined ? undefined : { frameId };
      try {
        const data = await deps.getFillData(parsed.cipherId, parsed.kind);
        const command: FillCommand = { type: 'autofill.fill', scope: parsed.scope, kind: parsed.kind, data };
        await deps.tabs.sendMessage(tab.id, command, options);
      } catch (err) {
        // Reprompt-protected items refuse inline release; tell the page to surface that, never the data.
        if (isReprompt(err)) {
          const command: FillErrorCommand = { type: 'autofill.fillError', code: 'reprompt_required' };
          await deps.tabs.sendMessage(tab.id, command, options);
        }
        // denied / locked / sync_required: silently no-op.
      }
    },
  };
}

function isReprompt(err: unknown): boolean {
  return typeof err === 'object' && err !== null && (err as { code?: string }).code === 'reprompt_required';
}
