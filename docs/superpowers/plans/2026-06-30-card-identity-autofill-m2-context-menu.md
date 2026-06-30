# 卡 / 身份自动填充 — 里程碑 2 实现计划（右键上下文菜单）

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 在任意页面右键 → Vaultwarden 上下文菜单，选一张卡 / 一个身份填入当前表单；右键落在可识别的单个字段上时支持「只填此字段」。

**Architecture:** 复用里程碑 1 的 worker 能力（`findFillItems`/`getFillData`）与 content 填充逻辑（`field-detection`/`fill-card-identity`/`field-map`）。新增：后台 `context-menu` 模块（构建/重建菜单 + 点击分发）、`background/index.ts` 接线（注册/刷新/onClicked）、content 端 `runtime.onMessage` 接收下发指令并填充（整表单 / 单字段）+ 轻量提示条。

**Tech Stack:** TypeScript、MV3、`browser.contextMenus` + `browser.tabs.sendMessage`（webextension-polyfill）、esbuild（新模块作为既有入口 import 自动打包）、vitest + happy-dom。

## Global Constraints

- 设计依据：`docs/superpowers/specs/2026-06-30-card-identity-autofill-design.md`（第 9 节）。里程碑 1 已合入 main。
- 安全红线：master password / UserKey / 明文 vault **不得进入 content script**；机密只随显式用户操作（菜单点击）一次性返回；不写 `storage` / DOM attribute / console / 页面全局。
- **锁定 / 未登录时菜单不显示任何 vault 条目名**（避免泄露名称）。
- **reprompt 条目**：菜单标 🔒；点击时 worker 抛 `reprompt_required`，**绝不返回字段数据**；content 显示「请在扩展中验证」提示，不填充。
- 单字段填充复用 `field-map` 分类 + 合成 `DetectedFillForm`，**不新增填充逻辑**。
- 后台 → content 的下发指令经 `browser.tabs.sendMessage`（来自扩展、可信）；content 校验消息形状。
- 代码标识符与路径用英文；不填 hidden/disabled/readonly 字段；不自动提交。
- 测试命令：单文件 `npx vitest run <path>`；类型 `npm run typecheck`；全量 `npm test`；打包 `npm run build`。
- 提交粒度：每个 Task 末尾提交一次。

---

## 文件结构

新增：
- `src/background/context-menu.ts` — 工厂 `createContextMenu(deps)`：`refresh()` 重建菜单、`handleClick()` 分发；纯函数 `shouldRefreshMenu(type)`。
- `src/background/context-menu.test.ts`
- `src/content/notice.ts` — 轻量自消失提示条（closed shadow），用于 reprompt 提示。
- `src/content/notice.test.ts`

修改：
- `src/manifest.json` — `permissions` 增加 `contextMenus`。
- `src/manifest.test.ts` — 断言含 `contextMenus`。
- `src/messaging/protocol.ts` — 新增 `FillCommand` / `FillErrorCommand`（后台→content，不入 RequestMessage 联合）。
- `src/background/index.ts` — 注册 context-menu（onInstalled/onClicked/SW 启动刷新 + onMessage 后按 `shouldRefreshMenu` 刷新）。
- `src/content/autofill.ts` — `runtime.onMessage` 接收 `autofill.fill`/`autofill.fillError`、`contextmenu` 事件暂存元素、整表单 / 单字段填充。
- `src/content/autofill.test.ts` — 对应测试。

---

## Task 1: manifest 增加 contextMenus 权限

**Files:**
- Modify: `src/manifest.json`
- Test: `src/manifest.test.ts`

**Interfaces:**
- Produces: `contextMenus` permission available to the service worker.

- [ ] **Step 1: 写失败测试**

在 `src/manifest.test.ts` 中追加（与现有 permissions 断言并列）：

```ts
  it('requests the contextMenus permission for right-click fill', () => {
    expect(manifest.permissions).toContain('contextMenus');
  });
```

（`manifest` 变量已在该测试文件顶部加载；若变量名不同，对齐现有断言的用法。）

- [ ] **Step 2: 运行确认失败**

Run: `npx vitest run src/manifest.test.ts -t contextMenus`
Expected: FAIL（permissions 不含 contextMenus）

- [ ] **Step 3: 实现**

`src/manifest.json` 的 `permissions` 改为：

```json
  "permissions": ["storage", "alarms", "clipboardRead", "clipboardWrite", "contextMenus"],
```

- [ ] **Step 4: 运行确认通过**

Run: `npx vitest run src/manifest.test.ts`
Expected: PASS

- [ ] **Step 5: 提交**

```bash
git add src/manifest.json src/manifest.test.ts
git commit -m "feat: request contextMenus permission"
```

---

## Task 2: protocol — 下发指令类型

**Files:**
- Modify: `src/messaging/protocol.ts`

**Interfaces:**
- Consumes: `FillKind` / `CardFillData` / `IdentityFillData`（里程碑 1）
- Produces:
  - `interface FillCommand { type: 'autofill.fill'; scope: 'form' | 'field'; kind: FillKind; data: CardFillData | IdentityFillData }`
  - `interface FillErrorCommand { type: 'autofill.fillError'; code: 'reprompt_required' }`
  - `type ContentCommand = FillCommand | FillErrorCommand`

- [ ] **Step 1: 新增类型**

在 `src/messaging/protocol.ts` 中，`IdentityFillData` 接口之后新增（这些是后台→content 的单向指令，**不**加入 `RequestMessage`/`ResponseMessage` 联合）：

```ts
/** Background → content: fill a detected form (scope 'form') or only the last right-clicked field
 *  (scope 'field') with the chosen card/identity. Sent via tabs.sendMessage from the context menu. */
export interface FillCommand {
  type: 'autofill.fill';
  scope: 'form' | 'field';
  kind: FillKind;
  data: CardFillData | IdentityFillData;
}

/** Background → content: the chosen item could not be released inline (reprompt-protected). */
export interface FillErrorCommand {
  type: 'autofill.fillError';
  code: 'reprompt_required';
}

export type ContentCommand = FillCommand | FillErrorCommand;
```

- [ ] **Step 2: 类型检查通过**

Run: `npm run typecheck`
Expected: 0 errors（仅新增类型，暂无消费者）。

- [ ] **Step 3: 提交**

```bash
git add src/messaging/protocol.ts
git commit -m "feat: protocol types for context-menu fill commands"
```

---

## Task 3: context-menu 模块

**Files:**
- Create: `src/background/context-menu.ts`
- Test: `src/background/context-menu.test.ts`

**Interfaces:**
- Consumes: `FillKind` / `FillItemCandidate` / `CardFillData` / `IdentityFillData` / `FillCommand` / `FillErrorCommand`（protocol）；`SessionState`（'loggedOut'|'locked'|'unlocked'）
- Produces:
  - `interface ContextMenuDeps { getState; findFillItems; getFillData; menus; tabs }`
  - `createContextMenu(deps): { refresh(): Promise<void>; handleClick(menuItemId, tab, frameId): Promise<void> }`
  - `shouldRefreshMenu(requestType: string): boolean`

- [ ] **Step 1: 写失败测试**

`src/background/context-menu.test.ts`:

```ts
import { describe, it, expect, vi } from 'vitest';
import { createContextMenu, shouldRefreshMenu } from './context-menu.js';

function makeDeps(state: 'loggedOut' | 'locked' | 'unlocked', cards: any[] = [], identities: any[] = []) {
  const created: any[] = [];
  const sent: any[] = [];
  const deps = {
    getState: vi.fn(async () => state),
    findFillItems: vi.fn(async (kind: 'card' | 'identity') => (kind === 'card' ? cards : identities)),
    getFillData: vi.fn(async () => ({ number: '4111' })),
    menus: { removeAll: vi.fn(async () => {}), create: vi.fn((p: any) => { created.push(p); }) },
    tabs: { sendMessage: vi.fn(async (id: number, msg: unknown, opts?: any) => { sent.push({ id, msg, opts }); }) },
  };
  return { deps, created, sent };
}

describe('context menu', () => {
  it('builds nothing but a removeAll when locked', async () => {
    const { deps, created } = makeDeps('locked', [{ id: 'c1', name: 'Visa', favorite: false }]);
    await createContextMenu(deps).refresh();
    expect(deps.menus.removeAll).toHaveBeenCalled();
    expect(created).toHaveLength(0); // no vault item names leak when locked
  });

  it('builds root + form/field groups with one item per card/identity when unlocked', async () => {
    const { deps, created } = makeDeps('unlocked', [{ id: 'c1', name: 'Visa', favorite: false }], [{ id: 'i1', name: 'Ada', favorite: false }]);
    await createContextMenu(deps).refresh();
    const ids = created.map((c) => c.id);
    expect(ids).toContain('vw-root');
    // each card appears under a form-scope and a field-scope group:
    expect(ids).toContain('vw-fill|form|card|c1');
    expect(ids).toContain('vw-fill|field|card|c1');
    expect(ids).toContain('vw-fill|form|identity|i1');
    expect(ids).toContain('vw-fill|field|identity|i1');
  });

  it('marks reprompt items with a lock and omits empty kinds', async () => {
    const { deps, created } = makeDeps('unlocked', [{ id: 'c1', name: 'Amex', favorite: false, reprompt: true }], []);
    await createContextMenu(deps).refresh();
    const item = created.find((c) => c.id === 'vw-fill|form|card|c1');
    expect(item.title).toContain('Amex');
    expect(item.title).toContain('🔒');
    // no identity group when there are no identities
    expect(created.some((c) => c.id === 'vw-identity-form')).toBe(false);
  });

  it('on click: fetches fill data and sends a fill command to the clicked frame', async () => {
    const { deps, sent } = makeDeps('unlocked', [{ id: 'c1', name: 'Visa', favorite: false }]);
    await createContextMenu(deps).handleClick('vw-fill|field|card|c1', { id: 7 }, 3);
    expect(deps.getFillData).toHaveBeenCalledWith('c1', 'card');
    expect(sent[0]).toEqual({ id: 7, msg: { type: 'autofill.fill', scope: 'field', kind: 'card', data: { number: '4111' } }, opts: { frameId: 3 } });
  });

  it('on click of a reprompt item: sends a fillError instead of data', async () => {
    const { deps, sent } = makeDeps('unlocked');
    deps.getFillData = vi.fn(async () => { throw Object.assign(new Error('x'), { code: 'reprompt_required' }); });
    await createContextMenu(deps).handleClick('vw-fill|form|card|c9', { id: 7 }, 0);
    expect(sent[0].msg).toEqual({ type: 'autofill.fillError', code: 'reprompt_required' });
  });

  it('ignores clicks with no tab id or unrecognized menu id', async () => {
    const { deps, sent } = makeDeps('unlocked');
    await createContextMenu(deps).handleClick('vw-fill|form|card|c1', undefined, 0);
    await createContextMenu(deps).handleClick('something-else', { id: 7 }, 0);
    expect(sent).toHaveLength(0);
    expect(deps.getFillData).not.toHaveBeenCalled();
  });

  it('shouldRefreshMenu fires for sync/auth/cipher mutations, not for reads', () => {
    expect(shouldRefreshMenu('vault.sync')).toBe(true);
    expect(shouldRefreshMenu('auth.lock')).toBe(true);
    expect(shouldRefreshMenu('vault.createCipher')).toBe(true);
    expect(shouldRefreshMenu('vault.getField')).toBe(false);
    expect(shouldRefreshMenu('autofill.findFillItems')).toBe(false);
  });
});
```

- [ ] **Step 2: 运行确认失败**

Run: `npx vitest run src/background/context-menu.test.ts`
Expected: FAIL（模块不存在）

- [ ] **Step 3: 实现 `src/background/context-menu.ts`**

```ts
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
  const scope: 'form' | 'field' = parts[1] === 'field' ? 'field' : 'form';
  const kind: FillKind = parts[2] === 'identity' ? 'identity' : 'card';
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
```

- [ ] **Step 4: 运行确认通过**

Run: `npx vitest run src/background/context-menu.test.ts`
Expected: PASS（7 个用例）

- [ ] **Step 5: 提交**

```bash
git add src/background/context-menu.ts src/background/context-menu.test.ts
git commit -m "feat: context-menu builder + click dispatch for card/identity fill"
```

---

## Task 4: 后台接线（index.ts）

**Files:**
- Modify: `src/background/index.ts`

**Interfaces:**
- Consumes: `createContextMenu` / `shouldRefreshMenu`（Task 3）；既有 `auth` / `vault` / `router` / `alarms` 实例
- Produces: 注册的上下文菜单（onInstalled + SW 启动刷新、onClicked 分发、onMessage 后条件刷新）

> 说明：`index.ts` 是组合根，本项目对其无单测；本任务以 `npm run typecheck` + `npm run build` 为验证门，并做一次人工冒烟。

- [ ] **Step 1: 加导入与实例**

在 `src/background/index.ts` 顶部 import 区追加：

```ts
import { createContextMenu, shouldRefreshMenu } from './context-menu.js';
```

在 `const router = createRouter(...)` 之后追加：

```ts
const contextMenu = createContextMenu({
  getState: () => auth.getState(),
  findFillItems: (kind) => vault.findFillItems(kind),
  getFillData: (cipherId, kind) => vault.getFillData(cipherId, kind),
  menus: {
    removeAll: () => browser.contextMenus.removeAll(),
    create: (props) => { browser.contextMenus.create(props as Parameters<typeof browser.contextMenus.create>[0]); },
  },
  tabs: {
    sendMessage: (tabId, message, options) => browser.tabs.sendMessage(tabId, message, options),
  },
});
```

- [ ] **Step 2: 注册 onClicked + 启动/安装刷新**

在 `browser.runtime.onInstalled.addListener(...)` 内（现有回调体里）追加一行：

```ts
  void contextMenu.refresh().catch(() => {});
```

在文件中已有 `browser.alarms.onAlarm.addListener(...)` 附近、模块顶层追加（SW 每次唤醒重建一次菜单）：

```ts
void contextMenu.refresh().catch(() => {});

browser.contextMenus.onClicked.addListener((info, tab) => {
  void contextMenu.handleClick(String(info.menuItemId), tab, info.frameId);
});
```

- [ ] **Step 3: onMessage 后条件刷新**

把现有的：

```ts
browser.runtime.onMessage.addListener(async (message: unknown) => {
  await alarms.touch();
  return router.handle(message as RequestMessage);
});
```

改为：

```ts
browser.runtime.onMessage.addListener(async (message: unknown) => {
  await alarms.touch();
  const response = await router.handle(message as RequestMessage);
  if (typeof message === 'object' && message !== null && typeof (message as { type?: unknown }).type === 'string'
      && shouldRefreshMenu((message as { type: string }).type)) {
    void contextMenu.refresh().catch(() => {});
  }
  return response;
});
```

- [ ] **Step 4: 验证**

Run: `npm run typecheck`
Expected: 0 errors
Run: `npm run build`
Expected: `build done`（`dist/background.js` 含 context-menu）。
（人工冒烟见收尾。）

- [ ] **Step 5: 提交**

```bash
git add src/background/index.ts
git commit -m "feat: wire context menu (install/startup refresh, onClicked, post-message refresh)"
```

---

## Task 5: content 端接收与填充（+ 提示条）

**Files:**
- Create: `src/content/notice.ts`
- Test: `src/content/notice.test.ts`
- Modify: `src/content/autofill.ts`
- Test: `src/content/autofill.test.ts`

**Interfaces:**
- Consumes: `FillCommand` / `FillErrorCommand` / `ContentCommand`（protocol）；`detectCardForms` / `detectIdentityForms` / `DetectedFillForm` / `FillFieldElement`（field-detection）；`fillCardForm` / `fillIdentityForm`（fill-card-identity）；`classifyCardField` / `classifyIdentityField`（field-map）；`browser`（webextension-polyfill）
- Produces:
  - `src/content/notice.ts`: `showNotice(message: string): void`（closed shadow、约 4s 自消失）
  - `autofill.ts`: `runtime.onMessage` 监听 + `contextmenu` 暂存 + 导出 `handleContentCommand(command: ContentCommand): void`（便于直测）

- [ ] **Step 1: notice 失败测试**

`src/content/notice.test.ts`:

```ts
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
```

- [ ] **Step 2: 运行确认失败**

Run: `npx vitest run src/content/notice.test.ts`
Expected: FAIL（模块不存在）

- [ ] **Step 3: 实现 `src/content/notice.ts`**

```ts
// A small, self-dismissing notice bar in a closed shadow root — used to surface context-menu fill
// errors (e.g. a reprompt-protected item) without exposing anything to the page.
const STYLE = `
  :host { all: initial; }
  .bar {
    position: fixed; right: 16px; bottom: 16px; z-index: 2147483647;
    max-width: 320px; padding: 10px 14px;
    font: 13px/1.4 -apple-system, "Segoe UI", system-ui, Roboto, sans-serif;
    color: #fff; background: #1f2636; border-radius: 10px;
    box-shadow: 0 12px 32px rgba(0,0,0,.35);
  }
`;

export function showNotice(message: string): void {
  const host = document.createElement('div');
  host.dataset.vwNotice = '';
  const shadow = host.attachShadow({ mode: 'closed' });
  shadow.innerHTML = `<style>${STYLE}</style><div class="bar"></div>`;
  (shadow.querySelector('.bar') as HTMLElement).textContent = message;
  document.documentElement.append(host);
  const view = host.ownerDocument.defaultView;
  if (view) view.setTimeout(() => host.remove(), 4000);
}
```

- [ ] **Step 4: 运行确认通过**

Run: `npx vitest run src/content/notice.test.ts`
Expected: PASS

- [ ] **Step 5: autofill content 失败测试**

在 `src/content/autofill.test.ts` 顶部的 mock 区，新增 webextension-polyfill 的 mock（因 autofill.ts 现在直接 import `browser`），放在其它 `vi.mock` 旁：

```ts
vi.mock('webextension-polyfill', () => ({
  default: { runtime: { onMessage: { addListener: vi.fn() } } },
}));
```

并在 `import { startAutofill } ...` 那行改为同时导入新导出：

```ts
import { startAutofill, handleContentCommand } from './autofill.js';
```

在 `describe('autofill controller', …)` 内追加（直测填充处理，不经 browser）：

```ts
  it('fills only the right-clicked field on a field-scope command', async () => {
    document.body.innerHTML = `
      <form>
        <input autocomplete="cc-number" id="num">
        <input autocomplete="cc-csc" id="csc">
      </form>`;
    const csc = document.getElementById('csc') as HTMLInputElement;
    csc.dispatchEvent(new MouseEvent('contextmenu', { bubbles: true }));
    handleContentCommand({ type: 'autofill.fill', scope: 'field', kind: 'card', data: { number: '4111', code: '123' } });
    expect((document.getElementById('csc') as HTMLInputElement).value).toBe('123'); // only the CVC
    expect((document.getElementById('num') as HTMLInputElement).value).toBe('');   // number untouched
  });

  it('fills the whole detected form on a form-scope command', async () => {
    document.body.innerHTML = `
      <form>
        <input autocomplete="cc-number" id="num">
        <input autocomplete="cc-csc" id="csc">
      </form>`;
    handleContentCommand({ type: 'autofill.fill', scope: 'form', kind: 'card', data: { number: '4111', code: '123' } });
    expect((document.getElementById('num') as HTMLInputElement).value).toBe('4111');
    expect((document.getElementById('csc') as HTMLInputElement).value).toBe('123');
  });

  it('shows a notice (no fill) on a fillError command', async () => {
    document.body.innerHTML = `<form><input autocomplete="cc-number" id="num"></form>`;
    handleContentCommand({ type: 'autofill.fillError', code: 'reprompt_required' });
    expect(document.querySelector('[data-vw-notice]')).toBeTruthy();
    expect((document.getElementById('num') as HTMLInputElement).value).toBe('');
  });
```

- [ ] **Step 6: 运行确认失败**

Run: `npx vitest run src/content/autofill.test.ts -t command`
Expected: FAIL（`handleContentCommand` 未导出）

- [ ] **Step 7: 实现 `src/content/autofill.ts` 变更**

7a) 顶部追加导入：

```ts
import browser from 'webextension-polyfill';
import { classifyCardField, classifyIdentityField, type CardRole, type IdentityRole } from './field-map.js';
import type { FillFieldElement } from './field-detection.js';
import type { ContentCommand, FillCommand } from '../messaging/protocol.js';
import { showNotice } from './notice.js';
```

（`detectCardForms`/`detectIdentityForms`/`DetectedFillForm`/`fillCardForm`/`fillIdentityForm`/`CardFillData`/`IdentityFillData` 已在里程碑 1 导入；若缺则补。）

7b) 模块顶层追加右键元素暂存 + 消息监听（放在文件靠近 `startAutofill()` 调用处之前）：

```ts
// Remember the most recently right-clicked element so a field-scope context-menu fill knows its target.
let lastContextElement: Element | null = null;
document.addEventListener('contextmenu', (event) => { lastContextElement = event.target as Element | null; }, true);

browser.runtime.onMessage.addListener((message: unknown) => {
  if (isContentCommand(message)) handleContentCommand(message);
  // No response needed; return nothing (a non-Promise) so the channel closes immediately.
});
```

7c) 追加处理函数与守卫（导出 `handleContentCommand` 供测试）：

```ts
export function handleContentCommand(command: ContentCommand): void {
  if (command.type === 'autofill.fillError') {
    showNotice('Protected item — open the extension to verify');
    return;
  }
  if (command.scope === 'field') {
    fillSingleField(command);
  } else {
    fillWholeForm(command);
  }
}

function fillWholeForm(command: FillCommand): void {
  const forms = command.kind === 'card' ? detectCardForms(document) : detectIdentityForms(document);
  if (forms.length === 0) return;
  // Prefer the form containing the right-clicked element; otherwise the first detected form.
  const form = forms.find((f) => lastContextElement && containsField(f, lastContextElement)) ?? forms[0]!;
  if (command.kind === 'card') fillCardForm(form, command.data as CardFillData);
  else fillIdentityForm(form, command.data as IdentityFillData);
}

function fillSingleField(command: FillCommand): void {
  const el = lastContextElement;
  if (!el || !(el instanceof HTMLInputElement || el instanceof HTMLSelectElement)) return;
  const hints = {
    autocomplete: el.getAttribute('autocomplete') ?? '', name: el.getAttribute('name') ?? '', id: el.id,
    ariaLabel: el.getAttribute('aria-label') ?? '', placeholder: el.getAttribute('placeholder') ?? '',
    type: el instanceof HTMLInputElement ? el.type : 'select',
  };
  if (command.kind === 'card') {
    const role = classifyCardField(hints);
    if (!role) return;
    const form = { kind: 'card' as const, id: 'vw-ctx', fields: new Map([[role as CardRole, el as FillFieldElement]]), anchor: el };
    fillCardForm(form, command.data as CardFillData);
  } else {
    const role = classifyIdentityField(hints);
    if (!role) return;
    const form = { kind: 'identity' as const, id: 'vw-ctx', fields: new Map([[role as IdentityRole, el as FillFieldElement]]), anchor: el };
    fillIdentityForm(form, command.data as IdentityFillData);
  }
}

function containsField(form: DetectedFillForm, el: Element): boolean {
  for (const field of form.fields.values()) if (field === el) return true;
  return false;
}

function isContentCommand(value: unknown): value is ContentCommand {
  if (!isRecord(value)) return false;
  if (value.type === 'autofill.fillError') return value.code === 'reprompt_required';
  return value.type === 'autofill.fill'
    && (value.scope === 'form' || value.scope === 'field')
    && (value.kind === 'card' || value.kind === 'identity')
    && isRecord(value.data);
}
```

（`isRecord` 已存在于 autofill.ts，复用。`fillSingleField` 构造的合成 `DetectedFillForm` 只含被点字段一个角色，`fillCardForm/fillIdentityForm` 对缺失角色自动跳过——单字段填充因此零新增填充逻辑。注意 `exp` 合并 / `fullName` 合成在单字段命中这些角色时仍按里程碑 1 逻辑工作。）

- [ ] **Step 8: 运行确认通过 + 全量回归**

Run: `npx vitest run src/content/autofill.test.ts`
Expected: PASS（含新增 3 个命令用例 + 既有用例不回归）
Run: `npm test`
Expected: 全绿
Run: `npm run typecheck`
Expected: 0 errors
Run: `npm run build`
Expected: `build done`

- [ ] **Step 9: 提交**

```bash
git add src/content/notice.ts src/content/notice.test.ts src/content/autofill.ts src/content/autofill.test.ts
git commit -m "feat: receive context-menu fill commands (whole form / single field) + reprompt notice"
```

---

## 收尾：人工验收

- [ ] `npm run build` → 加载 `dist/` 为未打包扩展。登录并同步含卡 + 身份的 vault。
- [ ] 在结账页输入框右键 → Vaultwarden ▸ Fill card ▸ {卡} → 整张卡表单被填。
- [ ] 在卡号框右键 → Vaultwarden ▸ Fill this field from card ▸ {卡} → 仅卡号框被填。
- [ ] 地址页同样验证 Fill identity / Fill this field from identity。
- [ ] 锁定 vault → 右键菜单不出现 Vaultwarden 条目（或无 vault 条目名）；解锁后恢复。
- [ ] 对 reprompt 卡 → 菜单标 🔒，点击后页面出现「请在扩展中验证」提示且不填充。

---

## Self-Review 结论

- **Spec 覆盖**（设计第 9 节）：manifest 权限→Task1；下发指令类型→Task2；菜单构建/重建/锁定隐藏/onClicked→Task3+4；reprompt 标记与提示→Task3（🔒+fillError）+Task5（notice）；整表单 vs 单字段→Task5；后台→content 仅经扩展消息→Task4/5。
- **占位符**：无 TBD/TODO，每个代码步骤含完整实现与测试。
- **类型一致**：`FillCommand`/`FillErrorCommand`/`ContentCommand`（Task2）在 Task3/5 一致引用；`shouldRefreshMenu`/`createContextMenu`（Task3）在 Task4 一致引用；单字段填充复用里程碑 1 的 `fillCardForm`/`fillIdentityForm`/`classifyCardField`/`classifyIdentityField`，无重名漂移。
- **复用而非重写**：单字段填充用合成 `DetectedFillForm` 调既有填充函数；菜单条目仅含名称（无机密）；机密仅在点击后经 `getFillData`（worker，reprompt 门）流转。
