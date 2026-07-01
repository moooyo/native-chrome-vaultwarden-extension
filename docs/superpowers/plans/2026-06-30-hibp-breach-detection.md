# HIBP 泄露检测实现计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 给密码健康报告加「检查泄露」——用 HIBP Pwned Passwords k-anonymity 查每个登录密码的泄露次数，完整密码/哈希不出 worker。

**Architecture:** `core/vault/pwned.ts`（worker 内 SHA-1、只发 5 位前缀、比对后缀）+ `vault-service.getPwnedReport`（去重、并发限流、只回传次数）+ `vault.checkPwned` 路由 + manifest host_permissions + popup 按需按钮。

**Tech Stack:** TypeScript、MV3、`crypto.subtle` SHA-1、vitest（注入 fetch）。

## Global Constraints

- 设计依据：`docs/superpowers/specs/2026-06-30-hibp-breach-detection-design.md`。
- **隐私红线**：SHA-1 在 worker 内算；只把哈希**前 5 位十六进制前缀**发给 `api.pwnedpasswords.com`；完整密码/完整哈希/后缀绝不发给服务器；跨消息边界只回传每条的 `pwnedCount`。
- 请求带 `Add-Padding: true`。
- 按需触发（用户点按钮），不自动/定时；不写 `storage`/console 明文。
- HIBP hex 用**大写**（HIBP range 端点后缀为大写）。
- 代码标识符/路径英文。
- 测试命令：单文件 `npx vitest run <path>`；类型 `npm run typecheck`；全量 `npm test`；打包 `npm run build`。

---

## 文件结构

新增：
- `src/core/vault/pwned.ts` — `sha1Hex`、`pwnedCount`。
- `src/core/vault/pwned.test.ts`。

修改：
- `src/core/vault/vault-service.ts` — `getPwnedReport`。
- `src/core/vault/vault-service.test.ts`。
- `src/messaging/protocol.ts` / `src/background/router.ts` — `vault.checkPwned`。
- `src/background/router.test.ts`。
- `src/manifest.json` / `src/manifest.test.ts` — host_permissions。
- `src/ui/popup/popup.ts` — 健康报告「Check for breaches」按钮 + 标注。

---

## Task 1: pwned.ts（k-anonymity 查询）

**Files:**
- Create: `src/core/vault/pwned.ts`
- Test: `src/core/vault/pwned.test.ts`

**Interfaces:**
- Consumes: `utf8ToBytes`（`../crypto/encoding.js`）；`crypto.subtle`
- Produces:
  - `sha1Hex(text: string): Promise<string>`（大写 hex）
  - `pwnedCount(password: string, fetchFn?: typeof fetch, sha1?: (t: string) => Promise<string>): Promise<number>`

- [ ] **Step 1: 写失败测试**

`src/core/vault/pwned.test.ts`:

```ts
import { describe, it, expect, vi } from 'vitest';
import { sha1Hex, pwnedCount } from './pwned.js';

describe('sha1Hex', () => {
  it('is the uppercase hex of SHA-1', async () => {
    expect(await sha1Hex('password')).toBe('5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8');
  });
});

describe('pwnedCount', () => {
  it('sends ONLY the 5-char prefix (+Add-Padding) and returns the matching suffix count', async () => {
    const suffix = '5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8'.slice(5); // 35 chars
    const fetchFn = vi.fn(async (url: string, init: RequestInit) => {
      expect(String(url)).toBe('https://api.pwnedpasswords.com/range/5BAA6');
      expect((init.headers as Record<string, string>)['Add-Padding']).toBe('true');
      return new Response(`0000000000000000000000000000000000A:5\r\n${suffix}:12345\r\nFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:0`);
    }) as unknown as typeof fetch;
    expect(await pwnedCount('password', fetchFn)).toBe(12345);
  });
  it('returns 0 when the suffix is absent', async () => {
    const fetchFn = (async () => new Response('ABCDEF:3\nFEDCBA:0')) as unknown as typeof fetch;
    expect(await pwnedCount('x', fetchFn, async () => '11111' + 'Z'.repeat(35))).toBe(0);
  });
  it('throws on a non-2xx response', async () => {
    const fetchFn = (async () => new Response('', { status: 503 })) as unknown as typeof fetch;
    await expect(pwnedCount('x', fetchFn)).rejects.toThrow();
  });
});
```

- [ ] **Step 2: 运行确认失败**

Run: `npx vitest run src/core/vault/pwned.test.ts`
Expected: FAIL（模块不存在）

- [ ] **Step 3: 实现 `src/core/vault/pwned.ts`**

```ts
// HIBP Pwned Passwords (k-anonymity). The password is SHA-1'd IN THE WORKER; only the first 5 hex
// characters of the hash are sent to the API. The full password / full hash / suffix never leave the
// device — the suffix is matched locally against the returned range. `Add-Padding` hides the hit count.

import { utf8ToBytes } from '../crypto/encoding.js';

const HIBP_RANGE = 'https://api.pwnedpasswords.com/range/';

/** Uppercase hex of SHA-1(text). HIBP's range endpoint returns uppercase suffixes. */
export async function sha1Hex(text: string): Promise<string> {
  const digest = await globalThis.crypto.subtle.digest('SHA-1', utf8ToBytes(text) as BufferSource);
  return Array.from(new Uint8Array(digest)).map((b) => b.toString(16).padStart(2, '0')).join('').toUpperCase();
}

/**
 * Look up a password in HIBP Pwned Passwords via k-anonymity. Returns the breach count (0 if not found).
 * Throws on a network / non-2xx error. `fetchFn`/`sha1` are injectable for tests.
 */
export async function pwnedCount(
  password: string,
  fetchFn: typeof fetch = fetch,
  sha1: (text: string) => Promise<string> = sha1Hex,
): Promise<number> {
  const hash = await sha1(password);
  const prefix = hash.slice(0, 5);
  const suffix = hash.slice(5).toUpperCase();
  const res = await fetchFn(`${HIBP_RANGE}${prefix}`, { headers: { 'Add-Padding': 'true' } });
  if (!res.ok) throw new Error(`HIBP request failed: ${res.status}`);
  const body = await res.text();
  for (const line of body.split('\n')) {
    const sep = line.indexOf(':');
    if (sep < 0) continue;
    if (line.slice(0, sep).trim().toUpperCase() === suffix) {
      return Number.parseInt(line.slice(sep + 1).trim(), 10) || 0;
    }
  }
  return 0;
}
```

- [ ] **Step 4: 运行确认通过**

Run: `npx vitest run src/core/vault/pwned.test.ts`
Expected: PASS
Run: `npm run typecheck`
Expected: 0 errors

- [ ] **Step 5: 提交**

```bash
git add src/core/vault/pwned.ts src/core/vault/pwned.test.ts
git commit -m "feat: HIBP pwned-password k-anonymity lookup (prefix only leaves the worker)"
```

---

## Task 2: vault-service.getPwnedReport

**Files:**
- Modify: `src/core/vault/vault-service.ts`
- Test: `src/core/vault/vault-service.test.ts`

**Interfaces:**
- Consumes: `pwnedCount`（Task 1）；现有 `getPasswordHealth` 的解密路径（VAULT_CACHE、userKey、buildOrgKeys、decryptCipher）
- Produces: `getPwnedReport(): Promise<Array<{ id: string; pwnedCount: number }>>`

- [ ] **Step 1: 写失败测试**

在 `vault-service.test.ts` 顶部加对 pwned 模块的 mock（放在其它 `vi.mock` 旁），并追加测试：

```ts
vi.mock('./pwned.js', () => ({
  pwnedCount: vi.fn(async (pw: string) => (pw === 'reused-weak' ? 42 : 0)),
}));

// …在 describe('VaultService', …) 内：
  it('getPwnedReport dedupes by password, maps counts back per id, and returns no passwords', async () => {
    const enc = async (s: string) => encUnder(s, testUserKey); // existing helper
    const sync: SyncResponse = {
      profile: { id: 'u', email: 'u@example.com' },
      ciphers: [
        { id: 'a', type: 1, name: await enc('A'), favorite: false, organizationId: null, login: { password: await enc('reused-weak') } },
        { id: 'b', type: 1, name: await enc('B'), favorite: false, organizationId: null, login: { password: await enc('reused-weak') } },
        { id: 'c', type: 1, name: await enc('C'), favorite: false, organizationId: null, login: { password: await enc('unique-safe') } },
      ],
    };
    const { service } = await makeService(sync);
    await service.sync();
    const entries = await service.getPwnedReport();
    expect(entries).toEqual([{ id: 'a', pwnedCount: 42 }, { id: 'b', pwnedCount: 42 }, { id: 'c', pwnedCount: 0 }]);
    const { pwnedCount } = await import('./pwned.js');
    expect((pwnedCount as any).mock.calls.length).toBe(2); // deduped: 'reused-weak' + 'unique-safe'
    expect(JSON.stringify(entries)).not.toContain('reused-weak'); // no password crosses the boundary
  });
```

> 注：对齐 `vault-service.test.ts` 现有的 `encUnder`/`testUserKey`/`makeService` 用法；若登录条目 fixture 的字段名不同（如 `login.password` 的封装），按文件里既有的登录 fixture 写法对齐。

- [ ] **Step 2: 运行确认失败**

Run: `npx vitest run src/core/vault/vault-service.test.ts -t getPwnedReport`
Expected: FAIL（未定义）

- [ ] **Step 3: 实现**

顶部 import 加 `import { pwnedCount } from './pwned.js';`。在 `getPasswordHealth` 之后插入：

```ts
  /** Check each login password against HIBP (k-anonymity). Decrypts in the worker, dedupes by password,
   *  looks up unique passwords (concurrency-limited), and returns only per-id breach counts. */
  async getPwnedReport(): Promise<Array<{ id: string; pwnedCount: number }>> {
    const cache = await this.deps.localStore.get<SyncResponse>(VAULT_CACHE_KEY);
    if (!cache) throw new AppError('sync_required', 'Sync required');
    const userKey = await this.deps.session.loadUserKey();
    if (!userKey) throw new AppError('locked', 'Vault is locked');
    const orgKeys = await this.buildOrgKeys(cache.profile);
    const logins: Array<{ id: string; password: string }> = [];
    for (const cipher of cache.ciphers) {
      if (cipher.type !== 1 || cipher.deletedDate) continue;
      const decrypted = await decryptCipher(cipher, userKey, orgKeys);
      if (decrypted && !decrypted.undecryptable && decrypted.password) logins.push({ id: decrypted.id, password: decrypted.password });
    }
    const unique = [...new Set(logins.map((l) => l.password))];
    const byPassword = new Map<string, number>();
    const LIMIT = 6;
    try {
      for (let i = 0; i < unique.length; i += LIMIT) {
        const batch = unique.slice(i, i + LIMIT);
        const counts = await Promise.all(batch.map((pw) => pwnedCount(pw)));
        batch.forEach((pw, j) => byPassword.set(pw, counts[j]!));
      }
    } catch {
      throw new AppError('error', 'Could not reach the breach service');
    }
    return logins.map((l) => ({ id: l.id, pwnedCount: byPassword.get(l.password) ?? 0 }));
  }
```

- [ ] **Step 4: 运行确认通过**

Run: `npx vitest run src/core/vault/vault-service.test.ts`
Expected: PASS（整文件）
Run: `npm run typecheck`
Expected: 0 errors

- [ ] **Step 5: 提交**

```bash
git add src/core/vault/vault-service.ts src/core/vault/vault-service.test.ts
git commit -m "feat: VaultService.getPwnedReport (HIBP over decrypted logins, counts only cross the boundary)"
```

---

## Task 3: protocol + router — vault.checkPwned

**Files:**
- Modify: `src/messaging/protocol.ts`, `src/background/router.ts`
- Test: `src/background/router.test.ts`

**Interfaces:**
- Consumes: `getPwnedReport`（Task 2）
- Produces: `{ type: 'vault.checkPwned' }` → `{ ok: true; data: { entries: Array<{ id: string; pwnedCount: number }> } }`

- [ ] **Step 1: protocol 加消息 + 响应分支**

在 `RequestMessage` 的 `vault.getPasswordHealth` 附近加：

```ts
  | { type: 'vault.checkPwned' }
```

在 `ResponseMessage` 加一条：

```ts
  | { ok: true; data: { entries: Array<{ id: string; pwnedCount: number }> } }
```

- [ ] **Step 2: 写失败测试**

追加到 `router.test.ts`：

```ts
  it('routes vault.checkPwned to vault.getPwnedReport', async () => {
    const getPwnedReport = vi.fn(async () => [{ id: 'a', pwnedCount: 5 }]);
    const router = createRouter({ auth: {}, vault: { getPwnedReport } as never, settings: {
      getServerUrl: vi.fn(), saveServerUrl: vi.fn(), getDefaultUriMatchStrategy: vi.fn(async () => 0), saveDefaultUriMatchStrategy: vi.fn(), getLockTimeout: vi.fn(async () => '15'), saveLockTimeout: vi.fn(),
    } as never });
    const res = await router.handle({ type: 'vault.checkPwned' });
    expect(getPwnedReport).toHaveBeenCalled();
    expect(res).toEqual({ ok: true, data: { entries: [{ id: 'a', pwnedCount: 5 }] } });
  });
```

- [ ] **Step 3: 运行确认失败**

Run: `npx vitest run src/background/router.test.ts -t checkPwned`
Expected: FAIL

- [ ] **Step 4: 实现 router 分支**

在 `router.ts` 的 `case 'vault.getPasswordHealth':` 之后插入：

```ts
          case 'vault.checkPwned': {
            if (!deps.vault.getPwnedReport) throw new Error('vault.getPwnedReport is not wired');
            return { ok: true, data: { entries: await deps.vault.getPwnedReport() } };
          }
```

- [ ] **Step 5: 运行确认通过**

Run: `npx vitest run src/background/router.test.ts`
Expected: PASS
Run: `npm run typecheck`
Expected: 0 errors

- [ ] **Step 6: 提交**

```bash
git add src/messaging/protocol.ts src/background/router.ts src/background/router.test.ts
git commit -m "feat: route vault.checkPwned"
```

---

## Task 4: manifest — HIBP host permission

**Files:**
- Modify: `src/manifest.json`
- Test: `src/manifest.test.ts`

**Interfaces:**
- Produces: 安装时授予的 `https://api.pwnedpasswords.com/*` host permission

- [ ] **Step 1: 写失败测试**

在 `src/manifest.test.ts` 追加：

```ts
  it('grants the HIBP host permission for breach checks', () => {
    expect(manifest.host_permissions).toContain('https://api.pwnedpasswords.com/*');
  });
```

- [ ] **Step 2: 运行确认失败**

Run: `npx vitest run src/manifest.test.ts -t HIBP`
Expected: FAIL（无 host_permissions）

- [ ] **Step 3: 实现**

在 `src/manifest.json` 的 `optional_host_permissions` 那行**之后**（或 `permissions` 之后）新增一个键：

```json
  "host_permissions": ["https://api.pwnedpasswords.com/*"],
```

- [ ] **Step 4: 运行确认通过**

Run: `npx vitest run src/manifest.test.ts`
Expected: PASS

- [ ] **Step 5: 提交**

```bash
git add src/manifest.json src/manifest.test.ts
git commit -m "feat: grant api.pwnedpasswords.com host permission"
```

---

## Task 5: popup — 「Check for breaches」按钮 + 标注

**Files:**
- Modify: `src/ui/popup/popup.ts`

**Interfaces:**
- Consumes: `vault.checkPwned`（Task 3）；现有 `renderHealthReport`
- Produces: 健康报告的泄露检查按钮 + 每条泄露标注

> popup 无单测；以 typecheck/build + 人工冒烟为门。

- [ ] **Step 1: 重构 renderHealthReport 支持泄露标注**

把 `renderHealthReport` 中「渲染 entries」的部分抽成可复用的内联函数并在其中加入 pwned 标签；在列表下方加「Check for breaches」按钮。将现有从 `body.innerHTML = entries.map(...)` 到其后的点击绑定，替换为：

```ts
  const pwnedById = new Map<string, number>();
  const renderEntries = (): void => {
    body.innerHTML = entries.map((e) => {
      const pwned = pwnedById.get(e.id);
      const tags = [
        e.weak ? '<span class="tag tag-warn">Weak</span>' : '',
        e.reuseCount > 1 ? `<span class="tag tag-warn">Reused &times;${e.reuseCount}</span>` : '',
        pwned != null ? (pwned > 0 ? `<span class="tag tag-danger">⚠️ Found in ${pwned} breaches</span>` : `<span class="tag">✓ Not found</span>`) : '',
      ].filter(Boolean).join(' ');
      return `<button class="item" type="button" data-id="${escapeHtml(e.id)}">
        <span class="monogram" style="--mono-h:${hueFor(e.name)}">${escapeHtml(monogramLetter(e.name))}</span>
        <span class="item-body"><span class="item-name"><span class="title">${escapeHtml(e.name)}</span></span><span class="item-sub">${tags}</span></span>
        <span class="chevron">${icon('chevron')}</span>
      </button>`;
    }).join('') + `<div class="detail-actions"><button id="checkPwned" type="button" class="btn btn-block">${icon('shield')}<span>Check for breaches</span></button></div>`;
    for (const row of body.querySelectorAll<HTMLElement>('.item')) {
      row.addEventListener('click', () => renderDetail(row.dataset.id!));
    }
    document.getElementById('checkPwned')!.addEventListener('click', () => void checkBreaches());
  };
  const checkBreaches = async (): Promise<void> => {
    const btn = document.getElementById('checkPwned') as HTMLButtonElement;
    btn.disabled = true; btn.querySelector('span')!.textContent = 'Checking…';
    const r = await sendRequest({ type: 'vault.checkPwned' });
    if (!r.ok) {
      btn.disabled = false; btn.querySelector('span')!.textContent = 'Check for breaches';
      const note = document.createElement('p'); note.className = 'note error';
      note.textContent = r.error.message; btn.parentElement!.append(note);
      return;
    }
    for (const p of (r.data as { entries: Array<{ id: string; pwnedCount: number }> }).entries) pwnedById.set(p.id, p.pwnedCount);
    renderEntries();
  };
  renderEntries();
```

（同时把该函数体里原来紧随的 `body.innerHTML = entries.map(...)` 旧块与旧的点击绑定循环删除——已被 `renderEntries()` 取代。健康视图没有 `#detailStatus`，故错误用内联 `note` 元素展示，不用 `setDetailStatus`。）

- [ ] **Step 2: 验证**

Run: `npm run typecheck`
Expected: 0 errors
Run: `npm run build`
Expected: `build done`
Run: `npm test`
Expected: 全绿（无回归）

- [ ] **Step 3: 提交**

```bash
git add src/ui/popup/popup.ts
git commit -m "feat: check passwords against HIBP from the health report"
```

---

## Task 6: LIVE HIBP 契约测试（可选）

**Files:**
- Create: `test/live/pwned.live.test.ts`

**Interfaces:**
- Consumes: `pwnedCount`（Task 1）

> `LIVE=1` 门控；命中真实 HIBP 公共 API（无需 vault 服务器）。

- [ ] **Step 1: 写 live 测试**

```ts
// Live HIBP contract check. Skipped unless LIVE=1. Run: LIVE=1 npx vitest run test/live/pwned.live.test.ts
import { describe, it, expect } from 'vitest';
import { pwnedCount } from '../../src/core/vault/pwned.js';
const LIVE = Boolean(process.env.LIVE);

(LIVE ? describe : describe.skip)('live HIBP', () => {
  it('reports a large breach count for the notorious "password"', async () => {
    const n = await pwnedCount('password');
    expect(n).toBeGreaterThan(1000);
  }, 30_000);
  it('reports 0 for a very unlikely random string', async () => {
    const n = await pwnedCount(`vw-${Date.now()}-${Math.random().toString(36).slice(2)}-unlikely`);
    expect(n).toBe(0);
  }, 30_000);
});
```

> 注：`Math.random()`/`Date.now()` 在普通测试文件里可用（非 workflow 脚本约束）。

- [ ] **Step 2: 默认 skip**

Run: `npx vitest run test/live/pwned.live.test.ts`
Expected: describe 被 skip（0 失败）。

- [ ] **Step 3: LIVE 实跑**

Run: `LIVE=1 npx vitest run test/live/pwned.live.test.ts`
Expected: PASS（`password` 泄露数 > 1000；随机串 = 0）。若网络不可达则回报（控制器裁定）。

- [ ] **Step 4: 提交**

```bash
git add test/live/pwned.live.test.ts
git commit -m "test: live HIBP contract (pwned password vs. random)"
```

---

## 收尾：人工验收

- [ ] `npm run build` → 加载 `dist/`，解锁 → 密码健康 → 「Check for breaches」→ 弱/复用条目若曾泄露显示「⚠️ Found in N breaches」，安全的显示「✓ Not found」。
- [ ] 断网/HIBP 不可达 → 错误提示，不崩。

---

## Self-Review 结论

- **Spec 覆盖**：k-anonymity 查询→Task1；worker 编排（去重/限流/只回传次数）→Task2；路由→Task3；host_permissions→Task4；popup 按钮→Task5；LIVE 契约→Task6。
- **占位符**：无 TBD/TODO；纯/worker 逻辑含完整实现与测试；popup 以 typecheck/build + 冒烟为门。
- **类型一致**：`sha1Hex`/`pwnedCount`（Task1）在 Task2/6 一致引用；`{ id, pwnedCount }` 形状在 Task2/3/5 一致；`vault.checkPwned` 消息全程一致。
- **隐私**：只发 5 位前缀；密码/完整哈希不出 worker；报告只含次数——Task1/2 的测试直接验证（URL 只含前缀、entries 不含密码）。
