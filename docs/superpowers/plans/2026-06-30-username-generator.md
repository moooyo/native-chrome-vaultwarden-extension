# 用户名生成器（本地类型）实现计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 在生成器里增加本地用户名生成——加号别名、catch-all、随机词——纯本地、无外部依赖；并给登录编辑器 username 字段加一个 Random-word 生成按钮。

**Architecture:** 纯函数模块 `core/generator/username.ts`（注入随机源，与 password/passphrase 同风格）+ popup 生成器面板新增 Username 模式 + 编辑器 username 生成按钮。全本地，不涉及 vault 机密/网络/storage。

**Tech Stack:** TypeScript、MV3、vitest。

## Global Constraints

- 设计依据：`docs/superpowers/specs/2026-06-30-username-generator-design.md`。
- 全本地纯计算：不涉及 UserKey/主密码/明文库，不联网，不写 `storage`（除生成值填入表单/复制）。
- 随机源默认 `cryptoRandomInt`（`password.ts` 已导出），注入以便确定性单测。
- 随机词复用 `PASSPHRASE_WORDLIST`（`wordlist.js`）。
- 生成历史仅驻内存，与现有密码历史一致（复用 `addPasswordToHistory` / `genHistory`）。
- 转发邮箱别名不在范围。
- 代码标识符/路径英文。
- 测试命令：单文件 `npx vitest run <path>`；类型 `npm run typecheck`；全量 `npm test`；打包 `npm run build`。

---

## 文件结构

新增：
- `src/core/generator/username.ts` — 纯生成函数 + 类型 + 默认值。
- `src/core/generator/username.test.ts`。

修改：
- `src/ui/popup/popup.ts` — 生成器 Username 模式 + 编辑器 username 生成按钮。

---

## Task 1: username.ts（纯生成函数）

**Files:**
- Create: `src/core/generator/username.ts`
- Test: `src/core/generator/username.test.ts`

**Interfaces:**
- Consumes: `cryptoRandomInt`（`./password.js`）；`PASSPHRASE_WORDLIST`（`./wordlist.js`）
- Produces:
  - `type UsernameType = 'plusAddressed' | 'catchAll' | 'randomWord'`
  - `interface UsernameGenOptions { randomLength: number; capitalize: boolean; includeNumber: boolean }`
  - `const DEFAULT_USERNAME_OPTIONS`
  - `randomAlphanumeric(length, randomInt?): string`
  - `generatePlusAddressedEmail(baseEmail, options, randomInt?): string`
  - `generateCatchAllEmail(domain, options, randomInt?): string`
  - `generateRandomWordUsername(options, randomInt?, words?): string`

- [ ] **Step 1: 写失败测试**

`src/core/generator/username.test.ts`:

```ts
import { describe, it, expect } from 'vitest';
import { randomAlphanumeric, generatePlusAddressedEmail, generateCatchAllEmail, generateRandomWordUsername, DEFAULT_USERNAME_OPTIONS } from './username.js';

const fixed = (v: number) => () => v; // deterministic randomInt: always returns v

describe('randomAlphanumeric', () => {
  it('produces the requested length from lowercase letters + digits', () => {
    expect(randomAlphanumeric(10, fixed(0))).toBe('aaaaaaaaaa'); // index 0 → 'a'
    expect(/^[a-z0-9]+$/.test(randomAlphanumeric(20, (n) => n - 1))).toBe(true); // last index → '9'
  });
});

describe('generatePlusAddressedEmail', () => {
  it('inserts +<random> before the @', () => {
    expect(generatePlusAddressedEmail('me@example.com', { ...DEFAULT_USERNAME_OPTIONS, randomLength: 4 }, fixed(0))).toBe('me+aaaa@example.com');
  });
  it('handles a base with no @ (no domain), trimming', () => {
    expect(generatePlusAddressedEmail('  me  ', { ...DEFAULT_USERNAME_OPTIONS, randomLength: 4 }, fixed(0))).toBe('me+aaaa');
  });
});

describe('generateCatchAllEmail', () => {
  it('builds <random>@domain and strips a leading @', () => {
    expect(generateCatchAllEmail('@example.com', { ...DEFAULT_USERNAME_OPTIONS, randomLength: 4 }, fixed(0))).toBe('aaaa@example.com');
  });
  it('empty domain → just the random part', () => {
    expect(generateCatchAllEmail('   ', { ...DEFAULT_USERNAME_OPTIONS, randomLength: 4 }, fixed(0))).toBe('aaaa');
  });
});

describe('generateRandomWordUsername', () => {
  const words = ['alpha', 'bravo'];
  it('default lowercase word', () => {
    expect(generateRandomWordUsername(DEFAULT_USERNAME_OPTIONS, fixed(0), words)).toBe('alpha');
  });
  it('capitalize + includeNumber', () => {
    expect(generateRandomWordUsername({ ...DEFAULT_USERNAME_OPTIONS, capitalize: true, includeNumber: true }, fixed(0), words)).toBe('Alpha0');
  });
});
```

- [ ] **Step 2: 运行确认失败**

Run: `npx vitest run src/core/generator/username.test.ts`
Expected: FAIL（模块不存在）

- [ ] **Step 3: 实现 `src/core/generator/username.ts`**

```ts
// Local username generators (Bitwarden-style): plus-addressed email, catch-all email, and random-word
// username. All pure and offline — no vault secret, no network. `randomInt` is injectable for tests.

import { cryptoRandomInt } from './password.js';
import { PASSPHRASE_WORDLIST } from './wordlist.js';

export type UsernameType = 'plusAddressed' | 'catchAll' | 'randomWord';

export interface UsernameGenOptions {
  /** Random local-part / suffix length for plus-addressed & catch-all. */
  randomLength: number;
  /** random-word: capitalize the first letter. */
  capitalize: boolean;
  /** random-word: append one 0-9 digit. */
  includeNumber: boolean;
}

export const DEFAULT_USERNAME_OPTIONS: UsernameGenOptions = { randomLength: 8, capitalize: false, includeNumber: false };

const ALPHANUM = 'abcdefghijklmnopqrstuvwxyz0123456789';

/** Lowercase letters + digits, unbiased via the injected randomInt (rejection sampling in cryptoRandomInt). */
export function randomAlphanumeric(length: number, randomInt: (maxExclusive: number) => number = cryptoRandomInt): string {
  const n = clamp(Math.trunc(length) || 0, 1, 64);
  let out = '';
  for (let i = 0; i < n; i++) out += ALPHANUM[randomInt(ALPHANUM.length)];
  return out;
}

/** `local+<random>@domain`. A base without '@' becomes `base+<random>` (no domain). Trims the base. */
export function generatePlusAddressedEmail(
  baseEmail: string,
  options: UsernameGenOptions,
  randomInt: (maxExclusive: number) => number = cryptoRandomInt,
): string {
  const trimmed = baseEmail.trim();
  const rand = randomAlphanumeric(clampLen(options.randomLength), randomInt);
  const at = trimmed.indexOf('@');
  if (at < 0) return `${trimmed}+${rand}`;
  return `${trimmed.slice(0, at)}+${rand}@${trimmed.slice(at + 1)}`;
}

/** `<random>@domain`. A leading '@' on the domain is stripped; an empty domain yields just the random part. */
export function generateCatchAllEmail(
  domain: string,
  options: UsernameGenOptions,
  randomInt: (maxExclusive: number) => number = cryptoRandomInt,
): string {
  const d = domain.trim().replace(/^@+/, '');
  const rand = randomAlphanumeric(clampLen(options.randomLength), randomInt);
  return d ? `${rand}@${d}` : rand;
}

/** A random word, optionally capitalized, optionally with a trailing 0-9 digit. */
export function generateRandomWordUsername(
  options: UsernameGenOptions,
  randomInt: (maxExclusive: number) => number = cryptoRandomInt,
  words: readonly string[] = PASSPHRASE_WORDLIST,
): string {
  if (words.length === 0) return '';
  let word = words[randomInt(words.length)]!;
  if (options.capitalize) word = word.charAt(0).toUpperCase() + word.slice(1);
  if (options.includeNumber) word = `${word}${randomInt(10)}`;
  return word;
}

function clampLen(len: number): number { return clamp(Math.trunc(len) || 0, 4, 32); }
function clamp(v: number, min: number, max: number): number { return Math.max(min, Math.min(max, v)); }
```

- [ ] **Step 4: 运行确认通过**

Run: `npx vitest run src/core/generator/username.test.ts`
Expected: PASS
Run: `npm run typecheck`
Expected: 0 errors

- [ ] **Step 5: 提交**

```bash
git add src/core/generator/username.ts src/core/generator/username.test.ts
git commit -m "feat: local username generators (plus-addressed, catch-all, random-word)"
```

---

## Task 2: popup — Username 模式 + 编辑器生成按钮

**Files:**
- Modify: `src/ui/popup/popup.ts`

**Interfaces:**
- Consumes: Task 1 的 `username.ts` 全部导出；现有 `renderGenerator` / `genMode` / `passwordGenOptionsHtml` / `passphraseGenOptionsHtml` / `addPasswordToHistory` / `genHistory` / `editorTextRow` / `icon` / `escapeHtml` / `sendRequest`
- Produces: 生成器 Username 模式（三类型子选择）+ 登录编辑器 username 生成按钮

> popup 无单测；以 `npm run typecheck` + `npm run build` + 人工冒烟为门。

- [ ] **Step 1: 导入 + 模块状态**

顶部（与其它 generator 导入并列）加：

```ts
import { generatePlusAddressedEmail, generateCatchAllEmail, generateRandomWordUsername, DEFAULT_USERNAME_OPTIONS, type UsernameType, type UsernameGenOptions } from '../../core/generator/username.js';
```

把 `let genMode: 'password' | 'passphrase' = 'password';` 改为：

```ts
let genMode: 'password' | 'passphrase' | 'username' = 'password';
let usernameType: UsernameType = 'plusAddressed';
let usernameGenOptions: UsernameGenOptions = { ...DEFAULT_USERNAME_OPTIONS };
let usernameBaseEmail = '';
let usernameDomain = '';
```

- [ ] **Step 2: 面板分段 + 选项 HTML**

在 `renderGenerator` 的分段 `<div class="seg">` 里，`modePassphrase` 按钮之后加：

```ts
          <button id="modeUsername" type="button" class="seg-btn${genMode === 'username' ? ' is-active' : ''}" role="tab" aria-selected="${genMode === 'username'}">Username</button>
```

把 readout 标题与选项区改为按三态选择。将现有：

```ts
          <div class="k">${icon('key')} Generated ${isPass ? 'passphrase' : 'password'}</div>
```
改为：
```ts
          <div class="k">${icon('key')} Generated ${genMode === 'username' ? 'username' : isPass ? 'passphrase' : 'password'}</div>
```

将 `${isPass ? passphraseGenOptionsHtml() : passwordGenOptionsHtml()}` 改为：

```ts
        ${genMode === 'username' ? usernameGenOptionsHtml() : isPass ? passphraseGenOptionsHtml() : passwordGenOptionsHtml()}
```

新增 `usernameGenOptionsHtml()`（放在 `passphraseGenOptionsHtml` 附近）：

```ts
function usernameGenOptionsHtml(): string {
  const t = usernameType;
  return `
    <div class="seg" role="tablist" style="margin-top:8px">
      <button id="utPlus" type="button" class="seg-btn${t === 'plusAddressed' ? ' is-active' : ''}" role="tab">Plus</button>
      <button id="utCatch" type="button" class="seg-btn${t === 'catchAll' ? ' is-active' : ''}" role="tab">Catch-all</button>
      <button id="utWord" type="button" class="seg-btn${t === 'randomWord' ? ' is-active' : ''}" role="tab">Random word</button>
    </div>
    ${t === 'plusAddressed' ? `<label class="ed-field"><span class="ed-label">Base email</span><input id="unBase" class="input" type="email" placeholder="you@example.com" value="${escapeHtml(usernameBaseEmail)}" /></label>` : ''}
    ${t === 'catchAll' ? `<label class="ed-field"><span class="ed-label">Catch-all domain</span><input id="unDomain" class="input" type="text" placeholder="example.com" value="${escapeHtml(usernameDomain)}" /></label>` : ''}
    ${t === 'randomWord' ? `
      <label class="gen-check"><input id="unCap" type="checkbox" ${usernameGenOptions.capitalize ? 'checked' : ''}/><span>Capitalize</span></label>
      <label class="gen-check"><input id="unNum" type="checkbox" ${usernameGenOptions.includeNumber ? 'checked' : ''}/><span>Include number</span></label>` : ''}
    ${t !== 'randomWord' ? `<label class="ed-field"><span class="ed-label">Random length</span><input id="unLen" class="input" type="number" min="4" max="32" value="${usernameGenOptions.randomLength}" /></label>` : ''}`;
}
```

- [ ] **Step 3: 模式切换 + 生成逻辑**

在 `renderGenerator` 的模式监听处（`modePassword`/`modePassphrase` 之后）加：

```ts
  document.getElementById('modeUsername')!.addEventListener('click', () => { genMode = 'username'; renderGenerator(); });
```

在 `readOptions` 内最前面加 username 分支（在 `if (isPass)` 之前）：

```ts
    if (genMode === 'username') {
      const lenEl = document.getElementById('unLen') as HTMLInputElement | null;
      if (lenEl) usernameGenOptions.randomLength = Math.min(Math.max(Math.trunc(Number(lenEl.value)) || 8, 4), 32);
      const capEl = document.getElementById('unCap') as HTMLInputElement | null;
      const numEl = document.getElementById('unNum') as HTMLInputElement | null;
      if (capEl) usernameGenOptions.capitalize = capEl.checked;
      if (numEl) usernameGenOptions.includeNumber = numEl.checked;
      const baseEl = document.getElementById('unBase') as HTMLInputElement | null;
      if (baseEl) usernameBaseEmail = baseEl.value;
      const domEl = document.getElementById('unDomain') as HTMLInputElement | null;
      if (domEl) usernameDomain = domEl.value;
      return;
    }
```

在 `regenerate` 的 `current = ...` 赋值处改为按三态：

```ts
    current = genMode === 'username'
      ? (usernameType === 'plusAddressed' ? generatePlusAddressedEmail(usernameBaseEmail, usernameGenOptions)
        : usernameType === 'catchAll' ? generateCatchAllEmail(usernameDomain, usernameGenOptions)
        : generateRandomWordUsername(usernameGenOptions))
      : isPass ? generatePassphrase(genPassphraseOptions) : generatePassword(genOptions);
    out.textContent = current || (genMode === 'username' ? 'Enter a base email / domain' : 'Enable at least one character set');
```

把 `optionIds` 计算改为包含 username 模式的 id，并绑定类型子分段 + base-email 异步预填。将现有：

```ts
  const optionIds = isPass
    ? ['genWords', 'genSep', 'genCap', 'genNum']
    : ['genLength', 'genLower', 'genUpper', 'genNumbers', 'genSpecial', 'genAmbiguous'];
  for (const id of optionIds) {
    document.getElementById(id)!.addEventListener('input', regenerate);
  }
```
改为：
```ts
  const optionIds = genMode === 'username'
    ? ['unLen', 'unCap', 'unNum', 'unBase', 'unDomain']
    : isPass
      ? ['genWords', 'genSep', 'genCap', 'genNum']
      : ['genLength', 'genLower', 'genUpper', 'genNumbers', 'genSpecial', 'genAmbiguous'];
  for (const id of optionIds) {
    document.getElementById(id)?.addEventListener('input', regenerate);
  }
  if (genMode === 'username') {
    for (const [id, t] of [['utPlus', 'plusAddressed'], ['utCatch', 'catchAll'], ['utWord', 'randomWord']] as const) {
      document.getElementById(id)!.addEventListener('click', () => { usernameType = t; renderGenerator(); });
    }
    // Best-effort prefill of the base email from the active account (only if the user hasn't typed one).
    if (usernameType === 'plusAddressed' && !usernameBaseEmail) {
      void sendRequest({ type: 'auth.listAccounts' }).then((r) => {
        if (!r.ok) return;
        const accounts = (r.data as { accounts?: Array<{ email: string; active?: boolean }> }).accounts ?? [];
        const email = (accounts.find((a) => a.active) ?? accounts[0])?.email;
        const el = document.getElementById('unBase') as HTMLInputElement | null;
        if (email && el && !el.value) { el.value = email; usernameBaseEmail = email; regenerate(); }
      });
    }
  }
```

> 注：`AccountSummary` 的实际字段名（`email`/`active`）以 `auth.listAccounts` 返回为准；若字段名不同，对齐之。

- [ ] **Step 4: 编辑器 username 生成按钮**

把登录编辑器的 `${editorTextRow('ed_username', 'Username', login.username ?? '')}` 改为带生成按钮的行（仿 `ed_password` 的结构）：

```ts
      <label class="ed-field"><span class="ed-label">Username</span>
        <div class="ed-password">
          <input id="ed_username" class="input" type="text" value="${escapeHtml(login.username ?? '')}" />
          <button id="ed_userGen" class="icon-btn" type="button" title="Generate username" aria-label="Generate username">${icon('refresh')}</button>
        </div>
      </label>
```

并在编辑器事件绑定处（`ed_pwGen` 监听附近）加：

```ts
    document.getElementById('ed_userGen')?.addEventListener('click', () => {
      (document.getElementById('ed_username') as HTMLInputElement).value = generateRandomWordUsername({ ...DEFAULT_USERNAME_OPTIONS, capitalize: true });
    });
```

- [ ] **Step 5: 验证**

Run: `npm run typecheck`
Expected: 0 errors
Run: `npm run build`
Expected: `build done`
Run: `npm test`
Expected: 全绿（无回归）
（人工冒烟见收尾。）

- [ ] **Step 6: 提交**

```bash
git add src/ui/popup/popup.ts
git commit -m "feat: username generator panel (plus/catch-all/random-word) + editor username generate button"
```

---

## 收尾：人工验收

- [ ] `npm run build` → 加载 `dist/`，解锁 → 生成器 → Username。
- [ ] Plus：base email 预填当前账户邮箱 → 生成 `local+随机@域`；改 base、改随机长度即时重算；复制。
- [ ] Catch-all：填域名 → `随机@域`。
- [ ] Random word：Capitalize/Include number 生效。
- [ ] 新建/编辑登录条目 → username 字段「生成」按钮填入一个随机词用户名。
- [ ] 密码/口令模式不回归。

---

## Self-Review 结论

- **Spec 覆盖**：三类生成 + randomAlphanumeric→Task1；面板 Username 模式 + 类型子选择 + 编辑器按钮→Task2。
- **占位符**：无 TBD/TODO；纯函数含完整实现与确定性测试；popup 以 typecheck/build + 冒烟为门（符合本项目页面无单测惯例）。
- **类型一致**：`UsernameType`/`UsernameGenOptions`/`DEFAULT_USERNAME_OPTIONS` + 三生成函数（Task1）在 Task2 一致引用。
- **本地/安全**：无 vault 机密、无网络、无 storage；历史复用现有内存机制。
