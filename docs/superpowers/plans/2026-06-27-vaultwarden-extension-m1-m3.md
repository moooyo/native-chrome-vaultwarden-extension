# Vaultwarden 浏览器扩展 M1-M3 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 构建一个原生（无框架）MV3 浏览器扩展，作为自托管 Vaultwarden 服务器客户端，完成登录解锁、同步解密、只读查看，全部加密在客户端按 Bitwarden 白皮书实现。

**Architecture:** 中心化后台 service worker 持有全部敏感逻辑（CryptoEngine / ApiClient / SessionManager / AuthService / VaultService）与解锁态；popup/options 为瘦 UI，经 `runtime` 类型化消息与后台通信。`core/` 为纯 TypeScript（零 `chrome.*` 依赖、可在 Node 下单测），`platform/` 隔离浏览器 API 为 Safari/Firefox 预留。

**Tech Stack:** Manifest V3、TypeScript、WebExtensions API（`webextension-polyfill`）、WebCrypto（PBKDF2/AES-256-CBC/HMAC-SHA256/HKDF-Expand）、esbuild（构建）、vitest（测试）、eslint（lint）。无前端/扩展框架。

设计依据 spec：`docs/superpowers/specs/2026-06-27-vaultwarden-extension-m1-m3-foundation-design.md`。
API 契约依据：`D:\Code\WinVaultWarden\docs\API.md` 与 `D:\Code\WinVaultWarden\docs\vaultwarden-api-contracts.md`。

## Global Constraints

每个任务的要求都隐含包含本节。值逐字取自 spec。

- **工具链与依赖一律最新稳定版**：安装命令统一用 `@latest`，由 `package.json` 记录解析到的版本。涉及 TypeScript、esbuild、vitest、eslint、typescript-eslint、`webextension-polyfill`、`@types/*`、Node LTS（开发机已 Node v26）。
- **Manifest V3**，`background.service_worker` 且 `type: "module"`。
- **KDF 仅 PBKDF2-HMAC-SHA256**；prelogin 返回 `kdf=1`(Argon2id) 时给友好提示、不崩溃；Argon2id 后续里程碑。
- **字段大小写严格照抄契约源码**：登录响应 PascalCase（`Key`/`PrivateKey`/`Kdf`/`KdfIterations`/`TwoFactorProviders`），sync/prelogin camelCase（`kdf`/`kdfIterations`/`profile`/`ciphers`）。**不可擅自统一大小写**。
- **登录固定参数**：`client_id=browser`、`device_type=2`(ChromeExtension)、`scope=api offline_access`、`device_name=chrome`、`device_identifier`=扩展生成并存 local 的稳定 GUID。
- **`connect/token` Content-Type 必须 `application/x-www-form-urlencoded`**；`prelogin`/`sync` 用 JSON。
- **Encrypt-then-MAC**：encType=2 必须先用**常数时间比较**校验 `HMAC-SHA256(macKey, iv||ct)`，通过才 AES-256-CBC 解密。
- **两处 salt 不同**：MasterKey 的 salt = email 小写；MasterPasswordHash 的 salt = 主密码明文、迭代 1 次。
- **HKDF-Expand != WebCrypto 的 HKDF**：仅做 RFC 5869 Expand 单块：`OKM = HMAC-SHA256(PRK, utf8(info) || 0x01)` 取前 32 字节。
- **安全红线**：主密码、MasterKey、UserKey 绝不落盘明文、不写日志、不出进程；唯一例外是 UserKey/私钥按方案 B 存 `storage.session`（内存级、关浏览器即清）。`storage.local` 只存密文或不可解密库的凭证。
- **storage 划分**：`session` = 明文 UserKey/私钥 + lastActivity；`local` = serverUrl、deviceId、access/refresh token、加密的 `Key`/`PrivateKey`+KDF 参数、加密库缓存、设置、记住设备 token。
- **个人库优先**：组织/集合条目（需 RSA org key）本阶段不解密，作为已知限制跳过。
- **所有 git 提交**结尾附：`Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>`。

---

## File Structure

实现按里程碑顺序产出以下文件，每个文件单一职责：

```text
package.json                       # 工具脚本与依赖（最新稳定版）
tsconfig.json                      # 严格 TS 配置
build.mjs                          # esbuild：三入口打包 + 拷贝静态文件
vitest.config.ts                   # 测试配置（node 环境）
eslint.config.mjs                  # lint
src/
├─ manifest.json                   # MV3 清单
├─ background/
│  ├─ index.ts                     # worker 入口：实例化依赖、注册 onMessage/alarms
│  └─ router.ts                    # createRouter(deps)：消息 -> service 调用
├─ core/
│  ├─ crypto/
│  │  ├─ encoding.ts               # utf8/base64/hex/constantTimeEqual
│  │  ├─ primitives.ts             # WebCrypto 薄封装
│  │  ├─ kdf.ts                    # deriveMasterKey/MasterPasswordHash/stretchMasterKey
│  │  ├─ encstring.ts              # parse + decrypt（含 mac 验证）
│  │  └─ keys.ts                   # SymmetricKey 类型 + unwrapSymmetricKey
│  ├─ api/
│  │  ├─ types.ts                  # 契约类型（大小写照抄）
│  │  └─ client.ts                 # ApiClient（注入 fetch + serverUrlProvider）
│  ├─ session/
│  │  ├─ session-manager.ts        # 状态机 + 密钥托管 + 持久化
│  │  └─ auth-service.ts           # login/2FA/unlock/refresh 编排
│  └─ vault/
│     ├─ models.ts                 # DecryptedCipher / CipherSummary / FieldName
│     ├─ decrypt.ts                # decryptCipher
│     ├─ search.ts                 # filterSummaries（纯函数）
│     └─ vault-service.ts          # sync/缓存/建库/getField
├─ platform/
│  └─ store.ts                     # KeyValueStore 接口 + memory + browser 实现
├─ messaging/
│  └─ protocol.ts                  # Request/Response 类型化协议
└─ ui/
   ├─ popup/{popup.html,popup.css,popup.ts}
   └─ options/{options.html,options.css,options.ts}
test/
└─ vectors.ts                      # 共享测试向量（真实可复现，已验证）
```

---

# 阶段 M1：地基 + 加密内核

产出：可加载的扩展骨架 + 通过测试的加密内核 + 安全存储抽象。

---

### Task 1: 工具链初始化（构建/测试/类型/lint 全部跑通）

**Files:**
- Create: `package.json`、`tsconfig.json`、`build.mjs`、`vitest.config.ts`、`eslint.config.mjs`、`.gitignore`
- Create: `src/core/crypto/smoke.ts`（临时占位，最后一步删除）
- Test: `test/smoke.test.ts`（临时占位）

**Interfaces:**
- Produces: 可用的 npm 脚本 `build` / `watch` / `typecheck` / `test` / `lint`；`dist/` 输出目录约定。

- [ ] **Step 1: 初始化 npm 工程并安装最新稳定版依赖**

在仓库根目录运行（npm.ps1 被策略拦截时用 `npm.cmd`）：

```bash
npm.cmd init -y
npm.cmd install webextension-polyfill@latest
npm.cmd install -D typescript@latest esbuild@latest vitest@latest eslint@latest typescript-eslint@latest @eslint/js@latest @types/node@latest @types/webextension-polyfill@latest
```

- [ ] **Step 2: 写 `package.json` 的 scripts 与模块类型**

把 `package.json` 的 `scripts` 与 `type` 改为（保留安装写入的 `dependencies`/`devDependencies` 版本号不动）：

```json
{
  "name": "vaultwarden-extension",
  "version": "0.1.0",
  "private": true,
  "type": "module",
  "scripts": {
    "build": "node build.mjs",
    "watch": "node build.mjs --watch",
    "typecheck": "tsc --noEmit",
    "test": "vitest run",
    "test:watch": "vitest",
    "lint": "eslint ."
  }
}
```

- [ ] **Step 3: 写 `tsconfig.json`**

```json
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "ESNext",
    "moduleResolution": "bundler",
    "lib": ["ES2022", "DOM", "DOM.Iterable", "WebWorker"],
    "types": ["node"],
    "strict": true,
    "noUncheckedIndexedAccess": true,
    "exactOptionalPropertyTypes": true,
    "noImplicitOverride": true,
    "verbatimModuleSyntax": true,
    "skipLibCheck": true,
    "resolveJsonModule": true,
    "isolatedModules": true,
    "noEmit": true
  },
  "include": ["src", "test", "build.mjs", "vitest.config.ts"]
}
```

- [ ] **Step 4: 写 `build.mjs`（esbuild 三入口 + 拷贝静态文件）**

```js
import * as esbuild from 'esbuild';
import { cp, rm, mkdir } from 'node:fs/promises';
import { join } from 'node:path';

const watch = process.argv.includes('--watch');
const outdir = 'dist';

async function copyStatic() {
  await cp('src/manifest.json', join(outdir, 'manifest.json'));
  for (const page of ['popup', 'options']) {
    await mkdir(join(outdir, 'ui', page), { recursive: true });
    await cp(`src/ui/${page}/${page}.html`, join(outdir, 'ui', page, `${page}.html`));
    await cp(`src/ui/${page}/${page}.css`, join(outdir, 'ui', page, `${page}.css`));
  }
}

const options = {
  entryPoints: {
    background: 'src/background/index.ts',
    'ui/popup/popup': 'src/ui/popup/popup.ts',
    'ui/options/options': 'src/ui/options/options.ts',
  },
  bundle: true,
  format: 'esm',
  target: 'es2022',
  outdir,
  sourcemap: true,
  logLevel: 'info',
};

await rm(outdir, { recursive: true, force: true });
await mkdir(outdir, { recursive: true });

if (watch) {
  const ctx = await esbuild.context(options);
  await ctx.watch();
  await copyStatic();
  console.log('watching...');
} else {
  await esbuild.build(options);
  await copyStatic();
  console.log('build done');
}
```

- [ ] **Step 5: 写 `vitest.config.ts`、`eslint.config.mjs`、`.gitignore`**

`vitest.config.ts`：

```ts
import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'node',
    include: ['test/**/*.test.ts', 'src/**/*.test.ts'],
  },
});
```

`eslint.config.mjs`：

```js
import js from '@eslint/js';
import tseslint from 'typescript-eslint';

export default tseslint.config(
  { ignores: ['dist/**', 'node_modules/**'] },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    languageOptions: {
      globals: {
        chrome: 'readonly',
        browser: 'readonly',
        btoa: 'readonly',
        atob: 'readonly',
      },
    },
    rules: { 'no-console': 'off' },
  },
);
```

`.gitignore`：

```text
node_modules/
dist/
*.zip
```

- [ ] **Step 6: 写占位测试，证明测试管线工作**

`src/core/crypto/smoke.ts`：

```ts
export function ping(): string {
  return 'pong';
}
```

`test/smoke.test.ts`：

```ts
import { describe, it, expect } from 'vitest';
import { ping } from '../src/core/crypto/smoke.js';

describe('toolchain smoke', () => {
  it('runs vitest and resolves ts imports', () => {
    expect(ping()).toBe('pong');
  });

  it('exposes WebCrypto subtle in the test environment', () => {
    expect(globalThis.crypto?.subtle).toBeDefined();
  });
});
```

- [ ] **Step 7: 运行 typecheck/test/lint，全部通过**

```bash
npm.cmd run typecheck
npm.cmd test
npm.cmd run lint
```

Expected: typecheck 无错；vitest 2 passed；eslint 无错。

- [ ] **Step 8: 删除占位、提交**

删除 `src/core/crypto/smoke.ts` 与 `test/smoke.test.ts`（仅验证管线）。

```bash
git rm src/core/crypto/smoke.ts test/smoke.test.ts
git add -A
git commit -m "chore: 初始化工具链（esbuild/vitest/eslint/tsconfig）

Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
```

---

### Task 2: 扩展骨架与 manifest（可在 Chrome 加载）

**Files:**
- Create: `src/manifest.json`
- Create: `src/background/index.ts`（最小 worker）
- Create: `src/ui/popup/popup.html`、`popup.css`、`popup.ts`（最小）
- Create: `src/ui/options/options.html`、`options.css`、`options.ts`（最小）

**Interfaces:**
- Produces: 可加载的 MV3 扩展；后续任务向 `background/index.ts` 注入路由，向 popup/options 填充逻辑。

- [ ] **Step 1: 写 `src/manifest.json`**

```json
{
  "manifest_version": 3,
  "name": "Vaultwarden Extension",
  "version": "0.1.0",
  "description": "Native MV3 client for self-hosted Vaultwarden.",
  "background": { "service_worker": "background.js", "type": "module" },
  "action": { "default_popup": "ui/popup/popup.html", "default_title": "Vaultwarden" },
  "options_ui": { "page": "ui/options/options.html", "open_in_tab": true },
  "permissions": ["storage", "alarms"],
  "optional_host_permissions": ["https://*/*", "http://*/*"]
}
```

- [ ] **Step 2: 写最小 `src/background/index.ts`**

```ts
import browser from 'webextension-polyfill';

browser.runtime.onInstalled.addListener(() => {
  console.log('[vaultwarden] service worker installed');
});

browser.runtime.onMessage.addListener(async () => {
  return { ok: false, error: { code: 'not_ready', message: 'router not wired yet' } };
});
```

- [ ] **Step 3: 写最小 popup**

`src/ui/popup/popup.html`：

```html
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <link rel="stylesheet" href="popup.css" />
</head>
<body>
  <main id="app"><p>Vaultwarden</p></main>
  <script type="module" src="popup.js"></script>
</body>
</html>
```

`src/ui/popup/popup.css`：

```css
body { width: 360px; min-height: 200px; margin: 0; font: 14px system-ui, sans-serif; }
#app { padding: 12px; }
```

`src/ui/popup/popup.ts`：

```ts
const app = document.getElementById('app');
if (app) app.textContent = 'Vaultwarden popup ready';
```

- [ ] **Step 4: 写最小 options**

`src/ui/options/options.html`：

```html
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <link rel="stylesheet" href="options.css" />
</head>
<body>
  <main id="app"><h1>Vaultwarden Settings</h1></main>
  <script type="module" src="options.js"></script>
</body>
</html>
```

`src/ui/options/options.css`：

```css
body { font: 14px system-ui, sans-serif; max-width: 640px; margin: 24px auto; padding: 0 16px; }
```

`src/ui/options/options.ts`：

```ts
const app = document.getElementById('app');
if (app) console.log('[vaultwarden] options ready');
```

- [ ] **Step 5: 构建并人工加载验证**

```bash
npm.cmd run build
```

Expected: `dist/` 含 `manifest.json`、`background.js`、`ui/popup/popup.{html,css,js}`、`ui/options/options.{html,css,js}`。Chrome `chrome://extensions` 加载 `dist/` 后扩展无错误，点击图标显示 “Vaultwarden popup ready”。

- [ ] **Step 6: 提交**

```bash
git add -A
git commit -m "feat: MV3 扩展骨架与 manifest（可加载）

Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
```

---

### Task 3: 编码工具 `encoding.ts`

**Files:**
- Create: `src/core/crypto/encoding.ts`
- Test: `src/core/crypto/encoding.test.ts`

**Interfaces:**
- Produces:
  - `utf8ToBytes(s: string): Uint8Array`
  - `bytesToUtf8(b: Uint8Array): string`
  - `base64ToBytes(s: string): Uint8Array`
  - `bytesToBase64(b: Uint8Array): string`
  - `hexToBytes(h: string): Uint8Array`
  - `bytesToHex(b: Uint8Array): string`
  - `constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean`

- [ ] **Step 1: 写失败测试 `encoding.test.ts`**

```ts
import { describe, it, expect } from 'vitest';
import {
  utf8ToBytes, bytesToUtf8, base64ToBytes, bytesToBase64,
  hexToBytes, bytesToHex, constantTimeEqual,
} from './encoding.js';

describe('encoding', () => {
  it('utf8 round-trips', () => {
    expect(bytesToUtf8(utf8ToBytes('Hello, 世界'))).toBe('Hello, 世界');
  });

  it('base64 round-trips and matches known value', () => {
    expect(bytesToBase64(utf8ToBytes('Hello, Vault!'))).toBe('SGVsbG8sIFZhdWx0IQ==');
    expect(bytesToUtf8(base64ToBytes('SGVsbG8sIFZhdWx0IQ=='))).toBe('Hello, Vault!');
  });

  it('hex round-trips', () => {
    expect(bytesToHex(hexToBytes('00ff10'))).toBe('00ff10');
  });

  it('rejects malformed hex', () => {
    expect(() => hexToBytes('0')).toThrow('invalid hex length');
    expect(() => hexToBytes('zz')).toThrow('invalid hex byte');
  });

  it('constantTimeEqual compares contents', () => {
    expect(constantTimeEqual(hexToBytes('0011'), hexToBytes('0011'))).toBe(true);
    expect(constantTimeEqual(hexToBytes('0011'), hexToBytes('0012'))).toBe(false);
    expect(constantTimeEqual(hexToBytes('00'), hexToBytes('0000'))).toBe(false);
  });
});
```

- [ ] **Step 2: 运行测试，确认失败**

Run: `npm.cmd test -- encoding`
Expected: FAIL（找不到 `./encoding.js` 导出）。

- [ ] **Step 3: 实现 `encoding.ts`**

```ts
const encoder = new TextEncoder();
const decoder = new TextDecoder();

export function utf8ToBytes(s: string): Uint8Array {
  return encoder.encode(s);
}

export function bytesToUtf8(b: Uint8Array): string {
  return decoder.decode(b);
}

export function bytesToBase64(b: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < b.length; i++) binary += String.fromCharCode(b[i]!);
  return btoa(binary);
}

export function base64ToBytes(s: string): Uint8Array {
  const binary = atob(s);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

export function bytesToHex(b: Uint8Array): string {
  let out = '';
  for (let i = 0; i < b.length; i++) out += b[i]!.toString(16).padStart(2, '0');
  return out;
}

export function hexToBytes(h: string): Uint8Array {
  if (h.length % 2 !== 0) throw new Error('invalid hex length');
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) {
    const byte = Number.parseInt(h.slice(i * 2, i * 2 + 2), 16);
    if (Number.isNaN(byte)) throw new Error('invalid hex byte');
    out[i] = byte;
  }
  return out;
}

export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}
```

- [ ] **Step 4: 运行测试，确认通过**

Run: `npm.cmd test -- encoding`
Expected: PASS（5 tests）。

- [ ] **Step 5: 提交**

```bash
git add src/core/crypto/encoding.ts src/core/crypto/encoding.test.ts
git commit -m "feat(crypto): 编码工具（utf8/base64/hex/常数时间比较）

Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
```

---

### Task 4: WebCrypto 原语 `primitives.ts`

**Files:**
- Create: `src/core/crypto/primitives.ts`
- Test: `src/core/crypto/primitives.test.ts`

**Interfaces:**
- Consumes: `encoding.ts` 的 `utf8ToBytes`
- Produces:
  - `pbkdf2Sha256(password: Uint8Array, salt: Uint8Array, iterations: number, lengthBytes: number): Promise<Uint8Array>`
  - `hkdfExpandSha256(prk: Uint8Array, info: string, lengthBytes: number): Promise<Uint8Array>`
  - `hmacSha256(key: Uint8Array, data: Uint8Array): Promise<Uint8Array>`
  - `aesCbc256Decrypt(key: Uint8Array, iv: Uint8Array, data: Uint8Array): Promise<Uint8Array>`

- [ ] **Step 1: 写失败测试 `primitives.test.ts`（含 PBKDF2/HMAC 标准 KAT）**

```ts
import { describe, it, expect } from 'vitest';
import { pbkdf2Sha256, hkdfExpandSha256, hmacSha256, aesCbc256Decrypt } from './primitives.js';
import { utf8ToBytes, bytesToHex, hexToBytes } from './encoding.js';

describe('primitives', () => {
  it('PBKDF2-HMAC-SHA256 matches known answers', async () => {
    const p = utf8ToBytes('password');
    const s = utf8ToBytes('salt');
    expect(bytesToHex(await pbkdf2Sha256(p, s, 1, 32)))
      .toBe('120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b');
    expect(bytesToHex(await pbkdf2Sha256(p, s, 4096, 32)))
      .toBe('c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a');
  });

  it('HMAC-SHA256 matches RFC 4231 test case 1', async () => {
    const key = new Uint8Array(20).fill(0x0b);
    const mac = await hmacSha256(key, utf8ToBytes('Hi There'));
    expect(bytesToHex(mac)).toBe('b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7');
  });

  it('HKDF-Expand (single block) equals verified Bitwarden-style stretch vectors', async () => {
    const prk = hexToBytes('c6e36acf506a7d05ec07ebe2c4f8406ccb1b69e761e71e61e7e24edc0b7736bd');
    expect(bytesToHex(await hkdfExpandSha256(prk, 'enc', 32)))
      .toBe('d2425697ee6622bac49a08c019c169ad0aa04ccb08f1ec76b580938e5c4d71ac');
    expect(bytesToHex(await hkdfExpandSha256(prk, 'mac', 32)))
      .toBe('0586d3103bfe6a5e5c72ec94d05907bda43b6b26bafeb67e896885e5addab596');
  });

  it('AES-256-CBC decrypts what WebCrypto encrypts', async () => {
    const key = hexToBytes('00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff');
    const iv = hexToBytes('0102030405060708090a0b0c0d0e0f10');
    const subtleKey = await crypto.subtle.importKey('raw', key, { name: 'AES-CBC' }, false, ['encrypt']);
    const plaintext = utf8ToBytes('Hello, AES-CBC!');
    const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-CBC', iv }, subtleKey, plaintext));
    const out = await aesCbc256Decrypt(key, iv, ct);
    expect(bytesToHex(out)).toBe(bytesToHex(plaintext));
  });
});
```

- [ ] **Step 2: 运行测试，确认失败**

Run: `npm.cmd test -- primitives`
Expected: FAIL（模块未实现）。

- [ ] **Step 3: 实现 `primitives.ts`**

```ts
import { utf8ToBytes } from './encoding.js';

const subtle = globalThis.crypto.subtle;

export async function pbkdf2Sha256(
  password: Uint8Array,
  salt: Uint8Array,
  iterations: number,
  lengthBytes: number,
): Promise<Uint8Array> {
  const baseKey = await subtle.importKey('raw', password, 'PBKDF2', false, ['deriveBits']);
  const bits = await subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
    baseKey,
    lengthBytes * 8,
  );
  return new Uint8Array(bits);
}

export async function hmacSha256(key: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
  const k = await subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return new Uint8Array(await subtle.sign('HMAC', k, data));
}

export async function hkdfExpandSha256(
  prk: Uint8Array,
  info: string,
  lengthBytes: number,
): Promise<Uint8Array> {
  if (lengthBytes > 32) throw new Error('hkdfExpand: only single-block (<=32B) supported');
  const infoBytes = utf8ToBytes(info);
  const input = new Uint8Array(infoBytes.length + 1);
  input.set(infoBytes, 0);
  input[infoBytes.length] = 0x01;
  return (await hmacSha256(prk, input)).slice(0, lengthBytes);
}

export async function aesCbc256Decrypt(
  key: Uint8Array,
  iv: Uint8Array,
  data: Uint8Array,
): Promise<Uint8Array> {
  const k = await subtle.importKey('raw', key, { name: 'AES-CBC' }, false, ['decrypt']);
  return new Uint8Array(await subtle.decrypt({ name: 'AES-CBC', iv }, k, data));
}
```

- [ ] **Step 4: 运行测试，确认通过**

Run: `npm.cmd test -- primitives`
Expected: PASS（4 tests）。

- [ ] **Step 5: 提交**

```bash
git add src/core/crypto/primitives.ts src/core/crypto/primitives.test.ts
git commit -m "feat(crypto): WebCrypto 原语（PBKDF2/HMAC/HKDF-Expand/AES-CBC）

Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
```

---

### Task 5: 密钥派生 `kdf.ts`（含真实向量）

**Files:**
- Create: `src/core/crypto/keys.ts`（先放 `SymmetricKey` 类型与 `symmetricKeyFromBytes`）
- Create: `src/core/crypto/kdf.ts`
- Create: `test/vectors.ts`
- Test: `src/core/crypto/kdf.test.ts`

**Interfaces:**
- Consumes: `pbkdf2Sha256`、`hkdfExpandSha256`、`utf8ToBytes`、`bytesToBase64`
- Produces:
  - `type SymmetricKey = { encKey: Uint8Array; macKey: Uint8Array }`
  - `symmetricKeyFromBytes(bytes: Uint8Array): SymmetricKey`
  - `deriveMasterKey(password: string, email: string, iterations: number): Promise<Uint8Array>`
  - `deriveMasterPasswordHash(masterKey: Uint8Array, password: string): Promise<string>`
  - `stretchMasterKey(masterKey: Uint8Array): Promise<SymmetricKey>`

- [ ] **Step 1: 写共享向量 `test/vectors.ts`**

```ts
export const KDF_VECTOR = {
  email: 'user@example.com',
  password: 'p4ssw0rd-Master!',
  iterations: 1000,
  masterKeyHex: 'c6e36acf506a7d05ec07ebe2c4f8406ccb1b69e761e71e61e7e24edc0b7736bd',
  masterPasswordHashB64: 'Zdrx2SQE0KLpsOmYbeUrSxqDlYP4kBxA2gckh8YR6Zg=',
};

export const KDF_VECTOR_600K = {
  email: 'user@example.com',
  password: 'p4ssw0rd-Master!',
  iterations: 600000,
  masterKeyHex: '0ec2123c51cbd5690086201e28957a85ffdfad6ce382983f27c73960aa6d20ee',
  masterPasswordHashB64: 'Ed32k/NteQHP1mkPQDcCsxylmWzEly7BxSD48blLBEQ=',
};

export const STRETCH_VECTOR = {
  encKeyHex: 'd2425697ee6622bac49a08c019c169ad0aa04ccb08f1ec76b580938e5c4d71ac',
  macKeyHex: '0586d3103bfe6a5e5c72ec94d05907bda43b6b26bafeb67e896885e5addab596',
};

export const USER_KEY_VECTOR = {
  akey:
    '2.SgDNFMTxhFrnqEdZTCSm6g==|dQ8ObREVFKlklPLeWSqsWkaWQQ4ezGoBddju71qRwUWuR/AdYm4voNb24Nh1kUhrtMJPdZKGzSS42fdAnvZeZcXFaanRpicPVUdqyZUrZUM=|yL4+bZWGI2eZ8bwHzgDzcEIUoR6LjfrE+jIZFoRlj+Y=',
  userKeyHex:
    '00112233445566778899aabbccddeeff102132435465768798a9bacbdcedfe0ffedcba98765432100123456789abcdefcafebabedeadbeef0badc0ffee123456',
};

export const FIELD_VECTOR = {
  encString:
    '2.q1vT7cBqU9RjFUCj5KxSfw==|Njj6Rz3WuZoxIP6/zklx8w==|/1UdG6Q68nXxuAFWjRiAk2ZZwpFpcZ+x1V+9d4baXAs=',
  plaintext: 'Hello, Vault!',
};

export const TAMPERED_FIELD_ENCSTRING =
  '2.q1vT7cBqU9RjFUCj5KxSfw==|Njj6Rz3WuZoxIP6/zklx8w==|/1UdG6Q68nXxuAFWjRiAk2ZZwpFpcZ+x1V+9d4baXAo=';
```

- [ ] **Step 2: 写失败测试 `kdf.test.ts`**

```ts
import { describe, it, expect } from 'vitest';
import { deriveMasterKey, deriveMasterPasswordHash, stretchMasterKey } from './kdf.js';
import { symmetricKeyFromBytes } from './keys.js';
import { bytesToHex, hexToBytes } from './encoding.js';
import { KDF_VECTOR, STRETCH_VECTOR } from '../../../test/vectors.js';

describe('kdf', () => {
  it('derives the master key from password + email salt', async () => {
    const mk = await deriveMasterKey(KDF_VECTOR.password, KDF_VECTOR.email, KDF_VECTOR.iterations);
    expect(bytesToHex(mk)).toBe(KDF_VECTOR.masterKeyHex);
  });

  it('uppercase email yields the same master key (salt is lowercased)', async () => {
    const mk = await deriveMasterKey(KDF_VECTOR.password, 'USER@EXAMPLE.COM', KDF_VECTOR.iterations);
    expect(bytesToHex(mk)).toBe(KDF_VECTOR.masterKeyHex);
  });

  it('derives the master password hash (base64, salt=password, one iteration)', async () => {
    const mk = hexToBytes(KDF_VECTOR.masterKeyHex);
    expect(await deriveMasterPasswordHash(mk, KDF_VECTOR.password)).toBe(KDF_VECTOR.masterPasswordHashB64);
  });

  it('stretches the master key via HKDF-Expand into enc+mac halves', async () => {
    const stretched = await stretchMasterKey(hexToBytes(KDF_VECTOR.masterKeyHex));
    expect(bytesToHex(stretched.encKey)).toBe(STRETCH_VECTOR.encKeyHex);
    expect(bytesToHex(stretched.macKey)).toBe(STRETCH_VECTOR.macKeyHex);
  });

  it('symmetricKeyFromBytes splits 64 bytes into 32/32', () => {
    const sk = symmetricKeyFromBytes(hexToBytes('aa'.repeat(32) + 'bb'.repeat(32)));
    expect(bytesToHex(sk.encKey)).toBe('aa'.repeat(32));
    expect(bytesToHex(sk.macKey)).toBe('bb'.repeat(32));
    expect(() => symmetricKeyFromBytes(hexToBytes('aa'.repeat(32)))).toThrow('symmetric key must be 64 bytes');
  });
});
```

- [ ] **Step 3: 运行测试，确认失败**

Run: `npm.cmd test -- kdf`
Expected: FAIL（模块未实现）。

- [ ] **Step 4: 实现 `keys.ts`**

```ts
export type SymmetricKey = { encKey: Uint8Array; macKey: Uint8Array };

export function symmetricKeyFromBytes(bytes: Uint8Array): SymmetricKey {
  if (bytes.length !== 64) {
    throw new Error(`symmetric key must be 64 bytes, got ${bytes.length}`);
  }
  return { encKey: bytes.slice(0, 32), macKey: bytes.slice(32, 64) };
}
```

- [ ] **Step 5: 实现 `kdf.ts`**

```ts
import { pbkdf2Sha256, hkdfExpandSha256 } from './primitives.js';
import { utf8ToBytes, bytesToBase64 } from './encoding.js';
import type { SymmetricKey } from './keys.js';

export async function deriveMasterKey(
  password: string,
  email: string,
  iterations: number,
): Promise<Uint8Array> {
  const salt = utf8ToBytes(email.trim().toLowerCase());
  return pbkdf2Sha256(utf8ToBytes(password), salt, iterations, 32);
}

export async function deriveMasterPasswordHash(
  masterKey: Uint8Array,
  password: string,
): Promise<string> {
  const hash = await pbkdf2Sha256(masterKey, utf8ToBytes(password), 1, 32);
  return bytesToBase64(hash);
}

export async function stretchMasterKey(masterKey: Uint8Array): Promise<SymmetricKey> {
  const encKey = await hkdfExpandSha256(masterKey, 'enc', 32);
  const macKey = await hkdfExpandSha256(masterKey, 'mac', 32);
  return { encKey, macKey };
}
```

- [ ] **Step 6: 运行测试，确认通过**

Run: `npm.cmd test -- kdf`
Expected: PASS（5 tests）。

- [ ] **Step 7: 提交**

```bash
git add src/core/crypto/keys.ts src/core/crypto/kdf.ts test/vectors.ts src/core/crypto/kdf.test.ts
git commit -m "feat(crypto): 密钥派生（MasterKey/MPH/stretch）+ 真实测试向量

Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
```

---

### Task 6: EncString 解析与解密 `encstring.ts`

**Files:**
- Create: `src/core/crypto/encstring.ts`
- Test: `src/core/crypto/encstring.test.ts`

**Interfaces:**
- Consumes: `hmacSha256`、`aesCbc256Decrypt`、`base64ToBytes`、`bytesToUtf8`、`constantTimeEqual`、`SymmetricKey`
- Produces:
  - `interface ParsedEncString { encType: number; iv: Uint8Array; ct: Uint8Array; mac: Uint8Array }`
  - `parseEncString(value: string): ParsedEncString`
  - `class EncStringMacError extends Error`
  - `class UnsupportedEncTypeError extends Error`
  - `decryptToBytes(value: string, key: SymmetricKey): Promise<Uint8Array>`
  - `decryptToText(value: string, key: SymmetricKey): Promise<string>`

- [ ] **Step 1: 写失败测试 `encstring.test.ts`**

```ts
import { describe, it, expect } from 'vitest';
import {
  parseEncString, decryptToBytes, decryptToText,
  EncStringMacError, UnsupportedEncTypeError,
} from './encstring.js';
import { symmetricKeyFromBytes } from './keys.js';
import { hexToBytes, bytesToHex } from './encoding.js';
import { USER_KEY_VECTOR, FIELD_VECTOR, TAMPERED_FIELD_ENCSTRING, STRETCH_VECTOR } from '../../../test/vectors.js';

const userKey = symmetricKeyFromBytes(hexToBytes(USER_KEY_VECTOR.userKeyHex));

describe('encstring', () => {
  it('parses an encType=2 string into iv|ct|mac', () => {
    const p = parseEncString(FIELD_VECTOR.encString);
    expect(p.encType).toBe(2);
    expect(p.iv.length).toBe(16);
    expect(p.mac.length).toBe(32);
    expect(p.ct.length).toBeGreaterThan(0);
  });

  it('rejects unsupported encType', () => {
    expect(() => parseEncString('4.aGVsbG8=')).toThrow(UnsupportedEncTypeError);
  });

  it('decrypts a field to text', async () => {
    expect(await decryptToText(FIELD_VECTOR.encString, userKey)).toBe(FIELD_VECTOR.plaintext);
  });

  it('decrypts the wrapped UserKey to its 64 raw bytes (via stretched key)', async () => {
    const stretched = {
      encKey: hexToBytes(STRETCH_VECTOR.encKeyHex),
      macKey: hexToBytes(STRETCH_VECTOR.macKeyHex),
    };
    const raw = await decryptToBytes(USER_KEY_VECTOR.akey, stretched);
    expect(bytesToHex(raw)).toBe(USER_KEY_VECTOR.userKeyHex);
  });

  it('throws EncStringMacError when the mac is tampered', async () => {
    await expect(decryptToText(TAMPERED_FIELD_ENCSTRING, userKey)).rejects.toBeInstanceOf(EncStringMacError);
  });
});
```

- [ ] **Step 2: 运行测试，确认失败**

Run: `npm.cmd test -- encstring`
Expected: FAIL（模块未实现）。

- [ ] **Step 3: 实现 `encstring.ts`**

```ts
import { hmacSha256, aesCbc256Decrypt } from './primitives.js';
import { base64ToBytes, bytesToUtf8, constantTimeEqual } from './encoding.js';
import type { SymmetricKey } from './keys.js';

export interface ParsedEncString {
  encType: number;
  iv: Uint8Array;
  ct: Uint8Array;
  mac: Uint8Array;
}

export class UnsupportedEncTypeError extends Error {}
export class EncStringMacError extends Error {}

export function parseEncString(value: string): ParsedEncString {
  const dot = value.indexOf('.');
  if (dot < 0) throw new UnsupportedEncTypeError('missing encType prefix');
  const encType = Number(value.slice(0, dot));
  const body = value.slice(dot + 1);
  if (encType !== 2) throw new UnsupportedEncTypeError(`unsupported encType ${encType}`);
  const parts = body.split('|');
  if (parts.length !== 3) throw new UnsupportedEncTypeError('encType=2 requires iv|ct|mac');
  return {
    encType,
    iv: base64ToBytes(parts[0]!),
    ct: base64ToBytes(parts[1]!),
    mac: base64ToBytes(parts[2]!),
  };
}

export async function decryptToBytes(value: string, key: SymmetricKey): Promise<Uint8Array> {
  const { iv, ct, mac } = parseEncString(value);
  const macData = new Uint8Array(iv.length + ct.length);
  macData.set(iv, 0);
  macData.set(ct, iv.length);
  const expected = await hmacSha256(key.macKey, macData);
  if (!constantTimeEqual(expected, mac)) throw new EncStringMacError('MAC verification failed');
  return aesCbc256Decrypt(key.encKey, iv, ct);
}

export async function decryptToText(value: string, key: SymmetricKey): Promise<string> {
  return bytesToUtf8(await decryptToBytes(value, key));
}
```

- [ ] **Step 4: 运行测试，确认通过**

Run: `npm.cmd test -- encstring`
Expected: PASS（5 tests）。

- [ ] **Step 5: 提交**

```bash
git add src/core/crypto/encstring.ts src/core/crypto/encstring.test.ts
git commit -m "feat(crypto): EncString 解析与解密（Encrypt-then-MAC 验证）

Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
```

---

### Task 7: 对称密钥解包 `keys.ts`（unwrap）

**Files:**
- Modify: `src/core/crypto/keys.ts`
- Test: `src/core/crypto/keys.test.ts`

**Interfaces:**
- Consumes: `decryptToBytes`
- Produces:
  - `unwrapSymmetricKey(protectedKey: string, wrappingKey: SymmetricKey): Promise<SymmetricKey>`

- [ ] **Step 1: 写失败测试 `keys.test.ts`**

```ts
import { describe, it, expect } from 'vitest';
import { unwrapSymmetricKey, symmetricKeyFromBytes } from './keys.js';
import { hexToBytes, bytesToHex } from './encoding.js';
import { USER_KEY_VECTOR, STRETCH_VECTOR } from '../../../test/vectors.js';

describe('keys.unwrapSymmetricKey', () => {
  it('unwraps the protected UserKey using the stretched master key', async () => {
    const stretched = { encKey: hexToBytes(STRETCH_VECTOR.encKeyHex), macKey: hexToBytes(STRETCH_VECTOR.macKeyHex) };
    const userKey = await unwrapSymmetricKey(USER_KEY_VECTOR.akey, stretched);
    const expected = symmetricKeyFromBytes(hexToBytes(USER_KEY_VECTOR.userKeyHex));
    expect(bytesToHex(userKey.encKey)).toBe(bytesToHex(expected.encKey));
    expect(bytesToHex(userKey.macKey)).toBe(bytesToHex(expected.macKey));
  });
});
```

- [ ] **Step 2: 运行测试，确认失败**

Run: `npm.cmd test -- keys`
Expected: FAIL（`unwrapSymmetricKey` 未定义）。

- [ ] **Step 3: 在 `keys.ts` 追加实现**

```ts
import { decryptToBytes } from './encstring.js';

export type SymmetricKey = { encKey: Uint8Array; macKey: Uint8Array };

export function symmetricKeyFromBytes(bytes: Uint8Array): SymmetricKey {
  if (bytes.length !== 64) {
    throw new Error(`symmetric key must be 64 bytes, got ${bytes.length}`);
  }
  return { encKey: bytes.slice(0, 32), macKey: bytes.slice(32, 64) };
}

export async function unwrapSymmetricKey(
  protectedKey: string,
  wrappingKey: SymmetricKey,
): Promise<SymmetricKey> {
  return symmetricKeyFromBytes(await decryptToBytes(protectedKey, wrappingKey));
}
```

- [ ] **Step 4: 运行测试，确认通过**

Run: `npm.cmd test -- keys`
Expected: PASS。

- [ ] **Step 5: 提交**

```bash
git add src/core/crypto/keys.ts src/core/crypto/keys.test.ts
git commit -m "feat(crypto): 对称密钥解包 unwrapSymmetricKey（UserKey/item key）

Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
```

---

### Task 8: 存储抽象 `platform/store.ts`

**Files:**
- Create: `src/platform/store.ts`
- Test: `src/platform/store.test.ts`

**Interfaces:**
- Produces:
  - `interface KeyValueStore { get<T>(key: string): Promise<T | undefined>; set(key: string, value: unknown): Promise<void>; remove(key: string): Promise<void>; clear(): Promise<void>; }`
  - `createMemoryStore(): KeyValueStore`
  - `createBrowserStore(area: 'local' | 'session'): KeyValueStore`

- [ ] **Step 1: 写失败测试 `store.test.ts`（仅测 memory 实现）**

```ts
import { describe, it, expect } from 'vitest';
import { createMemoryStore } from './store.js';

describe('memory store', () => {
  it('round-trips values and isolates keys', async () => {
    const s = createMemoryStore();
    expect(await s.get('missing')).toBeUndefined();
    await s.set('a', { n: 1 });
    expect(await s.get<{ n: number }>('a')).toEqual({ n: 1 });
    await s.remove('a');
    expect(await s.get('a')).toBeUndefined();
  });

  it('clear empties the store', async () => {
    const s = createMemoryStore();
    await s.set('a', 1);
    await s.set('b', 2);
    await s.clear();
    expect(await s.get('a')).toBeUndefined();
    expect(await s.get('b')).toBeUndefined();
  });

  it('deep-clones on write so later mutation does not leak in', async () => {
    const s = createMemoryStore();
    const obj = { n: 1 };
    await s.set('a', obj);
    obj.n = 99;
    expect(await s.get<{ n: number }>('a')).toEqual({ n: 1 });
  });
});
```

- [ ] **Step 2: 运行测试，确认失败**

Run: `npm.cmd test -- store`
Expected: FAIL（模块未实现）。

- [ ] **Step 3: 实现 `store.ts`**

```ts
import browser from 'webextension-polyfill';

export interface KeyValueStore {
  get<T>(key: string): Promise<T | undefined>;
  set(key: string, value: unknown): Promise<void>;
  remove(key: string): Promise<void>;
  clear(): Promise<void>;
}

export function createMemoryStore(): KeyValueStore {
  const map = new Map<string, string>();
  return {
    async get<T>(key: string): Promise<T | undefined> {
      const raw = map.get(key);
      return raw === undefined ? undefined : (JSON.parse(raw) as T);
    },
    async set(key, value) {
      map.set(key, JSON.stringify(value));
    },
    async remove(key) {
      map.delete(key);
    },
    async clear() {
      map.clear();
    },
  };
}

export function createBrowserStore(area: 'local' | 'session'): KeyValueStore {
  const storage = browser.storage[area];
  return {
    async get<T>(key: string): Promise<T | undefined> {
      const result = await storage.get(key);
      return result[key] as T | undefined;
    },
    async set(key, value) {
      await storage.set({ [key]: value });
    },
    async remove(key) {
      await storage.remove(key);
    },
    async clear() {
      await storage.clear();
    },
  };
}
```

- [ ] **Step 4: 运行测试，确认通过**

Run: `npm.cmd test -- store`
Expected: PASS（3 tests）。

- [ ] **Step 5: typecheck + 提交**

```bash
npm.cmd run typecheck
git add src/platform/store.ts src/platform/store.test.ts
git commit -m "feat(platform): KeyValueStore 抽象（memory + browser storage）

Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
```

**M1 完成检查**：`npm.cmd test` 全绿；`npm.cmd run build` 产出可加载 `dist/`；`npm.cmd run typecheck`、`npm.cmd run lint` 无错。加密内核已用 KAT + 真实向量验证。

---

# 阶段 M2：Vaultwarden API + 登录/会话/解锁

产出：可对 Vaultwarden 执行 prelogin、password grant、2FA 分支解析、token refresh、sync 调用；可把账号从 loggedOut -> unlocked/locked 状态切换，并按 MV3 lifecycle 安全托管 UserKey。

---

### Task 9: API 契约类型 `core/api/types.ts`

**Files:**
- Create: `src/core/api/types.ts`
- Test: `src/core/api/types.test.ts`

**Interfaces:**
- Produces:
  - `type KdfType = 0 | 1`
  - `interface PreloginResponse { kdf: KdfType; kdfIterations: number; kdfMemory?: number; kdfParallelism?: number }`
  - `interface LoginSuccessResponse { access_token: string; expires_in: number; refresh_token: string; token_type: string; Key: string; PrivateKey?: string; Kdf?: KdfType; KdfIterations?: number; TwoFactorToken?: string }`
  - `interface TwoFactorRequiredResponse { error: 'invalid_grant'; error_description: string; TwoFactorProviders: Record<string, unknown>; TwoFactorProviders2?: Record<string, unknown>; TwoFactorToken?: string }`
  - `interface SyncResponse { profile: SyncProfile; ciphers: CipherResponse[]; folders?: FolderResponse[] }`
  - `CipherResponse` covering personal Login ciphers needed by M3.

- [ ] **Step 1: 写失败测试 `types.test.ts`（大小写契约保护）**

```ts
import { describe, it, expect } from 'vitest';
import type { LoginSuccessResponse, PreloginResponse, SyncResponse, CipherResponse } from './types.js';

describe('api types casing', () => {
  it('keeps prelogin camelCase and login PascalCase distinct', () => {
    const prelogin: PreloginResponse = { kdf: 0, kdfIterations: 600000 };
    const login: LoginSuccessResponse = {
      access_token: 'a',
      expires_in: 3600,
      refresh_token: 'r',
      token_type: 'Bearer',
      Key: '2.iv|ct|mac',
      Kdf: 0,
      KdfIterations: 600000,
    };
    expect(prelogin.kdfIterations).toBe(600000);
    expect(login.Key).toBe('2.iv|ct|mac');
  });

  it('models camelCase sync ciphers', () => {
    const cipher: CipherResponse = {
      id: 'cipher-1',
      type: 1,
      name: '2.n|c|m',
      favorite: false,
      organizationId: null,
      login: { username: '2.u|c|m', password: '2.p|c|m', uris: [{ uri: '2.uri|c|m' }] },
    };
    const sync: SyncResponse = { profile: { id: 'user-1', email: 'user@example.com' }, ciphers: [cipher] };
    expect(sync.ciphers[0]?.login?.uris?.[0]?.uri).toBe('2.uri|c|m');
  });
});
```

- [ ] **Step 2: 运行测试，确认失败**

Run: `npm.cmd test -- types`
Expected: FAIL（模块未实现）。

- [ ] **Step 3: 实现 `types.ts`**

```ts
export type KdfType = 0 | 1; // 0 PBKDF2, 1 Argon2id (read-only unsupported in M1-M3)

export interface PreloginResponse {
  kdf: KdfType;
  kdfIterations: number;
  kdfMemory?: number;
  kdfParallelism?: number;
}

export interface LoginSuccessResponse {
  access_token: string;
  expires_in: number;
  refresh_token: string;
  token_type: string;
  Key: string;
  PrivateKey?: string;
  Kdf?: KdfType;
  KdfIterations?: number;
  TwoFactorToken?: string;
}

export interface TwoFactorRequiredResponse {
  error: 'invalid_grant';
  error_description: string;
  TwoFactorProviders: Record<string, unknown>;
  TwoFactorProviders2?: Record<string, unknown>;
  TwoFactorToken?: string;
}

export interface RefreshTokenResponse {
  access_token: string;
  expires_in: number;
  refresh_token: string;
  token_type: string;
}

export interface SyncProfile {
  id: string;
  email: string;
  name?: string | null;
}

export interface LoginUriResponse {
  uri?: string | null;
  match?: number | null;
}

export interface LoginCipherData {
  username?: string | null;
  password?: string | null;
  totp?: string | null;
  uris?: LoginUriResponse[] | null;
}

export interface CipherResponse {
  id: string;
  type: 1 | 2 | 3 | 4 | 5;
  name?: string | null;
  notes?: string | null;
  favorite?: boolean;
  organizationId?: string | null;
  folderId?: string | null;
  key?: string | null;
  login?: LoginCipherData | null;
  revisionDate?: string | null;
}

export interface FolderResponse {
  id: string;
  name?: string | null;
}

export interface SyncResponse {
  profile: SyncProfile;
  ciphers: CipherResponse[];
  folders?: FolderResponse[];
}
```

- [ ] **Step 4: 运行测试，确认通过**

Run: `npm.cmd test -- types`
Expected: PASS（2 tests）。

- [ ] **Step 5: 提交**

```bash
git add src/core/api/types.ts src/core/api/types.test.ts
git commit -m "feat(api): Vaultwarden API 契约类型（保留大小写）

Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
```

---

### Task 10: ApiClient prelogin + 设备 ID

**Files:**
- Create: `src/core/api/client.ts`
- Test: `src/core/api/client.test.ts`

**Interfaces:**
- Consumes: `KeyValueStore`、`PreloginResponse`
- Produces:
  - `type FetchFn = typeof fetch`
  - `interface ApiClientDeps { serverUrlProvider(): Promise<string>; fetchFn?: FetchFn; localStore: KeyValueStore }`
  - `class ApiClient { prelogin(email: string): Promise<PreloginResponse>; getDeviceIdentifier(): Promise<string> }`

- [ ] **Step 1: 写失败测试 `client.test.ts`（prelogin 请求格式 + device id 稳定）**

```ts
import { describe, it, expect, vi } from 'vitest';
import { ApiClient } from './client.js';
import { createMemoryStore } from '../../platform/store.js';

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
}

describe('ApiClient prelogin', () => {
  it('POSTs /identity/accounts/prelogin with lowercase email in JSON body', async () => {
    const fetchFn = vi.fn(async () => jsonResponse({ kdf: 0, kdfIterations: 600000 }));
    const api = new ApiClient({
      serverUrlProvider: async () => 'https://vw.example.com/',
      fetchFn,
      localStore: createMemoryStore(),
    });
    const res = await api.prelogin('USER@EXAMPLE.COM');
    expect(res).toEqual({ kdf: 0, kdfIterations: 600000 });
    expect(fetchFn).toHaveBeenCalledWith('https://vw.example.com/identity/accounts/prelogin', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email: 'user@example.com' }),
    });
  });

  it('stores and reuses a stable device identifier', async () => {
    const store = createMemoryStore();
    const api = new ApiClient({ serverUrlProvider: async () => 'https://vw.example.com', localStore: store });
    const first = await api.getDeviceIdentifier();
    const second = await api.getDeviceIdentifier();
    expect(first).toMatch(/[0-9a-f-]{36}/);
    expect(second).toBe(first);
  });
});
```

- [ ] **Step 2: 运行测试，确认失败**

Run: `npm.cmd test -- client`
Expected: FAIL（模块未实现）。

- [ ] **Step 3: 实现 `client.ts` 基础方法**

```ts
import type { KeyValueStore } from '../../platform/store.js';
import type { PreloginResponse } from './types.js';

export type FetchFn = typeof fetch;

export interface ApiClientDeps {
  serverUrlProvider(): Promise<string>;
  fetchFn?: FetchFn;
  localStore: KeyValueStore;
}

const DEVICE_ID_KEY = 'deviceIdentifier';

export class ApiClient {
  private readonly fetchFn: FetchFn;

  constructor(private readonly deps: ApiClientDeps) {
    this.fetchFn = deps.fetchFn ?? globalThis.fetch.bind(globalThis);
  }

  async prelogin(email: string): Promise<PreloginResponse> {
    return this.jsonRequest<PreloginResponse>('/identity/accounts/prelogin', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email: email.trim().toLowerCase() }),
    });
  }

  async getDeviceIdentifier(): Promise<string> {
    const existing = await this.deps.localStore.get<string>(DEVICE_ID_KEY);
    if (existing) return existing;
    const id = crypto.randomUUID();
    await this.deps.localStore.set(DEVICE_ID_KEY, id);
    return id;
  }

  private async jsonRequest<T>(path: string, init: RequestInit): Promise<T> {
    const response = await this.fetchFn(this.url(path), init);
    const body = await response.json();
    if (!response.ok) throw new ApiHttpError(response.status, body);
    return body as T;
  }

  private url(path: string): string {
    return new URL(path, this.serverUrl()).toString();
  }

  private serverUrl(): string {
    throw new Error('serverUrl must be loaded asynchronously via request helper');
  }
}

export class ApiHttpError extends Error {
  constructor(public readonly status: number, public readonly body: unknown) {
    super(`Vaultwarden API error ${status}`);
  }
}
```

- [ ] **Step 4: 修正异步 URL helper（让测试通过）**

把 `jsonRequest` 和 `url/serverUrl` 替换为：

```ts
  private async jsonRequest<T>(path: string, init: RequestInit): Promise<T> {
    const response = await this.fetchFn(await this.url(path), init);
    const body = await response.json();
    if (!response.ok) throw new ApiHttpError(response.status, body);
    return body as T;
  }

  private async url(path: string): Promise<string> {
    const base = await this.deps.serverUrlProvider();
    const normalized = base.endsWith('/') ? base : `${base}/`;
    return new URL(path.replace(/^\//, ''), normalized).toString();
  }
```

- [ ] **Step 5: 运行测试，确认通过**

Run: `npm.cmd test -- client`
Expected: PASS（2 tests）。

- [ ] **Step 6: 提交**

```bash
git add src/core/api/client.ts src/core/api/client.test.ts
git commit -m "feat(api): prelogin 与稳定设备标识

Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
```

---

### Task 11: ApiClient password grant + 2FA 解析

**Files:**
- Modify: `src/core/api/client.ts`
- Modify: `src/core/api/client.test.ts`

**Interfaces:**
- Consumes: `LoginSuccessResponse`、`TwoFactorRequiredResponse`
- Produces:
  - `type PasswordLoginResult = { kind: 'success'; data: LoginSuccessResponse } | { kind: 'twoFactor'; providers: number[]; token?: string }`
  - `passwordLogin(input: PasswordLoginInput): Promise<PasswordLoginResult>`
  - `sendEmailLogin(input: { email: string; twoFactorToken: string }): Promise<void>`

- [ ] **Step 1: 追加失败测试（form-urlencoded 固定参数 + 2FA 分支）**

追加到 `client.test.ts`：

```ts
describe('ApiClient password grant', () => {
  it('POSTs connect/token as form-urlencoded with required browser parameters', async () => {
    const store = createMemoryStore();
    await store.set('deviceIdentifier', 'device-123');
    const fetchFn = vi.fn(async () => jsonResponse({
      access_token: 'access',
      expires_in: 3600,
      refresh_token: 'refresh',
      token_type: 'Bearer',
      Key: '2.iv|ct|mac',
      Kdf: 0,
      KdfIterations: 600000,
    }));
    const api = new ApiClient({ serverUrlProvider: async () => 'https://vw.example.com', fetchFn, localStore: store });
    const result = await api.passwordLogin({ email: 'user@example.com', masterPasswordHash: 'mph' });
    expect(result.kind).toBe('success');
    const [, init] = fetchFn.mock.calls[0]!;
    expect(init.headers).toEqual({ 'content-type': 'application/x-www-form-urlencoded' });
    const form = new URLSearchParams(init.body as string);
    expect(form.get('grant_type')).toBe('password');
    expect(form.get('username')).toBe('user@example.com');
    expect(form.get('password')).toBe('mph');
    expect(form.get('scope')).toBe('api offline_access');
    expect(form.get('client_id')).toBe('browser');
    expect(form.get('device_type')).toBe('2');
    expect(form.get('device_identifier')).toBe('device-123');
    expect(form.get('device_name')).toBe('chrome');
  });

  it('parses 2FA-required invalid_grant into supported provider ids', async () => {
    const fetchFn = vi.fn(async () => jsonResponse({
      error: 'invalid_grant',
      error_description: 'Two factor required',
      TwoFactorProviders: { '0': {}, '1': {}, '7': {} },
      TwoFactorToken: 'tf-token',
    }, 400));
    const api = new ApiClient({ serverUrlProvider: async () => 'https://vw.example.com', fetchFn, localStore: createMemoryStore() });
    const result = await api.passwordLogin({ email: 'user@example.com', masterPasswordHash: 'mph' });
    expect(result).toEqual({ kind: 'twoFactor', providers: [0, 1, 7], token: 'tf-token' });
  });
});
```

- [ ] **Step 2: 运行测试，确认失败**

Run: `npm.cmd test -- client`
Expected: FAIL（`passwordLogin` 未定义）。

- [ ] **Step 3: 在 `client.ts` 添加类型**

```ts
import type {
  LoginSuccessResponse,
  PreloginResponse,
  RefreshTokenResponse,
  SyncResponse,
  TwoFactorRequiredResponse,
} from './types.js';

export interface PasswordLoginInput {
  email: string;
  masterPasswordHash: string;
  twoFactorProvider?: number;
  twoFactorToken?: string;
  remember?: boolean;
}

export type PasswordLoginResult =
  | { kind: 'success'; data: LoginSuccessResponse }
  | { kind: 'twoFactor'; providers: number[]; token?: string };
```

- [ ] **Step 4: 在 `ApiClient` 类中追加 `passwordLogin`、`sendEmailLogin` 与 `formRequest`**

```ts
  async passwordLogin(input: PasswordLoginInput): Promise<PasswordLoginResult> {
    const form = new URLSearchParams();
    form.set('grant_type', 'password');
    form.set('username', input.email.trim().toLowerCase());
    form.set('password', input.masterPasswordHash);
    form.set('scope', 'api offline_access');
    form.set('client_id', 'browser');
    form.set('device_type', '2');
    form.set('device_identifier', await this.getDeviceIdentifier());
    form.set('device_name', 'chrome');
    if (input.twoFactorProvider !== undefined && input.twoFactorToken) {
      form.set('two_factor_provider', String(input.twoFactorProvider));
      form.set('two_factor_token', input.twoFactorToken);
      form.set('two_factor_remember', input.remember ? '1' : '0');
    }

    const response = await this.fetchFn(await this.url('/identity/connect/token'), {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: form.toString(),
    });
    const body = await response.json();
    if (response.ok) return { kind: 'success', data: body as LoginSuccessResponse };

    if (response.status === 400 && isTwoFactorRequired(body)) {
      return {
        kind: 'twoFactor',
        providers: Object.keys(body.TwoFactorProviders).map(Number).sort((a, b) => a - b),
        token: body.TwoFactorToken,
      };
    }
    throw new ApiHttpError(response.status, body);
  }

  async sendEmailLogin(input: { email: string; twoFactorToken: string }): Promise<void> {
    await this.jsonRequest('/api/two-factor/send-email-login', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email: input.email.trim().toLowerCase(), token: input.twoFactorToken }),
    });
  }
```

在文件底部追加：

```ts
function isTwoFactorRequired(body: unknown): body is TwoFactorRequiredResponse {
  if (typeof body !== 'object' || body === null) return false;
  const candidate = body as Partial<TwoFactorRequiredResponse>;
  return candidate.error === 'invalid_grant'
    && typeof candidate.error_description === 'string'
    && candidate.error_description.toLowerCase().includes('two factor')
    && typeof candidate.TwoFactorProviders === 'object'
    && candidate.TwoFactorProviders !== null;
}
```

- [ ] **Step 5: 运行测试，确认通过**

Run: `npm.cmd test -- client`
Expected: PASS（4 tests）。

- [ ] **Step 6: 提交**

```bash
git add src/core/api/client.ts src/core/api/client.test.ts
git commit -m "feat(api): password grant 与 2FA-required 解析

Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
```

---

### Task 12: ApiClient refresh token + sync

**Files:**
- Modify: `src/core/api/client.ts`
- Modify: `src/core/api/client.test.ts`

**Interfaces:**
- Produces:
  - `refresh(refreshToken: string): Promise<RefreshTokenResponse>`
  - `sync(accessToken: string): Promise<SyncResponse>`

- [ ] **Step 1: 追加失败测试（refresh form + sync Bearer）**

追加到 `client.test.ts`：

```ts
describe('ApiClient refresh and sync', () => {
  it('refreshes using refresh_token grant', async () => {
    const store = createMemoryStore();
    await store.set('deviceIdentifier', 'device-123');
    const fetchFn = vi.fn(async () => jsonResponse({
      access_token: 'new-access',
      expires_in: 3600,
      refresh_token: 'new-refresh',
      token_type: 'Bearer',
    }));
    const api = new ApiClient({ serverUrlProvider: async () => 'https://vw.example.com', fetchFn, localStore: store });
    await expect(api.refresh('old-refresh')).resolves.toMatchObject({ access_token: 'new-access' });
    const [, init] = fetchFn.mock.calls[0]!;
    const form = new URLSearchParams(init.body as string);
    expect(form.get('grant_type')).toBe('refresh_token');
    expect(form.get('refresh_token')).toBe('old-refresh');
    expect(form.get('client_id')).toBe('browser');
  });

  it('syncs with Authorization Bearer token', async () => {
    const fetchFn = vi.fn(async () => jsonResponse({ profile: { id: 'u', email: 'u@example.com' }, ciphers: [] }));
    const api = new ApiClient({ serverUrlProvider: async () => 'https://vw.example.com', fetchFn, localStore: createMemoryStore() });
    await expect(api.sync('access')).resolves.toEqual({ profile: { id: 'u', email: 'u@example.com' }, ciphers: [] });
    expect(fetchFn).toHaveBeenCalledWith('https://vw.example.com/api/sync', {
      method: 'GET',
      headers: { authorization: 'Bearer access' },
    });
  });
});
```

- [ ] **Step 2: 运行测试，确认失败**

Run: `npm.cmd test -- client`
Expected: FAIL（方法未定义）。

- [ ] **Step 3: 在 `ApiClient` 类中实现 `refresh` 与 `sync`**

```ts
  async refresh(refreshToken: string): Promise<RefreshTokenResponse> {
    const form = new URLSearchParams();
    form.set('grant_type', 'refresh_token');
    form.set('refresh_token', refreshToken);
    form.set('client_id', 'browser');
    form.set('device_type', '2');
    form.set('device_identifier', await this.getDeviceIdentifier());
    form.set('device_name', 'chrome');
    const response = await this.fetchFn(await this.url('/identity/connect/token'), {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: form.toString(),
    });
    const body = await response.json();
    if (!response.ok) throw new ApiHttpError(response.status, body);
    return body as RefreshTokenResponse;
  }

  async sync(accessToken: string): Promise<SyncResponse> {
    return this.jsonRequest<SyncResponse>('/api/sync', {
      method: 'GET',
      headers: { authorization: `Bearer ${accessToken}` },
    });
  }
```

- [ ] **Step 4: 运行测试，确认通过**

Run: `npm.cmd test -- client`
Expected: PASS（6 tests）。

- [ ] **Step 5: 提交**

```bash
git add src/core/api/client.ts src/core/api/client.test.ts
git commit -m "feat(api): refresh token 与 sync 调用

Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
```

---

### Task 13: SessionManager 状态机与密钥托管

**Files:**
- Create: `src/core/session/session-manager.ts`
- Test: `src/core/session/session-manager.test.ts`

**Interfaces:**
- Consumes: `KeyValueStore`、`SymmetricKey`、encoding base64 helpers
- Produces:
  - `type SessionState = 'loggedOut' | 'locked' | 'unlocked'`
  - `interface PersistedAuth { email: string; accessToken: string; refreshToken: string; expiresAt: number; protectedKey: string; kdf: 0; kdfIterations: number; privateKey?: string }`
  - `class SessionManager` with `getState()`, `saveUnlocked(...)`, `lock()`, `logout()`, `loadUserKey()`, `saveTokens(...)`, `getPersistedAuth()`

- [ ] **Step 1: 写失败测试 `session-manager.test.ts`**

```ts
import { describe, it, expect } from 'vitest';
import { SessionManager } from './session-manager.js';
import { createMemoryStore } from '../../platform/store.js';
import { symmetricKeyFromBytes } from '../crypto/keys.js';
import { hexToBytes, bytesToHex } from '../crypto/encoding.js';
import { USER_KEY_VECTOR } from '../../../test/vectors.js';

const userKey = symmetricKeyFromBytes(hexToBytes(USER_KEY_VECTOR.userKeyHex));

describe('SessionManager', () => {
  it('starts loggedOut when no persisted auth exists', async () => {
    const sm = new SessionManager({ localStore: createMemoryStore(), sessionStore: createMemoryStore() });
    expect(await sm.getState()).toBe('loggedOut');
  });

  it('saveUnlocked persists tokens locally and userKey only in session storage', async () => {
    const local = createMemoryStore();
    const session = createMemoryStore();
    const sm = new SessionManager({ localStore: local, sessionStore: session });
    await sm.saveUnlocked({
      email: 'user@example.com',
      accessToken: 'access',
      refreshToken: 'refresh',
      expiresAt: 123,
      protectedKey: USER_KEY_VECTOR.akey,
      kdf: 0,
      kdfIterations: 600000,
      userKey,
    });
    expect(await sm.getState()).toBe('unlocked');
    expect((await local.get<Record<string, unknown>>('auth'))?.accessToken).toBe('access');
    expect(await local.get('userKey')).toBeUndefined();
    expect(bytesToHex((await sm.loadUserKey())!.encKey)).toBe(bytesToHex(userKey.encKey));
  });

  it('lock removes only session key and leaves persisted auth', async () => {
    const local = createMemoryStore();
    const session = createMemoryStore();
    const sm = new SessionManager({ localStore: local, sessionStore: session });
    await sm.saveUnlocked({
      email: 'user@example.com',
      accessToken: 'access',
      refreshToken: 'refresh',
      expiresAt: 123,
      protectedKey: USER_KEY_VECTOR.akey,
      kdf: 0,
      kdfIterations: 600000,
      userKey,
    });
    await sm.lock();
    expect(await sm.getState()).toBe('locked');
    expect(await sm.loadUserKey()).toBeUndefined();
    expect((await sm.getPersistedAuth())?.refreshToken).toBe('refresh');
  });

  it('logout removes both persisted auth and session key', async () => {
    const sm = new SessionManager({ localStore: createMemoryStore(), sessionStore: createMemoryStore() });
    await sm.saveUnlocked({
      email: 'user@example.com',
      accessToken: 'access',
      refreshToken: 'refresh',
      expiresAt: 123,
      protectedKey: USER_KEY_VECTOR.akey,
      kdf: 0,
      kdfIterations: 600000,
      userKey,
    });
    await sm.logout();
    expect(await sm.getState()).toBe('loggedOut');
  });
});
```

- [ ] **Step 2: 运行测试，确认失败**

Run: `npm.cmd test -- session-manager`
Expected: FAIL（模块未实现）。

- [ ] **Step 3: 实现 `session-manager.ts`**

```ts
import type { KeyValueStore } from '../../platform/store.js';
import type { SymmetricKey } from '../crypto/keys.js';
import { symmetricKeyFromBytes } from '../crypto/keys.js';
import { bytesToBase64, base64ToBytes } from '../crypto/encoding.js';

export type SessionState = 'loggedOut' | 'locked' | 'unlocked';

export interface PersistedAuth {
  email: string;
  accessToken: string;
  refreshToken: string;
  expiresAt: number;
  protectedKey: string;
  kdf: 0;
  kdfIterations: number;
  privateKey?: string;
}

export interface SaveUnlockedInput extends PersistedAuth {
  userKey: SymmetricKey;
}

export interface SessionManagerDeps {
  localStore: KeyValueStore;
  sessionStore: KeyValueStore;
}

const AUTH_KEY = 'auth';
const USER_KEY_KEY = 'userKey';

export class SessionManager {
  constructor(private readonly deps: SessionManagerDeps) {}

  async getState(): Promise<SessionState> {
    const auth = await this.getPersistedAuth();
    if (!auth) return 'loggedOut';
    const userKey = await this.loadUserKey();
    return userKey ? 'unlocked' : 'locked';
  }

  async saveUnlocked(input: SaveUnlockedInput): Promise<void> {
    const { userKey, ...auth } = input;
    await this.deps.localStore.set(AUTH_KEY, auth);
    await this.saveUserKey(userKey);
  }

  async saveTokens(tokens: { accessToken: string; refreshToken: string; expiresAt: number }): Promise<void> {
    const auth = await this.getPersistedAuth();
    if (!auth) throw new Error('cannot save tokens without persisted auth');
    await this.deps.localStore.set(AUTH_KEY, { ...auth, ...tokens });
  }

  async getPersistedAuth(): Promise<PersistedAuth | undefined> {
    return this.deps.localStore.get<PersistedAuth>(AUTH_KEY);
  }

  async loadUserKey(): Promise<SymmetricKey | undefined> {
    const stored = await this.deps.sessionStore.get<string>(USER_KEY_KEY);
    if (!stored) return undefined;
    return symmetricKeyFromBytes(base64ToBytes(stored));
  }

  async lock(): Promise<void> {
    await this.deps.sessionStore.remove(USER_KEY_KEY);
  }

  async logout(): Promise<void> {
    await this.deps.sessionStore.remove(USER_KEY_KEY);
    await this.deps.localStore.remove(AUTH_KEY);
  }

  private async saveUserKey(userKey: SymmetricKey): Promise<void> {
    const raw = new Uint8Array(64);
    raw.set(userKey.encKey, 0);
    raw.set(userKey.macKey, 32);
    await this.deps.sessionStore.set(USER_KEY_KEY, bytesToBase64(raw));
  }
}
```

- [ ] **Step 4: 运行测试，确认通过**

Run: `npm.cmd test -- session-manager`
Expected: PASS（4 tests）。

- [ ] **Step 5: 提交**

```bash
git add src/core/session/session-manager.ts src/core/session/session-manager.test.ts
git commit -m "feat(session): SessionManager 状态机与 session storage 密钥托管

Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
```

---

### Task 14: AuthService 登录/2FA/解锁编排

**Files:**
- Create: `src/core/session/auth-service.ts`
- Test: `src/core/session/auth-service.test.ts`

**Interfaces:**
- Consumes: `ApiClient`、`SessionManager`、`deriveMasterKey`、`deriveMasterPasswordHash`、`stretchMasterKey`、`unwrapSymmetricKey`
- Produces:
  - `login(input: { email: string; masterPassword: string }): Promise<AuthResult>`
  - `submitTwoFactor(input: { provider: 0 | 1; code: string; remember?: boolean }): Promise<AuthResult>`
  - `sendEmailCode(): Promise<void>`
  - `unlock(masterPassword: string): Promise<void>`
  - `getState(): Promise<SessionState>`
  - `lock(): Promise<void>`
  - `logout(): Promise<void>`

- [ ] **Step 1: 写失败测试 `auth-service.test.ts`（成功登录 + 2FA pending + unlock）**

```ts
import { describe, it, expect, vi } from 'vitest';
import { AuthService } from './auth-service.js';
import { SessionManager } from './session-manager.js';
import { createMemoryStore } from '../../platform/store.js';
import type { ApiClient } from '../api/client.js';
import { KDF_VECTOR, USER_KEY_VECTOR } from '../../../test/vectors.js';

function makeService(api: Partial<ApiClient>) {
  const sm = new SessionManager({ localStore: createMemoryStore(), sessionStore: createMemoryStore() });
  return { sm, auth: new AuthService({ api: api as ApiClient, session: sm, now: () => 1000 }) };
}

describe('AuthService', () => {
  it('logs in and stores unlocked session when password grant succeeds', async () => {
    const api = {
      prelogin: vi.fn(async () => ({ kdf: 0, kdfIterations: KDF_VECTOR.iterations })),
      passwordLogin: vi.fn(async () => ({
        kind: 'success',
        data: {
          access_token: 'access',
          expires_in: 3600,
          refresh_token: 'refresh',
          token_type: 'Bearer',
          Key: USER_KEY_VECTOR.akey,
          Kdf: 0,
          KdfIterations: KDF_VECTOR.iterations,
        },
      })),
    };
    const { auth, sm } = makeService(api);
    await expect(auth.login({ email: KDF_VECTOR.email, masterPassword: KDF_VECTOR.password }))
      .resolves.toEqual({ kind: 'unlocked' });
    expect(await sm.getState()).toBe('unlocked');
    expect(api.passwordLogin.mock.calls[0]![0].masterPasswordHash).toBe(KDF_VECTOR.masterPasswordHashB64);
  });

  it('keeps pending login in memory when 2FA is required', async () => {
    const api = {
      prelogin: vi.fn(async () => ({ kdf: 0, kdfIterations: KDF_VECTOR.iterations })),
      passwordLogin: vi.fn(async () => ({ kind: 'twoFactor', providers: [0, 1, 7], token: 'tf' })),
    };
    const { auth, sm } = makeService(api);
    await expect(auth.login({ email: KDF_VECTOR.email, masterPassword: KDF_VECTOR.password }))
      .resolves.toEqual({ kind: 'twoFactor', providers: [0, 1], token: 'tf' });
    expect(await sm.getState()).toBe('loggedOut');
  });

  it('unlock derives key from persisted auth without calling prelogin', async () => {
    const { auth, sm } = makeService({});
    await sm.saveUnlocked({
      email: KDF_VECTOR.email,
      accessToken: 'access',
      refreshToken: 'refresh',
      expiresAt: 1000,
      protectedKey: USER_KEY_VECTOR.akey,
      kdf: 0,
      kdfIterations: KDF_VECTOR.iterations,
      userKey: { encKey: new Uint8Array(32), macKey: new Uint8Array(32) },
    });
    await sm.lock();
    await expect(auth.unlock(KDF_VECTOR.password)).resolves.toBeUndefined();
    expect(await sm.getState()).toBe('unlocked');
  });
});
```

- [ ] **Step 2: 运行测试，确认失败**

Run: `npm.cmd test -- auth-service`
Expected: FAIL（模块未实现）。

- [ ] **Step 3: 实现 `auth-service.ts`**

```ts
import type { ApiClient, PasswordLoginResult } from '../api/client.js';
import { deriveMasterKey, deriveMasterPasswordHash, stretchMasterKey } from '../crypto/kdf.js';
import { unwrapSymmetricKey } from '../crypto/keys.js';
import type { SessionManager, SessionState } from './session-manager.js';

export type AuthResult =
  | { kind: 'unlocked' }
  | { kind: 'twoFactor'; providers: Array<0 | 1>; token?: string };

export interface AuthServiceDeps {
  api: ApiClient;
  session: SessionManager;
  now?: () => number;
}

interface PendingLogin {
  email: string;
  masterPasswordHash: string;
  stretchedMasterKey: Awaited<ReturnType<typeof stretchMasterKey>>;
  kdfIterations: number;
  twoFactorToken?: string;
}

export class AuthService {
  private pendingLogin?: PendingLogin;
  private readonly now: () => number;

  constructor(private readonly deps: AuthServiceDeps) {
    this.now = deps.now ?? (() => Date.now());
  }

  async login(input: { email: string; masterPassword: string }): Promise<AuthResult> {
    const email = input.email.trim().toLowerCase();
    const prelogin = await this.deps.api.prelogin(email);
    if (prelogin.kdf !== 0) throw new Error('Argon2id accounts are not supported in this MVP');
    const masterKey = await deriveMasterKey(input.masterPassword, email, prelogin.kdfIterations);
    const masterPasswordHash = await deriveMasterPasswordHash(masterKey, input.masterPassword);
    const stretchedMasterKey = await stretchMasterKey(masterKey);
    const result = await this.deps.api.passwordLogin({ email, masterPasswordHash });
    return this.finishPasswordLogin({
      result,
      pending: { email, masterPasswordHash, stretchedMasterKey, kdfIterations: prelogin.kdfIterations },
    });
  }

  async submitTwoFactor(input: { provider: 0 | 1; code: string; remember?: boolean }): Promise<AuthResult> {
    if (!this.pendingLogin) throw new Error('no pending 2FA login');
    const result = await this.deps.api.passwordLogin({
      email: this.pendingLogin.email,
      masterPasswordHash: this.pendingLogin.masterPasswordHash,
      twoFactorProvider: input.provider,
      twoFactorToken: input.code,
      remember: input.remember,
    });
    return this.finishPasswordLogin({ result, pending: this.pendingLogin });
  }

  async sendEmailCode(): Promise<void> {
    if (!this.pendingLogin?.twoFactorToken) throw new Error('no pending 2FA token');
    await this.deps.api.sendEmailLogin({ email: this.pendingLogin.email, twoFactorToken: this.pendingLogin.twoFactorToken });
  }

  async unlock(masterPassword: string): Promise<void> {
    const auth = await this.deps.session.getPersistedAuth();
    if (!auth) throw new Error('not logged in');
    const masterKey = await deriveMasterKey(masterPassword, auth.email, auth.kdfIterations);
    const userKey = await unwrapSymmetricKey(auth.protectedKey, await stretchMasterKey(masterKey));
    await this.deps.session.saveUnlocked({ ...auth, userKey });
  }

  getState(): Promise<SessionState> {
    return this.deps.session.getState();
  }

  lock(): Promise<void> {
    return this.deps.session.lock();
  }

  logout(): Promise<void> {
    this.pendingLogin = undefined;
    return this.deps.session.logout();
  }

  private async finishPasswordLogin(input: { result: PasswordLoginResult; pending: PendingLogin }): Promise<AuthResult> {
    if (input.result.kind === 'twoFactor') {
      const supported = input.result.providers.filter((p): p is 0 | 1 => p === 0 || p === 1);
      this.pendingLogin = input.result.token
        ? { ...input.pending, twoFactorToken: input.result.token }
        : input.pending;
      return input.result.token
        ? { kind: 'twoFactor', providers: supported, token: input.result.token }
        : { kind: 'twoFactor', providers: supported };
    }
    const data = input.result.data;
    const userKey = await unwrapSymmetricKey(data.Key, input.pending.stretchedMasterKey);
    const saveInput = {
      email: input.pending.email,
      accessToken: data.access_token,
      refreshToken: data.refresh_token,
      expiresAt: this.now() + data.expires_in * 1000,
      protectedKey: data.Key,
      kdf: 0 as const,
      kdfIterations: input.pending.kdfIterations,
      userKey,
    };
    await this.deps.session.saveUnlocked(data.PrivateKey ? { ...saveInput, privateKey: data.PrivateKey } : saveInput);
    this.pendingLogin = undefined;
    return { kind: 'unlocked' };
  }
}
```

- [ ] **Step 4: 运行测试，确认通过**

Run: `npm.cmd test -- auth-service`
Expected: PASS（3 tests）。

- [ ] **Step 5: 提交**

```bash
git add src/core/session/auth-service.ts src/core/session/auth-service.test.ts
git commit -m "feat(session): AuthService 登录/2FA/解锁编排

Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
```

---

### Task 15: token 刷新 + idle lock/alarm 编排

**Files:**
- Modify: `src/core/session/auth-service.ts`
- Modify: `src/core/session/auth-service.test.ts`
- Create: `src/background/alarms.ts`
- Test: `src/background/alarms.test.ts`

**Interfaces:**
- Produces:
  - `AuthService.refreshIfNeeded(skewMs?: number): Promise<void>`
  - `createAlarmHandlers(input: { auth: Pick<AuthService, 'lock'>; idleMs: number; now(): number; getLastActivity(): Promise<number | undefined>; setLastActivity(n: number): Promise<void> }): { touch(): Promise<void>; handleAlarm(name: string): Promise<void> }`

- [ ] **Step 1: 追加 AuthService refresh 失败测试**

追加到 `auth-service.test.ts`：

```ts
it('refreshIfNeeded refreshes expiring tokens and persists the replacements', async () => {
  const api = {
    refresh: vi.fn(async () => ({
      access_token: 'new-access',
      expires_in: 3600,
      refresh_token: 'new-refresh',
      token_type: 'Bearer',
    })),
  };
  const { auth, sm } = makeService(api);
  await sm.saveUnlocked({
    email: KDF_VECTOR.email,
    accessToken: 'old-access',
    refreshToken: 'old-refresh',
    expiresAt: 1100,
    protectedKey: USER_KEY_VECTOR.akey,
    kdf: 0,
    kdfIterations: KDF_VECTOR.iterations,
    userKey: { encKey: new Uint8Array(32), macKey: new Uint8Array(32) },
  });
  await auth.refreshIfNeeded(5000);
  expect(api.refresh).toHaveBeenCalledWith('old-refresh');
  expect((await sm.getPersistedAuth())?.accessToken).toBe('new-access');
});
```

- [ ] **Step 2: 实现 `refreshIfNeeded`**

在 `AuthService` 类中追加：

```ts
  async refreshIfNeeded(skewMs = 60_000): Promise<void> {
    const auth = await this.deps.session.getPersistedAuth();
    if (!auth) return;
    if (auth.expiresAt - this.now() > skewMs) return;
    const refreshed = await this.deps.api.refresh(auth.refreshToken);
    await this.deps.session.saveTokens({
      accessToken: refreshed.access_token,
      refreshToken: refreshed.refresh_token,
      expiresAt: this.now() + refreshed.expires_in * 1000,
    });
  }
```

- [ ] **Step 3: 写 `alarms.test.ts`**

```ts
import { describe, it, expect, vi } from 'vitest';
import { createAlarmHandlers } from './alarms.js';

describe('background alarms', () => {
  it('touch stores last activity timestamp', async () => {
    let stored: number | undefined;
    const handlers = createAlarmHandlers({
      auth: { lock: vi.fn() },
      idleMs: 1000,
      now: () => 2000,
      getLastActivity: async () => stored,
      setLastActivity: async (n) => { stored = n; },
    });
    await handlers.touch();
    expect(stored).toBe(2000);
  });

  it('locks when idle alarm fires after idle window', async () => {
    const lock = vi.fn(async () => {});
    const handlers = createAlarmHandlers({
      auth: { lock },
      idleMs: 1000,
      now: () => 2501,
      getLastActivity: async () => 1000,
      setLastActivity: async () => {},
    });
    await handlers.handleAlarm('idle-lock');
    expect(lock).toHaveBeenCalledTimes(1);
  });

  it('does not lock for unrelated alarms', async () => {
    const lock = vi.fn(async () => {});
    const handlers = createAlarmHandlers({
      auth: { lock },
      idleMs: 1000,
      now: () => 2501,
      getLastActivity: async () => 1000,
      setLastActivity: async () => {},
    });
    await handlers.handleAlarm('other');
    expect(lock).not.toHaveBeenCalled();
  });
});
```

- [ ] **Step 4: 实现 `background/alarms.ts`**

```ts
export const IDLE_LOCK_ALARM = 'idle-lock';

export interface AlarmHandlerDeps {
  auth: { lock(): Promise<void> };
  idleMs: number;
  now(): number;
  getLastActivity(): Promise<number | undefined>;
  setLastActivity(value: number): Promise<void>;
}

export function createAlarmHandlers(deps: AlarmHandlerDeps) {
  return {
    async touch(): Promise<void> {
      await deps.setLastActivity(deps.now());
    },

    async handleAlarm(name: string): Promise<void> {
      if (name !== IDLE_LOCK_ALARM) return;
      const last = await deps.getLastActivity();
      if (last === undefined) return;
      if (deps.now() - last > deps.idleMs) await deps.auth.lock();
    },
  };
}
```

- [ ] **Step 5: 运行测试，确认通过**

Run: `npm.cmd test -- auth-service alarms`
Expected: PASS。

- [ ] **Step 6: 提交**

```bash
git add src/core/session/auth-service.ts src/core/session/auth-service.test.ts src/background/alarms.ts src/background/alarms.test.ts
git commit -m "feat(session): token 刷新与 idle lock alarm 编排

Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
```

**M2 完成检查**：`npm.cmd test -- client session-manager auth-service alarms` 全绿；password grant 固定参数、2FA provider 支持范围、refresh/sync Bearer、UserKey session 托管均有测试覆盖。

---

# 阶段 M3：sync/read-only vault UI

产出：已解锁后可同步个人库、列出登录项、搜索、按需解密字段并复制密码；options 可配置 serverUrl 并申请 host permission。

---

### Task 16: Vault 模型与单个 cipher 解密

**Files:**
- Create: `src/core/vault/models.ts`
- Create: `src/core/vault/decrypt.ts`
- Test: `src/core/vault/decrypt.test.ts`

**Interfaces:**
- Consumes: `CipherResponse`、`SymmetricKey`、`decryptToText`、`unwrapSymmetricKey`
- Produces:
  - `type FieldName = 'username' | 'password' | 'totp' | 'notes'`
  - `interface CipherSummary { id: string; name: string; username?: string; uris: string[]; type: 1 | 2 | 3 | 4 | 5; favorite: boolean; undecryptable?: boolean }`
  - `interface DecryptedCipher extends CipherSummary { password?: string; totp?: string; notes?: string }`
  - `decryptCipher(cipher: CipherResponse, userKey: SymmetricKey): Promise<DecryptedCipher | undefined>`

- [ ] **Step 1: 写失败测试 `decrypt.test.ts`**

```ts
import { describe, it, expect } from 'vitest';
import { decryptCipher } from './decrypt.js';
import { symmetricKeyFromBytes } from '../crypto/keys.js';
import { hexToBytes } from '../crypto/encoding.js';
import { FIELD_VECTOR, USER_KEY_VECTOR } from '../../../test/vectors.js';
import type { CipherResponse } from '../api/types.js';

const userKey = symmetricKeyFromBytes(hexToBytes(USER_KEY_VECTOR.userKeyHex));

describe('decryptCipher', () => {
  it('decrypts a personal login cipher', async () => {
    const cipher: CipherResponse = {
      id: 'cipher-1',
      type: 1,
      name: FIELD_VECTOR.encString,
      favorite: true,
      organizationId: null,
      login: {
        username: FIELD_VECTOR.encString,
        password: FIELD_VECTOR.encString,
        totp: FIELD_VECTOR.encString,
        uris: [{ uri: FIELD_VECTOR.encString }],
      },
    };
    const out = await decryptCipher(cipher, userKey);
    expect(out).toEqual({
      id: 'cipher-1',
      type: 1,
      favorite: true,
      name: FIELD_VECTOR.plaintext,
      username: FIELD_VECTOR.plaintext,
      password: FIELD_VECTOR.plaintext,
      totp: FIELD_VECTOR.plaintext,
      uris: [FIELD_VECTOR.plaintext],
    });
  });

  it('skips organization ciphers in M3', async () => {
    const cipher: CipherResponse = {
      id: 'org-1',
      type: 1,
      name: FIELD_VECTOR.encString,
      favorite: false,
      organizationId: 'org',
      login: { username: FIELD_VECTOR.encString },
    };
    await expect(decryptCipher(cipher, userKey)).resolves.toBeUndefined();
  });
});
```

- [ ] **Step 2: 运行测试，确认失败**

Run: `npm.cmd test -- decrypt`
Expected: FAIL（模块未实现）。

- [ ] **Step 3: 实现 `models.ts`**

```ts
export type FieldName = 'username' | 'password' | 'totp' | 'notes';

export interface CipherSummary {
  id: string;
  name: string;
  username?: string;
  uris: string[];
  type: 1 | 2 | 3 | 4 | 5;
  favorite: boolean;
  undecryptable?: boolean;
}

export interface DecryptedCipher extends CipherSummary {
  password?: string;
  totp?: string;
  notes?: string;
}
```

- [ ] **Step 4: 实现 `decrypt.ts`**

```ts
import type { CipherResponse } from '../api/types.js';
import { decryptToText } from '../crypto/encstring.js';
import type { SymmetricKey } from '../crypto/keys.js';
import { unwrapSymmetricKey } from '../crypto/keys.js';
import type { DecryptedCipher } from './models.js';

export async function decryptCipher(
  cipher: CipherResponse,
  userKey: SymmetricKey,
): Promise<DecryptedCipher | undefined> {
  if (cipher.organizationId) return undefined;
  const key = cipher.key ? await unwrapSymmetricKey(cipher.key, userKey) : userKey;
  const name = await decryptRequired(cipher.name, key, '(no name)');
  const login = cipher.login ?? undefined;
  const uris = await Promise.all((login?.uris ?? [])
    .map(async (u) => (u.uri ? decryptToText(u.uri, key) : undefined)));
  const out: DecryptedCipher = {
    id: cipher.id,
    type: cipher.type,
    favorite: cipher.favorite ?? false,
    name,
    uris: uris.filter((u): u is string => Boolean(u)),
  };
  const username = await decryptOptional(login?.username, key);
  const password = await decryptOptional(login?.password, key);
  const totp = await decryptOptional(login?.totp, key);
  const notes = await decryptOptional(cipher.notes, key);
  if (username) out.username = username;
  if (password) out.password = password;
  if (totp) out.totp = totp;
  if (notes) out.notes = notes;
  return out;
}

async function decryptRequired(value: string | null | undefined, key: SymmetricKey, fallback: string): Promise<string> {
  return value ? decryptToText(value, key) : fallback;
}

async function decryptOptional(value: string | null | undefined, key: SymmetricKey): Promise<string | undefined> {
  return value ? decryptToText(value, key) : undefined;
}
```

- [ ] **Step 5: 运行测试，确认通过**

Run: `npm.cmd test -- decrypt`
Expected: PASS（2 tests）。

- [ ] **Step 6: 提交**

```bash
git add src/core/vault/models.ts src/core/vault/decrypt.ts src/core/vault/decrypt.test.ts
git commit -m "feat(vault): 个人登录 cipher 解密

Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
```

---

### Task 17: VaultService sync/cache/listItems/getField + 搜索纯函数

**Files:**
- Create: `src/core/vault/search.ts`
- Create: `src/core/vault/vault-service.ts`
- Test: `src/core/vault/search.test.ts`
- Test: `src/core/vault/vault-service.test.ts`

**Interfaces:**
- Consumes: `ApiClient.sync`、`AuthService.refreshIfNeeded`、`SessionManager`、`decryptCipher`
- Produces:
  - `filterSummaries(items: CipherSummary[], query: string): CipherSummary[]`
  - `class VaultService { sync(): Promise<CipherSummary[]>; listItems(): Promise<CipherSummary[]>; getField(id: string, field: FieldName): Promise<string | undefined>; clearCache(): Promise<void> }`

- [ ] **Step 1: 写 `search.test.ts`**

```ts
import { describe, it, expect } from 'vitest';
import { filterSummaries } from './search.js';
import type { CipherSummary } from './models.js';

const items: CipherSummary[] = [
  { id: '1', type: 1, name: 'GitHub', username: 'octo', uris: ['https://github.com'], favorite: false },
  { id: '2', type: 1, name: 'Email', username: 'me@example.com', uris: ['https://mail.example.com'], favorite: true },
];

describe('filterSummaries', () => {
  it('returns all items for blank query', () => {
    expect(filterSummaries(items, '')).toEqual(items);
  });

  it('matches name, username, and uri case-insensitively', () => {
    expect(filterSummaries(items, 'git').map((i) => i.id)).toEqual(['1']);
    expect(filterSummaries(items, 'ME@').map((i) => i.id)).toEqual(['2']);
    expect(filterSummaries(items, 'github.com').map((i) => i.id)).toEqual(['1']);
  });
});
```

- [ ] **Step 2: 实现 `search.ts`**

```ts
import type { CipherSummary } from './models.js';

export function filterSummaries(items: CipherSummary[], query: string): CipherSummary[] {
  const q = query.trim().toLowerCase();
  if (!q) return items;
  return items.filter((item) => {
    const haystack = [item.name, item.username ?? '', ...item.uris].join('\n').toLowerCase();
    return haystack.includes(q);
  });
}
```

- [ ] **Step 3: 写 `vault-service.test.ts`**

```ts
import { describe, it, expect, vi } from 'vitest';
import { VaultService } from './vault-service.js';
import { createMemoryStore } from '../../platform/store.js';
import { SessionManager } from '../session/session-manager.js';
import type { ApiClient } from '../api/client.js';
import type { AuthService } from '../session/auth-service.js';
import { symmetricKeyFromBytes } from '../crypto/keys.js';
import { hexToBytes } from '../crypto/encoding.js';
import { FIELD_VECTOR, USER_KEY_VECTOR } from '../../../test/vectors.js';
import type { SyncResponse } from '../api/types.js';

function makeSync(): SyncResponse {
  return {
    profile: { id: 'u', email: 'u@example.com' },
    ciphers: [{
      id: 'cipher-1',
      type: 1,
      name: FIELD_VECTOR.encString,
      favorite: false,
      organizationId: null,
      login: { username: FIELD_VECTOR.encString, password: FIELD_VECTOR.encString, uris: [{ uri: FIELD_VECTOR.encString }] },
    }],
  };
}

async function makeService(syncResponse = makeSync()) {
  const localStore = createMemoryStore();
  const sm = new SessionManager({ localStore, sessionStore: createMemoryStore() });
  await sm.saveUnlocked({
    email: 'u@example.com',
    accessToken: 'access',
    refreshToken: 'refresh',
    expiresAt: 999999,
    protectedKey: USER_KEY_VECTOR.akey,
    kdf: 0,
    kdfIterations: 1000,
    userKey: symmetricKeyFromBytes(hexToBytes(USER_KEY_VECTOR.userKeyHex)),
  });
  const api = { sync: vi.fn(async () => syncResponse) } as unknown as ApiClient;
  const auth = { refreshIfNeeded: vi.fn(async () => {}) } as unknown as AuthService;
  return { service: new VaultService({ api, auth, session: sm, localStore }), api };
}

describe('VaultService', () => {
  it('syncs, caches encrypted response, and returns summaries without password', async () => {
    const { service, api } = await makeService();
    const list = await service.sync();
    expect(api.sync).toHaveBeenCalledWith('access');
    expect(list).toEqual([{ id: 'cipher-1', type: 1, favorite: false, name: FIELD_VECTOR.plaintext, username: FIELD_VECTOR.plaintext, uris: [FIELD_VECTOR.plaintext] }]);
  });

  it('getField decrypts the requested field on demand from encrypted cache', async () => {
    const { service } = await makeService();
    await service.sync();
    await expect(service.getField('cipher-1', 'password')).resolves.toBe(FIELD_VECTOR.plaintext);
  });

  it('marks undecryptable ciphers without failing the whole list', async () => {
    const bad = makeSync();
    bad.ciphers[0]!.name = '2.bad|bad|bad';
    const { service } = await makeService(bad);
    const list = await service.sync();
    expect(list).toEqual([{ id: 'cipher-1', type: 1, favorite: false, name: '(undecryptable)', uris: [], undecryptable: true }]);
  });
});
```

- [ ] **Step 4: 运行测试，确认失败**

Run: `npm.cmd test -- search vault-service`
Expected: `search` PASS（若已实现），`vault-service` FAIL（模块未实现）。

- [ ] **Step 5: 实现 `vault-service.ts`**

```ts
import type { ApiClient } from '../api/client.js';
import type { CipherResponse, SyncResponse } from '../api/types.js';
import type { SessionManager } from '../session/session-manager.js';
import type { AuthService } from '../session/auth-service.js';
import type { KeyValueStore } from '../../platform/store.js';
import type { CipherSummary, FieldName } from './models.js';
import { decryptCipher } from './decrypt.js';

export interface VaultServiceDeps {
  api: ApiClient;
  auth: Pick<AuthService, 'refreshIfNeeded'>;
  session: SessionManager;
  localStore: KeyValueStore;
}

const VAULT_CACHE_KEY = 'vaultCache';
const SUMMARY_CACHE_KEY = 'vaultSummaries';

export class VaultService {
  constructor(private readonly deps: VaultServiceDeps) {}

  async sync(): Promise<CipherSummary[]> {
    await this.deps.auth.refreshIfNeeded();
    const auth = await this.deps.session.getPersistedAuth();
    if (!auth) throw new Error('not logged in');
    const response = await this.deps.api.sync(auth.accessToken);
    await this.deps.localStore.set(VAULT_CACHE_KEY, response);
    const summaries = await this.decryptSummaries(response.ciphers);
    await this.deps.localStore.set(SUMMARY_CACHE_KEY, summaries);
    return summaries;
  }

  async listItems(): Promise<CipherSummary[]> {
    return (await this.deps.localStore.get<CipherSummary[]>(SUMMARY_CACHE_KEY)) ?? [];
  }

  async getField(id: string, field: FieldName): Promise<string | undefined> {
    const cache = await this.deps.localStore.get<SyncResponse>(VAULT_CACHE_KEY);
    if (!cache) throw new Error('vault is not synced');
    const cipher = cache.ciphers.find((c) => c.id === id);
    if (!cipher) return undefined;
    const userKey = await this.deps.session.loadUserKey();
    if (!userKey) throw new Error('vault is locked');
    const decrypted = await decryptCipher(cipher, userKey);
    return decrypted?.[field];
  }

  async clearCache(): Promise<void> {
    await this.deps.localStore.remove(VAULT_CACHE_KEY);
    await this.deps.localStore.remove(SUMMARY_CACHE_KEY);
  }

  private async decryptSummaries(ciphers: CipherResponse[]): Promise<CipherSummary[]> {
    const userKey = await this.deps.session.loadUserKey();
    if (!userKey) throw new Error('vault is locked');
    const out: CipherSummary[] = [];
    for (const cipher of ciphers) {
      try {
        const decrypted = await decryptCipher(cipher, userKey);
        if (decrypted) {
          const summary: CipherSummary = {
            id: decrypted.id,
            type: decrypted.type,
            favorite: decrypted.favorite,
            name: decrypted.name,
            uris: decrypted.uris,
          };
          if (decrypted.username) summary.username = decrypted.username;
          if (decrypted.undecryptable) summary.undecryptable = true;
          out.push(summary);
        }
      } catch {
        out.push({
          id: cipher.id,
          type: cipher.type,
          favorite: cipher.favorite ?? false,
          name: '(undecryptable)',
          uris: [],
          undecryptable: true,
        });
      }
    }
    return out;
  }
}
```

- [ ] **Step 6: 运行测试，确认通过**

Run: `npm.cmd test -- search vault-service`
Expected: PASS（5 tests）。

- [ ] **Step 7: 提交**

```bash
git add src/core/vault/search.ts src/core/vault/search.test.ts src/core/vault/vault-service.ts src/core/vault/vault-service.test.ts
git commit -m "feat(vault): sync 缓存、摘要列表与按需字段解密

Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
```

---

### Task 18: 类型化消息协议与后台 router

**Files:**
- Create: `src/messaging/protocol.ts`
- Create: `src/background/router.ts`
- Test: `src/background/router.test.ts`

**Interfaces:**
- Consumes: `AuthService`、`VaultService`
- Produces:
  - `RequestMessage` / `ResponseMessage` discriminated unions
  - `sendRequest<T extends RequestMessage>(request: T): Promise<ResponseMessage>`
  - `createRouter(deps): { handle(request: RequestMessage): Promise<ResponseMessage> }`

- [ ] **Step 1: 写 `protocol.ts`**

```ts
import browser from 'webextension-polyfill';
import type { AuthResult } from '../core/session/auth-service.js';
import type { SessionState } from '../core/session/session-manager.js';
import type { CipherSummary, FieldName } from '../core/vault/models.js';

export type RequestMessage =
  | { type: 'auth.getState' }
  | { type: 'auth.login'; email: string; masterPassword: string }
  | { type: 'auth.submitTwoFactor'; provider: 0 | 1; code: string; remember?: boolean }
  | { type: 'auth.sendEmailCode' }
  | { type: 'auth.unlock'; masterPassword: string }
  | { type: 'auth.lock' }
  | { type: 'auth.logout' }
  | { type: 'vault.sync' }
  | { type: 'vault.listItems' }
  | { type: 'vault.getField'; id: string; field: FieldName }
  | { type: 'settings.get' }
  | { type: 'settings.save'; serverUrl: string };

export type ResponseMessage =
  | { ok: true; data: { state: SessionState } }
  | { ok: true; data: AuthResult }
  | { ok: true; data: CipherSummary[] }
  | { ok: true; data: { value?: string } }
  | { ok: true; data: { serverUrl?: string } }
  | { ok: true; data: null }
  | { ok: false; error: { code: string; message: string } };

export async function sendRequest(request: RequestMessage): Promise<ResponseMessage> {
  return browser.runtime.sendMessage(request) as Promise<ResponseMessage>;
}
```

- [ ] **Step 2: 写失败测试 `router.test.ts`**

```ts
import { describe, it, expect, vi } from 'vitest';
import { createRouter } from './router.js';

describe('router', () => {
  it('routes auth.getState', async () => {
    const router = createRouter({
      auth: { getState: vi.fn(async () => 'locked') },
      vault: {},
      settings: { getServerUrl: vi.fn(), saveServerUrl: vi.fn() },
    });
    await expect(router.handle({ type: 'auth.getState' })).resolves.toEqual({ ok: true, data: { state: 'locked' } });
  });

  it('turns thrown errors into ok:false responses', async () => {
    const router = createRouter({
      auth: { login: vi.fn(async () => { throw new Error('bad password'); }) },
      vault: {},
      settings: { getServerUrl: vi.fn(), saveServerUrl: vi.fn() },
    });
    await expect(router.handle({ type: 'auth.login', email: 'u', masterPassword: 'p' }))
      .resolves.toEqual({ ok: false, error: { code: 'error', message: 'bad password' } });
  });

  it('routes vault.getField', async () => {
    const router = createRouter({
      auth: {},
      vault: { getField: vi.fn(async () => 'secret') },
      settings: { getServerUrl: vi.fn(), saveServerUrl: vi.fn() },
    });
    await expect(router.handle({ type: 'vault.getField', id: '1', field: 'password' }))
      .resolves.toEqual({ ok: true, data: { value: 'secret' } });
  });
});
```

- [ ] **Step 3: 实现 `router.ts`**

```ts
import type { AuthService } from '../core/session/auth-service.js';
import type { VaultService } from '../core/vault/vault-service.js';
import type { RequestMessage, ResponseMessage } from '../messaging/protocol.js';

export interface RouterDeps {
  auth: Partial<AuthService>;
  vault: Partial<VaultService>;
  settings: {
    getServerUrl(): Promise<string | undefined>;
    saveServerUrl(serverUrl: string): Promise<void>;
  };
}

export function createRouter(deps: RouterDeps) {
  return {
    async handle(request: RequestMessage): Promise<ResponseMessage> {
      try {
        switch (request.type) {
          case 'auth.getState':
            if (!deps.auth.getState) throw new Error('auth.getState is not wired');
            return { ok: true, data: { state: await deps.auth.getState() } };
          case 'auth.login':
            if (!deps.auth.login) throw new Error('auth.login is not wired');
            return { ok: true, data: await deps.auth.login({ email: request.email, masterPassword: request.masterPassword }) };
          case 'auth.submitTwoFactor':
            if (!deps.auth.submitTwoFactor) throw new Error('auth.submitTwoFactor is not wired');
            return {
              ok: true,
              data: await deps.auth.submitTwoFactor(request.remember === undefined
                ? { provider: request.provider, code: request.code }
                : { provider: request.provider, code: request.code, remember: request.remember }),
            };
          case 'auth.sendEmailCode':
            if (!deps.auth.sendEmailCode) throw new Error('auth.sendEmailCode is not wired');
            await deps.auth.sendEmailCode();
            return { ok: true, data: null };
          case 'auth.unlock':
            if (!deps.auth.unlock) throw new Error('auth.unlock is not wired');
            await deps.auth.unlock(request.masterPassword);
            return { ok: true, data: null };
          case 'auth.lock':
            if (!deps.auth.lock) throw new Error('auth.lock is not wired');
            await deps.auth.lock();
            return { ok: true, data: null };
          case 'auth.logout':
            if (!deps.auth.logout) throw new Error('auth.logout is not wired');
            await deps.auth.logout();
            return { ok: true, data: null };
          case 'vault.sync':
            if (!deps.vault.sync) throw new Error('vault.sync is not wired');
            return { ok: true, data: await deps.vault.sync() };
          case 'vault.listItems':
            if (!deps.vault.listItems) throw new Error('vault.listItems is not wired');
            return { ok: true, data: await deps.vault.listItems() };
          case 'vault.getField':
            if (!deps.vault.getField) throw new Error('vault.getField is not wired');
            {
              const value = await deps.vault.getField(request.id, request.field);
              return { ok: true, data: value === undefined ? {} : { value } };
            }
          case 'settings.get':
            {
              const serverUrl = await deps.settings.getServerUrl();
              return { ok: true, data: serverUrl === undefined ? {} : { serverUrl } };
            }
          case 'settings.save':
            await deps.settings.saveServerUrl(request.serverUrl);
            return { ok: true, data: null };
        }
      } catch (err) {
        return { ok: false, error: { code: 'error', message: err instanceof Error ? err.message : String(err) } };
      }
    },
  };
}
```

- [ ] **Step 4: 运行测试，确认通过**

Run: `npm.cmd test -- router`
Expected: PASS（3 tests）。

- [ ] **Step 5: 提交**

```bash
git add src/messaging/protocol.ts src/background/router.ts src/background/router.test.ts
git commit -m "feat(background): 类型化消息协议与 router

Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
```

---

### Task 19: 后台 worker wiring（依赖实例化、alarms、settings）

**Files:**
- Modify: `src/background/index.ts`
- Create: `src/background/settings.ts`
- Test: `src/background/settings.test.ts`

**Interfaces:**
- Consumes: `createBrowserStore`、`ApiClient`、`SessionManager`、`AuthService`、`VaultService`、`createRouter`、`createAlarmHandlers`
- Produces: 真实 service worker wiring；settings 服务：`getServerUrl()` / `saveServerUrl(serverUrl)`

- [ ] **Step 1: 写 `settings.test.ts`**

```ts
import { describe, it, expect } from 'vitest';
import { createSettingsService } from './settings.js';
import { createMemoryStore } from '../platform/store.js';

describe('settings service', () => {
  it('normalizes serverUrl and stores it', async () => {
    const settings = createSettingsService(createMemoryStore());
    await settings.saveServerUrl('https://vw.example.com/base/');
    expect(await settings.getServerUrl()).toBe('https://vw.example.com/base/');
  });

  it('rejects non-http URLs', async () => {
    const settings = createSettingsService(createMemoryStore());
    await expect(settings.saveServerUrl('file:///tmp/x')).rejects.toThrow('serverUrl must start with http:// or https://');
  });
});
```

- [ ] **Step 2: 实现 `settings.ts`**

```ts
import type { KeyValueStore } from '../platform/store.js';

const SERVER_URL_KEY = 'serverUrl';

export function createSettingsService(store: KeyValueStore) {
  return {
    async getServerUrl(): Promise<string | undefined> {
      return store.get<string>(SERVER_URL_KEY);
    },

    async saveServerUrl(serverUrl: string): Promise<void> {
      const url = new URL(serverUrl);
      if (url.protocol !== 'https:' && url.protocol !== 'http:') {
        throw new Error('serverUrl must start with http:// or https://');
      }
      await store.set(SERVER_URL_KEY, url.toString());
    },
  };
}
```

- [ ] **Step 3: 替换 `background/index.ts` 为真实 wiring**

```ts
import browser from 'webextension-polyfill';
import { ApiClient } from '../core/api/client.js';
import { AuthService } from '../core/session/auth-service.js';
import { SessionManager } from '../core/session/session-manager.js';
import { VaultService } from '../core/vault/vault-service.js';
import { createBrowserStore } from '../platform/store.js';
import { createRouter } from './router.js';
import { createSettingsService } from './settings.js';
import { createAlarmHandlers, IDLE_LOCK_ALARM } from './alarms.js';
import type { RequestMessage } from '../messaging/protocol.js';

const localStore = createBrowserStore('local');
const sessionStore = createBrowserStore('session');
const settings = createSettingsService(localStore);
const session = new SessionManager({ localStore, sessionStore });
const api = new ApiClient({
  serverUrlProvider: async () => {
    const serverUrl = await settings.getServerUrl();
    if (!serverUrl) throw new Error('serverUrl is not configured');
    return serverUrl;
  },
  localStore,
});
const auth = new AuthService({ api, session });
const vault = new VaultService({ api, auth, session, localStore });
const router = createRouter({ auth, vault, settings });
const alarms = createAlarmHandlers({
  auth,
  idleMs: 15 * 60 * 1000,
  now: () => Date.now(),
  getLastActivity: () => sessionStore.get<number>('lastActivity'),
  setLastActivity: (n) => sessionStore.set('lastActivity', n),
});

browser.runtime.onInstalled.addListener(() => {
  browser.alarms.create(IDLE_LOCK_ALARM, { periodInMinutes: 1 });
});

browser.runtime.onMessage.addListener(async (message: unknown) => {
  await alarms.touch();
  return router.handle(message as RequestMessage);
});

browser.alarms.onAlarm.addListener((alarm) => {
  void alarms.handleAlarm(alarm.name);
});
```

- [ ] **Step 4: 运行测试 + 构建**

```bash
npm.cmd test -- settings
npm.cmd run typecheck
npm.cmd run build
```

Expected: settings tests PASS；typecheck/build 无错。

- [ ] **Step 5: 提交**

```bash
git add src/background/index.ts src/background/settings.ts src/background/settings.test.ts
git commit -m "feat(background): service worker wiring 与 settings 存储

Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
```

---

### Task 20: Popup 登录/2FA UI

**Files:**
- Modify: `src/ui/popup/popup.html`
- Modify: `src/ui/popup/popup.css`
- Modify: `src/ui/popup/popup.ts`

**Interfaces:**
- Consumes: `sendRequest`、`AuthResult`
- Produces: loggedOut -> login form；2FA 分支支持 Authenticator(0) 与 Email(1)；成功登录后进入 unlocked view（下一任务完善列表）。

- [ ] **Step 1: 替换 `popup.html`**

```html
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <link rel="stylesheet" href="popup.css" />
</head>
<body>
  <main id="app"></main>
  <script type="module" src="popup.js"></script>
</body>
</html>
```

- [ ] **Step 2: 写基础样式 `popup.css`**

```css
body { width: 380px; min-height: 360px; margin: 0; font: 14px system-ui, sans-serif; color: #1f2328; background: #fff; }
#app { padding: 14px; }
h1 { font-size: 18px; margin: 0 0 12px; }
label { display: block; margin: 10px 0 4px; font-weight: 600; }
input, select, button { box-sizing: border-box; width: 100%; font: inherit; }
input, select { padding: 8px; border: 1px solid #d0d7de; border-radius: 6px; }
button { margin-top: 12px; padding: 8px; border: 0; border-radius: 6px; background: #0969da; color: #fff; cursor: pointer; }
button.secondary { background: #57606a; }
button.danger { background: #cf222e; }
.error { color: #cf222e; margin-top: 8px; white-space: pre-wrap; }
.muted { color: #57606a; }
.row { display: flex; gap: 8px; align-items: center; }
.row > * { flex: 1; }
.item { border-bottom: 1px solid #d8dee4; padding: 8px 0; cursor: pointer; }
.item strong { display: block; }
.item span { color: #57606a; font-size: 12px; }
```

- [ ] **Step 3: 实现 `popup.ts` 登录/2FA 部分**

```ts
import { sendRequest } from '../../messaging/protocol.js';
import type { AuthResult } from '../../core/session/auth-service.js';

type View =
  | { kind: 'loading' }
  | { kind: 'loggedOut'; error?: string }
  | { kind: 'twoFactor'; providers: Array<0 | 1>; error?: string }
  | { kind: 'locked'; error?: string }
  | { kind: 'unlocked'; error?: string };

const app = document.getElementById('app')!;
let twoFactorProviders: Array<0 | 1> = [];

void init();

async function init() {
  render({ kind: 'loading' });
  const response = await sendRequest({ type: 'auth.getState' });
  if (!response.ok) return render({ kind: 'loggedOut', error: response.error.message });
  const { state } = response.data as { state: 'loggedOut' | 'locked' | 'unlocked' };
  render({ kind: state });
}

function render(view: View) {
  if (view.kind === 'loading') {
    app.innerHTML = '<p class="muted">Loading...</p>';
    return;
  }
  if (view.kind === 'loggedOut') return renderLogin(view.error);
  if (view.kind === 'twoFactor') return renderTwoFactor(view.providers, view.error);
  if (view.kind === 'locked') return renderLocked(view.error);
  return renderUnlockedShell(view.error);
}

function renderLogin(error?: string) {
  app.innerHTML = `
    <h1>Vaultwarden</h1>
    <form id="loginForm">
      <label>Email</label><input id="email" type="email" autocomplete="username" required />
      <label>Master password</label><input id="password" type="password" autocomplete="current-password" required />
      <button type="submit">Log in</button>
      ${error ? `<p class="error">${escapeHtml(error)}</p>` : ''}
    </form>`;
  document.getElementById('loginForm')!.addEventListener('submit', async (event) => {
    event.preventDefault();
    const email = (document.getElementById('email') as HTMLInputElement).value;
    const masterPassword = (document.getElementById('password') as HTMLInputElement).value;
    const result = await sendRequest({ type: 'auth.login', email, masterPassword });
    await handleAuthResult(result);
  });
}

function renderTwoFactor(providers: Array<0 | 1>, error?: string) {
  twoFactorProviders = providers;
  app.innerHTML = `
    <h1>Two-step login</h1>
    <form id="twoFactorForm">
      <label>Provider</label>
      <select id="provider">${providers.map((p) => `<option value="${p}">${p === 0 ? 'Authenticator app' : 'Email'}</option>`).join('')}</select>
      <label>Code</label><input id="code" inputmode="numeric" autocomplete="one-time-code" required />
      <button type="submit">Continue</button>
      ${providers.includes(1) ? '<button id="sendEmail" class="secondary" type="button">Send email code</button>' : ''}
      ${error ? `<p class="error">${escapeHtml(error)}</p>` : ''}
    </form>`;
  document.getElementById('twoFactorForm')!.addEventListener('submit', async (event) => {
    event.preventDefault();
    const provider = Number((document.getElementById('provider') as HTMLSelectElement).value) as 0 | 1;
    const code = (document.getElementById('code') as HTMLInputElement).value;
    await handleAuthResult(await sendRequest({ type: 'auth.submitTwoFactor', provider, code }));
  });
  document.getElementById('sendEmail')?.addEventListener('click', async () => {
    const response = await sendRequest({ type: 'auth.sendEmailCode' });
    if (!response.ok) render({ kind: 'twoFactor', providers: twoFactorProviders, error: response.error.message });
  });
}

function renderLocked(error?: string) {
  app.innerHTML = `
    <h1>Unlock</h1>
    <form id="unlockForm">
      <label>Master password</label><input id="unlockPassword" type="password" autocomplete="current-password" required />
      <button type="submit">Unlock</button>
      <button id="logout" type="button" class="danger">Log out</button>
      ${error ? `<p class="error">${escapeHtml(error)}</p>` : ''}
    </form>`;
  document.getElementById('unlockForm')!.addEventListener('submit', async (event) => {
    event.preventDefault();
    const masterPassword = (document.getElementById('unlockPassword') as HTMLInputElement).value;
    const response = await sendRequest({ type: 'auth.unlock', masterPassword });
    render(response.ok ? { kind: 'unlocked' } : { kind: 'locked', error: response.error.message });
  });
  document.getElementById('logout')!.addEventListener('click', async () => {
    await sendRequest({ type: 'auth.logout' });
    render({ kind: 'loggedOut' });
  });
}

function renderUnlockedShell(error?: string) {
  app.innerHTML = `<h1>Vault</h1><p class="muted">Unlocked. Vault list will be wired in Task 22.</p>${error ? `<p class="error">${escapeHtml(error)}</p>` : ''}`;
}

async function handleAuthResult(response: Awaited<ReturnType<typeof sendRequest>>) {
  if (!response.ok) return render({ kind: 'loggedOut', error: response.error.message });
  const data = response.data as AuthResult;
  if (data.kind === 'twoFactor') render({ kind: 'twoFactor', providers: data.providers });
  else render({ kind: 'unlocked' });
}

function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]!));
}
```

- [ ] **Step 4: 构建检查**

Run: `npm.cmd run build`
Expected: PASS；加载扩展，popup 显示登录表单或解锁表单。

- [ ] **Step 5: 提交**

```bash
git add src/ui/popup/popup.html src/ui/popup/popup.css src/ui/popup/popup.ts
git commit -m "feat(ui): popup 登录、2FA 与解锁表单

Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
```

---

### Task 21: Popup 解锁视图改进 + logout/lock 控制

**Files:**
- Modify: `src/ui/popup/popup.ts`
- Modify: `src/ui/popup/popup.css`

**Interfaces:**
- Consumes: `sendRequest`
- Produces: unlocked shell 中可手动 sync、lock、logout；Task 22 会把 sync 结果渲染成列表。

- [ ] **Step 1: 在 `popup.css` 追加 header/action 样式**

```css
.header { display: flex; justify-content: space-between; gap: 8px; align-items: center; }
.header h1 { margin: 0; }
.header button { width: auto; margin: 0; padding: 6px 8px; }
.toolbar { display: flex; gap: 8px; margin: 10px 0; }
.toolbar button { margin: 0; }
```

- [ ] **Step 2: 替换 `renderUnlockedShell`**

```ts
function renderUnlockedShell(error?: string) {
  app.innerHTML = `
    <div class="header">
      <h1>Vault</h1>
      <button id="lock" class="secondary" type="button">Lock</button>
    </div>
    <div class="toolbar">
      <button id="sync" type="button">Sync</button>
      <button id="logoutUnlocked" class="danger" type="button">Log out</button>
    </div>
    <div id="vaultList"><p class="muted">Sync to load vault items.</p></div>
    ${error ? `<p class="error">${escapeHtml(error)}</p>` : ''}`;
  document.getElementById('lock')!.addEventListener('click', async () => {
    await sendRequest({ type: 'auth.lock' });
    render({ kind: 'locked' });
  });
  document.getElementById('logoutUnlocked')!.addEventListener('click', async () => {
    await sendRequest({ type: 'auth.logout' });
    render({ kind: 'loggedOut' });
  });
  document.getElementById('sync')!.addEventListener('click', async () => {
    const response = await sendRequest({ type: 'vault.sync' });
    if (!response.ok) render({ kind: 'unlocked', error: response.error.message });
    else {
      const items = response.data as unknown[];
      (document.getElementById('vaultList')!).innerHTML = `<p class="muted">Loaded ${items.length} items. List rendering arrives in Task 22.</p>`;
    }
  });
}
```

- [ ] **Step 3: 构建检查**

Run: `npm.cmd run build`
Expected: PASS；popup unlocked shell 显示 Sync/Lock/Log out。

- [ ] **Step 4: 提交**

```bash
git add src/ui/popup/popup.ts src/ui/popup/popup.css
git commit -m "feat(ui): popup unlocked 控制（sync/lock/logout）

Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
```

---

### Task 22: Popup 列表与搜索

**Files:**
- Modify: `src/ui/popup/popup.ts`
- Modify: `src/ui/popup/popup.css`

**Interfaces:**
- Consumes: `CipherSummary`、`filterSummaries`、`sendRequest({ type: 'vault.listItems' | 'vault.sync' })`
- Produces: 可搜索的只读条目列表；点击条目进入详情（Task 23 完善复制）。

- [ ] **Step 1: 在 `popup.ts` 顶部导入类型与搜索**

```ts
import { sendRequest } from '../../messaging/protocol.js';
import type { AuthResult } from '../../core/session/auth-service.js';
import type { CipherSummary } from '../../core/vault/models.js';
import { filterSummaries } from '../../core/vault/search.js';
```

- [ ] **Step 2: 增加状态变量**

```ts
let vaultItems: CipherSummary[] = [];
```

- [ ] **Step 3: 替换 `renderUnlockedShell` 为列表版**

```ts
function renderUnlockedShell(error?: string) {
  app.innerHTML = `
    <div class="header">
      <h1>Vault</h1>
      <button id="lock" class="secondary" type="button">Lock</button>
    </div>
    <div class="toolbar">
      <button id="sync" type="button">Sync</button>
      <button id="logoutUnlocked" class="danger" type="button">Log out</button>
    </div>
    <input id="search" placeholder="Search vault" />
    <div id="vaultList"></div>
    ${error ? `<p class="error">${escapeHtml(error)}</p>` : ''}`;
  bindUnlockedControls();
  void loadCachedList();
}

function bindUnlockedControls() {
  document.getElementById('lock')!.addEventListener('click', async () => {
    await sendRequest({ type: 'auth.lock' });
    render({ kind: 'locked' });
  });
  document.getElementById('logoutUnlocked')!.addEventListener('click', async () => {
    await sendRequest({ type: 'auth.logout' });
    vaultItems = [];
    render({ kind: 'loggedOut' });
  });
  document.getElementById('sync')!.addEventListener('click', async () => {
    const response = await sendRequest({ type: 'vault.sync' });
    if (!response.ok) return render({ kind: 'unlocked', error: response.error.message });
    vaultItems = response.data as CipherSummary[];
    renderVaultList();
  });
  document.getElementById('search')!.addEventListener('input', renderVaultList);
}

async function loadCachedList() {
  const response = await sendRequest({ type: 'vault.listItems' });
  if (response.ok) {
    vaultItems = response.data as CipherSummary[];
    renderVaultList();
  }
}

function renderVaultList() {
  const list = document.getElementById('vaultList');
  if (!list) return;
  const query = (document.getElementById('search') as HTMLInputElement | null)?.value ?? '';
  const filtered = filterSummaries(vaultItems, query);
  if (filtered.length === 0) {
    list.innerHTML = '<p class="muted">No items.</p>';
    return;
  }
  list.innerHTML = filtered.map((item) => `
    <div class="item" data-id="${escapeHtml(item.id)}">
      <strong>${escapeHtml(item.name)}</strong>
      <span>${escapeHtml(item.username ?? item.uris[0] ?? '')}</span>
      ${item.undecryptable ? '<span class="error">undecryptable</span>' : ''}
    </div>`).join('');
  for (const row of list.querySelectorAll<HTMLElement>('.item')) {
    row.addEventListener('click', () => renderDetail(row.dataset.id!));
  }
}

function renderDetail(id: string) {
  const item = vaultItems.find((i) => i.id === id);
  if (!item) return;
  app.innerHTML = `
    <button id="back" class="secondary" type="button">Back</button>
    <h1>${escapeHtml(item.name)}</h1>
    <p class="muted">${escapeHtml(item.username ?? '')}</p>
    ${item.uris.map((u) => `<p><a href="${escapeHtml(u)}" target="_blank" rel="noreferrer">${escapeHtml(u)}</a></p>`).join('')}
    <button id="copyPassword" type="button">Copy password</button>`;
  document.getElementById('back')!.addEventListener('click', () => render({ kind: 'unlocked' }));
  document.getElementById('copyPassword')!.addEventListener('click', async () => {
    const response = await sendRequest({ type: 'vault.getField', id, field: 'password' });
    if (!response.ok) return renderDetailError(item, response.error.message);
    const { value } = response.data as { value?: string };
    if (!value) return renderDetailError(item, 'Password is empty');
    await navigator.clipboard.writeText(value);
  });
}

function renderDetailError(item: CipherSummary, message: string) {
  app.insertAdjacentHTML('beforeend', `<p class="error">${escapeHtml(message)}</p>`);
}
```

- [ ] **Step 4: 构建检查**

Run: `npm.cmd run build`
Expected: PASS；sync 后显示条目列表，搜索按名称/用户名/URI 过滤。

- [ ] **Step 5: 提交**

```bash
git add src/ui/popup/popup.ts src/ui/popup/popup.css
git commit -m "feat(ui): popup vault 列表与搜索

Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
```

---

### Task 23: Popup 详情页复制密码 + 自动清剪贴板

**Files:**
- Modify: `src/ui/popup/popup.ts`
- Modify: `src/ui/popup/popup.css`

**Interfaces:**
- Consumes: `navigator.clipboard`（popup 上下文）
- Produces: 详情页按需取 password；复制后 60 秒内若剪贴板仍等于该密码则清空。

- [ ] **Step 1: 在 `popup.css` 追加状态样式**

```css
.success { color: #1a7f37; margin-top: 8px; }
.detail-actions { display: grid; gap: 8px; margin-top: 12px; }
```

- [ ] **Step 2: 替换 `renderDetail` 的按钮区域**

把 `renderDetail` 中 `<button id="copyPassword"...` 那一段替换为：

```ts
    <div class="detail-actions">
      <button id="copyPassword" type="button">Copy password</button>
      <button id="copyUsername" class="secondary" type="button">Copy username</button>
    </div>
    <div id="detailStatus"></div>`;
```

并把 `copyPassword` handler 替换为：

```ts
  document.getElementById('copyPassword')!.addEventListener('click', async () => {
    const response = await sendRequest({ type: 'vault.getField', id, field: 'password' });
    if (!response.ok) return setDetailStatus(response.error.message, true);
    const { value } = response.data as { value?: string };
    if (!value) return setDetailStatus('Password is empty', true);
    await copyWithClear(value);
    setDetailStatus('Password copied. Clipboard clears in 60 seconds if unchanged.', false);
  });
  document.getElementById('copyUsername')!.addEventListener('click', async () => {
    if (!item.username) return setDetailStatus('Username is empty', true);
    await copyWithClear(item.username);
    setDetailStatus('Username copied. Clipboard clears in 60 seconds if unchanged.', false);
  });
```

- [ ] **Step 3: 在 `popup.ts` 追加复制 helper**

```ts
async function copyWithClear(value: string): Promise<void> {
  await navigator.clipboard.writeText(value);
  window.setTimeout(() => {
    void (async () => {
      const current = await navigator.clipboard.readText();
      if (current === value) await navigator.clipboard.writeText('');
    })();
  }, 60_000);
}

function setDetailStatus(message: string, isError: boolean) {
  const status = document.getElementById('detailStatus');
  if (!status) return;
  status.innerHTML = `<p class="${isError ? 'error' : 'success'}">${escapeHtml(message)}</p>`;
}
```

- [ ] **Step 4: 构建检查**

Run: `npm.cmd run build`
Expected: PASS；详情页复制密码成功，60 秒后剪贴板清空（若内容未被用户改写）。

- [ ] **Step 5: 提交**

```bash
git add src/ui/popup/popup.ts src/ui/popup/popup.css
git commit -m "feat(ui): 按需复制密码并自动清剪贴板

Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
```

---

### Task 24: Options 页 serverUrl 配置 + host permission

**Files:**
- Modify: `src/ui/options/options.html`
- Modify: `src/ui/options/options.css`
- Modify: `src/ui/options/options.ts`

**Interfaces:**
- Consumes: `sendRequest({ type: 'settings.get' | 'settings.save' })`、`browser.permissions.request`
- Produces: 用户可保存 serverUrl；保存前为该 origin 申请 host permission。

- [ ] **Step 1: 替换 `options.html`**

```html
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <link rel="stylesheet" href="options.css" />
</head>
<body>
  <main>
    <h1>Vaultwarden Settings</h1>
    <form id="settingsForm">
      <label for="serverUrl">Server URL</label>
      <input id="serverUrl" type="url" placeholder="https://vault.example.com/" required />
      <button type="submit">Save</button>
    </form>
    <div id="status"></div>
  </main>
  <script type="module" src="options.js"></script>
</body>
</html>
```

- [ ] **Step 2: 替换 `options.css`**

```css
body { font: 14px system-ui, sans-serif; max-width: 720px; margin: 32px auto; padding: 0 16px; color: #1f2328; }
h1 { font-size: 22px; }
label { display: block; font-weight: 600; margin: 12px 0 6px; }
input, button { box-sizing: border-box; width: 100%; font: inherit; }
input { padding: 8px; border: 1px solid #d0d7de; border-radius: 6px; }
button { margin-top: 12px; padding: 8px; border: 0; border-radius: 6px; background: #0969da; color: #fff; cursor: pointer; }
.success { color: #1a7f37; margin-top: 10px; }
.error { color: #cf222e; margin-top: 10px; }
```

- [ ] **Step 3: 实现 `options.ts`**

```ts
import browser from 'webextension-polyfill';
import { sendRequest } from '../../messaging/protocol.js';

const form = document.getElementById('settingsForm') as HTMLFormElement;
const input = document.getElementById('serverUrl') as HTMLInputElement;
const status = document.getElementById('status')!;

void init();

async function init() {
  const response = await sendRequest({ type: 'settings.get' });
  if (response.ok) {
    const { serverUrl } = response.data as { serverUrl?: string };
    if (serverUrl) input.value = serverUrl;
  }
}

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  try {
    const normalized = new URL(input.value).toString();
    const originPattern = new URL(normalized).origin + '/*';
    const granted = await browser.permissions.request({ origins: [originPattern] });
    if (!granted) {
      setStatus('Host permission was not granted.', true);
      return;
    }
    const response = await sendRequest({ type: 'settings.save', serverUrl: normalized });
    if (!response.ok) {
      setStatus(response.error.message, true);
      return;
    }
    setStatus('Saved.', false);
  } catch (err) {
    setStatus(err instanceof Error ? err.message : String(err), true);
  }
});

function setStatus(message: string, isError: boolean) {
  status.innerHTML = `<p class="${isError ? 'error' : 'success'}">${escapeHtml(message)}</p>`;
}

function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]!));
}
```

- [ ] **Step 4: 构建与人工验证**

```bash
npm.cmd run build
```

Expected: PASS。Chrome options 页能读取/保存 server URL；保存时弹 host permission 请求；同意后 settings.get 返回已保存 URL。

- [ ] **Step 5: 提交**

```bash
git add src/ui/options/options.html src/ui/options/options.css src/ui/options/options.ts
git commit -m "feat(ui): options 配置 serverUrl 并申请 host permission

Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
```

---

### Task 25: 全量验收与文档索引

**Files:**
- Modify: `README.md`

**Interfaces:**
- Consumes: 全部 M1-M3 功能
- Produces: README 中记录开发命令、加载方式、M1-M3 范围与手工验收清单。

- [ ] **Step 1: 更新 `README.md`**

````md
# Native Vaultwarden Browser Extension

Native Manifest V3 browser extension for a self-hosted Vaultwarden server. The extension uses the WebExtensions API with TypeScript and no frontend framework.

## Scope

M1-M3 provides:

- PBKDF2-HMAC-SHA256 login derivation, Bitwarden-style Master Password Hash, HKDF-Expand stretching, EncString encType=2 decrypt with MAC verification before AES-CBC decrypt.
- Vaultwarden prelogin, password grant, Authenticator/Email 2FA branch, refresh token, and sync API calls.
- MV3 service worker-centered session management with UserKey stored only in `storage.session`.
- Read-only vault sync, search, detail view, and on-demand password copy.

Organization ciphers and Argon2id accounts are not decrypted in this milestone.

## Development

```bash
npm.cmd install
npm.cmd test
npm.cmd run typecheck
npm.cmd run lint
npm.cmd run build
```

Load `dist/` from Chrome `chrome://extensions` with Developer Mode enabled.

## Manual acceptance

1. Start or point to a Vaultwarden server and create an existing account with PBKDF2 KDF.
2. Build the extension with `npm.cmd run build`.
3. Load `dist/` as an unpacked extension.
4. Open Options and save the Vaultwarden base URL, approving the host permission prompt.
5. Open the popup and log in with email + master password.
6. If the server requires 2FA, complete Authenticator or Email login.
7. Click Sync and confirm personal login ciphers are listed.
8. Search by item name, username, and URI.
9. Open a login item and copy the password.
10. Wait 60 seconds and confirm the clipboard clears if unchanged.
11. Click Lock, reopen the popup, unlock with the master password, and confirm cached items are available.
12. Log out and confirm the popup returns to the login form.
````

- [ ] **Step 2: 运行全部自动检查**

```bash
npm.cmd test
npm.cmd run typecheck
npm.cmd run lint
npm.cmd run build
```

Expected: 全部 PASS。

- [ ] **Step 3: 手工验收**

按 README 的 “Manual acceptance” 12 步执行。Expected：M1-M3 范围内全部通过；组织库/Argon2id 显示不支持而非崩溃。

- [ ] **Step 4: 提交**

```bash
git add README.md
git commit -m "docs: 记录开发命令与 M1-M3 手工验收

Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
```

---

## Final Verification

执行计划后必须完成：

```bash
npm.cmd test
npm.cmd run typecheck
npm.cmd run lint
npm.cmd run build
git status --short
```

Expected:
- `npm.cmd test` 全部通过。
- `npm.cmd run typecheck` 无 TypeScript 错误。
- `npm.cmd run lint` 无 lint 错误。
- `npm.cmd run build` 产出可加载的 MV3 `dist/`。
- `git status --short` 仅显示预期的未提交文件；若执行者按每任务提交，最终应为空。

---

## Self-Review Notes

1. **Spec coverage:** M1（工具链、MV3、crypto、store）、M2（prelogin/login/2FA/refresh/session/alarms）、M3（sync/decrypt/list/search/copy/options/manual acceptance）均有对应任务；M4 autofill、注册、Argon2id、组织 RSA 解密明确不在本阶段。
2. **Placeholder scan:** 已检查并清除禁止性占位表达；每个实现步骤都给出具体文件、命令或代码。
3. **Type consistency:** `SymmetricKey`、`KeyValueStore`、`ApiClient`、`SessionManager`、`AuthService`、`VaultService`、`RequestMessage`/`ResponseMessage` 的签名在任务间一致；登录 PascalCase 与 sync/prelogin camelCase 保持契约大小写。
