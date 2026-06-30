# 文件 Sends — 里程碑 2 实现计划（接收端访问页）

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 一个独立扩展页，粘贴 Send 分享链接后**匿名访问 + 解密**文本、或**下载并解密**文件；并给 M1 的文件 Send 创建补上传失败清理。

**Architecture:** 接收端用 send key（来自链接、对收件人公开）解密，**无 vault 机密**，故在页面内自包含完成（不经 service worker）。可测的访问/解密逻辑抽成纯核心 `send-access.ts`（注入 `fetch`）。

**Tech Stack:** TypeScript、MV3、`fetch` + `chrome.permissions.request`、esbuild、vitest（fetch 注入）+ `LIVE=1` 真实服务端往返。

## Global Constraints

- 设计依据：`docs/superpowers/specs/2026-06-30-file-sends-and-receive-page-design.md`（里程碑 2）。M1（发送端）已在 main。
- **协议已用真实服务端（Vaultwarden 2025.12）实测确认**（见下「Verified protocol」）——按这些事实实现，勿凭文档臆测。
- 接收端**无 vault 机密入场**：send key 来自 URL；不经 worker；不写 `storage`/console/DOM attribute；用后不持久化 send key。
- 文件解密复用 `attachments.ts` 的 `decryptAttachmentFile` 配 `deriveSendKey(sendKey)`；密码哈希复用 `sends.ts` 的 `hashSendPassword`。
- 跨服务器：链接自带 serverUrl；未授权 origin 在用户手势内 `chrome.permissions.request`；仅 http/https。
- 代码标识符/路径英文。
- 测试命令：单文件 `npx vitest run <path>`；类型 `npm run typecheck`；全量 `npm test`；打包 `npm run build`；真实服务端 `LIVE=1 npx vitest run test/live/sends.live.test.ts`。

## Verified protocol（真实服务端实测）

- 访问（匿名）：`POST {server}/api/sends/access/{accessId}`，体 `{ password? }` → 200，返回
  `{ id, type, name(EncString), text: {text,hidden}|null, file: { fileName(EncString), id, sizeName }|null, object:"send-access" }`。
  **响应里的 `id` 是 sendId（UUID），不是 accessId**；**无 `key` 字段**（收件人从 URL 派生）。
- 文件下载 URL：`POST {server}/api/sends/{sendId}/access/file/{fileId}`（**用 access 响应的 `id`，即 sendId**），体 `{ password? }`
  → 200，返回 `{ id:fileId, object:"send-fileDownload", url }`。**`url` 是绝对地址**（含 `?t={JWT}`）。
- 文件字节：GET 该绝对 url（匿名）→ EncArrayBuffer（首字节=2）→ `decryptAttachmentFile(buf, deriveSendKey(sendKey))` 还原。
- 密码错/需要密码：预期 `401`（未实测密码分支——live 测试可补，实现按 401→password_required 处理）。

---

## 文件结构

新增：
- `src/core/vault/send-access.ts` — 接收端核心（注入 fetch）：`parseSendUrl` / `decryptAccessedSend` / `accessSend` / `requestFileDownloadUrl` / `downloadAndDecryptFile` / `sendPasswordHash` + `AccessedSend` 类型。
- `src/core/vault/send-access.test.ts`
- `src/ui/receive/receive.html` + `receive.ts` + `receive.css`
- `test/live/sends.live.test.ts`（`LIVE=1` 门控的端到端往返）

修改：
- `src/core/vault/vault-service.ts` — `createFileSend` 上传失败清理。
- `src/core/vault/vault-service.test.ts` — 对应测试。
- `build.mjs` — `ui/receive/receive` 入口 + 静态拷贝。
- `src/ui/popup/popup.ts` — Sends 面板「Receive a Send」入口。

---

## Task 1: send-access 纯逻辑（parse + decrypt）

**Files:**
- Create: `src/core/vault/send-access.ts`
- Test: `src/core/vault/send-access.test.ts`

**Interfaces:**
- Consumes: `deriveSendKey` / `hashSendPassword`（`sends.js`）；`decryptToText`（`encstring.js`）；`base64UrlToBytes`（`encoding.js`）；`SymmetricKey`（`keys.js`）
- Produces:
  - `interface ParsedSendUrl { serverUrl: string; accessId: string; sendKey: Uint8Array }`
  - `interface AccessedSend { id: string; type: number; name: string; text?: string; fileName?: string; fileId?: string; sizeName?: string }`
  - `type SendAccessError = 'invalid_link' | 'password_required' | 'unavailable' | 'decrypt_failed'`
  - `parseSendUrl(link: string): ParsedSendUrl`
  - `decryptAccessedSend(raw: unknown, sendKey: Uint8Array): Promise<AccessedSend>`
  - `sendPasswordHash(password: string, sendKey: Uint8Array): Promise<string>`

- [ ] **Step 1: 写失败测试**

`src/core/vault/send-access.test.ts`:

```ts
import { describe, it, expect } from 'vitest';
import { parseSendUrl, decryptAccessedSend, sendPasswordHash } from './send-access.js';
import { deriveSendKey } from './sends.js';
import { encryptToText } from '../crypto/encstring.js';
import { bytesToBase64Url } from '../crypto/encoding.js';

const sendKey = new Uint8Array(16).fill(7);

describe('parseSendUrl', () => {
  it('parses server, accessId and send key from a share link', () => {
    const link = `https://vault.example/#/send/AbC123/${bytesToBase64Url(sendKey)}`;
    const parsed = parseSendUrl(link);
    expect(parsed.serverUrl).toBe('https://vault.example');
    expect(parsed.accessId).toBe('AbC123');
    expect(Array.from(parsed.sendKey)).toEqual(Array.from(sendKey));
  });
  it('rejects a non-send or malformed link', () => {
    expect(() => parseSendUrl('https://vault.example/#/login')).toThrowError(/invalid_link/);
    expect(() => parseSendUrl('not a url')).toThrowError(/invalid_link/);
    expect(() => parseSendUrl('https://vault.example/#/send/acc/')).toThrowError(/invalid_link/);
  });
  it('rejects a key that is not 16 bytes', () => {
    expect(() => parseSendUrl(`https://vault.example/#/send/acc/${bytesToBase64Url(new Uint8Array(8))}`)).toThrowError(/invalid_link/);
  });
});

describe('decryptAccessedSend', () => {
  it('decrypts a text send name + text', async () => {
    const derived = await deriveSendKey(sendKey);
    const raw = { id: 'send-1', type: 0, name: await encryptToText('Greeting', derived), text: { text: await encryptToText('hello', derived) } };
    const out = await decryptAccessedSend(raw, sendKey);
    expect(out).toMatchObject({ id: 'send-1', type: 0, name: 'Greeting', text: 'hello' });
  });
  it('decrypts a file send name + file name, keeping fileId/sizeName', async () => {
    const derived = await deriveSendKey(sendKey);
    const raw = { id: 'send-2', type: 1, name: await encryptToText('Doc', derived), file: { fileName: await encryptToText('secret.pdf', derived), id: 'f1', sizeName: '3 KB' } };
    const out = await decryptAccessedSend(raw, sendKey);
    expect(out).toMatchObject({ id: 'send-2', type: 1, name: 'Doc', fileName: 'secret.pdf', fileId: 'f1', sizeName: '3 KB' });
    expect(out.text).toBeUndefined();
  });
});

describe('sendPasswordHash', () => {
  it('derives a stable base64 hash for a password + send key', async () => {
    const a = await sendPasswordHash('pw', sendKey);
    const b = await sendPasswordHash('pw', sendKey);
    expect(a).toBe(b);
    expect(a).not.toContain('pw');
  });
});
```

- [ ] **Step 2: 运行确认失败**

Run: `npx vitest run src/core/vault/send-access.test.ts`
Expected: FAIL（模块不存在）

- [ ] **Step 3: 实现 `src/core/vault/send-access.ts`（纯部分）**

```ts
// Recipient-side Send access: parse a share link and decrypt the accessed Send with the URL send key.
// No vault secret is involved — the send key comes from the link, which is public to the recipient — so
// this runs in the receive page (not the service worker). Network functions take an injected fetch.

import { deriveSendKey, hashSendPassword } from './sends.js';
import { decryptToText } from '../crypto/encstring.js';
import { base64UrlToBytes } from '../crypto/encoding.js';
import type { SymmetricKey } from '../crypto/keys.js';

export interface ParsedSendUrl {
  serverUrl: string;
  accessId: string;
  sendKey: Uint8Array;
}

export interface AccessedSend {
  /** The send id from the access response — used for the file-download route (NOT the accessId). */
  id: string;
  type: number; // 0 text, 1 file
  name: string;
  text?: string;
  fileName?: string;
  fileId?: string;
  sizeName?: string;
}

export type SendAccessError = 'invalid_link' | 'password_required' | 'unavailable' | 'decrypt_failed';

export function sendAccessError(code: SendAccessError): Error & { code: SendAccessError } {
  return Object.assign(new Error(code), { code });
}

/** Parse `{server}/#/send/{accessId}/{base64url(16-byte sendKey)}`. Throws 'invalid_link' on any defect. */
export function parseSendUrl(link: string): ParsedSendUrl {
  const trimmed = link.trim();
  const marker = '#/send/';
  const at = trimmed.indexOf(marker);
  if (at < 0) throw sendAccessError('invalid_link');
  const serverUrl = trimmed.slice(0, at).replace(/\/$/, '');
  if (!/^https?:\/\//.test(serverUrl)) throw sendAccessError('invalid_link');
  const [accessId, keyPart, ...extra] = trimmed.slice(at + marker.length).split('/');
  if (!accessId || !keyPart || extra.length) throw sendAccessError('invalid_link');
  let sendKey: Uint8Array;
  try { sendKey = base64UrlToBytes(keyPart); } catch { throw sendAccessError('invalid_link'); }
  if (sendKey.length !== 16) throw sendAccessError('invalid_link');
  return { serverUrl, accessId, sendKey };
}

/** The password hash a Send expects, from a plaintext password + the URL send key (PBKDF2, reused). */
export async function sendPasswordHash(password: string, sendKey: Uint8Array): Promise<string> {
  return hashSendPassword(password, sendKey);
}

/** Decrypt the accessed Send's name + text (type 0) or file name (type 1) with the URL send key. */
export async function decryptAccessedSend(raw: unknown, sendKey: Uint8Array): Promise<AccessedSend> {
  const r = (raw ?? {}) as {
    id?: string; type?: number; name?: string;
    text?: { text?: string } | null;
    file?: { fileName?: string; id?: string; sizeName?: string } | null;
  };
  const derived = await deriveSendKey(sendKey);
  const out: AccessedSend = {
    id: r.id ?? '',
    type: r.type ?? 0,
    name: r.name ? await safeDecrypt(r.name, derived) : '(no name)',
  };
  if (r.type === 0 && r.text?.text) out.text = await safeDecrypt(r.text.text, derived);
  if (r.type === 1 && r.file) {
    if (r.file.fileName) out.fileName = await safeDecrypt(r.file.fileName, derived);
    if (r.file.id) out.fileId = r.file.id;
    if (r.file.sizeName) out.sizeName = r.file.sizeName;
  }
  return out;
}

async function safeDecrypt(value: string, key: SymmetricKey): Promise<string> {
  try { return await decryptToText(value, key); } catch { return '(undecryptable)'; }
}
```

- [ ] **Step 4: 运行确认通过**

Run: `npx vitest run src/core/vault/send-access.test.ts`
Expected: PASS

- [ ] **Step 5: 提交**

```bash
git add src/core/vault/send-access.ts src/core/vault/send-access.test.ts
git commit -m "feat: send-access parse + decrypt (recipient side, no vault secret)"
```

---

## Task 2: send-access 网络逻辑（access + download）

**Files:**
- Modify: `src/core/vault/send-access.ts`
- Test: `src/core/vault/send-access.test.ts`

**Interfaces:**
- Consumes: `deriveSendKey`（sends.js）；`decryptAttachmentFile`（attachments.js）；Task 1 的 `sendAccessError`
- Produces:
  - `accessSend(fetchFn: typeof fetch, serverUrl: string, accessId: string, passwordHash?: string): Promise<unknown>`
  - `requestFileDownloadUrl(fetchFn: typeof fetch, serverUrl: string, sendId: string, fileId: string, passwordHash?: string): Promise<string>`
  - `downloadAndDecryptFile(fetchFn: typeof fetch, downloadUrl: string, serverUrl: string, sendKey: Uint8Array): Promise<Uint8Array>`

- [ ] **Step 1: 写失败测试**

追加到 `send-access.test.ts`（注入 fake fetch）：

```ts
import { accessSend, requestFileDownloadUrl, downloadAndDecryptFile } from './send-access.js';
import { encryptAttachmentFile } from './attachments.js';

function jsonRes(body: unknown, status = 200): Response { return new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } }); }

describe('accessSend', () => {
  it('POSTs the accessId (anonymous) and returns the JSON; sends password hash when given', async () => {
    const calls: Array<[string, RequestInit]> = [];
    const fetchFn = (async (u: string, init: RequestInit) => { calls.push([String(u), init]); return jsonRes({ id: 'send-1', type: 0 }); }) as unknown as typeof fetch;
    const res = await accessSend(fetchFn, 'https://vault.example', 'acc1', 'HASH');
    expect(String(calls[0]![0])).toBe('https://vault.example/api/sends/access/acc1');
    expect(JSON.parse(calls[0]![1].body as string)).toEqual({ password: 'HASH' });
    expect(res).toMatchObject({ id: 'send-1' });
  });
  it('maps 401 to password_required', async () => {
    const fetchFn = (async () => new Response('', { status: 401 })) as unknown as typeof fetch;
    await expect(accessSend(fetchFn, 'https://vault.example', 'acc1')).rejects.toMatchObject({ code: 'password_required' });
  });
});

describe('requestFileDownloadUrl', () => {
  it('POSTs to /api/sends/{sendId}/access/file/{fileId} and returns the url', async () => {
    const calls: string[] = [];
    const fetchFn = (async (u: string) => { calls.push(String(u)); return jsonRes({ url: 'http://abs/url?t=jwt' }); }) as unknown as typeof fetch;
    const url = await requestFileDownloadUrl(fetchFn, 'https://vault.example', 'send-1', 'f1');
    expect(calls[0]).toBe('https://vault.example/api/sends/send-1/access/file/f1');
    expect(url).toBe('http://abs/url?t=jwt');
  });
});

describe('downloadAndDecryptFile', () => {
  it('GETs the absolute url and decrypts the EncArrayBuffer with the send key', async () => {
    const derived = await deriveSendKey(sendKey);
    const blob = await encryptAttachmentFile(new Uint8Array([9, 8, 7]), derived);
    const fetchFn = (async (u: string) => { expect(String(u)).toBe('http://abs/url?t=jwt'); return new Response(blob); }) as unknown as typeof fetch;
    const back = await downloadAndDecryptFile(fetchFn, 'http://abs/url?t=jwt', 'https://vault.example', sendKey);
    expect(Array.from(back)).toEqual([9, 8, 7]);
  });
  it('throws decrypt_failed on a corrupt blob', async () => {
    const fetchFn = (async () => new Response(new Uint8Array([2, 0, 0]))) as unknown as typeof fetch;
    await expect(downloadAndDecryptFile(fetchFn, 'http://abs/x', 'https://vault.example', sendKey)).rejects.toMatchObject({ code: 'decrypt_failed' });
  });
});
```

- [ ] **Step 2: 运行确认失败**

Run: `npx vitest run src/core/vault/send-access.test.ts -t accessSend`
Expected: FAIL（未定义）

- [ ] **Step 3: 实现（追加到 send-access.ts）**

```ts
import { decryptAttachmentFile } from './attachments.js';

/** POST /api/sends/access/{accessId} (anonymous). 401 → password_required. Returns the raw JSON. */
export async function accessSend(fetchFn: typeof fetch, serverUrl: string, accessId: string, passwordHash?: string): Promise<unknown> {
  const res = await fetchFn(`${serverUrl}/api/sends/access/${encodeURIComponent(accessId)}`, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify(passwordHash ? { password: passwordHash } : {}),
  });
  if (res.status === 401) throw sendAccessError('password_required');
  if (!res.ok) throw sendAccessError('unavailable');
  return res.json();
}

/** POST /api/sends/{sendId}/access/file/{fileId} → the absolute, JWT-protected download URL. */
export async function requestFileDownloadUrl(fetchFn: typeof fetch, serverUrl: string, sendId: string, fileId: string, passwordHash?: string): Promise<string> {
  const res = await fetchFn(`${serverUrl}/api/sends/${encodeURIComponent(sendId)}/access/file/${encodeURIComponent(fileId)}`, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify(passwordHash ? { password: passwordHash } : {}),
  });
  if (res.status === 401) throw sendAccessError('password_required');
  if (!res.ok) throw sendAccessError('unavailable');
  const json = (await res.json()) as { url?: string };
  if (!json.url) throw sendAccessError('unavailable');
  return json.url;
}

/** GET the download URL (absolute from the server; relative is prefixed with serverUrl) and decrypt. */
export async function downloadAndDecryptFile(fetchFn: typeof fetch, downloadUrl: string, serverUrl: string, sendKey: Uint8Array): Promise<Uint8Array> {
  const url = /^https?:\/\//.test(downloadUrl) ? downloadUrl : `${serverUrl}${downloadUrl}`;
  const res = await fetchFn(url);
  if (!res.ok) throw sendAccessError('unavailable');
  const buf = new Uint8Array(await res.arrayBuffer());
  try {
    return await decryptAttachmentFile(buf, await deriveSendKey(sendKey));
  } catch {
    throw sendAccessError('decrypt_failed');
  }
}
```

- [ ] **Step 4: 运行确认通过**

Run: `npx vitest run src/core/vault/send-access.test.ts`
Expected: PASS（全部）
Run: `npm run typecheck`
Expected: 0 errors

- [ ] **Step 5: 提交**

```bash
git add src/core/vault/send-access.ts src/core/vault/send-access.test.ts
git commit -m "feat: send-access network (access + file download, injected fetch)"
```

---

## Task 3: createFileSend 上传失败清理（M1 follow-up）

**Files:**
- Modify: `src/core/vault/vault-service.ts`
- Test: `src/core/vault/vault-service.test.ts`

**Interfaces:**
- Consumes: 现有 `createFileSend`、`api.deleteSend`
- Produces: 上传失败时删除孤儿 Send 并抛出原错误

- [ ] **Step 1: 写失败测试**

追加到 `vault-service.test.ts`：

```ts
  it('createFileSend deletes the orphan send if the blob upload fails', async () => {
    const { service, api } = await makeService();
    (api as any).createSendFile = vi.fn(async () => ({ url: '/sends/s9/file/f9', sendResponse: { id: 's9', accessId: 'a9', type: 1, file: { fileName: '2.enc' } } }));
    (api as any).uploadSendFileData = vi.fn(async () => { throw new Error('upload boom'); });
    (api as any).deleteSend = vi.fn(async () => {});
    const dataB64 = btoa(String.fromCharCode(1, 2, 3));
    await expect(service.createFileSend({ name: 'Doc', deletionDays: 7 }, dataB64, 'f.pdf', 'http://localhost:8080')).rejects.toThrow('upload boom');
    expect((api as any).deleteSend).toHaveBeenCalledWith('access', 's9');
  });
```

- [ ] **Step 2: 运行确认失败**

Run: `npx vitest run src/core/vault/vault-service.test.ts -t "orphan"`
Expected: FAIL（当前不清理，deleteSend 未被调用）

- [ ] **Step 3: 实现**

把 `createFileSend` 内 M1 加的 `// If the blob upload fails ...` 注释块 + `await this.deps.api.uploadSendFileData(...)` 这两行，替换为：

```ts
    const { url, sendResponse } = await this.deps.api.createSendFile(token, request);
    try {
      await this.deps.api.uploadSendFileData(token, url, encryptedFile, encryptedFileName);
    } catch (err) {
      // The Send record exists but holds no blob — delete the orphan, then surface the original error.
      await this.deps.api.deleteSend(token, sendResponse.id).catch(() => {});
      throw err;
    }
```

（保留其后的 `return decryptSend(sendResponse, userKey, serverUrl);`。）

- [ ] **Step 4: 运行确认通过**

Run: `npx vitest run src/core/vault/vault-service.test.ts`
Expected: PASS（整文件）
Run: `npm run typecheck`
Expected: 0 errors

- [ ] **Step 5: 提交**

```bash
git add src/core/vault/vault-service.ts src/core/vault/vault-service.test.ts
git commit -m "fix: delete the orphan Send if the file blob upload fails"
```

---

## Task 4: 接收页（ui/receive）+ build 入口

**Files:**
- Create: `src/ui/receive/receive.html`, `src/ui/receive/receive.ts`, `src/ui/receive/receive.css`
- Modify: `build.mjs`

**Interfaces:**
- Consumes: `send-access.ts`（Task 1/2）；`browser.permissions`（webextension-polyfill）；全局 `fetch`
- Produces: 一个独立扩展页，端到端接收 Send（页面 UI 无单测——以 typecheck/build + Task 6 live 往返 + 人工验收为门）

- [ ] **Step 1: build.mjs 加入口与拷贝**

在 `build.mjs` 的 `entryPoints` 加：

```js
    'ui/receive/receive': 'src/ui/receive/receive.ts',
```

在 `copyStatic` 的页面循环里把 `['popup', 'options']` 改为 `['popup', 'options', 'receive']`（这样 `receive.html`/`receive.css` 会被拷到 `dist/ui/receive/`）。

- [ ] **Step 2: `src/ui/receive/receive.html`**

```html
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <link rel="stylesheet" href="../theme.css" />
  <link rel="stylesheet" href="receive.css" />
</head>
<body>
  <div class="page">
    <header class="page-head">
      <div class="brand"><span class="brand-mark" id="brandMark"></span>
        <span class="titles"><span class="wordmark">Vaultwarden</span><span class="eyebrow">Receive a Send</span></span></div>
    </header>
    <main class="card settings">
      <div class="settings-head"><h1>Receive a Send</h1>
        <p class="muted">Paste a Vaultwarden Send link to view its text or download its file. The link's key decrypts it on this device.</p></div>
      <label class="field" for="link"><span class="field-label">Send link</span>
        <input id="link" class="input mono" type="url" placeholder="https://vault.example/#/send/…/…" /></label>
      <label class="field" id="passwordField" hidden for="password"><span class="field-label">Password</span>
        <input id="password" class="input" type="password" autocomplete="off" /></label>
      <div class="actions"><button type="button" class="btn" id="accessButton"><span>Access Send</span></button></div>
      <div id="result"></div>
      <div id="status" class="status" aria-live="polite"></div>
    </main>
  </div>
  <script type="module" src="receive.js"></script>
</body>
</html>
```

- [ ] **Step 3: `src/ui/receive/receive.css`**

```css
#result { margin-top: 16px; display: grid; gap: 10px; }
#result .send-name { font-weight: 650; }
#result .send-text { white-space: pre-wrap; word-break: break-word; font-family: ui-monospace, Menlo, Consolas, monospace; background: var(--surface-2, #f3f5fb); padding: 10px 12px; border-radius: 8px; }
#result .send-file { display: flex; align-items: center; gap: 10px; }
```

- [ ] **Step 4: `src/ui/receive/receive.ts`**

```ts
import browser from 'webextension-polyfill';
import { icon } from '../icons.js';
import {
  parseSendUrl, accessSend, decryptAccessedSend, requestFileDownloadUrl,
  downloadAndDecryptFile, sendPasswordHash, type ParsedSendUrl, type AccessedSend, type SendAccessError,
} from '../../core/vault/send-access.js';

const linkInput = document.getElementById('link') as HTMLInputElement;
const passwordField = document.getElementById('passwordField') as HTMLElement;
const passwordInput = document.getElementById('password') as HTMLInputElement;
const accessButton = document.getElementById('accessButton') as HTMLButtonElement;
const result = document.getElementById('result')!;
const status = document.getElementById('status')!;
document.getElementById('brandMark')!.innerHTML = icon('shield');

let busy = false;
accessButton.addEventListener('click', () => void onAccess());

const MESSAGES: Record<SendAccessError, string> = {
  invalid_link: 'Invalid Send link.',
  password_required: 'This Send needs a password.',
  unavailable: 'This Send is no longer available.',
  decrypt_failed: 'Could not decrypt — the link or file may be corrupted.',
};

async function onAccess(): Promise<void> {
  if (busy) return;
  result.innerHTML = '';
  let parsed: ParsedSendUrl;
  try { parsed = parseSendUrl(linkInput.value); } catch { return setStatus(MESSAGES.invalid_link, true); }

  busy = true; accessButton.disabled = true;
  try {
    if (!(await ensureHostPermission(parsed.serverUrl))) return setStatus(`Grant access to ${hostOf(parsed.serverUrl)} to receive this Send.`, true);
    const pwd = passwordInput.value;
    const passwordHash = pwd ? await sendPasswordHash(pwd, parsed.sendKey) : undefined;
    const raw = await accessSend(fetch, parsed.serverUrl, parsed.accessId, passwordHash);
    const send = await decryptAccessedSend(raw, parsed.sendKey);
    setStatus('', false);
    renderSend(parsed, send, passwordHash);
  } catch (err) {
    const code = (err as { code?: SendAccessError }).code;
    if (code === 'password_required') { passwordField.hidden = false; passwordInput.focus(); }
    setStatus(code ? MESSAGES[code] : 'Something went wrong.', true);
  } finally {
    busy = false; accessButton.disabled = false;
  }
}

function renderSend(parsed: ParsedSendUrl, send: AccessedSend, passwordHash?: string): void {
  if (send.type === 1) {
    result.innerHTML = `<div class="send-name">${escapeHtml(send.name)}</div>
      <div class="send-file">📎 ${escapeHtml(send.fileName ?? 'file')}${send.sizeName ? ` · ${escapeHtml(send.sizeName)}` : ''}
      <button type="button" class="btn" id="downloadButton"><span>Download</span></button></div>`;
    document.getElementById('downloadButton')!.addEventListener('click', () => void downloadFile(parsed, send, passwordHash));
  } else {
    result.innerHTML = `<div class="send-name">${escapeHtml(send.name)}</div><div class="send-text">${escapeHtml(send.text ?? '')}</div>`;
  }
}

async function downloadFile(parsed: ParsedSendUrl, send: AccessedSend, passwordHash?: string): Promise<void> {
  if (busy || !send.fileId) return;
  busy = true;
  try {
    const url = await requestFileDownloadUrl(fetch, parsed.serverUrl, send.id, send.fileId, passwordHash);
    const bytes = await downloadAndDecryptFile(fetch, url, parsed.serverUrl, parsed.sendKey);
    triggerDownload(bytes, send.fileName ?? 'download');
    setStatus('', false);
  } catch (err) {
    const code = (err as { code?: SendAccessError }).code;
    setStatus(code ? MESSAGES[code] : 'Download failed.', true);
  } finally {
    busy = false;
  }
}

function triggerDownload(bytes: Uint8Array, fileName: string): void {
  const url = URL.createObjectURL(new Blob([bytes as BlobPart]));
  const a = document.createElement('a');
  a.href = url; a.download = fileName; document.body.append(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 10_000);
}

/** Request host permission for the Send's origin (must run in a user gesture). `permissions.request`
 *  is idempotent — it returns true without a prompt when the origin is already granted, so calling it
 *  directly (no prior async `contains`) keeps the call inside the click's user-gesture window. */
async function ensureHostPermission(serverUrl: string): Promise<boolean> {
  const origin = `${new URL(serverUrl).origin}/*`;
  return browser.permissions.request({ origins: [origin] });
}

function hostOf(serverUrl: string): string { try { return new URL(serverUrl).host; } catch { return serverUrl; } }
function setStatus(message: string, isError: boolean): void { status.textContent = message; status.classList.toggle('error', isError); }
function escapeHtml(v: string): string { return v.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]!)); }
```

- [ ] **Step 5: 验证**

Run: `npm run typecheck`
Expected: 0 errors
Run: `npm run build`
Expected: `build done`，`dist/ui/receive/receive.html` / `receive.js` / `receive.css` 均存在。

- [ ] **Step 6: 提交**

```bash
git add src/ui/receive/receive.html src/ui/receive/receive.ts src/ui/receive/receive.css build.mjs
git commit -m "feat: standalone receive page for Sends (anonymous access + download)"
```

---

## Task 5: popup「Receive a Send」入口

**Files:**
- Modify: `src/ui/popup/popup.ts`

**Interfaces:**
- Consumes: `browser.tabs` / `browser.runtime.getURL`（webextension-polyfill）
- Produces: Sends 面板内打开接收页的按钮

> popup 无单测；以 typecheck/build + 人工冒烟为门。

- [ ] **Step 1: 加入口按钮**

在 `renderSends` 的「New Send」`ed-field` 块**之后**、`<div id="sendList">` 之前，插入：

```html
        <button id="send_receive" type="button" class="btn btn-secondary btn-block">${icon('mail')}<span>Receive a Send</span></button>
```

- [ ] **Step 2: 打开接收页**

在 `renderSends` 内（监听绑定处附近）追加：

```ts
  document.getElementById('send_receive')!.addEventListener('click', () => {
    void browser.tabs.create({ url: browser.runtime.getURL('ui/receive/receive.html') });
  });
```

> 若 `popup.ts` 尚未 `import browser from 'webextension-polyfill'`，在文件顶部加上该导入。

- [ ] **Step 3: 验证**

Run: `npm run typecheck`
Expected: 0 errors
Run: `npm run build`
Expected: `build done`

- [ ] **Step 4: 提交**

```bash
git add src/ui/popup/popup.ts
git commit -m "feat: open the receive page from the popup Sends panel"
```

---

## Task 6: LIVE 端到端往返（建文件 Send → access → 下载）

**Files:**
- Create: `test/live/sends.live.test.ts`

**Interfaces:**
- Consumes: M1 的 `buildFileSendRequest` + `ApiClient.createSendFile`/`uploadSendFileData`/`deleteSend`；M2 的 `send-access.ts`
- Produces: `LIVE=1` 门控的真实服务端往返（默认 skip），同时验证 M1 上传协议保真

> 实现者请用 `LIVE=1 npx vitest run test/live/sends.live.test.ts` 对 CLAUDE.md 的测试服务器（`http://10.0.1.20:8080`，当前网络可直连）实跑确认通过；不传 LIVE 时该 describe 被 skip，不影响 `npm test`。

- [ ] **Step 1: 写 live 测试**

`test/live/sends.live.test.ts`（结构对齐 `test/live/crud.live.test.ts` 的登录与门控）：

```ts
// Live end-to-end for file Sends: create a file Send, then access + download it via the recipient path.
// Skipped unless LIVE=1. Run: LIVE=1 npx vitest run test/live/sends.live.test.ts
import { describe, it, expect, vi } from 'vitest';
vi.mock('webextension-polyfill', () => ({ default: { storage: { local: {}, session: {} } } }));

import { ApiClient } from '../../src/core/api/client.js';
import { deriveMasterKey, deriveMasterPasswordHash, stretchMasterKey } from '../../src/core/crypto/kdf.js';
import { unwrapSymmetricKey } from '../../src/core/crypto/keys.js';
import { buildFileSendRequest, buildSendAccessUrl } from '../../src/core/vault/sends.js';
import { parseSendUrl, accessSend, decryptAccessedSend, requestFileDownloadUrl, downloadAndDecryptFile } from '../../src/core/vault/send-access.js';
import type { KeyValueStore } from '../../src/platform/store.js';

const SERVER = 'http://10.0.1.20:8080';
const EMAIL = 'test@winvaultwarden.local';
const PASSWORD = 'Test-Master-Password-1!';
const LIVE = Boolean(process.env.LIVE);

function memStore(): KeyValueStore {
  const m = new Map<string, unknown>();
  return { get: async <T>(k: string) => m.get(k) as T | undefined, set: async (k: string, v: unknown) => { m.set(k, v); }, remove: async (k: string) => { m.delete(k); } } as KeyValueStore;
}

(LIVE ? describe : describe.skip)('live file Send round-trip', () => {
  it('creates a file Send and receives it back via the access path', async () => {
    const api = new ApiClient({ serverUrlProvider: async () => SERVER, fetchFn: fetch, localStore: memStore() });
    const pre = await api.prelogin(EMAIL);
    const masterKey = await deriveMasterKey(PASSWORD, EMAIL, pre.kdfIterations);
    const login = await api.passwordLogin({ email: EMAIL, masterPasswordHash: await deriveMasterPasswordHash(masterKey, PASSWORD) });
    if (login.kind !== 'success') throw new Error('login failed');
    const token = login.data.access_token;
    const userKey = await unwrapSymmetricKey(login.data.Key, await stretchMasterKey(masterKey));

    const fileBytes = new Uint8Array([10, 20, 30, 40, 50]);
    const { request, sendKey, encryptedFile, encryptedFileName } = await buildFileSendRequest({ name: 'live', deletionDays: 1 }, 'live.bin', fileBytes, userKey);
    const created = await api.createSendFile(token, request);
    await api.uploadSendFileData(token, created.url, encryptedFile, encryptedFileName);

    // Recipient path: parse the share URL → access → download.
    const shareUrl = buildSendAccessUrl(SERVER, created.sendResponse.accessId, sendKey);
    const parsed = parseSendUrl(shareUrl);
    const raw = await accessSend(fetch, parsed.serverUrl, parsed.accessId);
    const send = await decryptAccessedSend(raw, parsed.sendKey);
    expect(send.type).toBe(1);
    expect(send.fileName).toBe('live.bin');
    const dl = await requestFileDownloadUrl(fetch, parsed.serverUrl, send.id, send.fileId!);
    const back = await downloadAndDecryptFile(fetch, dl, parsed.serverUrl, parsed.sendKey);
    expect(Array.from(back)).toEqual([10, 20, 30, 40, 50]);

    await api.deleteSend(token, created.sendResponse.id);
  }, 60_000);
});
```

- [ ] **Step 2: 默认（不传 LIVE）运行确认 skip**

Run: `npx vitest run test/live/sends.live.test.ts`
Expected: 该 describe 被 skip（0 失败）。

- [ ] **Step 3: LIVE 实跑确认通过**

Run: `LIVE=1 npx vitest run test/live/sends.live.test.ts`
Expected: PASS（真实服务端建→上传→access→下载→解密往返成功）。如失败，按真实响应调整 `send-access.ts` 或 client，并回报。

- [ ] **Step 4: 提交**

```bash
git add test/live/sends.live.test.ts
git commit -m "test: live end-to-end file Send create + receive round-trip"
```

---

## 收尾：人工验收

- [ ] `npm run build` → 加载 `dist/`，登录解锁，Sends 面板 → File 建一个文件 Send（得分享链接）。
- [ ] Sends 面板「Receive a Send」→ 接收页打开 → 粘贴该链接 → Access → 显示文件名 → Download 得到原文件。
- [ ] 文本 Send 链接 → 接收页显示文本。
- [ ] 非法链接 / 过期 / 错密码分别给出对应提示；跨服务器链接弹 host 权限请求。

---

## Self-Review 结论

- **Spec 覆盖**（里程碑 2）：parse/access/decrypt/download→Task1/2；接收页→Task4；popup 入口→Task5；孤儿清理→Task3；live 往返→Task6。协议按**真实服务端实测**固定（access 响应 `id`=sendId、下载 url 绝对）。
- **占位符**：无 TBD/TODO；每个代码步骤含完整实现与测试（接收页 UI 以 typecheck/build + live + 人工为门，符合本项目页面无单测惯例）。
- **类型一致**：`ParsedSendUrl`/`AccessedSend`/`SendAccessError`/`sendAccessError`（Task1）在 Task2/4/6 一致引用；`accessSend`/`requestFileDownloadUrl`/`downloadAndDecryptFile`（Task2）在 Task4/6 一致引用。
- **安全**：接收端无 vault 机密；send key 仅在页面内用于解密、不持久化；跨服务器经 `chrome.permissions.request`；文件名/文本渲染均 `escapeHtml`。
- **复用而非重写**：`deriveSendKey`/`hashSendPassword`/`decryptAttachmentFile`/`base64UrlToBytes` 全复用。
