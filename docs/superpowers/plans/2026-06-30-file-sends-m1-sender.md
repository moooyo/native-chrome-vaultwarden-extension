# 文件 Sends — 里程碑 1 实现计划（发送端：创建文件 Send）

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 让用户在 popup 创建**文件 Send**——本地加密文件、经 v2 两步上传到 Vaultwarden、并在 Sends 列表显示。

**Architecture:** 复用文本 Send 的 HKDF send key 与 worker 中心化加密；文件字节用 send key 加密为 **EncArrayBuffer**（直接复用 `attachments.ts`）。worker 派生 send key、加密文件名+文件、UserKey 包裹 send key，走 `POST /api/sends/file/v2`（JSON）→ `POST {返回 url}`（multipart）。popup 只传 base64 字节、拿回 SendSummary。

**Tech Stack:** TypeScript、MV3、vitest（fetch 注入），esbuild。

## Global Constraints

- 设计依据：`docs/superpowers/specs/2026-06-30-file-sends-and-receive-page-design.md`（里程碑 1）。
- 安全红线：UserKey/主密码/明文库/明文文件不出 worker；popup 只传 base64 字节、拿回 SendSummary（含分享 URL，不含 send key 外机密）。
- 文件加密**复用** `attachments.ts` 的 `encryptAttachmentFile`（EncArrayBuffer：`[2]‖iv‖mac‖ct`），配 `deriveSendKey(sendKey)` 得到的 `SymmetricKey`。
- 上传走 **v2**：`POST /api/sends/file/v2`（JSON）→ `POST /api{返回的 url}`（multipart 字段 `data`，文件名用加密文件名）。
- 文件大小上限（内存）：popup 端 100 MB，超限即拒绝。
- 代码标识符与路径英文。
- 测试命令：单文件 `npx vitest run <path>`；类型 `npm run typecheck`；全量 `npm test`；打包 `npm run build`。
- 提交粒度：每个 Task 末尾提交一次。

---

## 文件结构

修改：
- `src/core/api/types.ts` — `SendRequest` 加 `fileLength?`；新增 `SendFileUploadResponse`。
- `src/core/vault/sends.ts` — `buildFileSendRequest`、`decryptSend` 支持 type=1、`SendSummary` 加 `fileName?`/`sizeName?`、`SendInput.text` 改可选。
- `src/core/vault/sends.test.ts` — 文件 Send 往返测试。
- `src/core/api/client.ts` — `createSendFile`、`uploadSendFileData`。
- `src/core/api/client.test.ts` — 对应测试。
- `src/core/vault/vault-service.ts` — `createFileSend`。
- `src/core/vault/vault-service.test.ts` — 对应测试。
- `src/messaging/protocol.ts` / `src/background/router.ts` — `sends.createFile`。
- `src/background/router.test.ts` — 对应测试。
- `src/ui/popup/popup.ts` — Sends 面板 Text/File 切换 + 文件选择 + 文件创建（typecheck/build 验证，popup 无单测）。

---

## Task 1: api/types — SendRequest.fileLength + 上传响应类型

**Files:**
- Modify: `src/core/api/types.ts`

**Interfaces:**
- Produces: `SendRequest` 增加 `fileLength?: number | null`；新增 `interface SendFileUploadResponse { url: string; fileUploadType?: number; sendResponse: SendResponse }`

- [ ] **Step 1: 改类型**

在 `src/core/api/types.ts` 的 `SendRequest` 接口中，`file?: SendFileData | null;` 之后加一行：

```ts
  fileLength?: number | null;
```

在 `SendRequest` 接口之后新增：

```ts
/** Response of POST /api/sends/file/v2: where to upload the encrypted blob, plus the created Send. */
export interface SendFileUploadResponse {
  url: string;
  fileUploadType?: number;
  sendResponse: SendResponse;
}
```

- [ ] **Step 2: 类型检查**

Run: `npm run typecheck`
Expected: 0 errors（仅新增类型）。

- [ ] **Step 3: 提交**

```bash
git add src/core/api/types.ts
git commit -m "feat: SendRequest.fileLength + SendFileUploadResponse type"
```

---

## Task 2: sends.ts — 文件 Send 构造 + type=1 解密

**Files:**
- Modify: `src/core/vault/sends.ts`
- Test: `src/core/vault/sends.test.ts`

**Interfaces:**
- Consumes: `encryptAttachmentFile` / `decryptAttachmentFile`（`attachments.js`）；现有 `deriveSendKey` / `hashSendPassword` / `encryptToText` / `encryptToBytes` / `decryptToText`
- Produces:
  - `SendInput.text?` 改可选；`SendSummary` 加 `fileName?: string` / `sizeName?: string`
  - `buildFileSendRequest(input: SendInput, fileName: string, fileBytes: Uint8Array, userKey: SymmetricKey, deps?: SendCryptoDeps): Promise<{ request: SendRequest; sendKey: Uint8Array; encryptedFile: Uint8Array; encryptedFileName: string }>`
  - `decryptSend` 对 `send.type === 1` 解出 `fileName`/`sizeName`

- [ ] **Step 1: 写失败测试**

在 `src/core/vault/sends.test.ts` 追加（**复用文件顶部已有的** 模块级 `userKey` 常量与 `decryptSend`/`deriveSendKey` 导入；只需把 `buildFileSendRequest` 加进现有的 `from './sends.js'` 导入，并新增 `decryptAttachmentFile` 导入）：

```ts
// 顶部：现有 import { buildTextSendRequest, decryptSend, deriveSendKey, ... } from './sends.js' 加上 buildFileSendRequest
import { decryptAttachmentFile } from './attachments.js';

describe('file send', () => {
  const fileDeps = { randomBytes: (n: number) => new Uint8Array(n).fill(9), now: () => 0 };

  it('builds a type=1 request, encrypts the file (EncArrayBuffer round-trip) and file name', async () => {
    const fileBytes = new Uint8Array([1, 2, 3, 4, 5]);
    const { request, sendKey, encryptedFile, encryptedFileName } = await buildFileSendRequest(
      { name: 'Doc', deletionDays: 7 }, 'secret.pdf', fileBytes, userKey, fileDeps);
    expect(request.type).toBe(1);
    expect(request.file?.fileName).toBe(encryptedFileName);
    expect(request.fileLength).toBe(encryptedFile.length);
    // the encrypted blob round-trips back to the original bytes under the derived send key
    const derived = await deriveSendKey(sendKey);
    expect(Array.from(await decryptAttachmentFile(encryptedFile, derived))).toEqual([1, 2, 3, 4, 5]);
  });

  it('decryptSend surfaces the file name for a type=1 send', async () => {
    const { request } = await buildFileSendRequest(
      { name: 'Doc', deletionDays: 7 }, 'secret.pdf', new Uint8Array([1, 2, 3]), userKey, fileDeps);
    const resp = {
      id: 's1', accessId: 'acc1', type: 1, name: request.name, key: request.key,
      file: { id: 'f1', fileName: request.file!.fileName, size: '3', sizeName: '3 Bytes' },
      deletionDate: new Date(0).toISOString(), accessCount: 0,
    } as unknown as SendResponse;
    const summary = await decryptSend(resp, userKey, 'http://localhost:8080');
    expect(summary.type).toBe(1);
    expect(summary.fileName).toBe('secret.pdf');
    expect(summary.sizeName).toBe('3 Bytes');
  });
});
```

> `userKey`（模块级常量）、`decryptSend`/`deriveSendKey`（已导入）、`SendResponse`（已 `import type`）在 `sends.test.ts` 中均已就绪——勿重复声明/导入。

- [ ] **Step 2: 运行确认失败**

Run: `npx vitest run src/core/vault/sends.test.ts -t "file send"`
Expected: FAIL（`buildFileSendRequest` 未定义）

- [ ] **Step 3: 实现 sends.ts 变更**

3a) 顶部导入加：

```ts
import { encryptAttachmentFile } from './attachments.js';
```

3b) `SendInput` 把 `text: string;` 改为 `text?: string;`，并在 `buildTextSendRequest` 内把 `input.text` 用处改为 `input.text ?? ''`（找到 `text: { text: await encryptToText(input.text, derived) ...` 那行，改成 `encryptToText(input.text ?? '', derived)`）。

3c) `SendSummary` 接口加两字段：

```ts
  /** Decrypted file name for a file (type=1) send. */
  fileName?: string;
  /** Human-readable size (from the server's file.sizeName). */
  sizeName?: string;
```

3d) 在 `buildTextSendRequest` 之后新增：

```ts
/**
 * Build a create-file-send request: generate a send key, derive the field key, encrypt the file
 * (EncArrayBuffer, reusing the attachment format) and its name, wrap the send key under the user key,
 * hash the optional password. Returns the request plus the raw send key, encrypted blob and name.
 */
export async function buildFileSendRequest(
  input: SendInput,
  fileName: string,
  fileBytes: Uint8Array,
  userKey: SymmetricKey,
  deps: SendCryptoDeps = {},
): Promise<{ request: SendRequest; sendKey: Uint8Array; encryptedFile: Uint8Array; encryptedFileName: string }> {
  const randomBytes = deps.randomBytes ?? ((n) => globalThis.crypto.getRandomValues(new Uint8Array(n)));
  const now = deps.now ?? Date.now;
  const sendKey = randomBytes(16);
  const derived = await deriveSendKey(sendKey);
  const encryptedFile = await encryptAttachmentFile(fileBytes, derived);
  const encryptedFileName = await encryptToText(fileName, derived);
  const request: SendRequest = {
    type: 1,
    name: await encryptToText(input.name || fileName, derived),
    key: await encryptToBytes(sendKey, userKey),
    deletionDate: new Date(now() + clampDays(input.deletionDays, 1, 31) * DAY_MS).toISOString(),
    file: { fileName: encryptedFileName },
    fileLength: encryptedFile.length,
    disabled: false,
    hideEmail: false,
  };
  if (input.maxAccessCount && input.maxAccessCount > 0) request.maxAccessCount = Math.trunc(input.maxAccessCount);
  if (input.expirationDays && input.expirationDays > 0) {
    request.expirationDate = new Date(now() + input.expirationDays * DAY_MS).toISOString();
  }
  if (input.password) request.password = await hashSendPassword(input.password, sendKey);
  return { request, sendKey, encryptedFile, encryptedFileName };
}
```

3e) 在 `decryptSend` 内，`if (send.type === 0 && send.text?.text) ...` 那行之后追加文件分支：

```ts
  if (send.type === 1 && send.file?.fileName) out.fileName = await safeDecrypt(send.file.fileName, derived);
  if (send.file?.sizeName) out.sizeName = send.file.sizeName;
```

并确保 `SendSummary` 构造对象包含 `type: send.type`（现有代码已含 `type`）。

- [ ] **Step 4: 运行确认通过**

Run: `npx vitest run src/core/vault/sends.test.ts`
Expected: PASS（含既有文本 Send 测试不回归）

- [ ] **Step 5: 提交**

```bash
git add src/core/vault/sends.ts src/core/vault/sends.test.ts
git commit -m "feat: build file Send request + decrypt type=1 (reuse EncArrayBuffer)"
```

---

## Task 3: client.ts — v2 上传两步

**Files:**
- Modify: `src/core/api/client.ts`
- Test: `src/core/api/client.test.ts`

**Interfaces:**
- Consumes: `SendRequest` / `SendFileUploadResponse`（Task 1）；现有 `jsonRequest` / `noBodyRequest`
- Produces:
  - `createSendFile(accessToken: string, send: SendRequest): Promise<SendFileUploadResponse>`（POST `/api/sends/file/v2`）
  - `uploadSendFileData(accessToken: string, url: string, data: Uint8Array, encryptedFileName: string): Promise<void>`（POST `/api{url}` multipart）

- [ ] **Step 1: 写失败测试**

在 `src/core/api/client.test.ts` 追加（该文件用 `new ApiClient({ serverUrlProvider, fetchFn, localStore })` 构造、已有 `jsonResponse` 辅助；无 `makeClient` 工厂）：

```ts
  it('createSendFile POSTs the send to /api/sends/file/v2 and returns the upload target', async () => {
    const fetchFn = vi.fn(async () => jsonResponse({ url: '/sends/s1/file/f1', sendResponse: { id: 's1' } }));
    const api = new ApiClient({ serverUrlProvider: async () => 'https://vw.example.com', fetchFn, localStore: createMemoryStore() });
    const res = await api.createSendFile('tok', { type: 1, name: '2.enc', key: '2.k', deletionDate: 'd' } as never);
    expect(String(fetchFn.mock.calls[0]![0])).toContain('/api/sends/file/v2');
    expect((fetchFn.mock.calls[0]![1] as RequestInit).method).toBe('POST');
    expect(res.url).toBe('/sends/s1/file/f1');
  });

  it('uploadSendFileData POSTs multipart data to /api{url}', async () => {
    const fetchFn = vi.fn(async () => new Response(null, { status: 200 }));
    const api = new ApiClient({ serverUrlProvider: async () => 'https://vw.example.com', fetchFn, localStore: createMemoryStore() });
    await api.uploadSendFileData('tok', '/sends/s1/file/f1', new Uint8Array([1, 2, 3]), '2.encname');
    const [calledUrl, init] = fetchFn.mock.calls[0]!;
    expect(String(calledUrl)).toContain('/api/sends/s1/file/f1');
    expect((init as RequestInit).method).toBe('POST');
    expect((init as RequestInit).body).toBeInstanceOf(FormData);
  });
```

> `ApiClient`/`createMemoryStore`/`jsonResponse` 在 `client.test.ts` 中均已就绪。

- [ ] **Step 2: 运行确认失败**

Run: `npx vitest run src/core/api/client.test.ts -t SendFile`
Expected: FAIL（方法未定义）

- [ ] **Step 3: 实现**

在 `src/core/api/client.ts` 的 `createSend` 方法之后新增（镜像 `createSend` 的 header 风格与 `uploadAttachment` 的 multipart 风格）：

```ts
  /** Create a file Send (v2): POST the metadata, get back where to upload the encrypted blob. */
  async createSendFile(accessToken: string, send: SendRequest): Promise<SendFileUploadResponse> {
    return this.jsonRequest<SendFileUploadResponse>('/api/sends/file/v2', {
      method: 'POST',
      headers: { authorization: `Bearer ${accessToken}` },
      body: JSON.stringify(send),
    });
  }

  /** Upload the encrypted Send file blob to the URL returned by createSendFile (multipart, 204). The
   *  multipart filename is the encrypted file name, mirroring the attachment upload. */
  async uploadSendFileData(accessToken: string, url: string, data: Uint8Array, encryptedFileName: string): Promise<void> {
    const form = new FormData();
    form.append('data', new Blob([data as BlobPart], { type: 'application/octet-stream' }), encryptedFileName);
    const path = url.startsWith('/api') ? url : `/api${url}`;
    await this.noBodyRequest(path, {
      method: 'POST',
      headers: { authorization: `Bearer ${accessToken}` }, // no content-type: browser sets the multipart boundary
      body: form,
    });
  }
```

并在文件顶部从 `./types.js` 的导入里加上 `SendFileUploadResponse`。

- [ ] **Step 4: 运行确认通过**

Run: `npx vitest run src/core/api/client.test.ts`
Expected: PASS

- [ ] **Step 5: 提交**

```bash
git add src/core/api/client.ts src/core/api/client.test.ts
git commit -m "feat: ApiClient.createSendFile + uploadSendFileData (v2 two-step)"
```

---

## Task 4: vault-service.createFileSend

**Files:**
- Modify: `src/core/vault/vault-service.ts`
- Test: `src/core/vault/vault-service.test.ts`

**Interfaces:**
- Consumes: `buildFileSendRequest` / `decryptSend`（Task 2）；`createSendFile` / `uploadSendFileData`（Task 3）；现有 `requireUserKey` / `requireToken` / `base64ToBytes`
- Produces: `createFileSend(input: SendInput, dataB64: string, fileName: string, serverUrl: string): Promise<SendSummary>`

- [ ] **Step 1: 写失败测试**

在 `vault-service.test.ts` 追加（`makeService` 的 `api` 桩需加 `createSendFile`/`uploadSendFileData`）：

```ts
  it('createFileSend encrypts the file, uploads via v2, and returns a decrypted summary', async () => {
    const { service, api } = await makeService();
    (api as any).createSendFile = vi.fn(async (_t: string, req: any) => ({ url: '/sends/s1/file/f1', sendResponse: { ...req, id: 's1', accessId: 'acc1', file: { id: 'f1', fileName: req.file.fileName, sizeName: '3 Bytes' } } }));
    (api as any).uploadSendFileData = vi.fn(async () => {});
    const dataB64 = btoa(String.fromCharCode(1, 2, 3));
    const summary = await service.createFileSend({ name: 'Doc', deletionDays: 7 }, dataB64, 'secret.pdf', 'http://localhost:8080');
    expect((api as any).createSendFile).toHaveBeenCalled();
    expect((api as any).uploadSendFileData).toHaveBeenCalledWith('access', '/sends/s1/file/f1', expect.any(Uint8Array), expect.any(String));
    expect(summary.type).toBe(1);
    expect(summary.fileName).toBe('secret.pdf');
    expect(summary.url).toContain('/#/send/acc1/');
  });
```

> 若 `makeService` 的 `api` 桩集中定义，最好把 `createSendFile`/`uploadSendFileData` 加进那个桩对象（与 `createSend` 并列），而非用 `(api as any)`。按文件实际结构择优。

- [ ] **Step 2: 运行确认失败**

Run: `npx vitest run src/core/vault/vault-service.test.ts -t createFileSend`
Expected: FAIL（方法未定义）

- [ ] **Step 3: 实现**

在 `createTextSend` 之后插入：

```ts
  /** Create a file Send: encrypt the file in the worker (EncArrayBuffer), upload via v2, return it
   *  decrypted with its access URL. The plaintext file never leaves the worker. */
  async createFileSend(input: SendInput, dataB64: string, fileName: string, serverUrl: string): Promise<SendSummary> {
    const userKey = await this.requireUserKey();
    const token = await this.requireToken();
    const fileBytes = base64ToBytes(dataB64);
    const { request, encryptedFile, encryptedFileName } = await buildFileSendRequest(
      input, fileName, fileBytes, userKey, this.deps.now ? { now: this.deps.now } : {},
    );
    const { url, sendResponse } = await this.deps.api.createSendFile(token, request);
    await this.deps.api.uploadSendFileData(token, url, encryptedFile, encryptedFileName);
    return decryptSend(sendResponse, userKey, serverUrl);
  }
```

并在顶部 `import { buildTextSendRequest, decryptSend, ... } from './sends.js';` 处加上 `buildFileSendRequest`。

- [ ] **Step 4: 运行确认通过**

Run: `npx vitest run src/core/vault/vault-service.test.ts`
Expected: PASS（整文件不回归）

- [ ] **Step 5: 提交**

```bash
git add src/core/vault/vault-service.ts src/core/vault/vault-service.test.ts
git commit -m "feat: VaultService.createFileSend (encrypt in worker, v2 upload)"
```

---

## Task 5: protocol + router — sends.createFile

**Files:**
- Modify: `src/messaging/protocol.ts`, `src/background/router.ts`
- Test: `src/background/router.test.ts`

**Interfaces:**
- Consumes: `createFileSend`（Task 4）
- Produces: 消息 `{ type: 'sends.createFile'; input: SendInput; dataB64: string; fileName: string }` → 响应 `{ ok: true; data: { send: SendSummary } }`

- [ ] **Step 1: protocol 加消息**

在 `src/messaging/protocol.ts` 的 `RequestMessage` 里，`sends.createText` 那行之后加：

```ts
  | { type: 'sends.createFile'; input: SendInput; dataB64: string; fileName: string }
```

（`SendInput`/`SendSummary` 已在 protocol 顶部从 sends.js 导入；`{ ok:true; data:{ send: SendSummary } }` 响应分支已存在，复用。）

- [ ] **Step 2: 写失败测试**

在 `src/background/router.test.ts` 追加（复用 Task-7 风格的 settings 内联桩）：

```ts
  it('routes sends.createFile to vault.createFileSend with the server URL', async () => {
    const createFileSend = vi.fn(async () => ({ id: 's1', url: 'u', name: 'Doc', type: 1 }));
    const settings = { getServerUrl: vi.fn(async () => 'http://localhost:8080'), saveServerUrl: vi.fn(), getDefaultUriMatchStrategy: vi.fn(async () => 0), saveDefaultUriMatchStrategy: vi.fn(), getLockTimeout: vi.fn(async () => '15'), saveLockTimeout: vi.fn() };
    const router = createRouter({ auth: {}, vault: { createFileSend } as never, settings: settings as never });
    const res = await router.handle({ type: 'sends.createFile', input: { name: 'Doc', deletionDays: 7 } as never, dataB64: 'AQID', fileName: 'secret.pdf' });
    expect(createFileSend).toHaveBeenCalledWith({ name: 'Doc', deletionDays: 7 }, 'AQID', 'secret.pdf', 'http://localhost:8080');
    expect(res).toEqual({ ok: true, data: { send: { id: 's1', url: 'u', name: 'Doc', type: 1 } } });
  });
```

- [ ] **Step 3: 运行确认失败**

Run: `npx vitest run src/background/router.test.ts -t createFile`
Expected: FAIL（分支缺失）

- [ ] **Step 4: 实现 router 分支**

在 `router.ts` 的 `case 'sends.createText':` 块之后插入（镜像 createText：读 serverUrl、未配置抛错）：

```ts
          case 'sends.createFile': {
            if (!deps.vault.createFileSend) throw new Error('vault.createFileSend is not wired');
            const serverUrl = await deps.settings.getServerUrl();
            if (!serverUrl) throw new AppError('error', 'Server URL is not configured');
            return { ok: true, data: { send: await deps.vault.createFileSend(request.input, request.dataB64, request.fileName, serverUrl) } };
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
git commit -m "feat: route sends.createFile"
```

---

## Task 6: popup — Text/File 切换 + 文件创建

**Files:**
- Modify: `src/ui/popup/popup.ts`

**Interfaces:**
- Consumes: `sends.createFile`（Task 5）；现有 `fileToBase64` / `createSend` / `renderSends`
- Produces: Sends 面板的 Text/File 切换与文件 Send 创建

> popup 无单测；验证门为 `npm run typecheck` + `npm run build` + 人工冒烟。

- [ ] **Step 1: 面板加 Text/File 切换与文件输入**

在 `renderSends` 的「New text Send」`ed-field` 顶部加一个分段切换，并把文本专属字段与文件专属字段分组（用一个隐藏的文件输入）。把 `<span class="ed-label">New text Send</span>` 起的块改为：

```html
        <div class="ed-field"><span class="ed-label">New Send</span>
          <div class="seg" role="tablist">
            <button id="send_mode_text" type="button" class="seg-btn is-active" role="tab">Text</button>
            <button id="send_mode_file" type="button" class="seg-btn" role="tab">File</button>
          </div>
          ${editorTextRow('send_name', 'Name', '')}
          <div id="send_text_fields">
            <label class="ed-field"><span class="ed-label">Text to share</span><textarea id="send_text" class="input ed-textarea"></textarea></label>
            <label class="gen-check"><input id="send_hidden" type="checkbox" /><span>Hide text by default</span></label>
          </div>
          <div id="send_file_fields" hidden>
            <label class="ed-field"><span class="ed-label">File to share</span><input id="send_file" type="file" class="input" /></label>
          </div>
          <input id="send_password" class="input" type="password" placeholder="Password (optional)" autocomplete="new-password" />
          <div class="ed-grid">
            ${editorTextRow('send_expiry', 'Expire in days (optional)', '')}
            ${editorTextRow('send_deletion', 'Delete in days', '7')}
            ${editorTextRow('send_max', 'Max views (optional)', '')}
          </div>
          <button id="send_create" type="button" class="btn btn-block">${icon('plus')}<span>Create Send</span></button>
        </div>
```

- [ ] **Step 2: 切换逻辑 + 模式状态**

在 `renderSends` 内、`send_create` 监听处附近加切换处理（用一个局部状态变量驱动显示）：

```ts
  let sendMode: 'text' | 'file' = 'text';
  const setSendMode = (mode: 'text' | 'file') => {
    sendMode = mode;
    document.getElementById('send_text_fields')!.hidden = mode !== 'text';
    document.getElementById('send_file_fields')!.hidden = mode !== 'file';
    document.getElementById('send_mode_text')!.classList.toggle('is-active', mode === 'text');
    document.getElementById('send_mode_file')!.classList.toggle('is-active', mode === 'file');
  };
  document.getElementById('send_mode_text')!.addEventListener('click', () => setSendMode('text'));
  document.getElementById('send_mode_file')!.addEventListener('click', () => setSendMode('file'));
  document.getElementById('send_create')!.addEventListener('click', () => void createSend(sendMode));
```

（删除原先 `document.getElementById('send_create')!.addEventListener(...)` 那一行——已被上面替换。）

- [ ] **Step 3: createSend 支持文件分支**

把 `createSend` 改为接收 mode 并在 file 模式走 `sends.createFile`：

```ts
async function createSend(mode: 'text' | 'file' = 'text'): Promise<void> {
  if (isPending) return;
  const val = (id: string): string => (document.getElementById(id) as HTMLInputElement | HTMLTextAreaElement).value;
  const baseInput: SendInput = { name: val('send_name').trim() || 'Send', deletionDays: Number(val('send_deletion')) || 7 };
  const pwd = val('send_password'); if (pwd) baseInput.password = pwd;
  const expiry = Number(val('send_expiry')); if (expiry > 0) baseInput.expirationDays = expiry;
  const max = Number(val('send_max')); if (max > 0) baseInput.maxAccessCount = max;

  let request: import('../../messaging/protocol.js').RequestMessage;
  if (mode === 'file') {
    const file = (document.getElementById('send_file') as HTMLInputElement).files?.[0];
    if (!file) return setDetailStatus('Choose a file to share', true);
    if (file.size > 100 * 1024 * 1024) return setDetailStatus('File is too large (max 100 MB)', true);
    request = { type: 'sends.createFile', input: { ...baseInput, name: val('send_name').trim() || file.name }, dataB64: await fileToBase64(file), fileName: file.name };
  } else {
    const text = val('send_text');
    if (!text) return setDetailStatus('Enter the text to share', true);
    request = { type: 'sends.createText', input: { ...baseInput, text, hidden: (document.getElementById('send_hidden') as HTMLInputElement).checked } };
  }

  isPending = true;
  document.querySelectorAll<HTMLButtonElement>('.detail button').forEach((b) => (b.disabled = true));
  try {
    const response = await sendRequest(request);
    if (!response.ok) return setDetailStatus(response.error.message, true);
    const send = (response.data as { send: SendSummary }).send;
    await copyValue(send.url, 'Send link');
    (document.getElementById('send_name') as HTMLInputElement).value = '';
    if (mode === 'text') (document.getElementById('send_text') as HTMLTextAreaElement).value = '';
    else (document.getElementById('send_file') as HTMLInputElement).value = '';
    await loadSends();
  } finally {
    isPending = false;
    document.querySelectorAll<HTMLButtonElement>('.detail button').forEach((b) => (b.disabled = false));
  }
}
```

- [ ] **Step 4: 列表显示文件名**

在 `renderSendList` 的每条 `s.name` 行，文件 Send 追加文件名/大小副标题。把 `<div class="k">...</div>` 下的 `v-row` 副标题改为含文件信息：

```ts
      <div class="v-row"><span class="sub">${s.type === 1 && s.fileName ? `📎 ${escapeHtml(s.fileName)}${s.sizeName ? ` · ${escapeHtml(s.sizeName)}` : ''} · ` : ''}Deletes ${escapeHtml(new Date(s.deletionDate).toLocaleDateString())}${s.maxAccessCount != null ? ` · ${s.accessCount}/${s.maxAccessCount} views` : ''}</span></div>
```

- [ ] **Step 5: 验证**

Run: `npm run typecheck`
Expected: 0 errors
Run: `npm run build`
Expected: `build done`
（人工冒烟见收尾。）

- [ ] **Step 6: 提交**

```bash
git add src/ui/popup/popup.ts
git commit -m "feat: create file Sends from the popup (Text/File toggle + file picker)"
```

---

## 收尾：人工验收

- [ ] `npm run build` → 加载 `dist/`，登录解锁。
- [ ] Sends 面板 → File → 选一个小文件、设删除天数（可加密码/过期/最大次数）→ Create → 分享链接已复制、列表出现该文件 Send（📎 文件名）。
- [ ] 文本 Send 仍可正常创建（不回归）。
- [ ] （里程碑 2 落地后用接收页对该链接做端到端解密往返；本里程碑暂以创建+列表为准。）

---

## 里程碑 2（单独成计划，本计划不含）

接收端访问页：`core/vault/send-access.ts`（parseSendUrl/accessSend/decryptAccessedSend/requestFileDownloadUrl/downloadAndDecryptFile）+ 独立 `ui/receive` 页 + popup「Receive a Send」入口 + `build.mjs` 入口 + `chrome.permissions.request` 跨服务器授权 + `LIVE=1` 端到端往返（建文件 Send → access → 下载解密）。

---

## Self-Review 结论

- **Spec 覆盖**（里程碑 1）：fileLength/上传响应类型→Task1；文件构造 + type=1 解密 + EncArrayBuffer 复用→Task2；v2 两步上传→Task3；worker 编排→Task4；protocol/router→Task5；popup Text/File→Task6。
- **占位符**：无 TBD/TODO；每个代码步骤含完整实现与测试（popup 任务以 typecheck/build + 冒烟为门，符合本项目 popup 无单测惯例）。
- **类型一致**：`SendFileUploadResponse`（Task1）在 Task3/4 一致引用；`buildFileSendRequest`/`decryptSend`/`SendSummary.fileName`（Task2）在 Task4/6 一致引用；`createFileSend`（Task4）在 Task5/6 一致引用；`sends.createFile` 消息形状全程一致。
- **复用而非重写**：文件加密复用 `encryptAttachmentFile`；popup 复用 `fileToBase64`；上传镜像 `uploadAttachment` 的 multipart；列表复用 `decryptSend`。
