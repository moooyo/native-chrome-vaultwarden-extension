# 技术债登记（Tech Debt Register）

> 跟踪相对路线图（`docs/superpowers/specs/2026-06-27-vaultwarden-extension-m1-m3-foundation-design.md`）尚未交付/延后的工作。
> 本文随 RSA 私钥解密路径落地一并建立。代码标识符与路径保持英文。

## 已交付

- **密码生成器（Password generator）** ✅（本次落地，原 M5 的一部分）
  - `src/core/generator/password.ts`：Bitwarden 风格生成——保证每个启用字符集至少一个、满足
    数字/特殊字符的最小数量，其余位用 `crypto.getRandomValues`（拒绝采样去偏）填充后洗牌；
    可选「避免易混字符」(Il1O0)。随机源可注入以便确定性单测。
  - popup 工具栏新增生成器面板（长度/字符集开关、重新生成、复制）；纯本地运行，不涉及 vault 密钥。
  - **生成历史**（本次落地）：`core/generator/history.ts` 纯函数维护「最近优先、去重、上限 50」的列表；
    popup 面板在「重新生成 / 复制」时记录，逐条可复制、可清空。**仅驻内存**（popup 生命周期），
    绝不持久化——明文生成密码不落 `storage`，符合安全红线；登出即清。

- **TOTP 验证码生成 / 显示 / 自动填充** ✅（原 M6 已完整交付）
  - `src/core/vault/totp.ts`：RFC 6238 TOTP（HMAC-SHA1/256/512、可配 digits/period），
    支持裸 base32 密钥与 `otpauth://` URI；用 RFC 6238 Appendix B 标准向量做单测。
  - 密钥只在 worker 内解密：`vault-service.getTotpCode(id)` 仅把 6 位码 + 周期 + 剩余秒数过边界；
    `CipherSummary.hasTotp` 只暴露「是否有 TOTP」的布尔，不含密钥。
  - 路由 `vault.getTotp`；popup 登录详情展示验证码 + 倒计时（窗口翻转时自动取下一码），可复制。
  - **自动填充**（本次落地）：`form-detection` 识别一次性验证码字段（`autocomplete="one-time-code"`
    或 otp/2fa/verification-code 等名称提示），既能在登录表单内识别 TOTP 字段，也能识别**独立的
    二步验证页**（仅验证码字段）；`getAutofillCredentials` 在 worker 内现算当前验证码，密钥不过边界；
    `fill.ts` 把验证码写入 OTP 字段。仍待：暂无独立「仅 TOTP」候选的优先级排序（候选仍按 URI 匹配排序）。

- **组织条目（Organization cipher）解密** ✅（本次落地）
  - 链路：`Profile.organizations[].key`（encType=4 RSA-OAEP-SHA1 包裹）→ `keys.unwrapRsaWrappedKey`
    （内部 `parseRsaEncString` + `primitives.rsaOaepDecrypt`，账户私钥来自 `storage.session`）→
    组织 `SymmetricKey` → 用其解 `cipher.key` / 各字段。
  - `decrypt.buildOrgKeyMap(organizations, privateKey)` 把每个组织密钥解出并以 orgId 建图；
    `decryptCipher(cipher, userKey, orgKeys)` 对带 `organizationId` 的条目改用对应组织密钥为 base key。
  - `vault-service` 在 sync / 详情 / autofill 三处贯通组织密钥；组织登录项可参与自动填充。
  - `getSkippedOrgCount()` 现仅统计**密钥无法解包**的组织条目（如私钥被锁），UI 文案改为
    「N 个组织条目无法解密」。可解密的组织条目直接并入列表。

- **RSA EncString 哈希套件（encType 3/4/5/6）** ✅（本次落地）
  - `primitives.rsaOaepDecrypt(privateKey, data, hash)` 接受 OAEP 哈希参数；`unwrapRsaWrappedKey`
    按 encType 选哈希——encType 3/5（`Rsa2048_OaepSha256*`）用 SHA-256，4/6（`Rsa2048_OaepSha1*`）用 SHA-1。
  - `parseRsaEncString` 现识别 encType 3/4/5/6，对 5/6 把外层 `HMAC-SHA256` 解析进 `mac` 字段。
  - 以「复用同一 RSA 私钥包裹同一组织密钥」的 encType=3 向量做单测（见 `test/vectors.ts` 与 `tools/gen-vectors.mjs`）。
  - **边界（按设计）**：RSA EncString 的外层 MAC **有意不验证**——非对称（公钥）加密无收发双方共享的
    MAC 密钥，完整性来自 RSA-OAEP 填充（与上游 Bitwarden 一致：RSA 类型不校验 MAC）。组织密钥用
    encType=4，HMAC 变体在 Vaultwarden 中本就罕见。

- **集合（Collection）分组与名称** ✅（本次落地）
  - `/sync` 的 `collections[]` 与 cipher 的 `collectionIds[]` 已建模（`api/types.ts`）。
  - `decrypt.decryptCollections(collections, orgKeys)`：集合名用**组织密钥**解密；组织密钥不可用时
    跳过该集合（其条目本就被跳过），名称解密失败则降级为 `(undecryptable)`。
  - `vault-service` 在 sync 时解出集合、缓存、并把 `collectionIds` 带进条目摘要；`VaultListing`
    新增 `collections`。`search.filterByCollection` + `filterSummariesByFolderCollectionAndQuery`
    组合「文件夹 × 集合 × 文本」过滤。popup 新增集合下拉过滤（仅在存在集合时显示），登出即清。

- **对称加密原语 + 文件夹（Folder）CRUD** ✅（本次落地，原 M5 写入路径的第一段）
  - 写入地基：`primitives.aesCbc256Encrypt` + `encstring.encryptToBytes/encryptToText` 构造
    encType=2（AES-256-CBC + Encrypt-then-MAC、随机 IV，IV 可注入便于测试）。这是注册与 M5/M8
    其余 CRUD 的共同前置（此前代码库只有解密）。往返 + 防篡改 + 随机 IV 单测。
  - `ApiClient.createFolder/updateFolder/deleteFolder`（`POST/PUT/DELETE /api/folders`，Bearer，
    DELETE 容忍空响应体）；mock fetch 单测。
  - `VaultService.createFolder/renameFolder/deleteFolder`：名称在 worker 内用 UserKey 加密后上送，
    成功后整库重新 `sync` 刷新缓存并回传 `VaultListing`；锁定时拒绝。
  - 路由 `vault.createFolder/renameFolder/deleteFolder`；popup 文件夹栏新增「新建 / 重命名 / 删除」
    内联编辑器（Enter 提交、Esc 取消、删除二次确认）。
  - 仍待：**条目（cipher）CRUD**（各类型字段的新增/编辑/删除/移动文件夹）。

## 仍待实现 / 明确超范围

- **条目（Cipher）CRUD**：写入地基（对称加密）已就绪，但登录/卡片/身份/备注各类型字段的
  新增/编辑/删除、`/ciphers` 端点与表单 UI 尚未实现。
- **Argon2id KDF**：需引入 WASM KDF。`prelogin`/登录成功两处守卫均抛
  `'Argon2id accounts are not supported in this MVP'`（`src/core/session/auth-service.ts`）。
- **注册（Registration）**：客户端账户密钥生成 + register 端点尚未实现（对称加密原语已具备，
  仍需随机 UserKey 生成、RSA keypair 生成与私钥包裹、register 契约）。

## 路线图指针（按里程碑）

| 里程碑 | 内容 |
|---|---|
| M5 | folders **CRUD** ✅ + 密码生成器 ✅（含生成历史）；剩余：ciphers **CRUD** |
| M6 | **TOTP** 验证码生成 / 显示 / **填充** ✅（已完整交付）|
| M7 | **passkeys**（`fido2Credentials` 私钥，WebAuthn 独立签名）|
| M8 | **Sends** 分享 CRUD + 加密 |

## 路线图之外、但属 Bitwarden 客户端标配（建议纳入规划）

- Vault 导出 / 导入。
- PIN 解锁 / 生物识别解锁。
- 多账户切换。
- 密码健康报告 / HIBP 泄露检测。
- 等价域名（equivalent domains）。
- 紧急访问（emergency access）。
