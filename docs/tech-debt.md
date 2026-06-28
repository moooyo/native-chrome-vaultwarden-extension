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

- **对称加密原语 + 条目/文件夹（Cipher/Folder）CRUD** ✅（本次落地，原 M5 写入路径）
  - 写入地基：`primitives.aesCbc256Encrypt` + `encstring.encryptToBytes/encryptToText` 构造
    encType=2（AES-256-CBC + Encrypt-then-MAC、随机 IV，IV 可注入便于测试）。往返 + 防篡改 + 随机 IV 单测。
  - **条目 CRUD**：`vault/encrypt.encryptCipher`（明文 `CipherInput` → 密文请求，按
    login/note/card/identity 用「加密→`decryptCipher` 往返」验证）；`ApiClient.create/update/deleteCipher`
    （`POST/PUT/DELETE /api/ciphers`）；`VaultService.createCipher/updateCipher/deleteCipher`（worker 内
    用 UserKey 加密后上送、成功重新 sync）+ `getCipherInput`（解密为可编辑明文，含机密）；路由/协议贯通；
    popup 工具栏「+」新增（四类型选择器 + 表单，含密码生成/显隐）、详情页「编辑/删除」（内联二次确认）。
  - **文件夹 CRUD**：`ApiClient.create/update/deleteFolder`（`/api/folders`）；`VaultService` 编排；
    popup 文件夹栏内联编辑器。
  - **真实服务端验证**：`test/live/crud.live.test.ts`（`LIVE=1` 门控，默认跳过）对 CLAUDE.md 的测试
    Vaultwarden（2025.12.0）跑通 登录→建→sync→解密往返→改→删。
  - 仍待：个人条目之外的**组织条目编辑 / 软删除回收站 / SshKey(type=5) 编辑 / 多 URI 编辑**。

- **注册（Registration）** ✅（本次落地，真实服务端验证）
  - `crypto/registration.buildRegistration(email, password, iters)`：客户端零知识生成——随机 64B
    UserKey（用 stretched master key 包成 `key`）+ 新 RSA-2048 keypair（公钥 SPKI base64、私钥 PKCS8
    用 UserKey 包成 `encryptedPrivateKey`）+ `masterPasswordHash`。往返单测（UserKey 解包、RSA 公私钥配对）。
  - `ApiClient.register` → `POST /identity/accounts/register`（RegisterData）；`AuthService.register`
    生成密钥后注册并**自动登录**；路由 `auth.register`；popup 登录页「Create account」→ 注册表单
    （邮箱/姓名/主密码/确认，长度与一致性校验）。
  - **真实服务端验证**：`test/live/crud.live.test.ts` 注册全新账户→登录→建条目并在新账户密钥下解密成功。

## 仍待实现 / 明确超范围

- **Argon2id KDF**（按要求暂忽略）：需引入 WASM KDF。`prelogin`/登录成功两处守卫均抛
  `'Argon2id accounts are not supported in this MVP'`（`src/core/session/auth-service.ts`）。

## 路线图指针（按里程碑）

| 里程碑 | 内容 |
|---|---|
| M5 | ciphers/folders **CRUD** ✅ + 密码生成器 ✅（含生成历史）|
| M6 | **TOTP** 验证码生成 / 显示 / **填充** ✅（已完整交付）|
| M7 | **passkeys**（`fido2Credentials` 私钥，WebAuthn 独立签名）|
| 注册 | 客户端账户密钥生成 + register 端点 ✅（已交付）|
| M8 | **Sends** 分享 CRUD + 加密 |

## 路线图之外、但属 Bitwarden 客户端标配（建议纳入规划）

- Vault 导出 / 导入 ✅（本次落地）：`vault/vault-io.ts`（Bitwarden 兼容未加密 JSON 的 `buildExportJson`
  / `parseImportJson`）；`VaultService.exportVault`（worker 内全量解密→明文 JSON，**显式用户操作**）
  / `importVault`（解析→逐条 createCipher→一次 sync）；popup 页脚「Export（二次确认明文）/ Import（选文件）」。
  剩余：加密导出（.json with password）、组织条目与文件夹关系的完整保真。
- PIN 解锁 / 生物识别解锁。
- 多账户切换。
- 密码健康报告 ✅（本次落地）：`vault/password-health.ts`（启发式强度评分 + 重复计数）；
  `VaultService.getPasswordHealth` 在 worker 内解密所有登录密码、只回传「弱/重复次数」标记（密码不过边界）；
  popup 工具栏「健康」按钮列出弱/重复项，点击跳条目。剩余：HIBP 泄露检测（需联网 k-anonymity 查询）。
- 等价域名（equivalent domains）✅（本次落地）：`vault/equivalent-domains.ts` 内置常见等价组
  （google/youtube、amazon 各区、microsoft/live 等）+ 合并 `/sync` 的用户自定义组；`uri-match`
  的 Domain 策略在两域名属同一等价组时也算命中；vault-service 在两处 autofill 匹配处构建索引并传入。
- 紧急访问（emergency access）。
