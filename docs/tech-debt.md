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

- **注册（Registration）** ✅（本次落地，真实服务端验证）：`crypto/registration.buildRegistration`
  客户端零知识生成随机 UserKey（包成 `key`）+ RSA-2048 keypair（公钥 SPKI、私钥用 UserKey 包成
  `encryptedPrivateKey`）+ `masterPasswordHash`；`ApiClient.register`→`POST /identity/accounts/register`；
  `AuthService.register` 注册后自动登录；popup 登录页「Create account」表单。live 测试注册→登录→建条目验证。

- **M7 passkeys** ✅（本次落地）：`vault/fido2.signFido2Assertion`（ES256 P-256，authenticatorData ‖
  SHA-256(clientDataJSON) 签名 + raw→DER；以公钥验签往返单测）；`decrypt` 解出 `login.fido2Credentials`
  （keyValue=PKCS8 base64url）；`VaultService.getPasskeyAssertion` 在 worker 内按 rpId/allowCredentials
  匹配并签名（私钥不过边界），摘要 `hasPasskey`、详情剥离 keyValue；MAIN world `page-webauthn` 包裹
  `navigator.credentials.get` + 隔离世界 `webauthn-bridge` 转发至 worker，无匹配则回退原生。
  仍待：`navigator.credentials.create`（注册新 passkey）、严格 `instanceof PublicKeyCredential` 的站点、计数器持久化。

## 安全缺陷（2026-06-28 完整性审计新发现）

> 由多代理完整性审计发现、并经代码核实的两处**安全回归**，不在原登记表内。优先级最高。

- **主密码二次验证（reprompt）解析但从不执行** 🔴 → **本次修复**
  - 原状：`cipher.reprompt`（0/1）在 `api/types.ts` 解析、`encrypt.ts` 编辑时保留，但
    `vault-service` 的 `getField`/`getTotpCode`/`getCipherInput`/`getAutofillCredentials` 均不校验，
    "查看前需主密码"的条目形同虚设。
  - 修复：worker 端在上述四处强制——reprompt 条目必须通过 `AuthService.verifyMasterPassword`
    校验主密码才释放机密，否则抛 `AppError('reprompt_required')`；`CipherSummary/DecryptedCipher/
    CipherInput` 新增 `reprompt` 布尔；编辑器新增「打开前需主密码」勾选；popup 详情/编辑在打开 reprompt
    条目前用可信扩展上下文（非页面）做主密码门；自动填充对 reprompt 条目**拒绝在页面内释放**，提示去扩展验证。
- **passkey 断言静默签名 + 谎报 userVerified** 🔴 → **本次修复**
  - 原状：`getPasskeyAssertion` 一旦匹配立即签名，无任何用户确认；`userVerified` 默认 `true` 且页面 shim
    不读取 `publicKey.userVerification`，UV 标志被无条件谎报。
  - 修复：`page-webauthn` 读取并透传 RP 的 `userVerification`；隔离世界 `webauthn-bridge` 在转发前弹出
    **用户同意确认**（closed shadow DOM），用户取消即回退原生；worker 不再硬编码 `userVerified`，按
    RP 要求与用户确认结果设置 UV 标志（`discouraged` → false）。

## 仍待实现 / 明确超范围

- **Argon2id KDF**（2026-06-28 明确决定暂不实现，已写入 `CLAUDE.md`）：需引入 WASM/纯 JS Argon2。
  `prelogin`/登录成功两处守卫均抛 `'Argon2id accounts are not supported in this MVP'`
  （`src/core/session/auth-service.ts`）。**这是单项最大的兼容性缺口**——Argon2 账户当前完全无法使用。

### 完整性审计缺口清单（2026-06-28，按优先级）

> 与 Bitwarden 官方客户端功能面对齐后的差距。⬆ 高 / ➖ 中 / ⬇ 低。

- ✅ **自定义字段（Text/Hidden/Boolean/Linked）**（已交付）：解密/显示（Hidden 按需揭示，reprompt 门控）
  /创建/编辑；Linked 只读保真。`encryptCipher` 写入、`mergeServerManagedFields` 不再盲带。
- ✅ **每条目密码历史 + passwordRevisionDate**（已交付）：改密时把旧密码 EncString 原样入史（上限 20）
  并更新修订时间；登录详情按需揭示（reprompt 门控）。
- ✅ **组织条目编辑修复 + 移动到组织（share）**（已交付）：`updateCipher` 改用组织密钥/每条目密钥加密并保留
  `organizationId`（修数据损坏）；`/api/ciphers/{id}/share` + 集合选择；带 passkey/历史的条目拒绝 share 以防丢数据。
  剩余：集合 CRUD、组织内改集合归属（move-without-org-change）。
- ✅ **保存/更新登录提示条**（已交付）：表单提交捕获 + 通知栏 + 页面驱动的 create/update。
- ✅ **Passphrase 生成器**（已交付）：内置词表 + 拒绝采样；生成器面板「Password/Passphrase」切换。
- ⬆ **2FA 扩展**（本次部分交付）：现支持所有**码型**提供方——Authenticator(0)/Email(1)/Duo passcode(2/6)/
  YubiKey OTP(3)，popup 提供选择器与按提供方提示。**仍待**：WebAuthn/FIDO2 安全密钥(7)（需托管 connector）、
  Duo push（异步轮询）、新设备 email OTP 提交、captcha/hCaptcha、SSO + Key Connector、设备批准/TDE、passwordless。
- ✅ **加密导出 + CSV/编码导入**（已交付）：密码保护导出（PBKDF2→HKDF stretch、encType=2 payload，Bitwarden
  格式）+ 加密导入（验证 MAC）；CSV 导入（Bitwarden CSV + 通用浏览器导出）；`parseImport` 自动识别 JSON/CSV。
  剩余：第三方专有格式（LastPass/1Password/KeePass 等）、CSV 卡/身份/自定义字段映射。
- ✅ **改主密码 / 改 KDF 迭代**（已交付）：重新包裹 UserKey（库不重新加密）+ 更新服务端与本地材料；
  KDF 迭代有下限保护。剩余：Argon2 目标 KDF（按范围暂忽略）、全库密钥轮换。
- ✅ **附件（attachments）**（已交付）：per-attachment key（库密钥包裹）+ EncArrayBuffer 文件格式；
  详情展示 + 按需下载解密（reprompt 门控）+ 上传（multipart，Vaultwarden 兼容）+ 删除。
- ✅ **Sends（文本 + 文件 + 接收端）**（已交付）：HKDF 多块派生 send key（`derive_shareable_key`）、文本/文件
  创建（文件经 send key 加密成 EncArrayBuffer、v2 两步上传）、列表/删除、密码哈希、分享链接（含 send key）。
  **接收端**（已交付，2026-06-30，里程碑 2；设计/计划见 `docs/superpowers/`）：独立 `ui/receive` 页 +
  `core/vault/send-access.ts`（parseSendUrl / 匿名 accessSend / decryptAccessedSend / 文件下载解密，注入 fetch、
  页面内无 vault 机密）；popup「Receive a Send」入口；跨服务器经 `chrome.permissions.request`；上传失败清理孤儿
  Send。协议经真实服务端实测固定（access 响应 `id`=sendId、下载 url 绝对），并有 `LIVE=1` 端到端往返测试。
  ✅ **编辑现有 Send**（已交付，2026-06-30）：`buildUpdateSendRequest` 复用现有 send key 重新加密改动字段、`PUT /api/sends/{id}`；popup 预填编辑视图。密码语义经真实服务端实测固定——保留＝省略字段、更改＝新客户端哈希、移除＝专用端点 `PUT /api/sends/{id}/remove-password`（`null`/`""` 不清除）；分享链接不变；文件 Send 仅元数据。有 `LIVE=1` 编辑往返测试。**Sends 特性至此全部完成（文本+文件+接收端+编辑）。**
- ✅ **Card/Identity 自动填充**（已交付，2026-06-30，两个里程碑；设计/计划见 `docs/superpowers/`）：
  - **M1 弹层填充**：`field-map`（autocomplete/name 提示→卡/身份角色，纯函数）+ `field-detection`（卡门槛＝有卡号；
    身份保守门槛＝地址信号或姓+名）+ `fill-card-identity`（合并 exp、月年下拉、`<select>` 匹配、全名合成）；
    worker `findFillItems`（列全部卡/身份，**无 URL 匹配**）/ `getFillData`（reprompt 门 + 剔除 SSN/护照/驾照）；
    弹层按 `kind` 泛化。CVC 渲染为 `type=password` 时抑制误挂登录弹层。
  - **M2 右键菜单**：`contextMenus` 权限 + `background/context-menu`（构建/重建、锁定/登出清空、onClicked 分发）+
    content `runtime.onMessage`（整表单 / 只填此字段，复用 M1 填充逻辑）+ reprompt 提示条；空闲自动锁定时刷新菜单。
  - **安全**：机密不入 content script、无 URL 匹配靠可信用户手势 + reprompt 门、身份国民 ID allowlist 剔除。
  - 剩余（小项）：reprompt 弹层锁徽标、菜单/提示文案 i18n、`nearestContainer` 跨模块去重。
- ⬆ **组织策略（policies）拉取与执行**；**全库密钥轮换**。
- ➖ 键盘快捷键（manifest `commands`）、
  **用户名/转发邮箱别名生成器**、HIBP 泄露检测、超时动作（锁定 vs 登出）、
  跨服务器多账户、集合 CRUD、i18n/`_locales`、生物识别解锁、徽章计数、账户指纹短语、Firefox 打包、
  Steam Guard TOTP、passkey 多凭据选择 UI。
- ➖ **空闲/自动锁定准确性**：靠 1 分钟轮询 `lastActivity`，且仅扩展消息更新它（非真实页面活动）；
  无 `chrome.idle`、无系统锁联动。**剪贴板自动清除**写死 60s、清除计时器在 popup 上下文（关闭即取消）。
- ➖ **记住设备 2FA token**：`remember` 传给 API 但返回的 token 从不捕获/回传，popup 也无勾选框。
- ⬇ passkey 注册（`navigator.credentials.create`）、`instanceof PublicKeyCredential`、WebAuthn 扩展
  （credProps/prf/largeBlob）、signCount 回写；encType 0/1 旧密文兼容解密；SSH-key(type 5) 编辑；
  Safari 打包；显式 CSP 收紧；同步 `/sync` profile 字段（securityStamp/策略/紧急访问等）。

## 路线图指针（按里程碑）

| 里程碑 | 内容 |
|---|---|
| M5 | ciphers/folders **CRUD** ✅ + 密码生成器 ✅（含生成历史）|
| M6 | **TOTP** 验证码生成 / 显示 / **填充** ✅（已完整交付）|
| M7 | **passkeys** ✅（已交付）：`fido2Credentials` 私钥解密 + WebAuthn 断言独立签名 |
| 注册 | 客户端账户密钥生成 + register 端点 ✅（已交付）|
| M8 | **Sends** 分享 CRUD + 加密 |

## 路线图之外、但属 Bitwarden 客户端标配（建议纳入规划）

- Vault 导出 / 导入 ✅（本次落地）：`vault/vault-io.ts`（Bitwarden 兼容未加密 JSON 的 `buildExportJson`
  / `parseImportJson`）；`VaultService.exportVault`（worker 内全量解密→明文 JSON，**显式用户操作**）
  / `importVault`（解析→逐条 createCipher→一次 sync）；popup 页脚「Export（二次确认明文）/ Import（选文件）」。
  剩余：加密导出（.json with password）、组织条目与文件夹关系的完整保真。
- PIN 解锁 ✅（本次落地）/ 生物识别解锁（仍待）：`AuthService.setPin/unlockWithPin/disablePin/
  isPinEnabled`——用 PIN 经 PBKDF2+stretch 派生 key 把 UserKey 包成 `pinProtectedUserKey` 存 local，
  解锁时反解（错误 PIN 触发 MAC 校验失败）。popup 页脚「PIN」设/删、锁屏在已设 PIN 时显示「Unlock with PIN」。
  **安全权衡**（已注释）：PIN 低熵，持久化的包裹块可离线暴力（PBKDF2 抬高成本），与上游 Bitwarden 一致。
- 多账户切换 ✅（本次落地）：`SessionManager` 附加账户注册表（`accounts` 映射，AUTH_KEY 仍是活动账户，
  向后兼容）；`listAccounts/switchAccount/removeAccount`（切换即锁定并清 PIN，由目标账户重新解锁）；
  `AuthService` 透传 + 路由/协议；popup 页脚「Accounts」列出/切换/移除/新增账户。
  剩余：跨**不同服务器**的多账户（当前假定同一自托管服务器）、每账户独立 PIN。
- 密码健康报告 ✅（本次落地）：`vault/password-health.ts`（启发式强度评分 + 重复计数）；
  `VaultService.getPasswordHealth` 在 worker 内解密所有登录密码、只回传「弱/重复次数」标记（密码不过边界）；
  popup 工具栏「健康」按钮列出弱/重复项，点击跳条目。剩余：HIBP 泄露检测（需联网 k-anonymity 查询）。
- 等价域名（equivalent domains）✅（本次落地）：`vault/equivalent-domains.ts` 内置常见等价组
  （google/youtube、amazon 各区、microsoft/live 等）+ 合并 `/sync` 的用户自定义组；`uri-match`
  的 Domain 策略在两域名属同一等价组时也算命中；vault-service 在两处 autofill 匹配处构建索引并传入。
- 紧急访问（emergency access）：**密码学核心已交付**——`primitives.rsaOaepEncrypt`（解密的对偶）+
  `session/emergency-access.grantEmergencyKey/recoverEmergencyKey`（授权人把 UserKey 包到受托人 RSA
  公钥=encType=4，受托人用私钥恢复；往返单测）。**仍待（专门里程碑，需第二账户 + 服务端）**：
  `/emergency-access` 端点（invite/accept/confirm/initiate/approve/takeover）、等待期状态机、UI。
