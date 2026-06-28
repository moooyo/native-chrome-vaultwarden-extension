# 技术债登记（Tech Debt Register）

> 跟踪相对路线图（`docs/superpowers/specs/2026-06-27-vaultwarden-extension-m1-m3-foundation-design.md`）尚未交付/延后的工作。
> 本文随 RSA 私钥解密路径落地一并建立。代码标识符与路径保持英文。

## 已交付

- **组织条目（Organization cipher）解密** ✅（本次落地）
  - 链路：`Profile.organizations[].key`（encType=4 RSA-OAEP-SHA1 包裹）→ `keys.unwrapRsaWrappedKey`
    （内部 `parseRsaEncString` + `primitives.rsaOaepDecrypt`，账户私钥来自 `storage.session`）→
    组织 `SymmetricKey` → 用其解 `cipher.key` / 各字段。
  - `decrypt.buildOrgKeyMap(organizations, privateKey)` 把每个组织密钥解出并以 orgId 建图；
    `decryptCipher(cipher, userKey, orgKeys)` 对带 `organizationId` 的条目改用对应组织密钥为 base key。
  - `vault-service` 在 sync / 详情 / autofill 三处贯通组织密钥；组织登录项可参与自动填充。
  - `getSkippedOrgCount()` 现仅统计**密钥无法解包**的组织条目（如私钥被锁），UI 文案改为
    「N 个组织条目无法解密」。可解密的组织条目直接并入列表。

## 仍待实现 / 明确超范围

- **集合（Collection）分组与名称**：组织条目本身已可解密，但 `/sync` 的 `collections[]`
  （集合对象、加密名称、条目→集合归属）尚未建模，因此 UI 暂无按集合的分组/过滤。
- **Argon2id KDF**：需引入 WASM KDF。`prelogin`/登录成功两处守卫均抛
  `'Argon2id accounts are not supported in this MVP'`（`src/core/session/auth-service.ts`）。
- **注册（Registration）**：客户端账户密钥生成 + register 端点尚未实现。
- **encType=6 外层 HMAC 校验**：`parseRsaEncString` 可识别 encType 3/4/6，但只取 RSA 数据段；
  encType=6 的外层 `HMAC-SHA256` 暂不验证（组织密钥用 encType=4，不受影响）。
- **RSA-OAEP-SHA256（encType=3/5）**：`rsaOaepDecrypt` 目前固定 SHA-1（Vaultwarden 对 PrivateKey 包裹
  的组织密钥用 encType=4=SHA-1）。如遇 encType=3/5 需新增 SHA-256 变体。

## 路线图指针（按里程碑）

| 里程碑 | 内容 |
|---|---|
| M5 | ciphers/folders **CRUD** + 密码生成器（含生成历史）|
| M6 | **TOTP** 验证码生成 / 显示 / 填充 |
| M7 | **passkeys**（`fido2Credentials` 私钥，WebAuthn 独立签名）|
| M8 | **Sends** 分享 CRUD + 加密 |

## 路线图之外、但属 Bitwarden 客户端标配（建议纳入规划）

- Vault 导出 / 导入。
- PIN 解锁 / 生物识别解锁。
- 多账户切换。
- 密码健康报告 / HIBP 泄露检测。
- 等价域名（equivalent domains）。
- 紧急访问（emergency access）。
