# 技术债登记（Tech Debt Register）

> 跟踪相对路线图（`docs/superpowers/specs/2026-06-27-vaultwarden-extension-m1-m3-foundation-design.md`）尚未交付/延后的工作。
> 本文随 RSA 私钥解密路径落地一并建立。代码标识符与路径保持英文。

## 已被 RSA 私钥解密解锁（可着手实现）

- **组织 / 集合（Organization / Collection）解密**
  - 组织条目携带一个 **RSA-OAEP 包裹**（encType=4）的组织对称密钥；账户的 RSA 私钥已可经
    `keys.decryptPrivateKey` + `primitives.rsaOaepDecrypt` 解出（PKCS8，存于 `storage.session`）。
  - 待实现的解包链：`Profile.Organizations[].Key` → `rsaOaepDecrypt(privateKey, orgKeyBlob)` →
    组织 `SymmetricKey` → 用其解 `cipher.key` / 各字段。
  - 现状：`src/core/vault/decrypt.ts` 仍对 `cipher.organizationId` 的条目返回 `undefined`（直接跳过）；
    `vault-service` 通过 `getSkippedOrgCount()` 暴露被跳过的数量，UI 提示「N 个组织条目暂不支持」。

## 仍被阻塞 / 明确超范围

- **Argon2id KDF**：需引入 WASM KDF。`prelogin`/登录成功两处守卫均抛
  `'Argon2id accounts are not supported in this MVP'`（`src/core/session/auth-service.ts`）。
- **注册（Registration）**：客户端账户密钥生成 + register 端点尚未实现。
- **encType=6 外层 HMAC 校验**：`parseRsaEncString` 可识别 encType 3/4/6，但只取 RSA 数据段；
  encType=6 的外层 `HMAC-SHA256` 暂不验证（待组织密钥解包时再处理）。
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
