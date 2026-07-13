# CLAUDE.md

本文件为本仓库提供给 Claude Code 的项目级指引。

## 项目概述

密屿 MiYu 是一个原生 Manifest V3 浏览器扩展，兼容 Bitwarden / Vaultwarden 服务端。
所有加密操作与库解密都在扩展本地完成，明文密钥只存在于 `storage.session`，锁定 / 登出
时清除。核心代码位于 `src/core`（crypto / vault / session / api），UI 在 `src/ui`，内容脚本
（自动填充、WebAuthn 桥接）在 `src/content`，后台 Service Worker 在 `src/background`。

## 实现范围决策（Scope decisions）

- **Argon2id KDF 暂不实现**。客户端目前仅支持 PBKDF2-HMAC-SHA256；遇到
  `kdf != 0`（Argon2id）的账户在 prelogin 与登录成功两处 **fail-close 抛错**
  （`src/core/session/auth-service.ts`），不静默降级。这是有意的范围边界，不是缺陷。
  - **影响**：用 Argon2id（Bitwarden 新账户默认值）创建的账户当前无法登录 / 解锁 / 注册。
  - **后续若要纳入**：引入 WASM 或纯 JS 的 Argon2 实现（如 `hash-wasm`），在
    `src/core/crypto/kdf.ts` 增加 `deriveMasterKey` 的 Argon2id 分支，并放开
    `auth-service` 的两处守卫。

## 测试

- 单元测试：`npm test`（vitest + happy-dom）。lint / typecheck / 生产构建见 README。
- **Live / e2e 测试需要你自己配置的一台 Vaultwarden 测试服务端，默认跳过。**
  通过环境变量提供 —— **切勿把真实服务器地址或账号凭据提交进仓库**：
  - `MIYU_SERVER`、`MIYU_EMAIL`、`MIYU_PASSWORD`
  - Live 测试：`LIVE=1 npx vitest run test/live/…`
  - e2e 冒烟：`npm run verify:e2e`
  - 自动填充测试数据：`npm run seed:testvault`（幂等，向 `MIYU_SERVER` 注入 localhost 匹配项）
  - 本地测试页：`npm run serve:testpage`（`http://localhost:8770`，用 `localhost` 名，passkey 才生效）

## 约定

- 用户对话用中文；代码、注释、文档、commit / PR、日志等仓库产物用英文。
- 版本号需在 `package.json` 与 `src/manifest.json` 保持一致（Chrome manifest 版本不能带
  预发布后缀）。发布由 git tag 触发，流程见 README 的 Release 一节。
