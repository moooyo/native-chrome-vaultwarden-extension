# 记住设备 2FA token（Remember-device 2FA）设计 — v2（对抗性评审后重写）

> v1 被 4 维评审（读 Vaultwarden 1.35.0 Rust 源码）逮到 blocker：**服务端每次复用都轮换 remember token**，v1 只在提交时捕获→"记住"只生效一次即回退。本 v2 修正捕获位置与回退逻辑，并补齐登出后撤销、isDeviceRemembered、per-server 键。

## 1. 目标

2FA 登录「记住本设备」：捕获服务端设备 remember token 持久化，下次登录自动带上（`two_factor_provider=5` Remember）跳过 2FA；**服务端每次成功都轮换该 token**，客户端须每次同步新 token。现状：`remember` 已传但**成功响应的 token 从不捕获**，popup 无勾选框。

## 2. 已存在 vs 待建（评审澄清）

**已存在（勿重复加）**：`auth.submitTwoFactor` 协议已含 `remember?`（`protocol.ts:99`），router 已透传（`router.ts:47-56`），`AuthService.submitTwoFactor` 已接受并转发给 `passwordLogin`，`ApiClient` 已设 `two_factor_remember`（`client.ts:64-67`），且均有测试。**唯一捕获侧缺口**：popup 2FA 表单不发 `remember`（`popup.ts:279`）。

**待建**：token 持久化 + 捕获（含轮换）+ 复用/回退 + 撤销 UI + `isDeviceRemembered`。

## 3. 服务端机制（Vaultwarden 1.35.0 源码已核）

- 成功且 `remember==1` 时，服务端 `refresh_twofactor_remember()` 生成**新** 180 字节 token、存库、并在成功响应 `TwoFactorToken` 返回。
- **复用路径自动置 `remember=1`**：`TwoFactorType::Remember` 分支在 token 有效时强制 `remember=1`（源码注释「否则只记住第一次」），**覆盖**客户端发的 `two_factor_remember=0` → 每次复用都轮换并返回新 token。
- **成功响应的 `TwoFactorToken` 恒为设备 remember token**（email 类 2FA 的 token 只出现在 400 分支）。`remember==0` 时成功响应**无** `TwoFactorToken`。
- 复用失效 token → 服务端返回 400 twoFactor-required，其 `providers` 是**真实已启用**提供方列表（Remember=5 是虚拟的、**从不**出现在该列表）。
- Remember provider 号 = **5**。

## 4. 架构 / 组件

### 4.1 `SessionManager`（新 per-(server,email) token 存储）
新 local key `REMEMBER_TOKENS_KEY='rememberDeviceTokens'`，映射 `Record<key, token>`，`key = ${serverUrl}\n${emailLower}`（避免跨服务器重放——评审 minor）：
```ts
getRememberDeviceToken(serverUrl: string, email: string): Promise<string | undefined>;
saveRememberDeviceToken(serverUrl: string, email: string, token: string): Promise<void>;
removeRememberDeviceToken(serverUrl: string, email: string): Promise<void>;
listRememberedDevices(): Promise<Array<{ serverUrl: string; email: string }>>;   // 供登录屏撤销
```
- **跨登出/锁定存活**（不在 logout/lock 清）；`removeAccount(email)` 时按当前 serverUrl 连带清。email 由调用方 `trim().toLowerCase()`（沿用现有约定）。

### 4.2 `AuthService`
- **捕获（评审 blocker 修正）**：在 `finishPasswordLogin` 的 **success 分支**，`if (result.data.TwoFactorToken) await session.saveRememberDeviceToken(serverUrl, pending.email, result.data.TwoFactorToken)`——**按 token 存在与否捕获、不看 remember 入参**。理由：服务端仅在 remember 参与时才返回 token（首次勾选 / 复用自动轮换），故存在即应保存，天然覆盖**轮换**。（`serverUrl` 由 `settings.getServerUrl()` 或注入 dep 取。）
- **复用（`login`）**：`const remembered = await session.getRememberDeviceToken(serverUrl, email)`；有则首次 `passwordLogin({ ..., twoFactorProvider: 5, twoFactorToken: remembered, remember: true })`。
  - `success` → `finishPasswordLogin`（其 success 分支捕获**轮换后**的新 token）。
  - `twoFactor` 结果（失效）→ `await session.removeRememberDeviceToken(serverUrl, email)`，**直接把该结果喂给 finishPasswordLogin**（其 `providers` 已是真实挑战，**不再重发**——评审 important：重发多一轮 + 对 email-2FA 会发两封）。
  - **抛错**（非 twoFactor 的 400 / 5xx）→ **best-effort**：`removeRememberDeviceToken` 后**不带 token 重试一次** `passwordLogin`（保证回退到正常流程，评审 important）。
- **撤销**：`forgetDevice()` → 清当前账户 (serverUrl,email) token；`isDeviceRemembered(): Promise<boolean>` → 当前账户是否有 token。
- **无 token 的 fail-safe**：remember=true 但成功响应无 `TwoFactorToken` → 静默不存（下次仍提示 2FA），无副作用（评审 minor，明确为有意）。

### 4.3 协议 / router
- **勿重复**：`auth.submitTwoFactor` 的 remember 透传已存在。
- 新增：`{ type:'auth.forgetDevice' }` → `deps.auth.forgetDevice()`（响应 `{ok:true;data:null}`）；`{ type:'auth.isDeviceRemembered' }` → `{ ok:true; data:{ remembered:boolean } }`（评审：popup 撤销控件必须靠查询，非 login-result 标记）。

### 4.4 popup UI
- `renderTwoFactor`（`popup.ts:279`）：加 `<input type=checkbox id=tfRemember>`「Remember this device」；提交 `sendRequest({ type:'auth.submitTwoFactor', provider, code, remember: checked })`。
- **登录屏撤销**（评审 important：登出后账户已移出注册表、原撤销入口不可达）：登录屏在输入 email 后（或有任一 remember 记录时）显示「This device is remembered — Forget」→ `auth.forgetDevice`（对当前将登录的 email/server）或列出 `listRememberedDevices` 逐个清。已登录态：账户区显示「Forget this device」（gated on `auth.isDeviceRemembered`）。
- 文案英文。

## 5. 安全 / 边界
- remember token = **绕过 2FA 的设备凭据、跨登出持久化**——opt-in（勾选）。存 local，与 refresh_token 同级敏感度；非 vault 密钥、不出机密边界；不记日志、不显示 token 值。
- **每次复用轮换**：客户端在 success 分支同步新 token，保持与服务端一致（否则第二次即失效）。
- **失效 fail-safe**：失效/异常只回退到正常 2FA（非破坏性）；best-effort 复用确保任一失败都清 token + 回退。
- **可撤销**：登录屏 + 账户区双入口，登出后仍可 Forget（评审修正）。
- **per-(server,email) 键**：token 只回放给签发它的服务器。
- Argon2 超范围。

## 6. 需 live 探针 / SDD LIVE（经 SSH 隧道；测试账户须先启用 TOTP 2FA）
- **启用 TOTP**（源码钉死）：`POST /api/two-factor/authenticator`，body 需 `{ key:<base32 secret>, token:<用该 secret 现算的 6 位码>, masterPasswordHash }`（chicken-and-egg：用 `src/core/vault/totp.ts` 现算 code 作启用证明）；成功后账户启用 Authenticator(0)。
- **e2e**：登录触发 2FA → 提交 TOTP 码（`totp.ts` 生成）+ remember → 捕获 token → **重登录带 provider5** 跳过 2FA + **验证成功响应返回轮换后的新 token 且被捕获** → 再重登录仍跳过（证明轮换同步）。
- **清理**：`DELETE /api/two-factor/authenticator`（或禁用）+ 删账户，body 需 masterPasswordHash。
- LIVE 测试用临时 ApiClient 方法或原生 fetch（隧道）；复用 `totp.ts`。

## 7. 测试
- `session-manager.test.ts`：token get/save/remove、per-(server,email) 隔离、`removeAccount` 连带清、logout/lock **不**清、`listRememberedDevices`。
- `auth-service.test.ts`（注入 fake api/session）：**捕获**（success 带 TwoFactorToken→存，含轮换：第二次 success 存新 token；success 无 token→不存）；**复用**（有 token→首登带 provider5；success→跳过并存轮换 token；twoFactor→清 token + 直接用该结果、**不重发**；抛错→清 + 不带 token 重试一次）；`forgetDevice`/`isDeviceRemembered`。
- `router.test.ts` / protocol：`auth.forgetDevice`、`auth.isDeviceRemembered`（submitTwoFactor remember 已测，勿重复）。
- `LIVE=1`（`remember-2fa.live.test.ts`）：§6 e2e。
- popup：typecheck + build + 人工冒烟。

## 8. 非目标
- Argon2、非 remember 类 2FA、跨设备信任管理列表 UI（仅提供 forget）、服务端过期策略呈现、i18n。
