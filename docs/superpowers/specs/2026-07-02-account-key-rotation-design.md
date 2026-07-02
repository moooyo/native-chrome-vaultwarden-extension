# 全库密钥轮换（Account key rotation）设计 — v2（对抗性评审后重写）

> **v1 被 5 维对抗性评审（读 Vaultwarden 源码 + 客户端代码）判定会损坏库、全量不可行。** 本 v2 全面重写：核心正确、紧急访问/不可解条目 fail-close。**这是最高风险破坏性特性——一处重加密错误即永久损坏个人库。**

## 1. 目标与关键修正

生成**全新 UserKey**、重加密所有在 UserKey 下的账户级机密、原子更新服务端、重登记组织账户恢复；密码不变。

**评审驱动的关键修正（相对 v1）**：
- **重加密走 EncString/密钥层，绝不走 `decryptCipher→encryptCipher` 明文往返**（后者对 per-item key / passkey / 密码历史 / 附件 **有损、会永久损坏**）。
- **紧急访问 → fail-close**（不做重包）：服务端要求 emergency 数组是**所有 grantor 侧授权的超集**、且待确认/邮件邀请无公钥可取 → 全量重包不可能且不可测。有任一 grantor 侧授权即**拒绝轮换**。
- **成功后全量重登录**（服务端轮换 security stamp、旧 token 立即失效）。
- **超集约束**：服务端 `validate_keydata` 要求 payload 含**所有**自有个人条目/文件夹/Send（含回收站 trashed；缺一即 400、不删除）。
- **不可解 / 无法安全重包的条目 → fail-close 中止**（绝不发部分/损坏轮换）。

## 2. 范围

| 项目 | 处理 |
| --- | --- |
| 触发 | popup Security 编辑器（与改主密码同处，复用主密码输入 + `auth.*` 路由），强确认 |
| 重加密 | 个人条目（含 trashed，保留 deletedDate）、文件夹名、Send（重包 send key）、账户私钥 |
| 条目重加密方式 | **有 per-item key**：仅把 item key 原始字节 unwrap(old)→wrap(new)，字段/附件/passkey/历史密文**原样不动**。**无 key（keyless，本客户端创建的条目）**：对该条目在 UserKey 下的**每个 EncString 逐个 rewrap(old→new)**（通用、语义无关，覆盖 passkey/历史/自定义字段/附件 key）。 |
| 附件 | attachment key（EncString）随条目重包（keyed：在 item key 下、不动；keyless：随字段 rewrap），经 payload 的 `attachments2` 通道回传 |
| 组织恢复 | `profile.resetPasswordEnrolled` 的 org → `GET /api/organizations/{id}/keys` 公钥 → 新 UserKey 包 encType=4 → `{ organizationId, resetPasswordKey }` |
| **fail-close（拒绝轮换）** | ①任一 grantor 侧紧急访问授权（`GET /emergency-access/trusted` 非空）；②任一个人条目**不可解**（decrypt MAC 失败）；③自校验失败；④任一重包材料（org 公钥等）取不到；⑤Argon2 账户（既有守卫） |
| 成功后 | 更新本地全部会话材料 + **强制全量重登录** |
| 服务端 | 单一原子端点 `POST /api/accounts/key-management/rotate-user-account-keys`（旧 `/api/accounts/key` 404） |
| 不在范围 | 紧急访问重包、组织密钥轮换、改密码/改 KDF（已交付）、Argon2 |

## 3. 服务端契约（源码 + live 钉死）

端点/顶层 `KeyData` 见 v1 §4（已钉死，不变）。补充（评审自源码钉死）：
- `validate_keydata` 要求提供的 cipher/folder/send/emergencyAccess/reset id 集合 **⊇ 所有自有集合**（否则 400，**pre-mutation、不删除**）。org 条目按 `organization_uuid IS NULL` 排除在两侧——**org 条目不发、不受影响**。
- `accountData.ciphers` 项 = **`CipherData` + `id`**（+ `key`、`attachments2: { <attId>: { key, fileName } }`、`deletedDate`、`organizationId=null`）。精确形状由 plan 探针 + 源码钉死。
- `accountData.folders` 项 = `{ id, name }`；`accountData.sends` 项 = `SendData + id`（`key` = 重包后的 send key，其余字段密文原样）。
- `organizationAccountRecoveryUnlockData` 项 = `{ organizationId, resetPasswordKey }`（钉死）。`GET /api/organizations/{id}/keys` → `{ object:'organizationPublicKey', publicKey }`（钉死）。
- `accountPublicKey`：源为 **`GET /api/accounts/keys`**（返回存储的公钥）或从会话 PKCS8 私钥经 JWK 重建 SPKI（plan 择一钉死）。

## 4. worker 编排（`core/session/key-rotation.ts`，新）

1. **守卫**：登录 + 解锁 + `verifyMasterPassword`（注意 `verifyMasterPassword` 返回 bool 不抛，需自行判 false→抛错）；Argon2 已被登录守卫挡。
2. **fail-close 前置检查**：`GET /emergency-access/trusted` 非空 → 抛 `AppError('error','Remove your emergency-access contacts before rotating')`；有附件的账户仍轮换（附件 key 会重包，见 §2）。
3. **强制 fresh `sync()`** → 取当前完整原始密文集合（含 trashed）。
4. **生成新 UserKey**（64 随机字节）。
5. **重加密**（§2 方式；**通用 rewrap 原语** `rewrapEncString(enc, oldKey, newKey) = encryptToBytes(decryptToBytes(enc, oldKey), newKey)`）：
   - 个人条目：keyed→`cipher.key = rewrap(item key raw)`; keyless→逐 EncString rewrap（含 attachments[].key、fido2、history、fields、type-5 字段）。**decrypt 失败即抛（fail-close）**。保留 `id`/`deletedDate`。
   - 文件夹：`name = rewrap(name)`。
   - Send：`key = rewrap(send key)`，派生字段密文不动。
6. **包裹**：`masterKeyEncryptedUserKey = encryptToBytes(newUserKeyBytes, stretch(currentMasterKey))`（密码不变，`masterKeyAuthenticationHash` 原样重发）；`userKeyEncryptedAccountPrivateKey = rewrap(现私钥 PKCS8 到 newUserKey)`（或 `encryptToBytes(pkcs8, newUserKey)`）。
7. **组织恢复**：见 §2/§3。
8. **发送前严格自校验**：用**新 UserKey** 对每个重加密条目做**严格解密（失败即抛）**——keyed：unwrap 新 key 成功 + 抽解一字段；keyless：解每个 rewrap 后的 EncString；并校验私钥重包解回 PKCS8 与原一致。任一失败 → 中止、不 POST。
9. **POST** `KeyData`（原子）。非 2xx → 抛错、本地不变、可重试（超集/缺失类 400 提示「vault 在其它设备变更，请重新同步后重试」并自动 re-sync）。
10. **成功后**：写入新会话材料（新 protectedKey=masterKeyEncryptedUserKey、新 encPrivateKey=userKeyEncryptedAccountPrivateKey、新会话 UserKey、失效/清除 PIN 包裹块）；因服务端 security stamp 轮换、旧 token 已死 → **驱动全量重登录**（清 session、回登录页；重新登录自然拉到新材料，兼带自愈「响应丢失」情形）。

### 会话材料更新（评审 blocker：`updateMasterKeyMaterial` 不够）
新增 `SessionManager.applyRotatedKeys({ protectedKey, encPrivateKey, userKeyBytes })`：原子写 `PersistedAuth.protectedKey`+`encPrivateKey`、会话 UserKey、清 PIN 包裹块。（或直接走「成功即登出→重登录」，则无需在旧会话内热替换——更简单且避开 idle 竞争；见 §6 决策。）

## 5. 客户端 / 协议
- `ApiClient`：`rotateAccountKey(token, body)`；`getTrustedEmergencyAccess(token)`；`getOrganizationPublicKey(token, orgId)`；`getAccountPublicKey(token)`（若走 `/api/accounts/keys`）。
- crypto：`rewrapEncString`（新，`core/crypto` 或 `core/vault`）；对个人条目的 EncString 枚举/通用 rewrap 助手（`core/vault/rotate-cipher.ts`，纯函数、可单测）。
- `api/types.ts`：`OrganizationResponse` 加 `resetPasswordEnrolled?: boolean | null`。
- 协议/router：`{ type:'auth.rotateAccountKey'; masterPassword: string }` → `deps.auth.rotateAccountKey`（与 changeMasterPassword 同 `auth.*` 约定）。

## 6. UI（popup Security 编辑器）
- 与改主密码/改 KDF 同处（popup security 编辑器，复用当前主密码输入）。「Rotate encryption key」→ 强确认：说明「生成新加密密钥并重加密整个库；**完成后本设备与所有其它设备都需重新登录**；不可撤销；需主密码」。
- 若 `GET /emergency-access/trusted` 非空 → 提示「先移除紧急访问联系人再轮换」。
- 成功 → 走登出/重登录流（§4.10）。
- **决策点（plan 敲定）**：成功后「登出→重登录」（简单、避开 idle 竞争与热替换复杂度）vs 「热替换会话材料 + 后台标记」。推荐**登出→重登录**（旧 token 本就失效，最简且最安全）。

## 7. 安全 / 边界
- 原子服务端全或无；发送前**严格**自校验（失败即中止）；超集缺失/不可解/紧急授权/材料缺失一律 fail-close。
- 密钥/明文/私钥不出 worker；密码不变；`oldMasterKeyAuthenticationHash` 鉴权。
- **idle 竞争**：轮换期间不得被自动锁定清 UserKey——编排在 worker 内一次性持有 UserKey 完成；成功即登出（不再需要旧会话）。
- 无 reprompt 门（主密码已在 §4.1 验证一次；重加密走底层 rewrap，不经 service 的 reprompt 门）。
- 组织**条目**不重加密（org 密钥不受影响）；**恢复登记**重登记。

## 8. 需 plan 阶段 live 探针钉死（SSH 隧道已备）
1. **核心轮换端到端**（throwaway 单账户）：注册→建 keyless 条目（本客户端创建，含 login+card+自定义字段）+ 文件夹→**通用 rewrap** 重加密→POST→重登录→新 UserKey 严格解密验证往返、旧 key 失效。确认 `CipherData` 精确形状（id/key/deletedDate/attachments2）与「omit=拒绝非删除」。
2. **trashed 条目**：建条目→软删→轮换须含之且保持 trashed。
3. **组织恢复**：throwaway 建 org + 登记恢复 → 取 org 公钥 → 轮换含 recovery → 验证。
4. **附件**（若可）：建带附件条目→轮换→下载解密验证附件 key 重包（`attachments2`）。否则记为部分 + 单测。
5. **accountPublicKey 源**：`GET /api/accounts/keys` 响应形状 vs SPKI 重建。

## 9. 测试
- `rotate-cipher.test.ts`（纯，注入 key）：keyed 条目仅重包 key、字段密文不变；keyless 条目每个 EncString 被 rewrap 且新 key 严格解密还原；不可解字段→抛；trashed 保留；附件 key 重包；type-5/自定义字段/fido2/history 覆盖。
- `key-rotation.test.ts`（注入 fake api/session/crypto）：编排——fresh sync、私钥/UserKey 包裹、org 恢复组装、**严格自校验失败→不 POST**、紧急授权非空→fail-close、成功→写会话材料+触发重登录。
- `client.test.ts` / router / protocol：新端点 + `auth.rotateAccountKey` 分支。
- `LIVE=1`（`rotate.live.test.ts`）：§8.1 核心 + §8.2 trashed +（可行则）§8.3 org 恢复。紧急访问 = fail-close 单测（trusted 非空→拒绝）。
- typecheck + build + 人工冒烟。

## 10. 非目标
- 紧急访问重包（fail-close）、组织密钥轮换、改密码/改 KDF、Argon2、i18n、多设备主动登出（服务端 security stamp）。
