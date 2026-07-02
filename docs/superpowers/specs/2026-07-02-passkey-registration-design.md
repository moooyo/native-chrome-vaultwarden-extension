# Passkey 注册（`navigator.credentials.create`）设计

> 闭合已交付的 passkey **断言（get）** 能力。注册侧镜像断言路径：MAIN-world 包装 `create` → 隔离世界桥中转（候选查询 + 选择器同意）→ worker 生成 ES256 密钥对 + 造 attestationObject + 加密存 cipher → 回传 attestation 给页面构造 duck-typed `PublicKeyCredential`。

## 1. 目标 / 现状

- **目标**：站点调用 `navigator.credentials.create({publicKey})` 时，扩展可把新 passkey 存入 vault（新建登录条目 **或** 加到同域现有条目），并向站点返回合法的 attestation，使 RP 完成注册；此后该 passkey 可被已交付的断言路径使用。
- **现状（断言侧已交付，注册侧缺）**：`page-webauthn.ts` 只包 `get`（`create` 走原生，见其顶注「creation falls back to native」）；`vault-service` 有 `getPasskeyAssertion`/`hasMatchingPasskey`/`findPasskeyCredential`；`fido2.ts` 有 `signFido2Assertion`（ES256/P-256、DER 签名）；`encrypt.ts` 仅**原样携带**已有 `login.fido2Credentials`、不创建新的（`encrypt.ts:74`）。存储模型见 `Fido2CredentialData`（`api/types.ts:93`，全 EncString）与 `DecryptedFido2Credential`（`models.ts:99`）。

## 2. 组件 / 文件

- **新增 `src/core/crypto/cbor.ts`**：极简 CBOR **编码器**（仅 uint、负整数、byte string、text string、map；注册所需的固定形状）。附解码器仅用于测试（回验结构）。
- **新增 `src/core/vault/fido2-create.ts`**：注册侧加密。`generateFido2Keypair()`→{pkcs8(base64url), coseKey(bytes), credentialId(base64url,16 随机字节)}；`buildAttestationObject({rpId, coseKey, credentialId, userVerified})`→attestationObject(base64url)+authData(bytes)；`buildCreateClientDataJSON(challenge, origin)`。
- **改 `src/content/page-webauthn.ts`**：包装 `credentials.create`（镜像 `get`），校验 + 回退，成功时构造带 `AuthenticatorAttestationResponse` 的 duck-typed credential。
- **改 `src/content/webauthn-bridge.ts`**：中转 create（候选查询 → 选择器 → createPasskey → 回传）。
- **改 `src/content/passkey-consent.ts`**：新增注册选择器渲染（复用关闭式 shadow root + `isTrusted` 模式）。
- **改 `src/core/vault/vault-service.ts`**：`getPasskeyTargets(rpId)` + `createPasskey(params)`。
- **改 `src/messaging/protocol.ts` + `src/background/router.ts`**：2 条新消息。
- **可能改 `src/core/vault/models.ts`**：`getPasskeyTargets` 返回的候选类型（id/name/username）。

## 3. 数据流

```
页面 navigator.credentials.create({publicKey}) 
 → page-webauthn(MAIN, document_start):
    校验(见 §6 回退表)；提取 {rp.id, rp.name, user.id/name/displayName, challenge(b64url),
    pubKeyCredParams, excludeCredentials(b64url ids), authenticatorSelection.userVerification, origin}
    → postMessage 'vw-webauthn-create-request'
 → webauthn-bridge(隔离世界):
    ① excludeCredentials 非空 → vault.hasPasskey{rpId, allowedCredentialIds:excludeIds}；命中 → fallback(原生)
    ② vault.getPasskeyTargets{rpId} → [{id,name,username}]（同域现有登录条目，无机密）
    ③ 选择器(关闭式 shadow DOM)：标题「Save a passkey for <rpId>?」，选项＝New login item + 各候选 + Cancel
       取消/Esc/外点 → fallback(原生)
    ④ vault.createPasskey{rpId, rpName, userHandle(user.id b64url), userName, userDisplayName,
       challenge, origin, userVerification, targetCipherId?} 
    → 回传 'vw-webauthn-create-response' {credentialId, attestationObject, clientDataJSON}
 → page-webauthn: 构造 duck-typed PublicKeyCredential（response=AuthenticatorAttestationResponse）
```

- **UV 诚实**：`userVerified = userVerification !== 'discouraged'`（用户已在选择器确认＝用户在场/同意），worker 据此置 authData 的 UV 标志（同断言侧 `webauthn-bridge.ts:49-51`）。

## 4. Attestation 加密（`fido2-create.ts` + `cbor.ts`）

- **密钥对**：`subtle.generateKey({name:'ECDSA',namedCurve:'P-256'}, true, ['sign'])`；私钥 `exportKey('pkcs8')`→base64url 存 `keyValue`（与断言侧 `signFido2Assertion` 消费的格式一致）；公钥 `exportKey('raw')`（65 字节 `0x04‖x‖y`）取 x/y 各 32 字节。
- **COSE 公钥**（CBOR map，5 项）：`{1:2, 3:-7, -1:1, -2:<x 32B>, -3:<y 32B>}`（kty=EC2, alg=ES256, crv=P-256）。键为负整数（-1→CBOR `0x20`, -2→`0x21`, -3→`0x22`）。
- **credentialId**：`crypto.getRandomValues(new Uint8Array(16))`（16 字节；base64url 存储与返回）。
- **attestedCredentialData** = `AAGUID(16 个 0)` ‖ `credIdLen(uint16 BE)` ‖ `credId` ‖ `COSE公钥`。
- **authData** = `SHA-256(rpId)(32)` ‖ `flags(1)` ‖ `signCount(uint32 BE=0)` ‖ `attestedCredentialData`；`flags = UP(0x01) | (UV?0x04:0) | AT(0x40)`（含 AT，注册必带 attested cred data）。复用 `fido2.ts` 的 `buildAuthenticatorData` 思路但**追加** attestedCredentialData 段。
- **attestationObject** = CBOR map `{"fmt":"none","attStmt":{}(空 map),"authData":<bytes>}`（"none" 格式：Bitwarden 同款、password-manager 标准，RP 普遍接受、无需签名 attStmt）。
- **clientDataJSON** = `{"type":"webauthn.create","challenge":<b64url 原样>,"origin":<origin>,"crossOrigin":false}`（属性顺序与浏览器一致；`fido2.ts` 断言侧同风格）。

## 5. 存储（`vault-service.ts`）

- **`getPasskeyTargets(rpId)`**：要求已解锁 + 有缓存（否则抛 `locked`/`sync_required`，同 `findPasskeyCredential`）。遍历缓存登录条目（type===1，非 trashed），解密后按 **rpId 域匹配其 `login.uris`**（复用 `uri-match.ts` 的 host/域匹配逻辑，等价「rpId 为条目某 URI host 的可注册后缀或相等」）返回 `[{id, name, username}]`——**仅这三项**，密码/机密不过边界。
- **`createPasskey(params)`**：要求已解锁 + 有缓存。步骤：
  1. `generateFido2Keypair()` + `buildAttestationObject({rpId, coseKey, credentialId, userVerified})`。
  2. 组装明文 `DecryptedFido2Credential`-plus：`{credentialId, keyValue(pkcs8 b64url), rpId, counter:0, userHandle, userName?, rpName?}`；加密成 `Fido2CredentialData`（复用/新增 `encryptFido2Credential`，字段全 EncString；`keyType='public-key'`、`keyAlgorithm='ECDSA'`、`keyCurve='P-256'`、`discoverable='true'`、`counter='0'`、`userDisplayName?`）。
  3. **targetCipherId 存在**：从缓存取该 cipher（校验 type===1、非 trashed、属当前用户可写），把新 `Fido2CredentialData` **追加**到其 `login.fido2Credentials`（保留原有 passkey 及所有字段），走现有 update 路径（`encrypt.ts` 的 `mergeServerManagedFields` 会携带已有 passkey，注意新 passkey 需并入而非被携带覆盖——见 §8 风险）PUT `updateCipher`。
  4. **无 targetCipherId**：新建登录 cipher（`type:1, name: rpName || rpId, login:{ username: userName, uris:[{uri: 'https://'+rpId}], fido2Credentials:[新 Fido2CredentialData] }`）POST `createCipher`。
  5. **刷新 vault 缓存**（复用 `sync` 或把返回的 `CipherResponse` 并入缓存），使新 passkey 立即可被 `findPasskeyCredential` 断言。
  6. 返回 `{credentialId(b64url), attestationObject(b64url), clientDataJSON(b64url)}`。

## 6. 回退表（`page-webauthn.ts` 返回 `originalCreate(options)`；不破坏站点）

| 条件 | 处理 |
|---|---|
| 无 `options.publicKey` | 原生 |
| 非安全上下文 | 不包装（同 get） |
| `rpId`（`publicKey.rp.id ?? location.hostname`）非 `location.hostname` 的可注册后缀 | 原生 |
| `pubKeyCredParams` 不含 `alg === -7`（ES256） | 原生 |
| excludeCredentials 命中已存 passkey（bridge 探测 `vault.hasPasskey`） | 原生（避免重复注册，遵 WebAuthn §authenticatorMakeCredential 的 InvalidStateError 语义） |
| vault 锁定 / 无缓存（worker 抛 `locked`/`sync_required`） | 原生 |
| 用户在选择器取消/Esc/外点 | 原生 |
| 任意异常 | 原生（try/catch 包裹） |

## 7. 安全边界

- **私钥永不出 worker**：`fido2-create` 在 worker 生成密钥对；页面/桥仅见公开的 `attestationObject`/`clientDataJSON`/`credentialId`（`attestationObject` 内只含**公钥**）。
- **选择器候选无机密**：`getPasskeyTargets` 仅回 id/name/username（name/username 已在自动填充候选中暴露，同敏感度）；不回密码/passkey/私钥。
- **用户同意 = 用户在场**：注册前必过关闭式 shadow root 选择器 + `isTrusted` 真实点击（镜像断言侧 `passkey-consent.ts`）；页面脚本不可伪造。
- **诚实 UV**：仅 RP 非 `discouraged` 且用户确认时置 UV 标志（不无条件谎报，延续断言侧修复）。
- **excludeCredentials**：遵守以防在已注册设备上重复注册。
- **Argon2 超范围**；不改断言/reprompt/URL 匹配等 worker 既有守卫。

## 8. 已知风险 / 待评审重点

- **追加到现有 cipher 与 `mergeServerManagedFields` 的交互**（`encrypt.ts:74` 原样携带 `original.login.fido2Credentials`）：追加新 passkey 时须确保**并入**已有数组而非被「携带旧值」覆盖，且不重复加密已加密的旧项。需钉死 update 路径：worker 直接构造含「旧（已加密）+ 新（刚加密）」的完整 `fido2Credentials` 数组提交，绕开可能重复携带的合并逻辑。
- **CBOR 正确性**：COSE 负整数键（-1/-2/-3）与 map 长度、byte-string 长度前缀的编码必须精确；解码回验 + 真实 RP 冒烟兜底。
- **attestation "none" 的 authData**：AT 标志、AAGUID 全 0、credIdLen BE、COSE 键序（1,3,-1,-2,-3，CBOR canonical 顺序）。
- **duck-typed AttestationResponse 的字段**：`attestationObject`/`clientDataJSON`（ArrayBuffer）、`getAuthenticatorData()`/`getPublicKey()`/`getPublicKeyAlgorithm(-7)`/`getTransports([])`——RP 库多读这些；`instanceof PublicKeyCredential` 仍不成立（同 get 的已知限制）。
- **缓存刷新时机**：POST/PUT 后必须让缓存含新 passkey，否则「注册后立即断言」失败。
- **域匹配语义**：rpId 与条目 URI 的匹配须与断言侧 `findPasskeyCredential`（按精确 rpId 匹配 `cred.rpId`）自洽——注册写入的 `rpId` 与断言读取的 `rpId` 同源。

## 9. 测试

- **`cbor.test.ts`**：uint/负整数/byte/text/map 编码；COSE 键序；解码回验。
- **`fido2-create.test.ts`**：COSE 公钥结构（kty/alg/crv/x/y）；authData 布局（rpIdHash、flags=0x45(UP|UV|AT)、signCount0、AAGUID0、credIdLen、COSE）；attestationObject CBOR 解码回 `{fmt:'none',attStmt:{},authData}`；clientDataJSON 形状。**密钥对往返**：`generateFido2Keypair` → 用私钥经 `signFido2Assertion` 签一条断言 → 用从 attestation COSE 恢复的公钥 `subtle.verify` 验签通过（证明存的 `keyValue` 是可用真 passkey）。
- **`vault-service.test.ts`**：`getPasskeyTargets`（域匹配命中/不命中、只回 id/name/username、锁定/无缓存抛错）；`createPasskey`（新建 POST 请求形状含加密 fido2Credentials；追加到 target 保留已有字段+已有 passkey、不重复加密；缓存刷新后 `findPasskeyCredential` 能找到新 passkey；锁定抛错）。
- **`router.test.ts`/protocol**：`vault.getPasskeyTargets`、`vault.createPasskey` 转发 + 响应形状。
- **content**：`page-webauthn` create 包装回退条件（可单测的纯判定）；选择器渲染（`isTrusted`，镜像 `passkey-consent.test.ts`）。
- **人工浏览器冒烟（残余）**：对真实 RP（webauthn.io/真站）用扩展注册 passkey → 再用它登录（断言），验证 RP 接受我们的 attestation。CI 不可覆盖。
- **LIVE（可选）**：创建 passkey cipher → sync → 验证解密 + 断言路径找得到（服务端 cipher CRUD 往返，风险低）。

## 10. 非目标

- 非 ES256 算法（RS256 等）；packed/其它 attestation 格式；跨条目 passkey 管理 UI；PRF/largeBlob/credProps 扩展；signCount 服务端回写；`instanceof PublicKeyCredential` 兼容；conditional UI（`mediation`）。
