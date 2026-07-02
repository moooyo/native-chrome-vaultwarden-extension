# Passkey 注册（`navigator.credentials.create`）设计 — v2（对抗性评审后重写）

> v1 被 4 维评审（读真源码 + WebAuthn/CTAP2）逮到多个 blocker：**信任边界在可绕过的 MAIN world（跨域伪造，连累已交付断言路径）**、**无 PSL**、**追加到现有条目的密钥错配→整条目不可解密→毒化所有断言**、**「走 update 路径」丢失新 passkey**。v2 把信任边界移到 worker（PSL 校验，兼修已交付 get 路径），并钉死追加/加密/响应/回退/BE-BS。

## 0. 范围（含对既有代码的必要加固）

- **主体**：拦截 `navigator.credentials.create`，生成 ES256 passkey、造 attestation、存 vault（新建 or 追加同域个人登录条目）、返回给页面。
- **连带加固（评审驱动，触及已交付断言路径）**：
  1. **信任边界移到 worker**：桥（isolated world）从自身 `location` 盖 `origin`；worker 用 PSL 校验 `rpId ⊆ origin.host`。修复 get/create 共有的跨域伪造漏洞。
  2. `fido2.ts` 断言 authData **补 BE/BS 标志**（与注册一致，WebAuthn L3 §6.1.3）。
  3. `findPasskeyCredential` **加 per-cipher try/catch**（一个不可解密条目不得毒化所有断言）。
  这些是评审在既有代码中发现的真实安全/健壮缺陷，注册特性会复制它们，故一并修好共享边界。

## 1. 组件 / 文件

- **改 `src/core/vault/domain.ts`**：导出 `isRegistrableRpId(rpId, host): boolean` —— `(host===rpId || host.endsWith('.'+rpId))` 且 `getBaseDomain(rpId)` 存在且 `=== getBaseDomain(host)`（PSL 经 tldts；拒绝裸公共后缀如 `github.io`）。worker 侧用（tldts 已在 core，不进 content bundle）。
- **新增 `src/core/crypto/cbor.ts`**：极简 CBOR **编码器**（uint / 负整数 / bstr / tstr / map）；解码器仅测试用。
- **新增 `src/core/vault/fido2-create.ts`**：`generateFido2Keypair()`、`buildAttestationObject(...)`、`buildCreateClientDataJSON(...)`（详见 §4）。
- **改 `src/core/vault/fido2.ts`**：`buildAuthenticatorData` 的 flags 补 `BE(0x08)|BS(0x10)`（断言侧同步；见 §4/§10）。
- **改 `src/content/webauthn-bridge.ts`**：get + create 都从 `location` 盖 `origin`、门 `isSecureContext`；create 中转（候选查询 → 选择器 → createPasskey）。
- **改 `src/content/page-webauthn.ts`**：包 `create`（校验 + 回退 + 构造 duck-typed credential）。
- **改 `src/content/passkey-consent.ts`**：新增注册选择器渲染。
- **改 `src/core/vault/vault-service.ts`**：`getPasskeyTargets` + `createPasskey`；四个 passkey 方法都经 `assertRpIdForOrigin`；`findPasskeyCredential` 加 try/catch。
- **改 `src/core/api/client.ts`**：可能需要 `putCipherRaw(token, id, CipherRequest)`（直传原始请求、绕开 mergeServerManagedFields）——见 §5。
- **改 `src/messaging/protocol.ts` + `src/background/router.ts`**：2 条新消息 + 既有 passkey 消息补 `origin`。
- **改 `src/core/vault/models.ts`**：`PasskeyTarget = { id; name; username? }`。

## 2. 信任边界（评审 blocker #1/#2 修复）

- **桥是唯一可信来源**（页面不能直连 worker：manifest 无 `externally_connectable`；页面只能 postMessage 到 window 被桥接收）。故桥**必须**用自身上下文的值、不信 payload：
  - `origin = location.origin`（**覆盖** payload.origin）；`isSecureContext` 为假 → 回退。
  - `rpId` 取自 payload（RP 的声明），但**不在桥里信任**——转给 worker 由 PSL 校验。
- **worker `assertRpIdForOrigin(rpId, origin)`**：`const host = new URL(origin).hostname; if (!isRegistrableRpId(rpId, host)) throw AppError('error','rpId not valid for origin')`。**getPasskeyAssertion / hasMatchingPasskey / getPasskeyTargets / createPasskey 四者入口都调**。恶意页面即便伪造 payload.rpId，也会因 rpId 非 `location.hostname`（桥盖的真实 host）的可注册后缀而被拒。
- 既有 `vault.hasPasskey`/`vault.getPasskeyAssertion` 已有/需补 `origin`；`hasPasskey` 增 `origin` 字段。MAIN world 的朴素 `isRegistrableSuffix` 保留仅作**原生回退的快判**（非安全边界）。

## 3. 数据流（create）

```
页面 create({publicKey}) → page-webauthn(MAIN):
  校验(§6) → postMessage 'vw-webauthn-create-request' {rpId:publicKey.rp.id??host, rpName, userHandle:user.id(b64url),
    userName:user.name, userDisplayName:user.displayName, challenge(b64url), pubKeyCredParams, excludeIds(b64url[]),
    userVerification, authenticatorAttachment}
→ webauthn-bridge(isolated):
  origin=location.origin; if(!isSecureContext) fallback
  ① excludeIds 非空 → vault.hasPasskey{rpId, origin, allowedCredentialIds:excludeIds}; 命中 → fallback(原生)  // best-effort 去重
  ② vault.getPasskeyTargets{rpId, origin} → {targets:[{id,name,username}]}(同域个人登录, 无机密)
  ③ 选择器(关闭式 shadow DOM, isTrusted): 「Save a passkey for <rpId>?」 New login item + 各候选 + Cancel
     取消/Esc/外点/AbortSignal → fallback(原生)
  ④ vault.createPasskey{rpId, rpName, userHandle, userName, userDisplayName?, challenge, origin, userVerification, targetCipherId?}
  → {registration:{credentialId, attestationObject, clientDataJSON, authData, publicKeySpki, publicKeyAlgorithm:-7}}
  → postMessage 'vw-webauthn-create-response'
→ page-webauthn: 构造 duck-typed PublicKeyCredential（response=AuthenticatorAttestationResponse，见 §5.6）
```
- **UV 诚实**：`userVerified = userVerification !== 'discouraged'`（用户已在选择器确认）。

## 4. Attestation 加密（`fido2-create.ts` + `cbor.ts`）

- **密钥对**：`generateKey({name:'ECDSA',namedCurve:'P-256'}, true, ['sign'])`；私钥 `exportKey('pkcs8')`→base64url 存 `keyValue`；公钥 `exportKey('raw')`→65B `0x04‖x‖y`，取 x/y 各 32B；另 `exportKey('spki')`→SPKI DER（回给页面 getPublicKey）。
- **COSE 公钥**（CBOR map，键按 CBOR 规范：正整数在前、负整数在后）：`{1:2, 3:-7, -1:1, -2:bstr(x,32), -3:bstr(y,32)}`。负整数键编码：-1→`0x20`, -2→`0x21`, -3→`0x22`。
- **credentialId** = `getRandomValues(new Uint8Array(16))`。
- **attestedCredentialData** = `AAGUID(16 个 0)` ‖ `credIdLen(uint16 BE)` ‖ `credId` ‖ `COSE公钥`。
- **authData** = `SHA-256(rpId)(32)` ‖ `flags(1)` ‖ `signCount(uint32 BE=0)` ‖ `attestedCredentialData`；
  **flags = UP(0x01) | AT(0x40) | BE(0x08) | BS(0x10) | (UV?0x04:0)** = `0x5D`(含 UV) / `0x59`(无 UV)。同步 passkey 天然 backup-eligible + backed-up。
- **attestationObject** = CBOR map `{"fmt":"none","attStmt":{}(空 map),"authData":bstr}`。
- **clientDataJSON** = `{"type":"webauthn.create","challenge":<b64url 原样>,"origin":<桥盖的 origin>,"crossOrigin":false}`。
- **`fido2.ts` 断言侧同步**：`buildAuthenticatorData` 的 flags 补 `BE|BS`（get 无 AT）：`UP|BE|BS|(UV?UV)`，与注册的 BE/BS 一致（WebAuthn L3 §6.1.3 要求 BE 跨注册/断言不变）。加断言 flags 测试。

## 5. 存储（`vault-service.ts`）

- **`getPasskeyTargets({rpId, origin})`**：`assertRpIdForOrigin` → 要求解锁+缓存 → 遍历缓存**个人**（无 organizationId）type===1 非 trashed 登录，解密摘要按 `isRegistrableRpId(rpId, uriHost)` 匹配其 `CipherSummary.loginUris`（避免重复整解密），回 `[{id, name, username}]`——仅此三项。
- **`createPasskey(params)`**：`assertRpIdForOrigin` → 要求解锁+缓存。步骤：
  1. `generateFido2Keypair()` + `buildAttestationObject({rpId, coseKey, credentialId, userVerified})`。
  2. **确定加密密钥**：新建路径用账户 UserKey；追加路径用 `cipherFieldKey(original)`（per-cipher key if `original.key` else UserKey）。
  3. 明文 cred `{credentialId, keyValue(pkcs8 b64url), rpId, counter:0, userHandle, userName?, rpName?}` → 加密成 `Fido2CredentialData`（全 EncString；`keyType='public-key'`, `keyAlgorithm='ECDSA'`, `keyCurve='P-256'`, `discoverable='true'`, `counter='0'`, `userDisplayName?`）。
  4. **targetCipherId 存在（追加）**：
     - **worker 侧重新解析目标**：`target = getPasskeyTargets(rpId).find(id===targetCipherId)` 命中方可（评审安全 #: 不信 content-script 传的 id；且必须是同域个人可写登录）；否则抛错。
     - 从**原始 `CipherResponse` 逐字构造 `CipherRequest`**（name/username/password/uris/key/passwordHistory/fields 等全部原样 EncString），设 `login.fido2Credentials = [...original.login.fido2Credentials(原样), 新Fido2CredentialData]`，**PUT 原始请求**（`api.updateCipher` 直传该 request，**不经** `encryptCipher`/`mergeServerManagedFields`；若现有 `updateCipher(token,id,request)` 已是直传 CipherRequest 则复用，否则加 `putCipherRaw`）。
  5. **无 targetCipherId（新建）**：`{type:1, name: rpName||rpId, login:{ username:userName, uris:[{uri:'https://'+rpId}], fido2Credentials:[新Fido2CredentialData] }}` → `api.createCipher`。
  6. **原子/缓存**（评审 blocker #8）：POST/PUT 返回 `CipherResponse` 后，**把它合并进 VAULT 缓存**（替换/插入该 id），**不**再单独 `sync()`（sync 失败会抛→页面回退原生→孤儿+幻影）。合并失败也不影响已成功的服务端写——**写成功即返回 attestation**。
  7. 返回 `{credentialId(b64url), attestationObject(b64url), clientDataJSON(b64url), authData(b64url), publicKeySpki(b64url), publicKeyAlgorithm:-7}`。
- **`findPasskeyCredential` 加固**：循环内 `decryptCipher` 包 try/catch，单条目解密失败 `continue`（不再毒化整个断言）。

### 5.6 页面构造 AuthenticatorAttestationResponse（`page-webauthn.ts`）
duck-typed `PublicKeyCredential`：`id/rawId/type='public-key'/authenticatorAttachment='platform'`，`response = { attestationObject(AB), clientDataJSON(AB), getAuthenticatorData()→authData(AB), getPublicKey()→publicKeySpki(AB, SPKI DER), getPublicKeyAlgorithm()→-7, getTransports()→[] }`，`getClientExtensionResults()→{}`。`instanceof PublicKeyCredential` 仍不成立（同 get 的已知限制）。

## 6. 回退表（`page-webauthn.ts` 返回 `originalCreate(options)`）

| 条件 | 处理 |
|---|---|
| 无 `options.publicKey` / 非安全上下文 | 原生 / 不包装 |
| `rpId` 非 `location.hostname` 可注册后缀（MAIN 快判；worker PSL 终判） | 原生 |
| `pubKeyCredParams` 无 `alg===-7` | 原生 |
| `authenticatorSelection.authenticatorAttachment==='cross-platform'` | 原生 |
| excludeCredentials 命中已存 vault passkey | 原生（best-effort 去重，非 InvalidStateError；不在 vault 建重复项） |
| `options.signal` 已/在选择器期间 abort | 原生（尽早停止；若已 abort 直接不介入） |
| vault 锁定/无缓存 / worker rpId 校验失败 / 用户取消 / 任意异常 | 原生 |

## 7. 安全边界

- **私钥永不出 worker**：`attestationObject`/`publicKeySpki` 仅含**公钥**；私钥仅进加密后的 `keyValue`。
- **rpId/origin 在 worker 校验**（§2，PSL）；桥盖 origin，页面不能伪造跨域凭据。
- **targetCipherId 在 worker 重解析**（必属同域个人可写登录），不信 content-script 传的 id。
- **候选无机密**（id/name/username）；同意走关闭式 shadow root + `isTrusted`。
- **诚实 UV / BE / BS**；**追加加密用 cipherFieldKey**（不损坏 org/per-cipher 条目）；**org 条目不作追加目标**（仅个人）。
- Argon2 超范围；不改 reprompt/URL 匹配等既有守卫。

## 8. 测试

- **`cbor.test.ts`**：uint/负整数/bstr/tstr/map 编码 + COSE 键序 + 解码回验。
- **`fido2-create.test.ts`**：COSE 结构；authData flags=`0x5D`(UP|AT|BE|BS|UV)/`0x59`、AAGUID0、credIdLen BE、signCount0；attestationObject 解码回 `{fmt:'none',attStmt:{},authData}`；clientDataJSON。**密钥对往返**：生成→用私钥 `signFido2Assertion` 签断言→用从 COSE 恢复的公钥、**`derToRawSignature` 转 raw** 后 `subtle.verify` 通过。
- **`fido2.test.ts`**：断言 flags 含 BE|BS。
- **`domain.test.ts`**：`isRegistrableRpId` —— apex/子域命中、裸公共后缀(github.io)拒、跨域拒。
- **`vault-service.test.ts`**：`assertRpIdForOrigin`（rpId⊄origin 抛错）；`getPasskeyTargets`（域匹配、仅个人、只回三项、锁定抛错）；`createPasskey`（新建 POST 形状；追加从原始 CipherResponse 逐字 + `[...旧,新]` + 用 cipherFieldKey、保留字段+已有 passkey、不经 merge；缓存合并后 `findPasskeyCredential` 找得到；targetCipherId 非同域/org→拒；锁定抛错）；`findPasskeyCredential` 单条目解密失败不毒化其余。
- **`router.test.ts`/protocol**：两条新消息 + hasPasskey/getPasskeyAssertion 补 origin 的转发（含 targetCipherId 条件展开、判别键 `targets`/`registration`）。
- **content**：page-webauthn create 回退纯判定；桥 origin 覆盖；选择器 `isTrusted`（镜像 `passkey-consent.test.ts`）。
- **人工浏览器冒烟（残余）**：对真实 RP（webauthn.io/真站）注册→再断言登录，验 RP 接受 attestation（含 @simplewebauthn/py_webauthn 语义）。CI 不可覆盖。
- **LIVE（可选）**：createPasskey cipher → sync → 解密 + 断言找得到（服务端往返）。

## 9. protocol / router 形状

- Request：`{ type:'vault.getPasskeyTargets'; rpId:string; origin:string }`、`{ type:'vault.createPasskey'; rpId; rpName; userHandle; userName; userDisplayName?; challenge; origin; userVerification?; targetCipherId? }`；`vault.hasPasskey` 补 `origin`。
- Response：`{ ok:true; data:{ targets: PasskeyTarget[] } }`、`{ ok:true; data:{ registration: Fido2Registration } }`（判别键 `targets`/`registration`，桥用 `'targets' in data`/`'registration' in data` 收窄）。
- Router：镜像既有 `vault.*` guard-then-call；可选字段用条件展开（`...(request.targetCipherId ? {targetCipherId:request.targetCipherId} : {})`，因 `exactOptionalPropertyTypes`）。

## 10. 非目标

- 非 ES256；packed/其它 attestation；跨条目 passkey 管理 UI；PRF/largeBlob/credProps/conditional-mediation；signCount 服务端回写；`instanceof PublicKeyCredential`；追加到 org 条目（仅个人）；timeout 精确执行（忽略）。
