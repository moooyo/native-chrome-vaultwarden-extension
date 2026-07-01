# 空闲/自动锁定改进设计（Idle auto-lock: action + accuracy + clipboard clear）

> 本 spec 已经一轮 5 维对抗性评审（含 MV3 平台语义 + 读源码）修订。评审逮到的**applyAction 非幂等级联登出、offscreen 无类型、SW 消息路由竞争、execCommand 空选区不清剪贴板、settings 变更无重算落点、新设置协议未贯通、options 保存耦合 serverUrl/权限**等 blocker 均已并入。

## 1. 目标

三块紧耦合的安全计时改进：

- **超时动作可选**：空闲超时（及系统锁）触发时可选**锁定**或**登出**（现只锁定）。
- **空闲检测准确**：用 `chrome.idle`（真实 OS 输入 + 系统锁屏信号）取代现有「1 分钟轮询 `lastActivity`、仅扩展消息刷新」的近似机制。
- **剪贴板自动清除**：可配时长 + 计时移到后台 offscreen（不随 popup 关闭而取消）。

## 2. 范围

| 项目 | 处理方式 |
| --- | --- |
| 超时动作 | 新设置 `onIdleAction: 'lock' \| 'logout'`（默认 lock）；空闲超时与系统锁都执行此动作；选 logout 时 UI 显式警示 |
| 空闲检测 | `browser.idle.setDetectionInterval(超时秒数)` + `onStateChanged`（idle/locked→动作）；低频兜底 alarm 用 `queryState` 复查；退役 `lastActivity`/per-message `touch` |
| 幂等 | applyAction 前查 `isUnlocked()`，已锁/已登出则 no-op（防 onStateChanged 与兜底 alarm 双触发级联登出多账户） |
| 系统锁 | `onStateChanged('locked')` → 执行 `onIdleAction`（仅当启用数值超时时） |
| 剪贴板清除 | 新设置 `clipboardClearSeconds: 'never' \| 30 \| 60 \| 120 \| 300`（默认 60）；复制后 SW 排 alarm，触发时 offscreen 文档清空 |
| 设置协议 | 新 `settings.saveSecurity` 消息（onIdleAction+clipboardClearSeconds，**不含 serverUrl/权限**，解耦）；`settings.get` 响应扩展 |
| 权限 | manifest 加 `"idle"` 与 `"offscreen"` |
| 不在范围 | detectionInterval < 15s、sub-30s 剪贴板清除、独立「lock on system lock」开关、剪贴板「仅当未变才清」、i18n |

## 3. 关键决策（brainstorm + 评审后拍板）

- **系统锁 → 按配置动作 + logout 警示**：`'locked'` 与 `'idle'` 走同一 `onIdleAction`；仅在设置了数值超时（非 `never`/`onClose`）时处理。评审指出 logout-on-system-lock 是 footgun（系统锁频繁、每次销毁 session+移除 PIN），故**选 logout 时 UI 显式警示**「Log out will end your session on every system lock / idle timeout」。
- **applyAction 幂等**：`isUnlocked()` 守卫 + 锁定态 no-op（评审 blocker：双触发对 logout 会级联登出多个账户）。
- **chrome.idle 语义**：测**全局 OS 输入**，用户在别的 app 活跃时 vault 不锁——这是「离开电脑才锁」的正确语义（与 Bitwarden 一致），**非回归**：旧机制靠扩展消息陈旧度、并不反映真实在场；新机制更贴合威胁模型（人离开→idle/locked→锁）。已写明。
- **剪贴板清除机制**（评办 blocker：execCommand 空选区是 no-op）：offscreen 用 `navigator.clipboard.writeText('')` 为主；失败回退 `<textarea>` 置**单个空格**（非空）+ `execCommand('copy')`（保证覆盖机密）。二者都抹掉机密；具体哪条生效由**人工浏览器冒烟**钉死。**无条件清除、不持有/持久化明文**。
- **默认 `clipboardClearSeconds=60`**：保留 60s **时长**；但行为有意变更——**现在跨 popup 关闭存活 + 无条件清除**（不再「仅当未变且 popup 仍开才清」）。
- `clipboardClearSeconds` 只提供 ≥30s（Chrome alarm 最小延迟约 30s）；后台清除时机 **best-effort**（alarm 钳制 + SW 挂起可能略晚于 N 秒）。

## 4. 架构

```mermaid
flowchart TD
  subgraph SW[service worker (background/index.ts wiring)]
    IL["idle-lock.ts<br/>onStateChanged / onBackstopAlarm / applyDetection"]
    CB["clipboard.ts<br/>scheduleClear / handleClipboardAlarm"]
  end
  IDLE["browser.idle.onStateChanged (idle/locked/active)"] --> IL
  ALARM1["alarm: idle-lock backstop (1min)"] -->|queryState| IL
  IL -->|"isUnlocked? onIdleAction"| AUTH["auth.lock() / auth.logout()"]
  POPUP["popup 复制 → writeText + msg(scheduleClear)"] --> SWMSG["SW onMessage (guards non-owned msgs)"]
  SWMSG --> CB
  ALARM2["alarm: clipboard-clear (delay)"] --> CB
  CB -->|getContexts/createDocument + sendMessage| OFF["offscreen.ts<br/>writeText('') / execCommand(space)"]
```

## 5. 组件 A — 超时动作设置（`settings.ts`）

```ts
const ON_IDLE_ACTION_KEY = 'onIdleAction';
export type OnIdleAction = 'lock' | 'logout';
export const DEFAULT_ON_IDLE_ACTION: OnIdleAction = 'lock';
export function isOnIdleAction(v: unknown): v is OnIdleAction;
// service: getOnIdleAction(): Promise<OnIdleAction>; saveOnIdleAction(v): Promise<void>（校验）

const CLIPBOARD_CLEAR_KEY = 'clipboardClearSeconds';
export const CLIPBOARD_CLEAR_VALUES = ['never', '30', '60', '120', '300'] as const;
export type ClipboardClearSetting = (typeof CLIPBOARD_CLEAR_VALUES)[number];
export const DEFAULT_CLIPBOARD_CLEAR: ClipboardClearSetting = '60';
export function isClipboardClearSetting(v: unknown): v is ClipboardClearSetting;
/** Seconds or null when 'never'. */
export function clipboardClearToSeconds(v: ClipboardClearSetting): number | null;
// service: getClipboardClearSetting()/saveClipboardClearSetting()/getClipboardClearSeconds()
```

## 6. 组件 B — chrome.idle 检测（`src/background/idle-lock.ts`，新）

```ts
export type IdleState = 'active' | 'idle' | 'locked'; // = browser.idle.IdleState
export interface IdleLockDeps {
  getConfig(): Promise<{ idleSeconds: number | null; action: OnIdleAction }>; // idleSeconds=null → 禁用
  isUnlocked(): Promise<boolean>;      // 幂等守卫来源（评审 blocker）
  lock(): Promise<void>;
  logout(): Promise<void>;
  queryState(detectionSeconds: number): Promise<IdleState>;
  setDetectionInterval(seconds: number): void;
}
export function createIdleLock(deps: IdleLockDeps): {
  applyDetection(): Promise<void>;
  onStateChanged(state: IdleState): Promise<void>;
  onBackstopAlarm(): Promise<void>;
};
```

- **`applyAction`（内部）**：`if (idleSeconds===null) return;`（禁用）；`if (!(await deps.isUnlocked())) return;`（**幂等守卫**——已锁/已登出直接返回，防双触发级联）；`action==='logout' ? deps.logout() : deps.lock()`。
- **`onStateChanged(state)`**：`state==='idle' || state==='locked'` → `applyAction()`；`active` → 无操作。
- **`onBackstopAlarm()`**：读 config；启用则 `queryState(idleSeconds)`，`idle|locked` → `applyAction()`。
- **`applyDetection()`**：`setDetectionInterval(idleSeconds===null ? SENTINEL(4*3600) : Math.max(15, idleSeconds))`。
- **禁用抑制（澄清评审歧义）**：`'locked'` 事件**与 detectionInterval 无关**、总会触发；真正忽略它的是 `applyAction` 里的 `idleSeconds===null` 早退（no-op 门），**不是** sentinel interval——sentinel 仅让 `'idle'` 罕发，对 `'locked'` 无效。
- `idleSeconds` = `lockTimeoutToIdleMs(lockTimeout)/1000`（复用现有 `LockTimeoutSetting`；1/5/15/30 分钟 → 60/300/900/1800，均 ≥60）。

### 接线（`background/index.ts`）
- `idleLock` 用真实 deps 构造：`isUnlocked: async () => (await auth.getState()) === 'unlocked'`；`queryState/setDetectionInterval` 包 `browser.idle.*`；`lock/logout` 包 `auth.*`；`getConfig` 读 settings。
- SW 顶层：`browser.idle.onStateChanged.addListener((s) => void idleLock.onStateChanged(s))`；启动即 `void idleLock.applyDetection()`（setDetectionInterval 不保证跨 SW 重启保留，故每次启动重设）。
- `onInstalled`/启动：`browser.alarms.create(IDLE_LOCK_ALARM, { periodInMinutes: 1 })`；`onAlarm` 分发 `IDLE_LOCK_ALARM → idleLock.onBackstopAlarm()`、`CLIPBOARD_CLEAR_ALARM → clipboard.handleClipboardAlarm()`。
- **设置变更重算**（评审 blocker：router 够不到 idleLock）：在 index.ts 的 `onMessage` 里，`router.handle` 之后按 `message.type` 判断——`'settings.save' || 'settings.saveSecurity'` → `void idleLock.applyDetection()`（仿现有 `shouldRefreshMenu` 模式）。
- **移除** onMessage 里的 `alarms.touch()` 与 `lastActivity`；`alarms.ts` 的 idle 逻辑由 `idle-lock.ts` 取代（保留 alarm 名常量）。

## 7. 组件 C — 剪贴板后台清除

### `src/offscreen.html` + `src/offscreen.ts`（新）
- `offscreen.html`：最小页面，`<script src="offscreen.js">`（顶层路径，与 `createDocument({url:'offscreen.html'})` 一致）。
- `offscreen.ts`：`browser.runtime.onMessage` 收 **仅** `{ type: 'offscreen.clearClipboard' }`（其它 type 直接 `return`，不占响应）→ 清剪贴板 → 回 `{ ok: true } | { ok: false; error }`：
  ```ts
  try { await navigator.clipboard.writeText(''); }          // 主：真正清空
  catch { const ta = document.createElement('textarea'); ta.value = ' '; document.body.append(ta);
          ta.select(); document.execCommand('copy'); ta.remove(); }  // 回退：覆盖为空格（非空，execCommand 才生效）
  ```

### `src/background/clipboard.ts`（新，纯逻辑 + 注入 deps）
```ts
export const CLIPBOARD_CLEAR_ALARM = 'clipboard-clear';
export interface ClipboardDeps {
  getClearSeconds(): Promise<number | null>;   // null=never
  createAlarm(name: string, delayInMinutes: number): void;
  clearAlarm(name: string): void;
  ensureOffscreen(): Promise<void>;             // getContexts→无则 createDocument(url,reasons:['CLIPBOARD'],justification)
  sendOffscreen(msg: { type: 'offscreen.clearClipboard' }): Promise<unknown>;
  closeOffscreen(): Promise<void>;
}
export function createClipboard(deps: ClipboardDeps): {
  scheduleClear(): Promise<void>;
  handleClipboardAlarm(): Promise<void>;
};
```
- `scheduleClear()`：`s=getClearSeconds()`；`null` → `clearAlarm(CLIPBOARD_CLEAR_ALARM)`；否则 `createAlarm(CLIPBOARD_CLEAR_ALARM, Math.max(30,s)/60)`（同名 alarm 重复 create 会替换——即连续复制**去重合并**为最后一次，故意且安全）。
- `handleClipboardAlarm()`：`try { ensureOffscreen(); sendOffscreen({type:'offscreen.clearClipboard'}); } finally { closeOffscreen(); }`（**closeOffscreen 放 finally**，失败也关；失败吞掉不重排，避免唤醒循环）。
- **chrome.offscreen 无类型**（无 @types/chrome）：**所有 `chrome.offscreen.*`/`getContexts` 仅出现在 index.ts 的 deps 实现里**，用现有 `store.ts` 的窄化 cast 手法（`const oc = (globalThis as unknown as { chrome?: { offscreen?: {…}; runtime?: {…} } }).chrome`）。`clipboard.ts` 只依赖注入接口、可纯单测。
- `ensureOffscreen`：`getContexts({contextTypes:['OFFSCREEN_DOCUMENT']})` 非空则跳过；否则 `createDocument({ url:'offscreen.html', reasons:['CLIPBOARD'], justification:'Clear the clipboard after the copy auto-clear delay' })`（try/catch 吞「已存在」）。

### popup 复制流程（`popup.ts`）
- `copyWithClear`（~2600）：保留 `navigator.clipboard.writeText(value)`，**移除自身 `setTimeout` + readText 回比**，改为 `void sendRequest({ type: 'clipboard.scheduleClear' })`（fire-and-forget，失败不报错）。
- 状态文案在 `copyValue`（~2149）：改为 `${label} copied.${N===null ? '' : ` Clipboard clears in ${N} s.`}`——`N` 来自 popup 打开时 `settings.get` 缓存的 `clipboardClearSeconds`（`never`→null）。
- `clipboardRead` 权限清理：回比路径移除后 popup 不再 readText；`clipboardRead` 可保留（无害）或后续清理，本特性不动。

### 协议 / SW 接线
- `RequestMessage` 加 `{ type: 'clipboard.scheduleClear' }` → router `deps.clipboard.scheduleClear()`（response `{ ok:true, data:null }`）。
- **SW onMessage 守卫**（评审 blocker：SW 对所有消息返回 Promise，与 offscreen 监听器竞争）：`onMessage` 顶部对**非本 SW 拥有**的消息（如 `offscreen.*`、未知 type）**同步 `return;`（不返回 Promise）**，让 offscreen 的响应胜出。仅对已知 `RequestMessage` type 走 router。
- `onAlarm` 分发 `CLIPBOARD_CLEAR_ALARM → clipboard.handleClipboardAlarm()`。

## 8. 组件 D — options UI（安全设置，解耦）
- 评审 blocker：现 options 表单单一保存**强制** `new URL(serverUrl)` + `permissions.request`（lockTimeout 今天就被耦合）。新设置**不复用该表单**：
- options 页加独立「Security」小节：`onIdleAction`（Lock / Log out）+ `clipboardClearSeconds`（Never / 30s / 1 min / 2 min / 5 min）两个 `<select>`，**change 即存**——发新消息 `{ type:'settings.saveSecurity', onIdleAction, clipboardClearSeconds }`（**不含 serverUrl、不触发权限弹窗**）。
- 选 `Log out` 时在该小节显示警示文案（§3）。
- 初值：`settings.get` 响应扩展 `onIdleAction`/`clipboardClearSeconds`，init 时回填。
- 文案英文。

## 9. 协议扩展（`messaging/protocol.ts` + `router.ts`）
- 请求：`{ type:'settings.saveSecurity'; onIdleAction: OnIdleAction; clipboardClearSeconds: ClipboardClearSetting }`；`{ type:'clipboard.scheduleClear' }`。
- `settings.get` 响应对象加 `onIdleAction: OnIdleAction; clipboardClearSeconds: ClipboardClearSetting`。
- router：`settings.saveSecurity` → `saveOnIdleAction` + `saveClipboardClearSetting`；`clipboard.scheduleClear` → `deps.clipboard.scheduleClear()`；`settings.get` 补两字段。
- `settings.save`（旧，serverUrl 表单）**不变**（不塞新字段，避免耦合）。

## 10. 权限 / manifest / 构建
- `permissions` 加 `"idle"`、`"offscreen"`。
- `build.mjs`：`entryPoints` 加 `offscreen: 'src/offscreen.ts'`（→ `dist/offscreen.js`，顶层）；`copyStatic` 加一行 `await cp('src/offscreen.html', join(outdir, 'offscreen.html'))`（顶层，不在 ui/ 下）。
- `browser.idle` 经 polyfill（已类型化）；`chrome.offscreen`/`chrome.runtime.getContexts` 仅在 index.ts 用窄化 cast。

## 11. 安全 / 边界
- `chrome.idle` 是 OS 级信号；不引入机密跨边界通道；`onIdleAction` 只读设置。
- **applyAction 幂等**（`isUnlocked` 守卫）——无双触发级联登出。
- 剪贴板清除**不持有/持久化明文**，offscreen 仅写空串/空格覆盖；无 <30s 选项（后台不可靠）。
- 语义变更（chrome.idle 全局输入）已写明、非回归；`never`/`onClose` 关闭自动锁定与系统锁联动（与今日一致，非新增缺口）。
- 退役 `lastActivity` 后无回归：解锁态由 `chrome.idle` + 兜底 alarm 覆盖。
- 后台清除时机 best-effort（alarm 钳制/SW 挂起），文案不承诺精确 N 秒。

## 12. 测试计划
- `settings.test.ts`：`onIdleAction`/`clipboardClearSeconds` 读写、校验、默认、非法回退；`clipboardClearToSeconds`（never→null）。
- `idle-lock.test.ts`（注入 deps）：启用时 idle/locked→对应 lock/logout；active→无操作；**已锁（isUnlocked=false）→ applyAction no-op（防双触发，尤其 logout）**；禁用（idleSeconds=null）→ 全 no-op（含 locked）；`applyDetection` 启用/禁用设正确 interval（含 max(15,…) 下限）；`onBackstopAlarm` 的 idle/locked/active 分支。
- `clipboard.test.ts`（注入 deps）：`scheduleClear` never→clearAlarm、数值→createAlarm(max(30,s)/60)；`handleClipboardAlarm`→ensure→send→close（close 在 finally，send 抛错也 close）。
- `offscreen.test.ts`（`// @vitest-environment happy-dom`，stub `navigator.clipboard.writeText` + `document.execCommand`）：writeText('') 成功路径；writeText 抛错→execCommand 回退路径；非 `offscreen.clearClipboard` 消息不响应。
- `manifest.test.ts`：`permissions` 含 `idle`、`offscreen`。
- protocol/router：`settings.saveSecurity`、`clipboard.scheduleClear`、`settings.get` 新字段分支。
- `npm run typecheck` + `npm run build`（断言产出 `dist/offscreen.js` + `dist/offscreen.html`）+ **人工浏览器冒烟**：改超时/动作、锁屏、复制后关 popup 验证清除生效（**钉死 writeText('') vs execCommand 回退哪条真正清空**）。

## 13. 非目标
- <30s 剪贴板清除、剪贴板「仅当未变才清」。
- 独立「系统锁即锁」开关（与超时启用耦合）。
- `chrome.idle` 之外的活动源（页面级细粒度活动上报）。
- 把既有 lockTimeout 从 serverUrl 表单迁出（沿用现状；仅新设置解耦）。
- i18n。
