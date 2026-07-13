# 动画规格 · 密屿 MiYu

所有关键帧定义在 `密屿 · 插件设计.dc.html` 的 `<helmet><style>` 中，命名前缀 `mv`。基调：轻量克制，时长 0.15–0.6s，缓动统一 `ease-out`，强调色苔绿 `#0E8A72`（深色 `#45D6B5`）。生产实现请尊重 `prefers-reduced-motion: reduce`。

## 关键帧定义（可直接复制）
```css
@keyframes mvIn   { from { opacity:0; transform:translateY(6px);  } to { opacity:1; transform:none; } }
@keyframes mvUp   { from { opacity:0; transform:translate(-50%,6px);} to { opacity:1; transform:translate(-50%,0);} } /* toast 居中上移，按实际定位调整 */
@keyframes mvGrow { from { opacity:0; transform:translateY(-6px) scaleY(.95); } to { opacity:1; transform:none; } } /* transform-origin:top */
@keyframes mvStag { from { opacity:0; transform:translateY(7px);  } to { opacity:1; transform:none; } }
@keyframes mvPop  { 0% { transform:scale(.4); opacity:0; } 65% { transform:scale(1.12); opacity:1; } 100% { transform:scale(1); opacity:1; } }
@keyframes mvPulse{ 0% { box-shadow:0 0 0 0 rgba(14,138,114,.45); } 70% { box-shadow:0 0 0 6px rgba(14,138,114,0);} 100% { box-shadow:0 0 0 0 rgba(14,138,114,0);} }
@keyframes mvFill { 0% { background:rgba(14,138,114,.22);} 55% { background:rgba(14,138,114,.22);} 100% { background:transparent; } }
@keyframes mvType { from { opacity:0; transform:translateX(-5px);} to { opacity:1; transform:none; } }
@keyframes mvSpin { to { transform:rotate(360deg); } }
```

## 应用清单

### Popup 弹窗
| 元素 | 动画 | 参数 |
|---|---|---|
| 锁屏容器（解锁前） | mvIn | .22s |
| 顶栏（解锁后） | mvIn | .25s |
| 密钥库列表 · 当前网站匹配项 | mvStag | .3s，`delay = i * 45ms` |
| 密钥库列表 · 普通条目 | mvStag | .3s，`delay = i * 40ms + 120ms` |
| 条目详情内联卡（展开） | mvGrow | .2s，origin top |
| 密码生成器视图 | mvIn | .2s |
| 分类 chips | transition | background/color/border-color .15s |
| 分段控件 / 主题 / 类型切换 | transition | all .15s |
| 底部同步图标（同步中） | mvSpin | .8s linear infinite |

### 自动填充（content script）
| 元素 | 动画 | 参数 |
|---|---|---|
| 面板与输入框的连接圆点 | mvPulse | 2s ease-out infinite |
| 匹配项行（2c） | mvStag | .3s，`delay = i * 60ms` |
| **账号字段被填充（2c/2d）** | mvFill + 值 mvType | 用户名 .6s / .28s；密码 `delay .13s`，`mvFill … .13s both` + `mvType … .13s both` |
| 输入框右上角对勾角标（2c） | mvPop | .3s |
| 「已填充」胶囊（2c） | mvPop | .3s |
| 2FA 验证码 6 格（3a 填充后） | mvPop | .28s，`delay = i * 45ms`，`both` |
| Passkey 账户列表（3b） | mvStag | .3s，`delay = i * 60ms` |
| Passkey 验证成功对勾圆（3b） | mvPop | .32s |
| 锁定提示信息条（2f） | mvIn | .18s |

### 注册强密码（2e）
| 元素 | 动画 | 参数 |
|---|---|---|
| 强密码建议卡（弹出） | mvGrow | .22s，origin top |
| **新密码字段（使用后填充）** | mvFill + 值 mvType | .6s / .3s |
| **确认密码字段（使用后填充）** | mvFill + 值 mvType | `delay .13s`，`both` |
| 「已保存到密屿」对勾圆 | mvPop | .3s |

### 设置页（options）
| 元素 | 动画 | 参数 |
|---|---|---|
| 板块内容区（切换导航） | mvIn | .2s |
| 左侧导航项 hover | transition | background .15s |
| 新建 Send 表单（展开） | mvGrow | .22s，origin top |
| Send 类型 / 主题分段切换 | transition | all .15s |

## 触发方式说明
- **mvFill / mvType（字段自动填充）** 依赖「idle=`none` → filled=`具体动画值`」的绑定切换触发重播。原型中字段 `animation` 属性由状态派生；生产实现里，在把值写入输入框的同时将 animation 从无切到有即可，或用 `element.animate([...], {duration, easing})`（Web Animations API）更可控。用户名先播、密码延迟 0.13s，形成顺序录入观感。
- **mvStag（列表错落）** 每行 `animation-delay = 索引 * 间隔`；用 `both` 保持终态，避免入场前闪现。
- **mvPop（成功反馈）** 用于对勾、徽标、验证码格等一次性正反馈，带轻微过冲（1.12）。
- **mvPulse（连接圆点）** 持续循环，暗示侧挂面板归属于被聚焦的输入框。
