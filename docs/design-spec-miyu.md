# 密屿 MiYu — Design Spec (source of truth for the rewrite)

Distilled from `claude-design/design_handoff_miyu_extension/` (the design HTML inline styles are the
spec). Final design = `turn 2` + `turn 3` (ids `2x`/`3x`). Ignore `turn 1` (deprecated Fluent) and
`2d` (unchosen inline-pill autofill). Fidelity: pixel-level for every screen below.

## Color — Light

| Token (CSS var) | Value | Usage |
|---|---|---|
| `--mi-ink` | `#16181D` | primary button, strong text, titles |
| `--mi-ink-hover` | `#2A2D34` | primary button hover |
| `--mi-text-2` | `#565B66` | icon buttons, nav idle |
| `--mi-text-3` | `#6A6F7A` | form hints, mode-tab idle |
| `--mi-text-4` | `#3F444E` | generator row labels, outline-btn text |
| `--mi-muted` | `#8A8F99` | subtitles |
| `--mi-faint` | `#9AA0AA` | field labels, seconds, footnotes |
| `--mi-teal` | `#0E8A72` | logo block, toggle-on, TOTP bar, focus ring |
| `--mi-teal-text` | `#0B7A65` | teal labels/links, TOTP code, passkey key |
| `--mi-teal-10` | `rgba(14,138,114,.1)` | 填充 pill bg, gen-icon active bg, value pill |
| `--mi-teal-12` | `rgba(14,138,114,.12)` | register pill on-bg |
| `--mi-teal-18` | `rgba(14,138,114,.18)` | 填充 pill hover |
| `--mi-panel` | `#FCFCFB` | popup container, passkey dialog |
| `--mi-options-bg` | `#FAFAF8` | options root |
| `--mi-card` | `#fff` | detail card, setting cards, panels |
| `--mi-fill` | `#F1F1EE` | search box, unlock input, segmented containers |
| `--mi-fill-2` | `#F7F7F4` | generator result box, Send inputs, TOTP box |
| `--mi-row-hover` | `#F2F2EF` | list row / icon-btn / outline-btn hover |
| `--mi-icon-hover` | `rgba(22,24,29,.06)` | icon button hover |
| `--mi-line-1` | `rgba(22,24,29,.07)` | setting cards, sync-bar border |
| `--mi-line-2` | `rgba(22,24,29,.09)` | popup/panel border |
| `--mi-line-3` | `rgba(22,24,29,.14)` | chips idle, outline buttons, inputs |
| `--mi-danger` | `#C6453D` | delete, symbol coloring, weak strength |
| `--mi-danger-border` | `rgba(198,69,61,.3)` | danger card border |
| `--mi-sync-amber` | `#B8860B` | sync dot while syncing |
| `--mi-chevron` | `#C4C7CC` | list row chevron |
| strength | 极强 `#0E8A72` / 强 `#4C8A0E` / 中等 `#A66A00` / 较弱 `#C6453D` | |
| gen coloring | digit `#0B7A65`, symbol `#C6453D` | |

## Color — Dark

| Token | Value |
|---|---|
| `--mi-panel` | `#1F2229` |
| `--mi-options-bg` | `#17191E` |
| `--mi-card` / `--mi-fill` | `#262A33` |
| `--mi-ink` (text primary) | `#F2F3F5` |
| `--mi-text-2` | `#9AA0AC` |
| `--mi-text-4` | `#D6D9DE` |
| `--mi-faint` | `#7B818B` |
| `--mi-teal-text` / accent text | `#45D6B5` |
| `--mi-teal-10` | `rgba(69,214,181,.14)` |
| toggle ON track | `#2FBF9C` (⚠ NOT #45D6B5) |
| toggle OFF track | `rgba(255,255,255,.18)` |
| `--mi-line-1` | `rgba(255,255,255,.07)` |
| `--mi-line-2` | `rgba(255,255,255,.09)` |
| `--mi-line-3` | `rgba(255,255,255,.13/.14/.16)` |
| primary button | bg `#F2F3F5`→hover `#fff`, text `#16181D` |
| `--mi-row-hover` | `rgba(255,255,255,.05)` |
| `--mi-icon-hover` | `rgba(255,255,255,.07)` |
| `--mi-fill-2` | `#262A33` |
| popup shadow | `0 18px 44px rgba(0,0,0,.5)` |

Dark primary button is **inverted** (light bg, ink text). Logo block `#0E8A72` is identical in both themes.

## Fonts
- UI: `'Instrument Sans','Segoe UI',system-ui,sans-serif` (400/500/600/700).
- Mono: `'JetBrains Mono',ui-monospace,monospace` (400/500/600) — passwords, TOTP, generator output,
  version badges, shortcut keychip, register pills.
- Placeholder color: light `#9a9a9a`, dark `#8a8a8a`.

## Radii / shadows / spacing
- Radii: 16 (passkey dialog, toast), 14 (popup, side panels, register popover, big logo block),
  13 (chips, 填充 pill, register pills, filled badge), 12 (detail/setting card, gen result, info bar),
  10 (search, unlock input, row/tile, primary buttons, segmented), 9 (sidebar tile, inputs, 31–38px
  buttons, nav item, sidebar logo), 8 (24px logo, 28px top-bar icon buttons, mode-tab, Send tile, select),
  7 (24/26px small icon buttons, toolbar icon, mini-logo), 6 (26px copy-in-field, value pill, keychip,
  filled corner badge), 5 (16px mini-logo block, dark inputs), 50% (avatars, bio button, passkey circle, dots).
- Shadows: popup light `0 18px 44px rgba(20,24,32,.22)` / dark `0 18px 44px rgba(0,0,0,.5)`; side panel
  `0 16px 40px rgba(20,24,32,.16)`; passkey `0 24px 56px rgba(20,24,32,.28)`; card `0 2px 10px rgba(20,24,32,.05)`;
  saved-confirm `0 8px 22px rgba(20,24,32,.08)`; toggle knob `0 1px 2px rgba(0,0,0,.25)` (dark `.35`);
  segmented active `0 1px 3px rgba(0,0,0,.14)`.
- Spacing in use: 2,4,6,7,8,9,10,11,12,13,14,16,18,24,26,28.

## Animations
- `mvIn`: `from{opacity:0;translateY(-5px)} to{opacity:1}` — panel/dialog/popover entrance `.18s ease-out`
  (register popover `.16s`).
- `mvUp`: `from{opacity:0;translate(-50%,8px)} to{opacity:1;translate(-50%,0)}` — toast `.18s ease-out`.
- `mvSpin`: `to{rotate(360deg)}` — sync icon `.8s linear infinite`.
- toggle `background .15s` + knob `left .15s`; strength `all .2s`; TOTP progress `width 1s linear`;
  chip hover `opacity:.85`.

## Font sizes (px / weight)
10/600(ls.05em) field labels · 10.5 seconds/footnotes · 11 group labels/match-count/sync ·
11.5 subtitles/chips/hints/pills/toasts · 12 password/secondary/sm-buttons · 12.5 search/nav/row-user ·
13 row title/gen header/nav · 13.5 setting-card title/gen result mono · 14 popup brand · 15 sidebar brand/about ·
15.5 locked title · 16 panel host title/popup TOTP · 18 3a TOTP · 19 2FA input boxes · 24/650 options section title.

## Logo glyph
Concentric-circle mark on moss-green rounded block (block `#0E8A72` both themes). Parametric
`glyph(sz)`: container `relative; sz×sz`; ring `absolute; inset:0; border:{ring}px solid #fff; radius:50%`;
dot `absolute; left/top:sz*0.38; sz*0.24 square; radius:50%; bg:#fff`.
Instances: popup header 24 block r8 / glyph 11 ring2 dot(4,4,3); locked & about 46/44 block r14 / glyph18 ring2.5 dot(7,7,4);
autofill mini 16 block r5 / glyph8 ring1.5 dot(3,3,2); options sidebar 28 block r9 / glyph12 ring2 dot(4.5,4.5,3).

## Icons (inline SVG, viewBox 0 0 24 24, fill:none stroke:currentColor linecap:round, stroke-width 1.6–2.6)
| name | paths | sw |
|---|---|---|
| plus | `M12 5v14M5 12h14` | 1.8 |
| generator (wand) | `circle cx8 cy14 r4` `M11 11l8-8` `M16 6l2.5 2.5` | 1.7 |
| sliders (settings) | `M4 7h16M4 12h16M4 17h16` + 3 filled circles `cx9 cy7 / cx15 cy12 / cx7 cy17 r2` (fill = panel bg) | 1.6 |
| lock | `rect x5 y11 w14 h9 rx2` `M8 11V8a4 4 0 0 1 8 0v3` | 1.6 |
| search | `circle cx11 cy11 r7` `M16.5 16.5L21 21` | 1.8 |
| copy | `rect x9 y9 w11 h11 rx2` `M5 15V6a2 2 0 0 1 2-2h9` | 1.7 |
| eye | `M2 12s3.5-6 10-6 10 6 10 6-3.5 6-10 6S2 12 2 12z` `circle cx12 cy12 r3` | 1.6 |
| refresh | `M20 12a8 8 0 1 1-2.3-5.7` `M20 4v4h-4` | 1.7 |
| passkey/key | `circle cx8 cy9 r4` `M11 12l8 8` `M15 16l2.5-2.5` | 1.9 |
| check | `M5 12l5 5L20 7` | 2.4 |
| chevron-right | `M9 6l6 6-6 6` | 1.8 |
| chevron-down | `M6 9l6 6 6-6` | 2 |
| trash | `M4 7h16` `M9 7V5h6v2` `M6 7l1 13h10l1-13` | 1.7 |
| link | `M10 14a5 5 0 0 0 7 0l3-3a5 5 0 0 0-7-7l-1.5 1.5` `M14 10a5 5 0 0 0-7 0l-3 3a5 5 0 0 0 7 7l1.5-1.5` | 1.7 |
| file | `M13 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V9z` `M13 3v6h6` | 1.7 |
| text (note) | `rect x5 y4 w14 h17 rx2` `M9 9h6M9 13h6` | 1.7 |
| fingerprint | `circle cx12 cy13 r1.6` `M12 7a6 6 0 0 1 6 6c0 2-.4 3.8-1 5.4` `M6 13a6 6 0 0 1 3-5.2` `M8.5 20a12 12 0 0 0 1-4` | 1.6 |

## Toggle switch
40×20: track radius10, transition bg .15s. Knob 14×14 radius50% bg#fff top3 left3(off)/23(on)
transition left .15s shadow `0 1px 2px rgba(0,0,0,.25)`(d`.35`). ON `#0E8A72`(d`#2FBF9C`), OFF
`rgba(22,24,29,.15)`(d`rgba(255,255,255,.18)`). Send-form variant 36×19, knob 13×13 left3/23.

## Copy toast
Pill bg `rgba(22,24,29,.92)` fg#fff 11.5px padding6px13 radius16 `mvUp .18s`; centered; auto-dismiss 1900ms.
Dark popup: bg `rgba(242,243,245,.95)` fg#16181D. Password/TOTP copies append "· 30 秒后自动清除".
Position: popup `bottom:42`, panels/options `bottom:18`.

## TOTP meter
30s cycle; code format "XXX XXX" ls.08em; seconds label; progress track `height3 radius2
rgba(22,24,29,.08)`(d`rgba(255,255,255,.12)`) fill `#0E8A72`(d`#45D6B5`) `transition:width 1s linear`
width=round(left/30*100)%. Copy strips the space.

---

# Screens

## Popup (372×560) — 2a light / 2b dark+locked
Container: 372×560 flex column, bg `--mi-panel`, border 1px `--mi-line-2`, radius14, popup shadow, overflow hidden, `mvIn .18s`.

**Top bar** (`padding:12 14 9; gap:8`): logo 24 + brand "密屿" 14/600 ls.01em + spacer + 4 icon buttons
(28×28 radius8, svg15, `--mi-text-2`, hover `--mi-icon-hover`): 新建(plus)/生成器(wand)/设置(sliders)/锁定(lock).
Generator active → fg `--mi-teal-text` bg `--mi-teal-10`. No bottom tab bar.

**Search** (`margin:0 14; height34; bg --mi-fill; radius10; padding:0 11; gap8`): search icon14 `--mi-muted` + input 12.5px placeholder "搜索密钥库".

**Category chips** (`margin:10 14; gap6; wrap`): 全部/登录/银行卡/2FA/笔记/身份. Chip height25 padding0 11 radius13
font11.5. Selected: bg`--mi-ink` fg#fff w600. Idle: transparent, fg`--mi-text-2`, border1px`--mi-line-3` w500. Hover opacity.85.

**List** (`flex:1; overflow-y:auto; padding:0 8 8`): scrollbar thumb `rgba(0,0,0,.16)`(d`rgba(255,255,255,.2)`) w8 r4.
- **当前网站** group (only when query empty & cat=all): label "当前网站 · nebula.dev" 11/600 `--mi-muted` `padding:6 8 3`.
- Main group label `padding:8 8 3` 11/600 `--mi-muted`.
- **Row** (`padding:7 8; gap10; radius10; hover --mi-row-hover`): tile 34×34 radius10 (brand color) white 13/700
  + title 13/600 (+ passkey key-icon 12px `--mi-teal-text` if pk) + subtitle 11.5 `--mi-muted`. Current-site rows:
  right **填充 pill** (height25 padding0 11 radius13 bg`--mi-teal-10` fg`--mi-teal-text` 11.5/600 hover`--mi-teal-18`).
  Main rows: right copy-password icon (26×26 r7 `--mi-faint` opacity.6→1) + chevron 13 `--mi-chevron`.
- **Inline detail card** (expands under selected row; `margin:2 4 8; bg--mi-card; border1px rgba(22,24,29,.08);
  radius12; padding:11 13; gap9`): field label 10/600 ls.05em `--mi-faint`; username row (value 12.5 + copy);
  password row (value 12 mono, ls2px masked, eye+copy); TOTP row (code 16/600 mono `--mi-teal-text` ls.08em +
  seconds + meter + copy); actions (打开并填充 flex1 h31 r9 ink primary + 编辑 h31 padding0 13 r9 outline).

**Generator view** (replaces list; `padding:12 14; gap12`): header "密码生成器" 13/600 + close×.
Result box (bg`--mi-fill-2` border radius12 padding12; mono 13.5 lh1.6 break-all min-h44; digit/symbol coloring) +
strength bar (track h4 r2 + label). Length row ("长度" + value pill) + range (min8 max40 accent`--mi-teal`).
3 toggles (大写字母A–Z / 数字0–9 / 符号!@#$). Mode segmented (bg`--mi-fill` r10 pad3; tabs 随机/易记/PIN h27 r8;
active bg#fff w600 shadow). Buttons: 复制密码 (flex1 h34 r10 ink) + 重新生成 (34×34 r10 outline refresh).

**Sync bar** (`height32; flex-none; border-top 1px --mi-line-1; padding:0 14; gap7`): dot 6×6 (`--mi-teal` synced /
`--mi-sync-amber` syncing) + label 11 `--mi-muted` ("已同步 · 2 分钟前" / "正在同步…") + spacer + sync btn 24×24 r7
(spins .8s while syncing → "刚刚" after 1300ms).

**Locked state**: `flex:1; center column; gap10; padding24`: logo46 + "密屿已锁定" 15.5/600 + subtitle
"输入主密码以解锁密钥库" 12 `--mi-muted` mt-6 + input (236×36 bg`--mi-fill` border1px transparent radius10 pad0 12 13px,
focus border`--mi-teal`) + unlock btn (236×36 r10 ink primary) + biometric (36×36 r50% border, fingerprint `--mi-teal-text`) + hint 10.5.

## Autofill side panels (content Shadow DOM)
White card border1px`--mi-line-2` radius14 side-panel-shadow `mvIn .18s` overflow hidden. Never occlude the form.
Shared header (`padding:10 13 7; gap7`): mini-logo16 + "密屿" 11.5/600`--mi-teal-text` + spacer + match-count 10.5`--mi-faint`.

- **2c login match** (width 272): connector line (22×1.5 `rgba(22,24,29,.22)`) + dot (7×7 `--mi-teal`).
  Rows `padding:8 13; gap9; hover--mi-row-hover`: tile30 r9 + title12.5/600 + user11 + **填充** plain text
  11/600`--mi-teal-text` (no pill). Filled → 已填充 badge (h28 pad0 12 r14 bg`--mi-teal-10` border check+text) +
  input corner check (22×22 r6 bg`--mi-teal` white check).
- **3a 2FA** (width 276): header "1 个匹配项 · 2FA". Match row + TOTP box (`margin:0 13; bg--mi-fill-2; border;
  radius10; padding:9 11`: code 18/600 mono`--mi-teal-text` + seconds + meter). Actions 填充验证码 (ink) + copy.
  Host 6 boxes 40×46 r9 19/600 mono; filled border`rgba(14,138,114,.5)` bg`rgba(14,138,114,.05)`. Filled →
  已填充验证码 badge + 撤销 link.
- **2e register-generate**: popover (`top44; bg#fff; border; radius14; side-panel-shadow; padding:11 13 13`):
  header "密屿 · 强密码建议" + meta (极强/强/中等 · N 字符 · 含符号). Suggestion box (mono colorize). Length row
  (label + range + value). Rule pills `0–9`/`!@#$` (h26 pad0 11 r13 11.5/600 mono; on bg`--mi-teal-12`
  fg`--mi-teal-text` border`rgba(14,138,114,.25)`; off transparent fg`--mi-muted` border`--mi-line-3`) + 换一个.
  使用此密码 (ink). Footnote. After use → saved-confirm (check circle + "已保存到密屿" + sub + 撤销).
- **2f locked hint** (no in-page master-pw): input trailing gray lock; info bar below (bg`--mi-fill`(dark
  `#262A33`) border radius12 padding:11 13 gap10): lock circle + "密屿已锁定 · N 个匹配项不可见" 12.5/600 +
  "点击右上角工具栏中的 密屿图标解锁" 11.
- **3b passkey selector**: overlay `rgba(18,22,30,.28)`; dialog (302 width, top96, centered, bg`--mi-panel` border
  radius16 passkey-shadow `mvIn`): header (mini-logo + "密屿" + domain). Choose: icon circle40 + key + "选择通行密钥"
  14/600 + sub + account list (rows padding9 8 r10 hover, tile30 + name12.5/600 + user11 + chevron) + footer
  "改用密码登录" (h40 border-top). Done: check circle + "已验证通行密钥" + "正在以 {user} 登录…" + footer "返回".

## Options page (2g) — bg `--mi-options-bg`
**Sidebar** (width236 border-right1px`--mi-line-1` `padding:20 12 14`): brand block (logo28 + "密屿" 15/600 +
version badge `v1.3.0` 10px mono bg`--mi-icon-hover` r5 pad2 6). Nav 8 items (height34 r9 pad0 12 13px mb2;
active fg`--mi-ink` w600 bg`--mi-icon-hover`; idle fg`--mi-text-2`): 账户与同步/安全/自动填充/密码生成器/Send/外观/导入与导出/关于.
Spacer. User card (border-top; avatar28 r50% + name12/600 + email10.5).

**Content** (flex1 overflow-y; inner max-width720 `padding:28 40 44`): eyebrow "设置" 12 `--mi-muted` +
title 24/650 ls-.01em `margin:2 0 18`. Sections `gap8`.
**Setting-card**: bg`--mi-card` border1px`--mi-line-1` radius12 padding13 16; align center gap14; left col flex1
(title 13.5 + desc 11.5 `--mi-muted`); right control. Outline button h30 pad0 14 r9 border`--mi-line-3` 12.5px.
Select: real dropdown (prototype "cycle select" → true menu), h30 pad0 11 r9 border + chevron-down.

Sections:
- **账户与同步**: account card (avatar44 + "张之航" 14/600 + "…· 自托管 Vaultwarden" 12 + 管理账户) + 密钥库同步 card
  ("上次同步 · 2 分钟前" + **立即同步** outline w/ spinner→"刚刚") + 自动同步 toggle(on).
- **安全**: 自动锁定 select(1分钟/5分钟/15分钟/1小时/从不, def 5分钟) + 生物识别 toggle(on) + 主密码 (修改主密码).
- **自动填充**: 内联填充建议 toggle(on) + 填充后自动提交 toggle(off) + 快捷键 keychip "⌘⇧Space" mono + 更改.
- **密码生成器**: 默认长度 range(8–40, w180) + value pill(20) + 包含数字 toggle(on) + 包含符号 toggle(on).
- **Send**: intro card ("端到端加密的临时分享" + sub + **新建 Send** ink). Create form (border`--mi-teal .3`):
  type segmented 文本/文件 + 名称 + content + 有效期 select(1/3/7/30天) + 最大访问次数 select(1/5/10/无限制) +
  访问密码 toggle(36×19) + 创建并复制链接 + 取消. Active list (item card padding12 16 gap13, expired opacity.5):
  icon-tile34 r10 bg`--mi-teal .09` (text/file icon) + name13/600 + meta11.5 + copy-link + delete(danger).
  Footer 11 "链接与内容均在本地加密后上传…".
- **外观**: 主题 segmented 浅色/深色/跟随系统 (w230) + 语言 select 简体中文/English (⚠ no 日本語 — user decision) + 紧凑密度 toggle(off).
- **导入与导出**: 导入 (选择来源, sub "1Password、Bitwarden、Chrome、CSV") + 导出加密存档 + 删除本地数据 (danger card).
- **关于**: centered logo44 + "密屿 MiYu" 15/600 + "版本 x (build …)" 12 mono + 检查更新 ink. Footer links.

## Demo data (placeholders only — real data comes from vault)
Nebula 云 `#0B6BC2`(pk,match) / Forge 代码托管 `#3B3F46`(totp) / Quill 文档 `#7C5CBF`(pk) / Orbit Mail `#C2571A` /
北岸银行·借记卡 `#0F7B4F`(card) / 家庭 Wi-Fi `#946B00`(note) / 张之航·个人身份 `#5C5C5C`(id) / Aurora 音乐 `#B4275E`.
Tile color for real items: derive deterministically from the item name/id.
