# 卡 / 身份自动填充 — 里程碑 1 实现计划（表单检测 + 弹层填充）

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 让浏览器扩展在检测到信用卡表单 / 地址·联系人表单时，通过现有 Vaultwarden 弹层让用户点选一张卡 / 一个身份并填入该表单。

**Architecture:** 复用登录自动填充的中心化结构——service worker 持有 UserKey 与明文 vault，content script 只做检测/弹层/写入。给「检测→弹层→worker」链路引入判别符 `kind: 'login' | 'card' | 'identity'`，登录路径保持默认 `'login'` 不变。卡/身份**无 URI**，候选为该类型全部条目（不按 URL 匹配），授权来自显式可信用户手势 + reprompt 门。

**Tech Stack:** TypeScript、MV3、esbuild（`bundle:true`，新模块作为 `content/autofill` 入口的 import 自动打包）、vitest + happy-dom。

## Global Constraints

- 设计依据：`docs/superpowers/specs/2026-06-30-card-identity-autofill-design.md`。
- 安全红线：master password / MasterKey / UserKey / 明文 vault **不得进入 content script**；机密只在用户显式点选后一次性返回；不写 `storage` / DOM attribute / console / 页面全局。
- **reprompt 条目**一律拒绝页面内释放，抛 `reprompt_required`（worker 端）。
- 身份 **ssn / passportNumber / licenseNumber 不进页面填充**，即使解密结构里有也不回传。
- 卡/身份**不做 URL 匹配**（无 URI）。
- 代码标识符与路径用英文；不填 hidden / disabled / readonly 字段；不自动提交表单。
- 测试命令：单文件 `npx vitest run <path>`；类型 `npm run typecheck`；全量 `npm test`。
- 提交粒度：每个 Task 末尾提交一次。

---

## 文件结构

新增：
- `src/content/field-map.ts` — 纯函数：字段提示 → 卡/身份角色。无 DOM 依赖。
- `src/content/field-map.test.ts`
- `src/content/field-detection.ts` — `detectCardForms` / `detectIdentityForms`（DOM 扫描 + 门槛 + 锚点）。
- `src/content/field-detection.test.ts`
- `src/content/fill-card-identity.ts` — 按角色写入（含合并 exp、月年拆分、`<select>` 匹配、全名合成）。
- `src/content/fill-card-identity.test.ts`

修改：
- `src/messaging/protocol.ts` — 新增 `FillKind` / `FillItemCandidate` / `CardFillData` / `IdentityFillData` 类型与两条消息。
- `src/core/vault/vault-service.ts` — 新增 `findFillItems` / `getFillData`。
- `src/core/vault/vault-service.test.ts` — 对应测试。
- `src/background/router.ts` — 路由两条消息。
- `src/background/router.test.ts` — 对应测试。
- `src/content/popover.ts` — 引入 `kind` 与公共展示结构 `PopoverCandidate`。
- `src/content/popover.test.ts` — 适配新结构。
- `src/content/autofill.ts` — 挂卡/身份弹层并端到端接线。
- `src/content/autofill.test.ts` — 对应测试。

---

## Task 1: field-map（纯字段分类）

**Files:**
- Create: `src/content/field-map.ts`
- Test: `src/content/field-map.test.ts`

**Interfaces:**
- Produces:
  - `type CardRole = 'cardholderName' | 'number' | 'exp' | 'expMonth' | 'expYear' | 'code'`
  - `type IdentityRole = 'title' | 'firstName' | 'middleName' | 'lastName' | 'fullName' | 'address1' | 'address2' | 'address3' | 'city' | 'state' | 'postalCode' | 'country' | 'company' | 'email' | 'phone' | 'username'`
  - `interface FieldHints { autocomplete: string; name: string; id: string; ariaLabel: string; placeholder: string; type: string }`
  - `classifyCardField(hints: FieldHints): CardRole | undefined`
  - `classifyIdentityField(hints: FieldHints): IdentityRole | undefined`

- [ ] **Step 1: 写失败测试**

`src/content/field-map.test.ts`:

```ts
import { describe, expect, it } from 'vitest';
import { classifyCardField, classifyIdentityField, type FieldHints } from './field-map.js';

function hints(partial: Partial<FieldHints>): FieldHints {
  return { autocomplete: '', name: '', id: '', ariaLabel: '', placeholder: '', type: 'text', ...partial };
}

describe('card field classification', () => {
  it('maps cc-* autocomplete tokens, including a billing section prefix', () => {
    expect(classifyCardField(hints({ autocomplete: 'cc-number' }))).toBe('number');
    expect(classifyCardField(hints({ autocomplete: 'billing cc-csc' }))).toBe('code');
    expect(classifyCardField(hints({ autocomplete: 'cc-exp' }))).toBe('exp');
    expect(classifyCardField(hints({ autocomplete: 'cc-exp-month' }))).toBe('expMonth');
    expect(classifyCardField(hints({ autocomplete: 'cc-name' }))).toBe('cardholderName');
  });

  it('falls back to name/id hints', () => {
    expect(classifyCardField(hints({ name: 'cardNumber' }))).toBe('number');
    expect(classifyCardField(hints({ id: 'cvv' }))).toBe('code');
    expect(classifyCardField(hints({ name: 'cardholder-name' }))).toBe('cardholderName');
  });

  it('returns undefined for unrelated fields', () => {
    expect(classifyCardField(hints({ name: 'search' }))).toBeUndefined();
  });
});

describe('identity field classification', () => {
  it('maps standard address/contact autocomplete tokens', () => {
    expect(classifyIdentityField(hints({ autocomplete: 'given-name' }))).toBe('firstName');
    expect(classifyIdentityField(hints({ autocomplete: 'family-name' }))).toBe('lastName');
    expect(classifyIdentityField(hints({ autocomplete: 'shipping street-address' }))).toBe('address1');
    expect(classifyIdentityField(hints({ autocomplete: 'address-line2' }))).toBe('address2');
    expect(classifyIdentityField(hints({ autocomplete: 'address-level2' }))).toBe('city');
    expect(classifyIdentityField(hints({ autocomplete: 'postal-code' }))).toBe('postalCode');
    expect(classifyIdentityField(hints({ autocomplete: 'country-name' }))).toBe('country');
    expect(classifyIdentityField(hints({ autocomplete: 'name' }))).toBe('fullName');
  });

  it('does not misclassify "company name" as a full name', () => {
    expect(classifyIdentityField(hints({ name: 'company name' }))).toBe('company');
  });

  it('does not treat a username field as an identity name field', () => {
    // \bname\b must not match inside "username"
    expect(classifyIdentityField(hints({ name: 'username' }))).toBe('username');
  });
});
```

- [ ] **Step 2: 运行确认失败**

Run: `npx vitest run src/content/field-map.test.ts`
Expected: FAIL（`field-map.js` 不存在 / 函数未定义）

- [ ] **Step 3: 实现 `src/content/field-map.ts`**

```ts
// Pure field classification for card and identity autofill. Maps a field's hints
// (autocomplete tokens first, then name/id/aria/placeholder text) to a card or
// identity role. No DOM access — callers extract FieldHints from the element.

export type CardRole = 'cardholderName' | 'number' | 'exp' | 'expMonth' | 'expYear' | 'code';

export type IdentityRole =
  | 'title' | 'firstName' | 'middleName' | 'lastName' | 'fullName'
  | 'address1' | 'address2' | 'address3' | 'city' | 'state' | 'postalCode' | 'country'
  | 'company' | 'email' | 'phone' | 'username';

export interface FieldHints {
  autocomplete: string;
  name: string;
  id: string;
  ariaLabel: string;
  placeholder: string;
  type: string;
}

/** Lowercase autocomplete tokens, e.g. "billing cc-number" → ["billing","cc-number"]. */
function autocompleteTokens(hints: FieldHints): string[] {
  return hints.autocomplete.toLowerCase().split(/\s+/).filter(Boolean);
}

/** Combined lowercase name/id/aria/placeholder text for hint-based fallback. */
function hintText(hints: FieldHints): string {
  return `${hints.name} ${hints.id} ${hints.ariaLabel} ${hints.placeholder}`.toLowerCase();
}

const CARD_AUTOCOMPLETE: Record<string, CardRole> = {
  'cc-name': 'cardholderName',
  'cc-given-name': 'cardholderName',
  'cc-family-name': 'cardholderName',
  'cc-number': 'number',
  'cc-exp': 'exp',
  'cc-exp-month': 'expMonth',
  'cc-exp-year': 'expYear',
  'cc-csc': 'code',
};

const CARD_HINTS: Array<[RegExp, CardRole]> = [
  [/card.?holder|name.?on.?card|ccname|cc.?name/, 'cardholderName'],
  [/card.?number|cardnum|cc.?num|ccnumber|acctnum/, 'number'],
  [/exp.?month|expmonth|exp.?mm/, 'expMonth'],
  [/exp.?year|expyear|exp.?yy/, 'expYear'],
  [/expir|cc.?exp|card.?exp/, 'exp'],
  [/cvc|cvv|csc|security.?code|card.?code|verification.?value/, 'code'],
];

export function classifyCardField(hints: FieldHints): CardRole | undefined {
  for (const token of autocompleteTokens(hints)) {
    const role = CARD_AUTOCOMPLETE[token];
    if (role) return role;
  }
  const text = hintText(hints);
  for (const [re, role] of CARD_HINTS) if (re.test(text)) return role;
  return undefined;
}

const IDENTITY_AUTOCOMPLETE: Record<string, IdentityRole> = {
  'honorific-prefix': 'title',
  'given-name': 'firstName',
  'additional-name': 'middleName',
  'family-name': 'lastName',
  'name': 'fullName',
  'street-address': 'address1',
  'address-line1': 'address1',
  'address-line2': 'address2',
  'address-line3': 'address3',
  'address-level2': 'city',
  'address-level1': 'state',
  'postal-code': 'postalCode',
  'country': 'country',
  'country-name': 'country',
  'organization': 'company',
  'email': 'email',
  'tel': 'phone',
  'tel-national': 'phone',
  'username': 'username',
};

// Specific roles before the generic \bname\b fullName fallback so "company name"
// resolves to company, not fullName.
const IDENTITY_HINTS: Array<[RegExp, IdentityRole]> = [
  [/first.?name|given.?name|forename|fname/, 'firstName'],
  [/middle.?name|additional.?name|mname/, 'middleName'],
  [/last.?name|family.?name|surname|lname/, 'lastName'],
  [/company|organi[sz]ation|business/, 'company'],
  [/street|address.?line.?1|addr.?1|address1/, 'address1'],
  [/address.?line.?2|addr.?2|address2|apt|suite|unit/, 'address2'],
  [/address.?line.?3|addr.?3|address3/, 'address3'],
  [/postal|zip|post.?code/, 'postalCode'],
  [/\bcity\b|town|locality/, 'city'],
  [/\bstate\b|province|region|county/, 'state'],
  [/\bcountry\b/, 'country'],
  [/e.?mail/, 'email'],
  [/phone|mobile|\btel\b/, 'phone'],
  [/prefix|salutation|honorific/, 'title'],
  [/full.?name|your.?name|\bname\b/, 'fullName'],
];

export function classifyIdentityField(hints: FieldHints): IdentityRole | undefined {
  for (const token of autocompleteTokens(hints)) {
    const role = IDENTITY_AUTOCOMPLETE[token];
    if (role) return role;
  }
  const text = hintText(hints);
  for (const [re, role] of IDENTITY_HINTS) if (re.test(text)) return role;
  return undefined;
}
```

- [ ] **Step 4: 运行确认通过**

Run: `npx vitest run src/content/field-map.test.ts`
Expected: PASS

- [ ] **Step 5: 提交**

```bash
git add src/content/field-map.ts src/content/field-map.test.ts
git commit -m "feat: card/identity field classification (pure)"
```

---

## Task 2: protocol 共享类型与消息

**Files:**
- Modify: `src/messaging/protocol.ts`

**Interfaces:**
- Consumes: 无
- Produces:
  - `type FillKind = 'card' | 'identity'`
  - `interface FillItemCandidate { id: string; name: string; subtitle?: string; favorite: boolean; reprompt?: boolean }`
  - `interface CardFillData { cardholderName?: string; number?: string; expMonth?: string; expYear?: string; code?: string }`
  - `interface IdentityFillData { title?; firstName?; middleName?; lastName?; address1?; address2?; address3?; city?; state?; postalCode?; country?; company?; email?; phone?; username? }`（全部 `string | undefined`）
  - RequestMessage 新增 `{ type: 'autofill.findFillItems'; kind: FillKind }`、`{ type: 'autofill.getFillData'; cipherId: string; kind: FillKind }`
  - ResponseMessage 新增 `{ ok: true; data: FillItemCandidate[] }`、`{ ok: true; data: CardFillData | IdentityFillData }`

- [ ] **Step 1: 在 `AutofillCredentials` 之后插入类型**

`src/messaging/protocol.ts`，在 `AutofillCredentials` 接口块之后新增：

```ts
export type FillKind = 'card' | 'identity';

/** A card/identity candidate for the fill popover. Carries no secret — subtitle is brand/full name. */
export interface FillItemCandidate {
  id: string;
  name: string;
  subtitle?: string;
  favorite: boolean;
  /** True when reprompt-protected; cannot be filled inline (worker refuses). */
  reprompt?: boolean;
}

/** Fillable card fields. Number + code are sensitive; released only on explicit user selection. */
export interface CardFillData {
  cardholderName?: string;
  number?: string;
  expMonth?: string;
  expYear?: string;
  code?: string;
}

/** Fillable identity fields. National-ID secrets (ssn/passport/license) are intentionally absent. */
export interface IdentityFillData {
  title?: string;
  firstName?: string;
  middleName?: string;
  lastName?: string;
  address1?: string;
  address2?: string;
  address3?: string;
  city?: string;
  state?: string;
  postalCode?: string;
  country?: string;
  company?: string;
  email?: string;
  phone?: string;
  username?: string;
}
```

- [ ] **Step 2: 在 RequestMessage 末尾（`autofill.updateLogin` 之后）新增两条**

```ts
  | { type: 'autofill.findFillItems'; kind: FillKind }
  | { type: 'autofill.getFillData'; cipherId: string; kind: FillKind };
```

（注意：把原本结尾的 `;` 移到新最后一行；中间各行以 `|` 续接。）

- [ ] **Step 3: 在 ResponseMessage 中（`AutofillCredentials` 那行之后）新增两条**

```ts
  | { ok: true; data: FillItemCandidate[] }
  | { ok: true; data: CardFillData | IdentityFillData }
```

- [ ] **Step 4: 类型检查通过**

Run: `npm run typecheck`
Expected: 成功，无错误（仅新增类型，暂无消费者）。

- [ ] **Step 5: 提交**

```bash
git add src/messaging/protocol.ts
git commit -m "feat: protocol types for card/identity fill (findFillItems/getFillData)"
```

---

## Task 3: field-detection（卡/身份表单检测）

**Files:**
- Create: `src/content/field-detection.ts`
- Test: `src/content/field-detection.test.ts`

**Interfaces:**
- Consumes: `classifyCardField` / `classifyIdentityField` / `FieldHints`（Task 1）；`isFillableInput`（`form-detection.ts`，现有 export）
- Produces:
  - `type FillFieldElement = HTMLInputElement | HTMLSelectElement`
  - `interface DetectedFillForm { kind: 'card' | 'identity'; id: string; fields: Map<CardRole | IdentityRole, FillFieldElement>; anchor: HTMLElement }`
  - `detectCardForms(root?: ParentNode, exclude?: Set<Element>): DetectedFillForm[]`
  - `detectIdentityForms(root?: ParentNode, exclude?: Set<Element>): DetectedFillForm[]`

- [ ] **Step 1: 写失败测试**

`src/content/field-detection.test.ts`:

```ts
// @vitest-environment happy-dom
import { beforeEach, describe, expect, it } from 'vitest';
import { detectCardForms, detectIdentityForms } from './field-detection.js';

describe('card form detection', () => {
  beforeEach(() => { document.body.innerHTML = ''; });

  it('detects a card form when a card-number field is present', () => {
    document.body.innerHTML = `
      <form>
        <input autocomplete="cc-name">
        <input autocomplete="cc-number">
        <input autocomplete="cc-exp">
        <input autocomplete="cc-csc">
      </form>`;
    const forms = detectCardForms();
    expect(forms).toHaveLength(1);
    expect(forms[0]?.kind).toBe('card');
    expect(forms[0]?.fields.has('number')).toBe(true);
    expect(forms[0]?.fields.has('code')).toBe(true);
  });

  it('does not detect a card form without a number field', () => {
    document.body.innerHTML = `<form><input autocomplete="cc-csc"></form>`;
    expect(detectCardForms()).toEqual([]);
  });
});

describe('identity form detection (conservative)', () => {
  beforeEach(() => { document.body.innerHTML = ''; });

  it('detects an identity form when an address signal is present', () => {
    document.body.innerHTML = `
      <form>
        <input autocomplete="given-name">
        <input autocomplete="family-name">
        <input autocomplete="street-address">
        <input autocomplete="postal-code">
      </form>`;
    const forms = detectIdentityForms();
    expect(forms).toHaveLength(1);
    expect(forms[0]?.fields.has('address1')).toBe(true);
  });

  it('detects an identity form on a first+last name pair without an address', () => {
    document.body.innerHTML = `
      <form><input autocomplete="given-name"><input autocomplete="family-name"></form>`;
    expect(detectIdentityForms()).toHaveLength(1);
  });

  it('does not fire on a lone email/subscribe field', () => {
    document.body.innerHTML = `<form><input type="email" autocomplete="email"></form>`;
    expect(detectIdentityForms()).toEqual([]);
  });

  it('skips fields in the exclude set (already claimed by login detection)', () => {
    document.body.innerHTML = `
      <form>
        <input id="u" type="email" autocomplete="email">
        <input autocomplete="given-name">
        <input autocomplete="family-name">
      </form>`;
    const email = document.getElementById('u') as HTMLInputElement;
    const forms = detectIdentityForms(document, new Set([email]));
    expect(forms[0]?.fields.has('email')).toBe(false);
    expect(forms[0]?.fields.has('firstName')).toBe(true);
  });
});
```

- [ ] **Step 2: 运行确认失败**

Run: `npx vitest run src/content/field-detection.test.ts`
Expected: FAIL（模块不存在）

- [ ] **Step 3: 实现 `src/content/field-detection.ts`**

```ts
import { isFillableInput } from './form-detection.js';
import { classifyCardField, classifyIdentityField, type CardRole, type IdentityRole, type FieldHints } from './field-map.js';

export type FillFieldElement = HTMLInputElement | HTMLSelectElement;

export interface DetectedFillForm {
  kind: 'card' | 'identity';
  id: string;
  fields: Map<CardRole | IdentityRole, FillFieldElement>;
  anchor: HTMLElement;
}

let nextFillId = 0;

export function detectCardForms(root: ParentNode = document, exclude: Set<Element> = new Set()): DetectedFillForm[] {
  return detectForms(root, exclude, 'card');
}

export function detectIdentityForms(root: ParentNode = document, exclude: Set<Element> = new Set()): DetectedFillForm[] {
  return detectForms(root, exclude, 'identity');
}

function detectForms(root: ParentNode, exclude: Set<Element>, kind: 'card' | 'identity'): DetectedFillForm[] {
  const classify = kind === 'card' ? classifyCardField : classifyIdentityField;
  const fillable = Array.from(root.querySelectorAll<FillFieldElement>('input, select'))
    .filter(isFillableField)
    .filter((el) => !exclude.has(el));

  // Group by wrapping <form> or nearest container; first element per role wins.
  const groups = new Map<ParentNode, Map<CardRole | IdentityRole, FillFieldElement>>();
  for (const el of fillable) {
    const role = classify(hintsFor(el)) as CardRole | IdentityRole | undefined;
    if (!role) continue;
    const container = el.closest('form') ?? nearestContainer(el);
    let map = groups.get(container);
    if (!map) { map = new Map(); groups.set(container, map); }
    if (!map.has(role)) map.set(role, el);
  }

  const forms: DetectedFillForm[] = [];
  for (const fields of groups.values()) {
    if (!meetsThreshold(kind, fields)) continue;
    const anchor = anchorFor(kind, fields);
    if (!anchor) continue;
    forms.push({ kind, id: assignFillId(anchor), fields, anchor });
  }
  return forms;
}

function meetsThreshold(kind: 'card' | 'identity', fields: Map<string, FillFieldElement>): boolean {
  if (kind === 'card') return fields.has('number');
  if (fields.has('address1') || fields.has('postalCode')) return true;
  return fields.has('firstName') && fields.has('lastName');
}

function anchorFor(kind: 'card' | 'identity', fields: Map<string, FillFieldElement>): HTMLElement | undefined {
  const order = kind === 'card'
    ? ['number', 'cardholderName', 'exp', 'expMonth', 'code']
    : ['address1', 'firstName', 'lastName', 'fullName', 'postalCode', 'email'];
  for (const role of order) { const el = fields.get(role); if (el) return el; }
  return fields.values().next().value;
}

/** Visible + editable input or select; reuses the login detector's input rule for inputs. */
export function isFillableField(el: FillFieldElement): boolean {
  if (el instanceof HTMLInputElement) return isFillableInput(el);
  if (el.disabled || el.hidden) return false;
  return el.offsetParent != null || el.isConnected;
}

function hintsFor(el: FillFieldElement): FieldHints {
  return {
    autocomplete: el.getAttribute('autocomplete') ?? '',
    name: el.getAttribute('name') ?? '',
    id: el.id,
    ariaLabel: el.getAttribute('aria-label') ?? '',
    placeholder: el.getAttribute('placeholder') ?? '',
    type: el instanceof HTMLInputElement ? el.type : 'select',
  };
}

function nearestContainer(el: Element): ParentNode {
  return el.closest('form, section, main, article') ?? document;
}

function assignFillId(el: HTMLElement): string {
  const existing = el.dataset.vwFillId;
  if (existing) return existing;
  const id = `vw-fill-${nextFillId++}`;
  el.dataset.vwFillId = id;
  return id;
}
```

- [ ] **Step 4: 运行确认通过**

Run: `npx vitest run src/content/field-detection.test.ts`
Expected: PASS

- [ ] **Step 5: 提交**

```bash
git add src/content/field-detection.ts src/content/field-detection.test.ts
git commit -m "feat: detect card and identity forms (conservative thresholds)"
```

---

## Task 4: fill-card-identity（按角色写入）

**Files:**
- Create: `src/content/fill-card-identity.ts`
- Test: `src/content/fill-card-identity.test.ts`

**Interfaces:**
- Consumes: `DetectedFillForm` / `FillFieldElement`（Task 3）；`CardFillData` / `IdentityFillData`（Task 2）
- Produces:
  - `fillCardForm(form: DetectedFillForm, data: CardFillData): boolean`
  - `fillIdentityForm(form: DetectedFillForm, data: IdentityFillData): boolean`

- [ ] **Step 1: 写失败测试**

`src/content/fill-card-identity.test.ts`:

```ts
// @vitest-environment happy-dom
import { beforeEach, describe, expect, it } from 'vitest';
import { detectCardForms, detectIdentityForms } from './field-detection.js';
import { fillCardForm, fillIdentityForm } from './fill-card-identity.js';

describe('fillCardForm', () => {
  beforeEach(() => { document.body.innerHTML = ''; });

  it('fills number, cvc, and split month/year', () => {
    document.body.innerHTML = `
      <form>
        <input autocomplete="cc-number" id="num">
        <input autocomplete="cc-csc" id="csc">
        <input autocomplete="cc-exp-month" id="mm">
        <input autocomplete="cc-exp-year" id="yy">
      </form>`;
    const form = detectCardForms()[0]!;
    expect(fillCardForm(form, { number: '4111111111111111', code: '123', expMonth: '9', expYear: '2030' })).toBe(true);
    expect((document.getElementById('num') as HTMLInputElement).value).toBe('4111111111111111');
    expect((document.getElementById('csc') as HTMLInputElement).value).toBe('123');
    expect((document.getElementById('mm') as HTMLInputElement).value).toBe('9');
    expect((document.getElementById('yy') as HTMLInputElement).value).toBe('2030');
  });

  it('composes a combined MM/YY expiry field', () => {
    document.body.innerHTML = `<form><input autocomplete="cc-number"><input autocomplete="cc-exp" id="exp" placeholder="MM/YY"></form>`;
    const form = detectCardForms()[0]!;
    fillCardForm(form, { number: '4111', expMonth: '9', expYear: '2030' });
    expect((document.getElementById('exp') as HTMLInputElement).value).toBe('09/30');
  });

  it('matches a country/month <select> by value or visible text', () => {
    document.body.innerHTML = `
      <form>
        <input autocomplete="cc-number">
        <select autocomplete="cc-exp-month" id="mm"><option value="">--</option><option value="09">September</option></select>
      </form>`;
    const form = detectCardForms()[0]!;
    fillCardForm(form, { number: '4111', expMonth: '09' });
    expect((document.getElementById('mm') as HTMLSelectElement).value).toBe('09');
  });
});

describe('fillIdentityForm', () => {
  beforeEach(() => { document.body.innerHTML = ''; });

  it('fills address fields and composes a single full-name field', () => {
    document.body.innerHTML = `
      <form>
        <input autocomplete="name" id="full">
        <input autocomplete="street-address" id="street">
        <input autocomplete="postal-code" id="zip">
      </form>`;
    // address signal present → detected; full-name composed from parts.
    const form = detectIdentityForms()[0]!;
    fillIdentityForm(form, { firstName: 'Ada', lastName: 'Lovelace', address1: '1 Analytical Way', postalCode: 'EC1' });
    expect((document.getElementById('full') as HTMLInputElement).value).toBe('Ada Lovelace');
    expect((document.getElementById('street') as HTMLInputElement).value).toBe('1 Analytical Way');
    expect((document.getElementById('zip') as HTMLInputElement).value).toBe('EC1');
  });
});
```

- [ ] **Step 2: 运行确认失败**

Run: `npx vitest run src/content/fill-card-identity.test.ts`
Expected: FAIL（模块不存在）

- [ ] **Step 3: 实现 `src/content/fill-card-identity.ts`**

```ts
import type { CardFillData, IdentityFillData } from '../messaging/protocol.js';
import type { DetectedFillForm, FillFieldElement } from './field-detection.js';
import type { CardRole, IdentityRole } from './field-map.js';

export function fillCardForm(form: DetectedFillForm, data: CardFillData): boolean {
  let filled = false;
  const set = (role: CardRole, value: string | undefined) => {
    if (!value) return;
    const el = form.fields.get(role);
    if (el && setFieldValue(el, value)) filled = true;
  };
  set('cardholderName', data.cardholderName);
  set('number', data.number);
  set('code', data.code);
  set('expMonth', data.expMonth);
  set('expYear', data.expYear);
  const expEl = form.fields.get('exp');
  if (expEl && data.expMonth && data.expYear) {
    if (setFieldValue(expEl, formatExp(expEl, data.expMonth, data.expYear))) filled = true;
  }
  return filled;
}

export function fillIdentityForm(form: DetectedFillForm, data: IdentityFillData): boolean {
  let filled = false;
  const set = (role: IdentityRole, value: string | undefined) => {
    if (!value) return;
    const el = form.fields.get(role);
    if (el && setFieldValue(el, value)) filled = true;
  };
  set('title', data.title);
  set('firstName', data.firstName);
  set('middleName', data.middleName);
  set('lastName', data.lastName);
  set('address1', data.address1);
  set('address2', data.address2);
  set('address3', data.address3);
  set('city', data.city);
  set('state', data.state);
  set('postalCode', data.postalCode);
  set('country', data.country);
  set('company', data.company);
  set('email', data.email);
  set('phone', data.phone);
  set('username', data.username);
  const fullEl = form.fields.get('fullName');
  if (fullEl) {
    const full = [data.title, data.firstName, data.middleName, data.lastName].filter(Boolean).join(' ');
    if (full && setFieldValue(fullEl, full)) filled = true;
  }
  return filled;
}

/** Format a combined expiry value as MM/YY, or MM/YYYY when the field looks four-digit. */
function formatExp(el: FillFieldElement, month: string, year: string): string {
  const mm = month.padStart(2, '0').slice(-2);
  const placeholder = el.getAttribute('placeholder') ?? '';
  const wantsFour = /y{4}/i.test(placeholder) || (el instanceof HTMLInputElement && el.maxLength >= 7);
  const yy = wantsFour ? year.padStart(4, '20').slice(-4) : year.slice(-2);
  return `${mm}/${yy}`;
}

function setFieldValue(el: FillFieldElement, value: string): boolean {
  if (el instanceof HTMLSelectElement) return setSelectValue(el, value);
  el.value = value;
  el.dispatchEvent(new Event('input', { bubbles: true }));
  el.dispatchEvent(new Event('change', { bubbles: true }));
  return true;
}

function setSelectValue(select: HTMLSelectElement, value: string): boolean {
  const target = value.trim().toLowerCase();
  const option = Array.from(select.options).find(
    (o) => o.value.trim().toLowerCase() === target || o.text.trim().toLowerCase() === target,
  );
  if (!option) return false;
  select.value = option.value;
  select.dispatchEvent(new Event('input', { bubbles: true }));
  select.dispatchEvent(new Event('change', { bubbles: true }));
  return true;
}
```

- [ ] **Step 4: 运行确认通过**

Run: `npx vitest run src/content/fill-card-identity.test.ts`
Expected: PASS

- [ ] **Step 5: 提交**

```bash
git add src/content/fill-card-identity.ts src/content/fill-card-identity.test.ts
git commit -m "feat: fill card/identity forms by role (exp merge, select match, full-name compose)"
```

---

## Task 5: vault-service.findFillItems

**Files:**
- Modify: `src/core/vault/vault-service.ts`
- Test: `src/core/vault/vault-service.test.ts`

**Interfaces:**
- Consumes: `FillKind` / `FillItemCandidate`（Task 2）；现有 `SUMMARY_CACHE_KEY`、`CipherSummary`、`AppError`、`this.deps.session.loadUserKey`
- Produces: `findFillItems(kind: FillKind): Promise<FillItemCandidate[]>`

- [ ] **Step 1: 写失败测试**

在 `src/core/vault/vault-service.test.ts` 的 `describe('VaultService', …)` 内追加：

```ts
  it('findFillItems lists all cards (no URL match), sorted favorite-then-name, without secrets', async () => {
    const sync: SyncResponse = {
      profile: { id: 'u', email: 'u@example.com' },
      ciphers: [
        { id: 'card-b', type: 3, name: await encUnder('Visa B', testUserKey), favorite: false, organizationId: null,
          card: { brand: await encUnder('Visa', testUserKey), number: await encUnder('4111', testUserKey), code: await encUnder('123', testUserKey) } },
        { id: 'card-a', type: 3, name: await encUnder('Amex A', testUserKey), favorite: true, organizationId: null,
          card: { brand: await encUnder('Amex', testUserKey), number: await encUnder('3782', testUserKey), code: await encUnder('999', testUserKey) } },
        { id: 'login-x', type: 1, name: await encUnder('Login', testUserKey), favorite: false, organizationId: null,
          login: { username: await encUnder('u', testUserKey), password: await encUnder('p', testUserKey) } },
      ],
    };
    const { service } = await makeService(sync);
    await service.sync();
    const items = await service.findFillItems('card');
    expect(items.map((i) => i.id)).toEqual(['card-a', 'card-b']); // favorite first
    expect(items[0]).toMatchObject({ id: 'card-a', name: 'Amex A', subtitle: 'Amex', favorite: true });
    expect(JSON.stringify(items)).not.toContain('3782');
  });

  it('findFillItems throws locked when the vault is locked', async () => {
    const { service, session } = await makeService();
    await service.sync();
    await session.lock();
    await expect(service.findFillItems('identity')).rejects.toMatchObject({ code: 'locked' });
  });
```

- [ ] **Step 2: 运行确认失败**

Run: `npx vitest run src/core/vault/vault-service.test.ts -t findFillItems`
Expected: FAIL（`findFillItems` 未定义）

- [ ] **Step 3: 实现**

在 `src/core/vault/vault-service.ts` 顶部的 protocol 类型导入处补上类型（找到现有从 `../../messaging/protocol.js` 导入 `AutofillCandidate, AutofillCredentials` 的那行，追加 `FillKind, FillItemCandidate, CardFillData, IdentityFillData`）。若 vault-service 当前未从 protocol 导入，则新增：

```ts
import type { AutofillCandidate, AutofillCredentials, FillKind, FillItemCandidate, CardFillData, IdentityFillData } from '../../messaging/protocol.js';
```

在 `findAutofillCandidates` 方法之后插入：

```ts
  /** List every card (type 3) or identity (type 4) as a fill candidate. No URL match — card/identity
   *  have no URI; authorization is the user's explicit popover selection. Never returns secrets. */
  async findFillItems(kind: FillKind): Promise<FillItemCandidate[]> {
    const summaries = await this.deps.localStore.get<CipherSummary[]>(SUMMARY_CACHE_KEY);
    if (!summaries) throw new AppError('sync_required', 'Sync required');
    const userKey = await this.deps.session.loadUserKey();
    if (!userKey) throw new AppError('locked', 'Vault is locked');
    const wantType = kind === 'card' ? 3 : 4;
    const items = summaries
      .filter((item) => item.type === wantType && !item.undecryptable && !item.deletedDate)
      .map((item) => {
        const candidate: FillItemCandidate = { id: item.id, name: item.name, favorite: item.favorite };
        if (item.subtitle) candidate.subtitle = item.subtitle;
        if (item.reprompt) candidate.reprompt = true;
        return candidate;
      });
    items.sort((a, b) => {
      if (a.favorite !== b.favorite) return a.favorite ? -1 : 1;
      return a.name.localeCompare(b.name, undefined, { sensitivity: 'base' });
    });
    return items;
  }
```

- [ ] **Step 4: 运行确认通过**

Run: `npx vitest run src/core/vault/vault-service.test.ts -t findFillItems`
Expected: PASS

- [ ] **Step 5: 提交**

```bash
git add src/core/vault/vault-service.ts src/core/vault/vault-service.test.ts
git commit -m "feat: VaultService.findFillItems lists cards/identities (no URL match)"
```

---

## Task 6: vault-service.getFillData

**Files:**
- Modify: `src/core/vault/vault-service.ts`
- Test: `src/core/vault/vault-service.test.ts`

**Interfaces:**
- Consumes: `FillKind` / `CardFillData` / `IdentityFillData`（Task 2）；现有 `VAULT_CACHE_KEY`、`decryptCipher`、`buildOrgKeys`、`AppError`
- Produces: `getFillData(cipherId: string, kind: FillKind): Promise<CardFillData | IdentityFillData>`

- [ ] **Step 1: 写失败测试**

追加到 `vault-service.test.ts`：

```ts
  it('getFillData returns card fields including number/code on explicit fetch', async () => {
    const sync: SyncResponse = {
      profile: { id: 'u', email: 'u@example.com' },
      ciphers: [{ id: 'card-1', type: 3, name: await encUnder('Visa', testUserKey), favorite: false, organizationId: null,
        card: { number: await encUnder('4111111111111111', testUserKey), code: await encUnder('123', testUserKey), expMonth: await encUnder('9', testUserKey), expYear: await encUnder('2030', testUserKey) } }],
    };
    const { service } = await makeService(sync);
    await service.sync();
    await expect(service.getFillData('card-1', 'card')).resolves.toEqual({ number: '4111111111111111', code: '123', expMonth: '9', expYear: '2030' });
  });

  it('getFillData omits identity national-ID secrets (ssn/passport/license)', async () => {
    const sync: SyncResponse = {
      profile: { id: 'u', email: 'u@example.com' },
      ciphers: [{ id: 'id-1', type: 4, name: await encUnder('Me', testUserKey), favorite: false, organizationId: null,
        identity: { firstName: await encUnder('Ada', testUserKey), lastName: await encUnder('Lovelace', testUserKey),
          ssn: await encUnder('999-99-9999', testUserKey), passportNumber: await encUnder('P123', testUserKey), licenseNumber: await encUnder('L123', testUserKey) } }],
    };
    const { service } = await makeService(sync);
    await service.sync();
    const data = await service.getFillData('id-1', 'identity');
    expect(data).toMatchObject({ firstName: 'Ada', lastName: 'Lovelace' });
    expect(JSON.stringify(data)).not.toContain('999-99-9999');
    expect(JSON.stringify(data)).not.toContain('P123');
  });

  it('getFillData rejects a kind/type mismatch and reprompt items', async () => {
    const sync: SyncResponse = {
      profile: { id: 'u', email: 'u@example.com' },
      ciphers: [
        { id: 'card-1', type: 3, name: await encUnder('Visa', testUserKey), favorite: false, organizationId: null, reprompt: 1,
          card: { number: await encUnder('4111', testUserKey) } },
        { id: 'login-1', type: 1, name: await encUnder('L', testUserKey), favorite: false, organizationId: null,
          login: { password: await encUnder('p', testUserKey) } },
      ],
    };
    const { service } = await makeService(sync);
    await service.sync();
    await expect(service.getFillData('card-1', 'card')).rejects.toMatchObject({ code: 'reprompt_required' });
    await expect(service.getFillData('login-1', 'card')).rejects.toMatchObject({ code: 'denied' });
  });
```

> 注：`reprompt: 1` 是服务端字段；确认 `api/types.ts` 的 cipher 类型允许该字段（现有 reprompt 链路已解析它）。若类型不接受，按现有 fixtures 里 reprompt 的写法对齐。

- [ ] **Step 2: 运行确认失败**

Run: `npx vitest run src/core/vault/vault-service.test.ts -t getFillData`
Expected: FAIL（未定义）

- [ ] **Step 3: 实现**

在 `findFillItems` 之后插入：

```ts
  /** Decrypt a card/identity for filling. Refuses kind/type mismatch and reprompt items; strips
   *  identity national-ID secrets. Card number + code ARE returned (released on explicit selection). */
  async getFillData(cipherId: string, kind: FillKind): Promise<CardFillData | IdentityFillData> {
    const cache = await this.deps.localStore.get<SyncResponse>(VAULT_CACHE_KEY);
    if (!cache) throw new AppError('sync_required', 'Sync required');
    const userKey = await this.deps.session.loadUserKey();
    if (!userKey) throw new AppError('locked', 'Vault is locked');
    const cipher = cache.ciphers.find((c) => c.id === cipherId);
    if (!cipher) throw new AppError('denied', 'Autofill item is not allowed');
    const wantType = kind === 'card' ? 3 : 4;
    if (cipher.type !== wantType) throw new AppError('denied', 'Autofill item type mismatch');
    const orgKeys = await this.buildOrgKeys(cache.profile);
    const decrypted = await decryptCipher(cipher, userKey, orgKeys);
    if (!decrypted || decrypted.undecryptable) throw new AppError('denied', 'Autofill item is not allowed');
    if (decrypted.reprompt) throw new AppError('reprompt_required', 'This item requires master-password verification in the extension');
    if (kind === 'card') {
      const c = decrypted.card ?? {};
      const out: CardFillData = {};
      if (c.cardholderName) out.cardholderName = c.cardholderName;
      if (c.number) out.number = c.number;
      if (c.expMonth) out.expMonth = c.expMonth;
      if (c.expYear) out.expYear = c.expYear;
      if (c.code) out.code = c.code;
      return out;
    }
    const i = decrypted.identity ?? {};
    const out: IdentityFillData = {};
    const fields: Array<keyof IdentityFillData> = [
      'title', 'firstName', 'middleName', 'lastName', 'address1', 'address2', 'address3',
      'city', 'state', 'postalCode', 'country', 'company', 'email', 'phone', 'username',
    ];
    for (const key of fields) {
      const value = (i as Record<string, string | undefined>)[key];
      if (value) out[key] = value;
    }
    return out;
  }
```

- [ ] **Step 4: 运行确认通过**

Run: `npx vitest run src/core/vault/vault-service.test.ts -t getFillData`
Expected: PASS

- [ ] **Step 5: 提交**

```bash
git add src/core/vault/vault-service.ts src/core/vault/vault-service.test.ts
git commit -m "feat: VaultService.getFillData decrypts card/identity for filling (reprompt + secret guards)"
```

---

## Task 7: router 接线

**Files:**
- Modify: `src/background/router.ts`
- Test: `src/background/router.test.ts`

**Interfaces:**
- Consumes: `findFillItems` / `getFillData`（Task 5/6）
- Produces: 路由 `autofill.findFillItems` / `autofill.getFillData`

- [ ] **Step 1: 写失败测试**

`router.test.ts` 每个用例内联完整 settings 对象（无共享桩）。在文件顶部新增一个本地 helper 以免重复，再追加两条用例：

```ts
// 顶部 describe 内复用：内联 settings 桩（这两条路由不读 settings）。
const settingsStub = {
  getServerUrl: vi.fn(),
  saveServerUrl: vi.fn(),
  getDefaultUriMatchStrategy: vi.fn(async (): Promise<UriMatchStrategySetting> => 0),
  saveDefaultUriMatchStrategy: vi.fn(),
  getLockTimeout: vi.fn(async (): Promise<LockTimeoutSetting> => '15'),
  saveLockTimeout: vi.fn(),
};

it('routes autofill.findFillItems to vault.findFillItems', async () => {
  const findFillItems = vi.fn(async () => [{ id: 'c1', name: 'Visa', favorite: false }]);
  const router = createRouter({ auth: {}, vault: { findFillItems }, settings: settingsStub });
  const res = await router.handle({ type: 'autofill.findFillItems', kind: 'card' });
  expect(findFillItems).toHaveBeenCalledWith('card');
  expect(res).toEqual({ ok: true, data: [{ id: 'c1', name: 'Visa', favorite: false }] });
});

it('routes autofill.getFillData to vault.getFillData', async () => {
  const getFillData = vi.fn(async () => ({ number: '4111' }));
  const router = createRouter({ auth: {}, vault: { getFillData }, settings: settingsStub });
  const res = await router.handle({ type: 'autofill.getFillData', cipherId: 'c1', kind: 'card' });
  expect(getFillData).toHaveBeenCalledWith('c1', 'card');
  expect(res).toEqual({ ok: true, data: { number: '4111' } });
});
```

> `UriMatchStrategySetting` / `LockTimeoutSetting` 已在 `router.test.ts` 顶部导入。

- [ ] **Step 2: 运行确认失败**

Run: `npx vitest run src/background/router.test.ts -t FillItems`
Expected: FAIL（`is not wired` 抛错或分支缺失）

- [ ] **Step 3: 实现**

在 `router.ts` 的 `case 'autofill.updateLogin':` 块之后、`}` 闭合 switch 之前插入：

```ts
          case 'autofill.findFillItems': {
            if (!deps.vault.findFillItems) throw new Error('vault.findFillItems is not wired');
            return { ok: true, data: await deps.vault.findFillItems(request.kind) };
          }
          case 'autofill.getFillData': {
            if (!deps.vault.getFillData) throw new Error('vault.getFillData is not wired');
            return { ok: true, data: await deps.vault.getFillData(request.cipherId, request.kind) };
          }
```

- [ ] **Step 4: 运行确认通过**

Run: `npx vitest run src/background/router.test.ts`
Expected: PASS（全文件）

- [ ] **Step 5: 提交**

```bash
git add src/background/router.ts src/background/router.test.ts
git commit -m "feat: route autofill.findFillItems / getFillData"
```

---

## Task 8: popover 泛化（kind + 公共候选结构）

**Files:**
- Modify: `src/content/popover.ts`
- Test: `src/content/popover.test.ts`

**Interfaces:**
- Consumes: 无新增
- Produces:
  - `interface PopoverCandidate { id: string; name: string; sub?: string; favorite: boolean; reprompt?: boolean }`
  - `AutofillPopoverOptions` 新增 `kind?: 'login' | 'card' | 'identity'`
  - `AutofillPopover.showCandidates(candidates: PopoverCandidate[]): void`（签名变更）

- [ ] **Step 1: 改测试为新结构（先让其失败）**

把 `popover.test.ts` 中 `showCandidates([...])` 的入参改为公共结构，并新增 kind 头部断言。替换「renders candidates and calls onSelect when clicked」用例为：

```ts
  it('renders candidates (common shape) and calls onSelect when clicked', () => {
    const anchor = document.getElementById('pass') as HTMLElement;
    const onSelect = vi.fn();
    const popover = createAutofillPopover({ anchor, onOpen: vi.fn(), onSelect });
    popover.showCandidates([{ id: '1', name: 'Example', sub: 'me@example.com', favorite: false }]);
    trustedClick(popoverRoot(popover).querySelector<HTMLButtonElement>('button')!);
    expect(onSelect).toHaveBeenCalledWith('1');
    expect(popoverRoot(popover).textContent).toContain('me@example.com');
  });

  it('uses a card header when kind is card', () => {
    const anchor = document.getElementById('pass') as HTMLElement;
    const popover = createAutofillPopover({ anchor, kind: 'card', onOpen: vi.fn(), onSelect: vi.fn() });
    popover.showCandidates([{ id: '1', name: 'Visa', sub: 'Visa', favorite: false }]);
    expect(popoverRoot(popover).textContent).toContain('Fill card');
  });
```

（其余 `showCandidates` 调用——如有——一并改为公共结构。）

- [ ] **Step 2: 运行确认失败**

Run: `npx vitest run src/content/popover.test.ts`
Expected: FAIL（类型/文案不符）

- [ ] **Step 3: 实现 popover 变更**

`src/content/popover.ts`：

1) 删除 `import type { AutofillCandidate } …`，改为本地定义并替换接口：

```ts
export interface PopoverCandidate {
  id: string;
  name: string;
  /** username / matched URI (login) or brand / full name (card / identity). */
  sub?: string;
  favorite: boolean;
  reprompt?: boolean;
}

export interface AutofillPopover {
  element: HTMLElement;
  root: ShadowRoot;
  showStatus(message: string): void;
  showCandidates(candidates: PopoverCandidate[]): void;
  remove(): void;
}

export interface AutofillPopoverOptions {
  anchor: HTMLElement;
  kind?: 'login' | 'card' | 'identity';
  onOpen(): void;
  onSelect(cipherId: string): void;
}
```

2) 在 `createAutofillPopover` 内，按 kind 取文案：

```ts
  const kind = options.kind ?? 'login';
  const HEADER = { login: 'Fill from Vaultwarden', card: 'Fill card', identity: 'Fill identity' }[kind];
  const EMPTY = { login: 'No matching logins', card: 'No saved cards', identity: 'No saved identities' }[kind];
```

3) `showCandidates` 改用 `candidate.sub` 与 `HEADER`/`EMPTY`：

```ts
    showCandidates(candidates: PopoverCandidate[]) {
      if (candidates.length === 0) {
        render(`<div class="status">${LOCK}<span>${EMPTY}</span></div>`);
        return;
      }
      const rows = candidates.map((candidate) => `
        <button type="button" class="candidate">
          <span class="mono-chip" style="background:hsl(${hueFor(candidate.name)} 55% 48%)">${escapeHtml(monogramLetter(candidate.name))}</span>
          <span class="meta">
            <span class="name">${candidate.favorite ? STAR : ''}<span class="t">${escapeHtml(candidate.name)}</span></span>
            <span class="sub">${escapeHtml(candidate.sub ?? '')}</span>
          </span>
        </button>`).join('');
      render(`<div class="brandrow"><span class="mark">${SHIELD}</span><span class="label">${HEADER}</span></div><div class="list">${rows}</div>`);
      shadow.querySelectorAll<HTMLButtonElement>('button.candidate').forEach((button, index) => {
        button.addEventListener('click', (event) => {
          if (!event.isTrusted) return;
          options.onSelect(candidates[index]!.id);
        });
      });
    },
```

- [ ] **Step 4: 运行确认通过**

Run: `npx vitest run src/content/popover.test.ts`
Expected: PASS

- [ ] **Step 5: 提交**

```bash
git add src/content/popover.ts src/content/popover.test.ts
git commit -m "refactor: generalize popover with kind + common PopoverCandidate shape"
```

---

## Task 9: autofill 端到端接线

**Files:**
- Modify: `src/content/autofill.ts`
- Test: `src/content/autofill.test.ts`

**Interfaces:**
- Consumes: `detectCardForms` / `detectIdentityForms` / `DetectedFillForm`（Task 3）；`fillCardForm` / `fillIdentityForm`（Task 4）；`PopoverCandidate`（Task 8）；`FillItemCandidate` / `CardFillData` / `IdentityFillData` / `FillKind`（Task 2）
- Produces: 卡/身份弹层挂载与端到端填充；登录候选映射到 `PopoverCandidate`

- [ ] **Step 1: 写失败测试**

`autofill.test.ts` mock 了 `./popover.js`（FakePopover，存于 `popoverState.instances`，通过 `instance.options.onOpen/onSelect` 驱动）与 `./fill.js`；`./fill-card-identity.js` **不** mock，真实在 DOM 上写入。新增用例（放进 `describe('autofill controller', …)` 内）：

```ts
  it('attaches a card popover and fills the form on selection', async () => {
    vi.mocked(sendRequest)
      .mockResolvedValueOnce({ ok: true, data: [{ id: 'card-1', name: 'Visa', subtitle: 'Visa', favorite: false }] }) // findFillItems
      .mockResolvedValueOnce({ ok: true, data: { number: '4111111111111111', code: '123' } }); // getFillData
    document.body.innerHTML = '<form><input autocomplete="cc-number" id="num"><input autocomplete="cc-csc" id="csc"></form>';

    startAutofill('https://shop.example/checkout');
    const cardPopover = popoverState.instances.at(-1)!; // only the card popover is attached for this DOM
    cardPopover.options.onOpen();
    await new Promise((r) => setTimeout(r, 0));
    cardPopover.options.onSelect('card-1');
    await new Promise((r) => setTimeout(r, 0));

    expect(sendRequest).toHaveBeenCalledWith({ type: 'autofill.findFillItems', kind: 'card' });
    expect(sendRequest).toHaveBeenCalledWith({ type: 'autofill.getFillData', cipherId: 'card-1', kind: 'card' });
    expect((document.getElementById('num') as HTMLInputElement).value).toBe('4111111111111111');
    expect((document.getElementById('csc') as HTMLInputElement).value).toBe('123');
  });
```

> `popoverState` 是测试文件顶部用 `vi.hoisted` 定义的，同文件内可直接引用。该 DOM 只有卡字段、无 password/username，故只挂一个卡弹层，`.at(-1)` 即它。

- [ ] **Step 2: 运行确认失败**

Run: `npx vitest run src/content/autofill.test.ts -t card popover`
Expected: FAIL（未挂卡弹层）

- [ ] **Step 3: 实现 autofill 变更**

`src/content/autofill.ts`：

1) 顶部新增导入：

```ts
import { detectCardForms, detectIdentityForms, type DetectedFillForm } from './field-detection.js';
import { fillCardForm, fillIdentityForm } from './fill-card-identity.js';
import type { PopoverCandidate } from './popover.js';
import type { FillItemCandidate, CardFillData, IdentityFillData, FillKind } from '../messaging/protocol.js';
```

2) 重写 `attachPopovers`，并新增 `attachIfNew`：

```ts
function attachPopovers(getFrameUrl: FrameUrlProvider): void {
  if (!isHttpUrl(getFrameUrl())) return;
  const exclude = new Set<Element>();
  for (const form of detectLoginForms()) {
    for (const el of [form.usernameInput, form.passwordInput, form.totpInput]) if (el) exclude.add(el);
    attachIfNew(form.id, () => attachPopover(getFrameUrl, form));
  }
  for (const form of [...detectCardForms(document, exclude), ...detectIdentityForms(document, exclude)]) {
    attachIfNew(form.id, () => attachFillPopover(form));
  }
}

function attachIfNew(id: string, attach: () => void): void {
  const selector = `[data-vw-popover-for="${CSS.escape(id)}"]`;
  if (document.querySelector(selector)) return;
  attach();
}
```

3) 在 `attachPopover` 之后新增卡/身份的挂载与处理：

```ts
function attachFillPopover(form: DetectedFillForm): void {
  const popover = createAutofillPopover({
    anchor: form.anchor,
    kind: form.kind,
    onOpen: () => void loadFillCandidates(form.kind, popover),
    onSelect: (cipherId) => void fillSelectedFillItem(form, cipherId, popover),
  });
  popover.element.dataset.vwPopoverFor = form.id;
}

async function loadFillCandidates(kind: FillKind, popover: ReturnType<typeof createAutofillPopover>): Promise<void> {
  const response = await sendRequest({ type: 'autofill.findFillItems', kind });
  if (!response.ok) {
    popover.showStatus(messageForError(response.error.code, response.error.message));
    return;
  }
  if (Array.isArray(response.data) && isFillItemCandidates(response.data)) {
    popover.showCandidates(response.data.map(toPopoverCandidate));
  } else {
    popover.showStatus('Unexpected autofill response');
  }
}

async function fillSelectedFillItem(
  form: DetectedFillForm,
  cipherId: string,
  popover: ReturnType<typeof createAutofillPopover>,
): Promise<void> {
  const response = await sendRequest({ type: 'autofill.getFillData', cipherId, kind: form.kind });
  if (!response.ok) {
    popover.showStatus(messageForError(response.error.code, response.error.message));
    return;
  }
  if (!isFillData(response.data)) {
    popover.showStatus('Unexpected autofill response');
    return;
  }
  const filled = form.kind === 'card'
    ? fillCardForm(form, response.data as CardFillData)
    : fillIdentityForm(form, response.data as IdentityFillData);
  popover.showStatus(filled ? 'Filled' : 'No fillable fields');
}

function toPopoverCandidate(c: FillItemCandidate): PopoverCandidate {
  return { id: c.id, name: c.name, favorite: c.favorite, ...(c.subtitle ? { sub: c.subtitle } : {}), ...(c.reprompt ? { reprompt: true } : {}) };
}

function isFillItemCandidates(data: unknown[]): data is FillItemCandidate[] {
  return data.every((d) => isRecord(d) && typeof d.id === 'string' && typeof d.name === 'string' && typeof d.favorite === 'boolean' && isOptionalString(d.subtitle));
}

function isFillData(data: unknown): data is CardFillData & IdentityFillData {
  return isRecord(data) && Object.values(data).every((v) => v === undefined || typeof v === 'string');
}
```

4) 更新登录路径的 `loadCandidates`：把 `popover.showCandidates(response.data)` 改为映射到公共结构：

```ts
    popover.showCandidates(response.data.map((c) => ({
      id: c.id, name: c.name, favorite: c.favorite,
      ...(c.username ?? c.matchedUri ? { sub: c.username ?? c.matchedUri } : {}),
      ...(c.reprompt ? { reprompt: true } : {}),
    })));
```

（`isAutofillCandidates`/`isAutofillCandidate` 守卫保持不变，仍用于登录路径。）

- [ ] **Step 4: 运行确认通过 + 全量回归**

Run: `npx vitest run src/content/autofill.test.ts`
Expected: PASS
Run: `npm test`
Expected: 全绿（含既有登录/TOTP 自动填充用例不回归）
Run: `npm run typecheck`
Expected: 无错误

- [ ] **Step 5: 提交**

```bash
git add src/content/autofill.ts src/content/autofill.test.ts
git commit -m "feat: wire card/identity fill popovers end-to-end"
```

---

## 收尾：构建冒烟

- [ ] **构建并人工验收**

Run: `npm run build`
Expected: `build done`，`dist/content/autofill.js` 含新模块（esbuild 已 bundle import）。

按设计 spec 第 11 节人工验收 1–6 项跑一遍（卡结账页、地址页、单邮箱不弹、登录页不误弹、reprompt 提示）。如需真实服务端，用 CLAUDE.md 的测试 Vaultwarden（建一张卡 + 一个身份条目）。

---

## 里程碑 2（单独成计划，本计划不含）

里程碑 1 落地后，再就右键上下文菜单写第二份计划，内容：
- manifest 加 `contextMenus` 权限；`src/background/context-menu.ts`（构建/重建/锁定清除、`onClicked` 解析 → `vault.getFillData` → `tabs.sendMessage`）。
- content script 新增 `runtime.onMessage`：默认整表单填充；右键落单字段时「只填此字段」（监听 `contextmenu` 暂存元素 + field-map 归角色）。
- 复用里程碑 1 的 `findFillItems` / `getFillData` / `fill-card-identity` / `field-map`，不重复实现。

---

## Self-Review 结论

- **Spec 覆盖**：第 4 节字段映射→Task1；第 5 节检测门槛→Task3；第 6 节填充（exp/select/全名）→Task4；第 7 节 worker API→Task5/6/7；第 8 节弹层泛化→Task8；端到端→Task9；安全边界（reprompt / 机密字段剔除 / 无 URL 门）→Task5/6 测试覆盖。里程碑 2 明确划出。
- **占位符**：无 TBD/TODO，每个代码步骤含完整实现与测试。
- **类型一致**：`FillKind`/`FillItemCandidate`/`CardFillData`/`IdentityFillData`（Task2 定义）在 Task4/5/6/9 一致引用；`PopoverCandidate`（Task8）在 Task9 一致引用；`DetectedFillForm`/`FillFieldElement`（Task3）在 Task4/9 一致引用；方法名 `findFillItems`/`getFillData` 全程一致。
