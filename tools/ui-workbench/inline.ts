import { createAutofillPopover } from '../../src/content/popover.js';
import { createGeneratePanel, type GeneratePanelState } from '../../src/content/generate-fill.js';
import { createTotpPanel } from '../../src/content/totp-fill.js';
import { createSaveBar } from '../../src/content/save-bar.js';
import { createStructuredPreview, positionStructuredPreview } from '../../src/content/ui/structured-preview-element.js';
import { createFrameAutofillController } from '../../src/content/frame-autofill.js';
import { detectCardForms, detectIdentityForms } from '../../src/content/field-detection.js';
import { normalizeFillRoles, fillDataKeysForRoles } from '../../src/core/vault/fill-roles.js';

const scenario = new URL(location.href).searchParams.get('scenario') ?? 'inline-login';
const labels: Record<string, [string, string, string]> = {
  'inline-login': ['登录 GitHub', '电子邮箱', 'password'],
  'inline-card': ['付款信息', '持卡人', 'text'],
  'inline-identity': ['联系信息', '姓名', 'text'],
  'inline-generator': ['创建账户', '电子邮箱', 'password'],
  'inline-totp': ['两步验证', '验证码', 'text'],
  'inline-save': ['登录成功', '电子邮箱', 'password'],
  'inline-save-uncertain': ['登录成功', '电子邮箱', 'password'],
};
const [title, firstLabel, secondType] = labels[scenario] ?? labels['inline-login']!;
document.querySelector('h1')!.textContent = title;
document.querySelector('[data-first-label]')!.textContent = firstLabel;
const first = document.querySelector<HTMLInputElement>('[data-first]')!;
const second = document.querySelector<HTMLInputElement>('[data-second]')!;
second.type = secondType;
if (scenario === 'inline-card') document.querySelector('[data-second-label]')!.textContent = '卡号';
if (scenario === 'inline-identity') document.querySelector('[data-second-label]')!.textContent = '电子邮箱';
if (scenario === 'inline-totp') document.querySelector('[data-second-row]')!.remove();
if (scenario === 'inline-card' || scenario === 'inline-identity') {
  const card = scenario === 'inline-card';
  first.autocomplete = card ? 'cc-name' : 'name';
  first.name = card ? 'cardholderName' : 'fullName';
  first.value = card ? '已填写的持卡人' : '已填写的姓名';
  second.autocomplete = card ? 'cc-number' : 'email';
  second.name = card ? 'cardNumber' : 'email';
  for (const [label, autocomplete, name] of card
    ? [['有效期', 'cc-exp', 'expiry'], ['安全码', 'cc-csc', 'cvc']]
    : [['街道地址', 'address-line1', 'address'], ['电话号码', 'tel', 'phone']]) {
    const row = document.createElement('label');
    const caption = document.createElement('span'); caption.textContent = label!;
    const field = document.createElement('input'); field.autocomplete = autocomplete!; field.name = name!;
    field.dataset.structured = name!;
    row.append(caption, field); document.querySelector('.submit')!.before(row);
  }
  document.querySelector('form p')!.textContent = '已有姓名默认保留。可选择字段，填充后撤销；之后手动修改的内容会保留。';
}
let actionCount = 0;
const changed = (action: string) => { actionCount++; document.body.dataset.lastAction = action; document.body.dataset.actionCount = String(actionCount); };
const candidates = scenario === 'inline-card' ? [{ id: 'card', name: '旅行银行卡', sub: 'Visa · 4242', favorite: false }]
  : scenario === 'inline-identity' ? [{ id: 'identity', name: '林晓', sub: 'lin@example.test', favorite: false }]
  : [{ id: 'github', name: 'GitHub · 个人', sub: 'lin@example.test', favorite: true }, { id: 'work', name: 'GitHub · 工作', sub: 'lin@studio.example', favorite: false }];

if (scenario.startsWith('inline-save')) {
  first.value = 'lin@example.test'; second.value = 'Demo-only-2026!';
  createSaveBar({ message: '将 GitHub 的登录信息保存到密屿？', actionLabel: '保存登录信息', onAction: async () => { changed('save'); await new Promise((resolve) => setTimeout(resolve, 300)); return scenario !== 'inline-save-uncertain'; } });
} else if (scenario === 'inline-generator') {
  const state: GeneratePanelState = { mode: 'password', username: 'lin@example.test', password: 'Demo-8hQs!4pN7mZx', strength: '极强', length: 18, uppercase: true, lowercase: true, numbers: true, symbols: true, minNumbers: 1, minSymbols: 1, avoidAmbiguous: true, words: 6, capitalize: false, includeNumber: false, managed: false, disabledReason: '' };
  const patch = (update: Partial<GeneratePanelState>) => { Object.assign(state, update); panel.update(state); };
  const panel = createGeneratePanel({ anchor: second, onUsername: (username) => patch({ username }), onRegenerate: () => { changed('regenerate'); patch({ password: 'Demo-7wJr!3bK9sLp' }); }, onLength: (length) => patch({ length }), onUppercase: (uppercase) => patch({ uppercase }), onLowercase: (lowercase) => patch({ lowercase }), onNumbers: (numbers) => patch({ numbers }), onSymbols: (symbols) => patch({ symbols }), onMinNumbers: (minNumbers) => patch({ minNumbers }), onMinSymbols: (minSymbols) => patch({ minSymbols }), onAvoidAmbiguous: (avoidAmbiguous) => patch({ avoidAmbiguous }), onWords: (words) => patch({ words }), onCapitalize: (capitalize) => patch({ capitalize }), onIncludeNumber: (includeNumber) => patch({ includeNumber }), onUse: () => { first.value = state.username; second.value = state.password; changed('generate-fill'); panel.showFilled({ user: state.username }); } });
  panel.update(state);
} else if (scenario === 'inline-totp') {
  const panel = createTotpPanel({ anchor: first, onSelect: () => undefined, onChooseOther: () => undefined, onFill: () => { first.value = '482916'; changed('totp-fill'); panel.showFilled(); }, onCopy: () => changed('totp-copy'), onUndo: () => { if (first.value === '482916') first.value = ''; changed('totp-undo'); panel.update({ itemName: 'GitHub', itemUser: 'lin@example.test', code: '482916', remaining: 24 }); } });
  panel.update({ itemName: 'GitHub', itemUser: 'lin@example.test', code: '482916', remaining: 24 });
} else if (scenario === 'inline-card' || scenario === 'inline-identity') {
  const kind = scenario === 'inline-card' ? 'card' : 'identity';
  const controller = createFrameAutofillController({ root: document, frameUrl: () => location.href, now: Date.now });
  let reviewOpen = false;
  const panel = createAutofillPopover({ anchor: first, kind, sidePanel: true, candidates, onOpen: () => panel.showCandidates(candidates), onSelect: () => {
    const inspection = controller.inspect();
    const target = inspection.forms.find((entry) => entry.kind === kind);
    const detected = (kind === 'card' ? detectCardForms() : detectIdentityForms())[0];
    if (!target || target.kind === 'login' || !detected) { panel.showStatus('当前表单无法安全识别。'); return; }
    const values = new Map([...detected.fields].map(([role, field]) => [role, { field, value: field.value }]));
    reviewOpen = true; panel.hide();
    const close = () => { reviewOpen = false; controller.clearStructuredSelection(); preview.remove(); };
    const preview = createStructuredPreview({ kind, anchor: detected.anchor, itemName: candidates[0]!.name, site: 'example.test', fields: target.roles.map((role) => ({ role, hasValue: Boolean(values.get(role)?.value.trim()) })), onDismiss: close, onConfirm: (roles) => {
      if (roles.some((role) => values.get(role)?.field.value !== values.get(role)?.value)
        || !controller.prepareStructuredSelection(target.formId, inspection.generation, roles)) {
        preview.showError('表单内容已变化，请关闭并重新选择字段。'); return;
      }
      // The service boundary supplies only selected synthetic data keys. Actual form inspection,
      // staged native writes, field-selection enforcement, and undo all remain production code.
      const available = kind === 'card'
        ? { cardholderName: 'LIN XIAO', number: '4242424242424242', expMonth: '09', expYear: '2029', code: '123' }
        : { firstName: '晓', lastName: '林', email: 'lin@example.test', address1: '示例路 18 号', phone: '+86 138 0000 0000' };
      const keys = fillDataKeysForRoles(kind, roles) ?? [];
      const data = Object.fromEntries(keys.map((key) => [key, (available as Record<string, string>)[key]]));
      const outcome = target.kind === 'card'
        ? controller.commitStructured({ kind: 'card', formId: target.formId, roles: target.roles, selectedRoles: normalizeFillRoles('card', roles)!, expectedFrameUrl: inspection.frameUrl, expectedGeneration: inspection.generation, data })
        : controller.commitStructured({ kind: 'identity', formId: target.formId, roles: target.roles, selectedRoles: normalizeFillRoles('identity', roles)!, expectedFrameUrl: inspection.frameUrl, expectedGeneration: inspection.generation, data });
      if (outcome.status !== 'filled') { preview.showError('填充目标已变化，请重新选择字段。'); return; }
      const receipt = controller.takeStructuredUndo();
      if (!receipt) { preview.showError('填充状态已变化，请检查表单内容。'); return; }
      changed(kind + '-reviewed-fill'); preview.showReceipt(receipt); positionStructuredPreview(preview.element, detected.anchor);
    } });
    positionStructuredPreview(preview.element, detected.anchor);
  } });
  first.addEventListener('focus', () => { if (!reviewOpen) panel.open(); }); panel.open();
} else {
  const kind = 'login';
  const panel = createAutofillPopover({ anchor: first, kind, sidePanel: true, candidates, onOpen: () => panel.showCandidates(candidates), onSelect: () => {
    first.value = 'lin@example.test';
    second.value = 'Demo-only-2026!';
    changed(kind + '-fill'); panel.showFilled();
  } });
  first.addEventListener('focus', () => panel.open()); panel.open();
}
document.querySelector('form')!.addEventListener('submit', (event) => event.preventDefault());
