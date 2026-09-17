import '../../src/ui/popup/app.js';
import '../../src/ui/options/options-app.js';
import '../../src/ui/receive/receive-app.js';
import type { VwPopupApp } from '../../src/ui/popup/app.js';
import type { VwOptionsApp } from '../../src/ui/options/options-app.js';
import type { VwReceiveApp } from '../../src/ui/receive/receive-app.js';
import { initLocale, setLocale } from '../../src/ui/i18n/index.js';
import { initAppearance, setTheme } from '../../src/ui/theme.js';
import { initPrefs } from '../../src/ui/prefs.js';
import { encryptToText } from '../../src/core/crypto/encstring.js';
import { deriveSendKey } from '../../src/core/vault/sends.js';
import { bytesToBase64Url } from '../../src/core/crypto/encoding.js';
import { createFixtureState, createOptionsDeps, createRequest, FIXTURE_EMAIL, FIXTURE_PASSWORD, type FixtureState } from './fixtures.js';

const scenarios = [
  ['login', '登录', '账户'], ['unlock', '解锁', '账户'],
  ['popup', '扩展弹窗', '保险库'], ['workspace', '完整保险库', '保险库'], ['card', '银行卡详情', '保险库'], ['identity', '身份详情', '保险库'], ['reprompt', '受保护的公司卡', '保险库'], ['editor', '编辑登录项', '保险库'], ['editor-card', '编辑银行卡', '保险库'], ['editor-identity', '编辑身份', '保险库'], ['editor-failure', '保存失败与重试', '保险库'], ['ssh', '部署密钥', '保险库'],
  ['settings', '安全设置', '设置与分享'], ['settings-failure', '设置保存失败', '设置与分享'], ['autofill-settings', '自动填充设置', '设置与分享'], ['appearance', '外观设置', '设置与分享'], ['send', 'Send 分享', '设置与分享'], ['data', '导入与导出', '设置与分享'], ['recovery', '导入恢复', '设置与分享'], ['receive', '接收分享与邮箱验证', '设置与分享'],
  ['inline-login', '填充账号密码', '网站内联'], ['inline-card', '填充银行卡', '网站内联'], ['inline-identity', '填充身份', '网站内联'], ['inline-generator', '生成并填充密码', '网站内联'], ['inline-totp', '填充验证码', '网站内联'], ['inline-save', '保存成功自动关闭', '网站内联'], ['inline-save-uncertain', '保存结果未知', '网站内联'],
] as const;
const stage = document.getElementById('stage')!;
const nav = document.getElementById('scenarios')!;
const status = document.getElementById('fixture-status')!;
let currentState: FixtureState | undefined;
let selected = '';
let generation = 0;
let currentApp: VwPopupApp | VwOptionsApp | VwReceiveApp | undefined;

function updateStatus() {
  const calls = currentState?.calls ?? [];
  status.textContent = currentState?.failNextWrite ? '下一次保存将失败；表单内容应保留。' : `测试边界已处理 ${calls.length} 次调用；未连接真实账户。`;
  const log = document.getElementById('calls')!;
  log.textContent = calls.slice(-12).map((entry) => `${entry.type} · ${entry.result}`).join('\n');
}
function deepQuery<T extends Element = Element>(parent: ParentNode, selector: string): T | null {
  if (parent instanceof Element && parent.shadowRoot) {
    const shadow = deepQuery<T>(parent.shadowRoot, selector);
    if (shadow) return shadow;
  }
  const direct = parent.querySelector<T>(selector);
  if (direct) return direct;
  for (const element of parent.querySelectorAll('*')) {
    if (element.shadowRoot) { const found = deepQuery<T>(element.shadowRoot, selector); if (found) return found; }
  }
  return null;
}
async function settle() {
  for (let pass = 0; pass < 12; pass++) {
    await new Promise((resolve) => setTimeout(resolve, 25));
    const pending: Promise<unknown>[] = [];
    const visit = (parent: ParentNode) => {
      for (const element of parent.querySelectorAll('*')) {
        const component = element as Element & { updateComplete?: Promise<unknown> };
        if (component.updateComplete) pending.push(component.updateComplete);
        if (element.shadowRoot) visit(element.shadowRoot);
      }
    };
    visit(stage); await Promise.all(pending);
  }
}

async function receive() {
  const key = new Uint8Array(16).fill(7);
  const derived = await deriveSendKey(key);
  const raw = { id: 'workbench-send', type: 0, name: await encryptToText('项目交接说明', derived), text: { text: await encryptToText('这是通过生产 Send 解密逻辑读取的测试内容。所有网络响应都来自测试适配器。', derived), hidden: true } };
  const json = (body: unknown, code = 200) => new Response(JSON.stringify(body), { status: code, headers: { 'content-type': 'application/json' } });
  const app = document.createElement('vw-receive-app') as VwReceiveApp;
  app.deps = {
    requestOrigins: async () => ({ granted: true, newlyGranted: [] }), removeOrigin: async () => true, download: () => undefined,
    fetch: (async (input: RequestInfo | URL, init?: RequestInit) => {
      currentState?.calls.push({ type: 'receive.fixture-fetch', result: 'synthetic-response' }); updateStatus();
      if (String(input).includes('/connect/token')) {
        const form = new URLSearchParams(init?.body as string);
        if (!form.has('email')) return json({ error: 'invalid_request', error_description: 'email is required.', send_access_error_type: 'email_required' }, 400);
        if (!form.has('otp')) return json({ error: 'invalid_request', error_description: 'email and otp are required.', send_access_error_type: 'email_and_otp_required' }, 400);
        if (form.get('otp') !== '001234') return json({ error: 'invalid_grant', error_description: 'Invalid code' }, 400);
        return json({ access_token: 'SYNTHETIC_SEND_ACCESS_TOKEN', token_type: 'Bearer', expires_in: 300, scope: 'api.send.access' });
      }
      return json(raw);
    }) as typeof fetch,
  };
  stage.append(app); currentApp = app; await app.updateComplete;
  const input = deepQuery<HTMLInputElement>(app, '[data-link]');
  if (input) { input.value = `https://vault.example/#/send/workbench/${bytesToBase64Url(key)}`; input.dispatchEvent(new Event('input', { bubbles: true })); }
}

async function openScenario(id: string) {
  if (!scenarios.some(([value]) => value === id)) id = 'workspace';
  const ticket = ++generation;
  selected = id;
  currentApp = undefined;
  stage.replaceChildren();
  stage.dataset.kind = id.startsWith('inline-') ? 'inline' : id === 'popup' || id === 'login' || id === 'unlock' ? 'popup' : 'workspace';
  document.querySelectorAll<HTMLButtonElement>('[data-scenario]').forEach((button) => button.setAttribute('aria-current', button.dataset.scenario === id ? 'page' : 'false'));
  document.getElementById('scenario-title')!.textContent = scenarios.find(([value]) => value === id)?.[1] ?? '';
  history.replaceState(null, '', '#' + id);
  currentState = createFixtureState(id === 'login' ? 'loggedOut' : id === 'unlock' ? 'locked' : 'unlocked');
  currentState.failNextWrite = id.endsWith('-failure');
  currentState.recovery = id === 'recovery';
  (document.getElementById('fail-next') as HTMLButtonElement).disabled = id.startsWith('inline-') || ['receive', 'login', 'unlock'].includes(id);
  updateStatus();
  if (id.startsWith('inline-')) {
    const frame = document.createElement('iframe'); frame.title = '真实内联组件测试'; frame.src = 'inline.html?scenario=' + encodeURIComponent(id);
    stage.append(frame); return;
  }
  if (id === 'receive') { await receive(); return; }
  const section: Record<string, string> = { settings: 'security', 'settings-failure': 'security', 'autofill-settings': 'autofill', appearance: 'appearance', send: 'send', data: 'data', recovery: 'data' };
  if (section[id]) {
    const app = document.createElement('vw-options-app') as VwOptionsApp;
    app.deps = createOptionsDeps(currentState, updateStatus);
    app.selected = section[id] as VwOptionsApp['selected'];
    stage.append(app); currentApp = app; await settle(); return;
  }
  const app = document.createElement('vw-popup-app') as VwPopupApp & { workspace: boolean };
  app.workspace = !['popup', 'login', 'unlock'].includes(id);
  if (app.workspace) {
    app.style.height = 'calc(100vh - 170px)';
    app.style.minHeight = '640px';
  }
  app.request = createRequest(currentState, updateStatus);
  app.browser = { getActiveTabId: async () => 7, getActiveTabUrl: async () => 'https://github.example/login', captureVisibleTab: async () => '', openOptions: async () => openScenario('settings'), openWorkspace: async () => openScenario('workspace'), openReceive: async () => openScenario('receive'), openUrl: async () => undefined };
  stage.append(app); currentApp = app; await settle();
  if (generation !== ticket) return;
  const cipherId = id === 'card' || id === 'editor-card' ? 'card' : id === 'identity' || id === 'editor-identity' ? 'identity' : id === 'reprompt' ? 'protected-card' : id === 'ssh' ? 'ssh' : id.startsWith('editor') ? 'github' : null;
  if (cipherId) {
    const view = deepQuery(app, 'vw-vault-view');
    view?.dispatchEvent(new CustomEvent('vw-item-open', { detail: { cipherId }, bubbles: true, composed: true }));
    await settle();
    if (id.startsWith('editor')) { deepQuery<HTMLButtonElement>(app, '[data-edit]')?.click(); await settle(); }
  }
}

let group = '';
for (const [id, title, category] of scenarios) {
  if (group !== category) { group = category; const label = document.createElement('h2'); label.textContent = category; nav.append(label); }
  const button = document.createElement('button'); button.type = 'button'; button.dataset.scenario = id; button.textContent = title;
  button.addEventListener('click', () => { void openScenario(id); }); nav.append(button);
}
document.getElementById('reset')!.addEventListener('click', () => { void openScenario(selected); });
document.getElementById('fail-next')!.addEventListener('click', () => { if (currentState) { currentState.failNextWrite = true; updateStatus(); } });
document.getElementById('fixture-help')!.textContent = `测试账号 ${FIXTURE_EMAIL}  密码 ${FIXTURE_PASSWORD}  PIN 2468  邮箱验证码 001234`;
await initLocale(); setLocale('zh-CN', false);
await initAppearance(); setTheme('light', false); await initPrefs();
Object.assign(window, { uiWorkbench: {
  scenarios: scenarios.map(([id, title, category]) => ({ id, title, category })),
  open: openScenario,
  snapshot: () => ({ scenario: selected, route: currentApp && 'route' in currentApp ? currentApp.route.name : undefined, calls: currentState?.calls ?? [], fixture: true, productionComponents: true }),
} });
await openScenario(location.hash.slice(1) || 'workspace');
