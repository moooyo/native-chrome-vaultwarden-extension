/** Remote-only verification of real UI components with synthetic boundary adapters. */
/* global window, document */
import { chromium } from '@playwright/test';
import { mkdir, writeFile } from 'node:fs/promises';
import { resolve, join } from 'node:path';

const base = process.env.MIYU_UI_WORKBENCH_URL ?? 'http://127.0.0.1:4317';
const filter = process.env.MIYU_UI_CHECK_FILTER ?? '';
const output = resolve(process.env.MIYU_UI_EVIDENCE_DIR ?? 'test-results/final-ui');
await mkdir(output, { recursive: true });
const browser = await chromium.launch({ headless: true, ...(process.env.MIYU_BROWSER_EXECUTABLE ? { executablePath: process.env.MIYU_BROWSER_EXECUTABLE } : {}), args: ['--no-sandbox'] });
const page = await browser.newPage({ viewport: { width: 1440, height: 980 }, locale: 'zh-CN', colorScheme: 'light' });
page.setDefaultTimeout(8000);
const errors = [];
const checks = [];
const cases = [];
page.on('pageerror', (error) => errors.push(error.message));
await page.route('**/*', (route) => route.request().url().startsWith(base) ? route.continue() : route.abort());
async function check(name, run) {
  if (filter && !name.includes(filter)) return;
  try { await run(); checks.push({ name, passed: true }); }
  catch (error) {
    const failureImage = 'failed-' + name + '.png';
    await page.screenshot({ path: join(output, failureImage) }).catch(() => undefined);
    checks.push({ name, passed: false, message: String(error.message ?? error).slice(0, 1000), failureImage });
  }
}
function assert(condition, message) { if (!condition) throw new Error(message); }
async function open(id) {
  await page.evaluate((scenario) => window.uiWorkbench.open(scenario), id);
  await page.waitForTimeout(220);
}
async function closedControl(attributes, action = 'click') {
  const session = await page.context().newCDPSession(page);
  try {
    const tree = await session.send('DOM.getDocument', { depth: -1, pierce: true });
    const visit = (node) => {
      const attrs = Object.fromEntries(Array.from({ length: (node.attributes?.length ?? 0) / 2 }, (_, index) => [node.attributes[index * 2], node.attributes[index * 2 + 1]]));
      if (Object.entries(attributes).every(([key, value]) => attrs[key] === value)) return node;
      for (const child of [...(node.children ?? []), ...(node.shadowRoots ?? []), ...(node.contentDocument ? [node.contentDocument] : [])]) { const found = visit(child); if (found) return found; }
      return null;
    };
    const target = visit(tree.root); assert(target, 'Closed-shadow control was not found');
    if (action === 'checked') {
      const resolved = await session.send('DOM.resolveNode', { nodeId: target.nodeId });
      const property = await session.send('Runtime.callFunctionOn', { objectId: resolved.object.objectId, functionDeclaration: 'function () { return this.checked; }', returnByValue: true });
      return property.result.value;
    }
    const resolved = await session.send('DOM.resolveNode', { nodeId: target.nodeId });
    const visibility = await session.send('Runtime.callFunctionOn', { objectId: resolved.object.objectId, functionDeclaration: 'function () { const rect = this.getBoundingClientRect(); const view = this.ownerDocument.defaultView; return rect.top >= 0 && rect.left >= 0 && rect.bottom <= view.innerHeight && rect.right <= view.innerWidth; }', returnByValue: true });
    assert(visibility.result.value, 'Closed-shadow control is outside its visible frame viewport');
    const box = await session.send('DOM.getBoxModel', { nodeId: target.nodeId });
    const quad = box.model.border;
    await page.mouse.click((quad[0] + quad[4]) / 2, (quad[1] + quad[5]) / 2);
  } finally { await session.detach(); }
}

try {
  await page.goto(base, { waitUntil: 'networkidle' });
  await page.waitForFunction(() => Boolean(window.uiWorkbench));
  const scenarios = await page.evaluate(() => window.uiWorkbench.scenarios);
  for (const scene of scenarios) {
    await check('render-' + scene.id, async () => {
      await open(scene.id);
      const metadata = await page.evaluate(() => window.uiWorkbench.snapshot());
      const expectedRoute = scene.id === 'login' || scene.id === 'unlock' ? scene.id
        : ['card', 'identity', 'reprompt', 'ssh'].includes(scene.id) ? 'detail'
        : scene.id.startsWith('editor') ? 'editor'
        : ['workspace', 'popup'].includes(scene.id) ? 'vault' : undefined;
      if (expectedRoute) assert(metadata.route === expectedRoute, 'Scenario did not reach its expected production route');
      const controls = await page.locator('#stage').locator('input, button').count();
      assert(scene.id.startsWith('inline-') || controls > 0, 'Production surface is empty');
      assert(metadata.fixture && metadata.productionComponents, 'Fixture scope metadata is absent');
      const unsupported = metadata.calls.filter((call) => call.result === 'unsupported');
      assert(!unsupported.length, 'Initial fixture requests are unsupported: ' + unsupported.map((call) => call.type).join(', '));
      await page.screenshot({ path: join(output, scene.id + '.png') });
      cases.push({ ...scene, image: scene.id + '.png', route: metadata.route });
    });
  }
  await check('login-enters-real-vault', async () => {
    await open('login');
    await page.locator('vw-auth-views input[type=email]').fill('lin@example.test');
    await page.locator('vw-auth-views input[type=password]').fill('Demo-only-2026!');
    await page.locator('vw-auth-views button[type=submit]').click();
    await page.waitForFunction(() => window.uiWorkbench.snapshot().route === 'vault');
  });
  await check('card-secret-is-on-demand', async () => {
    await open('card');
    const before = await page.evaluate(() => window.uiWorkbench.snapshot());
    assert(!before.calls.some((call) => call.type === 'vault.getField'), 'Secret fetched before explicit action');
    const reveal = page.locator('vw-item-detail [data-reveal]').first();
    await reveal.click();
    await page.waitForFunction(() => window.uiWorkbench.snapshot().calls.some((call) => call.type === 'vault.getField'));
  });
  await check('protected-card-requires-reprompt', async () => {
    await open('reprompt');
    await page.locator('vw-reprompt-gate input[type=password]').fill('Demo-only-2026!');
    await page.locator('vw-reprompt-gate [data-unlock]').click();
    await page.waitForFunction(() => window.uiWorkbench.snapshot().calls.some((call) => call.type === 'auth.verifyMasterPassword'));
    await page.locator('vw-item-detail').waitFor({ state: 'visible' });
  });
  await check('save-failure-preserves-editor', async () => {
    await open('editor-failure');
    const editor = page.locator('vw-cipher-editor');
    const name = editor.locator('[data-field=name]');
    await name.fill('GitHub edited fixture');
    await editor.locator('[data-save]').click();
    await page.waitForFunction(() => window.uiWorkbench.snapshot().calls.some((call) => call.result === 'fixture-failure'));
    assert(await name.inputValue() === 'GitHub edited fixture', 'Editor cleared the draft after failure');
    assert((await page.evaluate(() => window.uiWorkbench.snapshot())).route === 'editor', 'Failure left the editor');
  });
  await check('cancel-discard-keeps-the-same-draft', async () => {
    await open('editor-identity');
    const editor = page.locator('vw-cipher-editor');
    await editor.locator('[data-field=name]').fill('Identity draft fixture');
    page.once('dialog', (dialog) => dialog.dismiss());
    await editor.locator('[data-back]').click();
    assert(await editor.locator('[data-field=name]').inputValue() === 'Identity draft fixture', 'Cancel discarded the identity draft');
    assert((await page.evaluate(() => window.uiWorkbench.snapshot())).route === 'editor', 'Cancel left the editor');
  });
  await check('settings-save-failure-and-retry', async () => {
    await open('settings-failure');
    await page.locator('vw-security-section [data-lock-select] select').selectOption('5');
    await page.locator('vw-security-section [data-save-field=lockTimeout][data-state=error]').waitFor();
    await page.locator('vw-security-section [data-retry-setting=lockTimeout]').click();
    await page.locator('vw-security-section [data-save-field=lockTimeout][data-state=saved]').waitFor();
    assert(await page.locator('vw-security-section [data-lock-select] select').inputValue() === '5', 'Retry did not retain the requested setting');
  });
  await check('import-completion-uses-current-operation-counts', async () => {
    await open('data');
    await page.locator('vw-data-section [data-import-file]').setInputFiles({ name: 'workbench.json', mimeType: 'application/json', buffer: Buffer.from('{"encrypted":false,"items":[]}') });
    await page.locator('vw-import-preview [data-confirm]').click();
    const result = page.locator('vw-data-section [data-import-result]');
    await result.waitFor();
    assert(await result.locator('[data-result-committed]').innerText() === '4', 'Current committed count is missing');
    assert(await result.locator('[data-result-unknown]').innerText() === '0', 'Completed import retained an unknown count');
  });
  await check('unknown-import-keeps-barrier-until-confirmation', async () => {
    await open('recovery');
    const section = page.locator('vw-data-section');
    assert(await section.locator('[data-import]').isDisabled(), 'Unknown recovery did not block another import');
    assert(await section.locator('[data-recovery-clear]').isDisabled(), 'Recovery cleared without acknowledgement');
    await section.locator('[data-recovery-unresolved] summary').click();
    await section.locator('[data-recovery-keep]').click();
    assert(await section.locator('[data-import]').isDisabled(), 'Keeping an unresolved result cleared the barrier');
    await section.locator('[data-recovery-confirm]').check();
    page.once('dialog', (dialog) => dialog.accept());
    await section.locator('[data-recovery-clear]').click();
    await page.waitForFunction(() => window.uiWorkbench.snapshot().calls.some((call) => call.type === 'recovery.clear'));
    await section.locator('[data-import]').click({ trial: true });
    assert(await section.locator('[data-import]').isEnabled(), 'Confirmed recovery did not allow a subsequent import');
  });
  await check('receiver-email-otp-and-hidden-text', async () => {
    await open('receive');
    const receive = page.locator('vw-receive-app');
    await receive.locator('[data-access]').click();
    await receive.locator('[data-email]').fill('lin@example.test');
    await receive.locator('[data-access]').click();
    await receive.locator('[data-otp]').waitFor();
    assert(await receive.locator('[data-resend]').isDisabled(), 'Resend cooldown was not active');
    const countdown = await receive.locator('[data-resend]').innerText();
    await page.waitForTimeout(1150);
    assert(await receive.locator('[data-resend]').innerText() !== countdown, 'Resend countdown did not tick');
    await receive.locator('[data-otp]').fill('001234');
    await receive.locator('[data-access]').click();
    await receive.locator('[data-reveal-text]').click();
    assert((await receive.locator('[data-send-text]').innerText()).includes('测试内容'), 'Production Send decryption did not reach the hidden text');
    await receive.locator('[data-hide-text]').click();
    assert(await receive.locator('[data-send-text]').count() === 0, 'Hide action retained the visible text');
  });
  await check('inline-login-keeps-trusted-events', async () => {
    await open('inline-login');
    const frame = page.frames().find((candidate) => candidate.url().includes('inline.html'));
    assert(frame, 'Inline frame missing');
    await closedControl({ role: 'option', 'aria-selected': 'true' });
    await frame.waitForFunction(() => document.body.dataset.actionCount === '1');
    assert(await frame.locator('[data-first]').inputValue() === 'lin@example.test', 'Trusted action did not fill the fixture');
  });
  await check('card-preview-selected-fields-and-safe-undo', async () => {
    await open('inline-card');
    const frame = page.frames().find((candidate) => candidate.url().includes('inline.html'));
    assert(frame, 'Inline frame missing');
    await closedControl({ role: 'option', 'aria-selected': 'true' });
    await frame.locator('[data-vw-structured-preview]').waitFor();
    assert(await closedControl({ type: 'checkbox', 'aria-label': '持卡人' }, 'checked') === false, 'Existing cardholder was preselected');
    assert(await closedControl({ type: 'checkbox', 'aria-label': '安全码' }, 'checked') === true, 'Empty CVC was not selectable');
    await closedControl({ type: 'checkbox', 'aria-label': '安全码' });
    await page.screenshot({ path: join(output, 'card-field-preview.png') });
    await closedControl({ class: 'primary' });
    await frame.waitForFunction(() => document.body.dataset.lastAction === 'card-reviewed-fill');
    assert(await frame.locator('[autocomplete=cc-name]').inputValue() === '已填写的持卡人', 'Unselected cardholder was overwritten');
    assert(await frame.locator('[autocomplete=cc-csc]').inputValue() === '', 'Unselected CVC was filled');
    assert(await frame.locator('[autocomplete=cc-number]').inputValue() === '4242424242424242', 'Selected card number was not filled');
    assert((await frame.locator('[autocomplete=cc-exp]').inputValue()).length > 0, 'Selected expiry was not filled');
    await frame.locator('[autocomplete=cc-number]').fill('Manual card number');
    await closedControl({ class: 'undo' });
    assert(await frame.locator('[autocomplete=cc-number]').inputValue() === 'Manual card number', 'Undo overwrote a subsequent user edit');
    assert(await frame.locator('[autocomplete=cc-exp]').inputValue() === '', 'Undo did not restore an unchanged filled field');
    await page.screenshot({ path: join(output, 'card-safe-undo.png') });
  });
  await check('identity-preview-selected-fields-and-safe-undo', async () => {
    await open('inline-identity');
    const frame = page.frames().find((candidate) => candidate.url().includes('inline.html'));
    assert(frame, 'Inline frame missing');
    await closedControl({ role: 'option', 'aria-selected': 'true' });
    await frame.locator('[data-vw-structured-preview]').waitFor();
    assert(await closedControl({ type: 'checkbox', 'aria-label': '姓名' }, 'checked') === false, 'Existing identity name was preselected');
    await closedControl({ type: 'checkbox', 'aria-label': '电话号码' });
    await page.screenshot({ path: join(output, 'identity-field-preview.png') });
    await closedControl({ class: 'primary' });
    await frame.waitForFunction(() => document.body.dataset.lastAction === 'identity-reviewed-fill');
    assert(await frame.locator('[autocomplete=name]').inputValue() === '已填写的姓名', 'Unselected identity name was overwritten');
    assert(await frame.locator('[autocomplete=tel]').inputValue() === '', 'Unselected phone was filled');
    assert(await frame.locator('[autocomplete=email]').inputValue() === 'lin@example.test', 'Selected email was not filled');
    assert((await frame.locator('[autocomplete=address-line1]').inputValue()).length > 0, 'Selected address was not filled');
    await frame.locator('[autocomplete=email]').fill('manual@example.test');
    await closedControl({ class: 'undo' });
    assert(await frame.locator('[autocomplete=email]').inputValue() === 'manual@example.test', 'Undo overwrote a subsequent email edit');
    assert(await frame.locator('[autocomplete=address-line1]').inputValue() === '', 'Undo did not restore an unchanged address');
    await page.screenshot({ path: join(output, 'identity-safe-undo.png') });
  });
  await check('save-success-auto-closes-after-three-seconds', async () => {
    await open('inline-save');
    const frame = page.frames().find((candidate) => candidate.url().includes('inline.html'));
    assert(frame, 'Inline frame missing');
    const before = await frame.evaluate(() => document.body.children.length);
    await closedControl({ id: 'vw-save-act' });
    await frame.waitForFunction(() => document.body.dataset.actionCount === '1');
    await page.waitForTimeout(1600);
    assert(await frame.evaluate(() => document.body.children.length) === before, 'Success closed too early');
    await frame.waitForFunction((count) => document.body.children.length < count, before, { timeout: 2500 });
  });
  await check('save-unknown-does-not-auto-close', async () => {
    await open('inline-save-uncertain');
    const frame = page.frames().find((candidate) => candidate.url().includes('inline.html'));
    assert(frame, 'Inline frame missing');
    const before = await frame.evaluate(() => document.body.children.length);
    await closedControl({ id: 'vw-save-act' });
    await frame.waitForFunction(() => document.body.dataset.actionCount === '1');
    await page.waitForTimeout(3400);
    assert(await frame.evaluate(() => document.body.children.length) === before, 'Unknown result was silently dismissed');
  });
  await check('no-runtime-errors', async () => assert(errors.length === 0, errors.join('\n')));
} finally {
  const report = { passed: checks.every((entry) => entry.passed), filter, scope: 'Actual production UI components using synthetic boundary adapters. Does not verify backend, permissions, or MV3 messaging.', checks, cases, errors };
  await writeFile(join(output, 'report.json'), JSON.stringify(report, null, 2));
  console.log(JSON.stringify({ passed: report.passed, checks: checks.length, failures: checks.filter((entry) => !entry.passed), output }, null, 2));
  await browser.close();
  if (!report.passed) process.exitCode = 1;
}
