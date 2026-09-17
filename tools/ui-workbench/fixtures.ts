import type { CipherInput, DecryptedCipher, KnownCipherSummary } from '../../src/core/vault/models.js';
import type { PopupRequest } from '../../src/ui/popup/types.js';
import type { LoadedSettings, OptionsDeps, OptionsVaultTransferClient } from '../../src/ui/options/types.js';
import type { SendSummary } from '../../src/core/vault/sends.js';
import { createGeneratorPolicySnapshot } from '../../src/core/generator/enterprise-password-policy.js';

/** Every value in this module is synthetic and intentionally public. No real worker is contacted. */
export const FIXTURE_PASSWORD = 'Demo-only-2026!';
export const FIXTURE_EMAIL = 'lin@example.test';
export const folders = [{ id: 'work', name: '工作' }, { id: 'personal', name: '个人' }];
export const organizations = [{ id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', name: '澄明工作室', isMember: true, canCreateItems: true, canCreateCollections: true, canEditCollections: true, canDeleteCollections: true, canManageCollections: true }];
export const collections = [{ id: 'engineering', organizationId: organizations[0]!.id, name: '工程团队', canAssignItems: true, canRename: true, canDelete: true, manage: true }];
const summaries: KnownCipherSummary[] = [
  { id: 'github', type: 1, name: 'GitHub', username: FIXTURE_EMAIL, uris: ['https://github.example'], loginUris: [{ uri: 'https://github.example', match: null }], favorite: true, hasTotp: true, passwordHistoryCount: 2, folderId: 'work' },
  { id: 'mail', type: 1, name: '工作邮箱', username: 'lin@studio.example', uris: ['https://mail.example'], loginUris: [{ uri: 'https://mail.example', match: null }], favorite: false, folderId: 'work' },
  { id: 'card', type: 3, name: '旅行银行卡', subtitle: 'Visa · 4242', uris: [], loginUris: [], favorite: false, folderId: 'personal' },
  { id: 'identity', type: 4, name: '林晓 · 个人资料', subtitle: FIXTURE_EMAIL, uris: [], loginUris: [], favorite: false, folderId: 'personal' },
  { id: 'protected-card', type: 3, name: '公司付款卡', subtitle: 'Visa · 1881 · 需验证', uris: [], loginUris: [], favorite: false, reprompt: true, organizationId: organizations[0]!.id, collectionIds: ['engineering'], access: { edit: true, viewPassword: true, clone: true, delete: true, restore: true, autofillTotp: false, viewTotp: false } },
  { id: 'note', type: 2, name: '旅行清单', subtitle: '安全笔记', uris: [], loginUris: [], favorite: false },
  { id: 'ssh', type: 5, name: '部署密钥', subtitle: 'Ed25519', uris: [], loginUris: [], favorite: false, folderId: 'work' },
];
const fieldsById: Record<string, Partial<DecryptedCipher>> = {
  github: { notes: '用于个人开发项目。', fields: [{ type: 0, name: '环境', value: 'Production' }], attachments: [{ id: 'guide', fileName: 'account-guide.pdf', sizeName: '24 KB' }] },
  card: { card: { cardholderName: 'LIN XIAO', brand: 'Visa', expMonth: '09', expYear: '2029' }, notes: '日常出行使用。' },
  'protected-card': { card: { cardholderName: 'CLARITY STUDIO', brand: 'Visa', expMonth: '12', expYear: '2029' } },
  identity: { identity: { firstName: '晓', lastName: '林', email: FIXTURE_EMAIL, phone: '+86 138 0000 0000', company: '澄明工作室', address1: '示例路 18 号', city: '上海', state: '上海', country: 'CN', postalCode: '200000' } },
  note: { notes: '护照、充电器、旅行保险。\n这些均为测试数据。' },
  ssh: { notes: '仅展示公开元数据，密钥值为测试文本。' },
};
const initialSends: SendSummary[] = [{ id: 'send-brief', accessId: 'workbench', type: 0, name: '项目交接说明', text: '这是一份测试分享。', hidden: true, url: 'https://vault.example/#/send/workbench/demo', deletionDate: new Date(Date.now() + 604800000).toISOString(), accessCount: 2, disabled: false, hideEmail: true, passwordProtected: false }];

export interface FixtureState {
  session: 'loggedOut' | 'locked' | 'unlocked';
  failNextWrite: boolean;
  calls: Array<{ type: string; result: string }>;
  items: KnownCipherSummary[];
  detail: Record<string, Partial<DecryptedCipher>>;
  sends: SendSummary[];
  settings: LoadedSettings;
  recovery: boolean;
}
export function createFixtureState(session: FixtureState['session'] = 'unlocked'): FixtureState {
  return { session, failNextWrite: false, calls: [], items: structuredClone(summaries), detail: structuredClone(fieldsById), sends: structuredClone(initialSends), recovery: false, settings: {
    serverUrl: 'https://vault.example/', defaultUriMatchStrategy: 0, inlineSuggestions: true, pageLoadFill: false, pageLoadFillDefault: false,
    autoCopyTotp: false, showMatchingLoginCount: true, savePromptEnabled: true, updatePromptEnabled: true, savePromptExcludedDomains: [], blockedDomains: [], autofillPolicyValid: true,
    websitePasskeys: { enabled: false, excludedDomains: [], valid: true }, httpAuth: { enabled: false, allowedOrigins: [], valid: true },
    lockTimeout: '15', onIdleAction: 'lock', clipboardClearSeconds: '60',
    enterprisePolicy: { pinUnlockAllowed: true, maximumVaultTimeoutManaged: false, maximumVaultTimeoutMode: 'local', uriMatchDefaultManaged: false, uriMatchDefaultMalformed: false, activateAutofillManaged: false },
    generator: createGeneratorPolicySnapshot(null, 1),
  } };
}
const success = (data: unknown = null) => ({ ok: true as const, data });
const failure = (message: string) => ({ ok: false as const, error: { code: 'network' as const, message } });
export function createRequest(state: FixtureState, changed: () => void): PopupRequest {
  const listing = () => ({ items: structuredClone(state.items), folders, collections, orgPermissions: organizations, personalCreationAllowed: true });
  const dispatch = async (request: Record<string, unknown>) => {
    const type = String(request.type);
    const log = { type, result: 'ok' };
    state.calls.push(log);
    await new Promise((resolve) => setTimeout(resolve, /save|create|update|verify|login|unlock|confirm/i.test(type) ? 180 : 15));
    changed();
    if (state.failNextWrite && /(?:save|create|update|delete|rotate|change)/i.test(type)) {
      state.failNextWrite = false; log.result = 'fixture-failure'; changed();
      return failure('暂时无法保存。修改内容已保留，请重试。');
    }
    const id = String(request.id ?? request.cipherId ?? '');
    const summary = state.items.find((item) => item.id === id);
    if (type === 'auth.getState') return success({ state: state.session, email: FIXTURE_EMAIL, serverUrl: state.settings.serverUrl });
    if (type === 'auth.listAccounts') return success({ accounts: [{ email: FIXTURE_EMAIL, active: true, name: '林晓', serverUrl: state.settings.serverUrl }] });
    if (/^(auth\.(sso\.status|accountPasskey\.status|pendingLogin\.status|deviceLogin\.status)|autofill\.continuation\.status)$/.test(type)) return success({ status: 'none' });
    if (type === 'auth.deviceLogin.approvals.list') return success({ approvals: [] });
    if (type === 'auth.pinStatus') return success({ enabled: true, available: true, allowed: true, requireMasterPasswordOnRestart: true });
    if (type === 'auth.isDeviceRemembered') return success({ remembered: false });
    if (type === 'auth.sso.requirement') return success({ required: false });
    if (['auth.login', 'auth.unlock', 'auth.unlockWithPin'].includes(type)) {
      if (request.masterPassword !== FIXTURE_PASSWORD && request.pin !== '2468') return failure('密码不正确，请使用上方标明的测试密码。');
      state.session = 'unlocked'; return success(type === 'auth.login' ? { kind: 'unlocked' } : { state: 'unlocked' });
    }
    if (type === 'auth.verifyMasterPassword') return success({ verified: request.masterPassword === FIXTURE_PASSWORD });
    if (type === 'auth.lock' || type === 'auth.logout') { state.session = type === 'auth.lock' ? 'locked' : 'loggedOut'; return success(); }
    if (type === 'vault.listItems' || type === 'vault.sync') return success(listing());
    if (type === 'vault.getSyncStatus') return success({ dirty: false, syncing: false, identity: 'fixture-account', lastSuccessfulSyncAt: Date.now() - 60000 });
    if (type === 'vault.getSkippedOrgCount') return success({ count: 0 });
    if (type === 'vault.getOrganizationDataOwnershipStatus') return success({ status: 'not_required' });
    if (type === 'vault.getCipherDetail') return success({ cipher: summary ? { ...summary, ...state.detail[id] } : null });
    if (type === 'vault.getCipherInput') {
      if (!summary || summary.type === 5) return success({ input: null });
      const input: CipherInput = { type: summary.type, name: summary.name, favorite: summary.favorite, reprompt: summary.reprompt, folderId: summary.folderId, notes: state.detail[id]?.notes, fields: state.detail[id]?.fields };
      if (summary.type === 1) input.login = { username: summary.username, password: FIXTURE_PASSWORD, uris: summary.loginUris };
      if (summary.type === 3) input.card = { ...state.detail[id]?.card, number: '4242424242424242', code: '123' };
      if (summary.type === 4) input.identity = { ...state.detail[id]?.identity, passportNumber: 'DEMO000001' };
      return success({ input });
    }
    if (type === 'vault.getField') return success({ value: request.field === 'card.number' ? '4242424242424242' : request.field === 'card.code' ? '123' : request.field === 'username' ? FIXTURE_EMAIL : request.field === 'password' ? FIXTURE_PASSWORD : 'DEMO000001' });
    if (type === 'vault.getCustomField') return success({ value: 'Demo-only-custom-value' });
    if (type === 'vault.getTotp') return success({ totp: { code: '482916', period: 30, remaining: 24 } });
    if (type === 'vault.getTotpCodes') return success({ entries: [{ cipherId: 'github', name: 'GitHub', username: FIXTURE_EMAIL, code: '482916', period: 30, remaining: 24 }] });
    if (type === 'vault.getPasswordHistory') return success({ history: [{ password: 'Previous-demo-only!', lastUsedDate: '2026-09-01T12:00:00Z' }] });
    if (type === 'vault.getSshKeyWriteAvailability') return success({ available: true });
    if (type === 'vault.getSshKeyDetails') return success({ sshKey: { publicKey: 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDemoOnly workstation', keyFingerprint: 'SHA256:DemoOnlyFingerprint', hasPrivateKey: true } });
    if (type === 'vault.revealSshPrivateKey') return success({ privateKey: 'DEMO PRIVATE KEY — NOT VALID KEY MATERIAL' });
    if (type === 'vault.updateCipher' || type === 'vault.createCipher') {
      const input = request.input as CipherInput;
      const nextId = id || 'created-' + state.items.length;
      const next: KnownCipherSummary = { id: nextId, type: input.type, name: input.name, username: input.login?.username, favorite: input.favorite ?? false, reprompt: input.reprompt, folderId: input.folderId ?? undefined, uris: (input.login?.uris ?? []).map((uri) => uri.uri), loginUris: input.login?.uris ?? [] };
      state.items = state.items.filter((item) => item.id !== nextId).concat(next);
      state.detail[nextId] = { ...state.detail[nextId], notes: input.notes, card: input.card, identity: input.identity, fields: input.fields };
      return success(listing());
    }
    if (type === 'vault.deleteCipher') { state.items = state.items.filter((item) => item.id !== id); return success(listing()); }
    if (type === 'vault.softDeleteCipher') { if (summary) summary.deletedDate = new Date().toISOString(); return success(listing()); }
    if (type === 'vault.restoreCipher') { if (summary) delete summary.deletedDate; return success(listing()); }
    if (type === 'vault.getPasswordHealth') return success({ entries: [] });
    if (type === 'autofill.getTabSuggestions') return success({ outcome: { status: 'ready', suggestions: [] } });
    if (type === 'settings.get') return success(structuredClone(state.settings));
    if (type === 'settings.save' || type === 'settings.saveSecurity') {
      const { type: _type, autofillSettings, ...patch } = request;
      Object.assign(state.settings, patch, autofillSettings && typeof autofillSettings === 'object' ? autofillSettings : {}); return success();
    }
    if (type === 'settings.saveWebsitePasskeys') { state.settings.websitePasskeys = { enabled: Boolean(request.enabled), excludedDomains: request.excludedDomains as string[], valid: true }; return success(); }
    if (type === 'settings.saveHttpAuth') { state.settings.httpAuth = { enabled: Boolean(request.enabled), allowedOrigins: request.allowedOrigins as string[], valid: true }; return success(); }
    if (type === 'generator.history.list') return success({ entries: [] });
    if (type === 'sends.list') return success({ sends: state.sends });
    if (type === 'sends.createText') { const input = request.input as Record<string, unknown>; state.sends.push({ ...initialSends[0]!, id: 'send-' + state.sends.length, name: String(input.name), text: String(input.text ?? ''), accessCount: 0 }); return success({ sends: state.sends }); }
    if (type === 'sends.delete') { state.sends = state.sends.filter((send) => send.id !== id); return success({ sends: state.sends }); }
    if (type === 'sends.update') { state.sends = state.sends.map((send) => send.id === id ? { ...send, ...(request.input as object) } : send); return success({ sends: state.sends }); }
    if (/^(vault\.popupOpened|clientEvent\.ack|clipboard\.|generator\.history\.)/.test(type)) return success();
    log.result = 'unsupported'; changed();
    return failure('当前测试场景未配置此操作。');
  };
  return dispatch as PopupRequest;
}

export function createOptionsDeps(state: FixtureState, changed: () => void): OptionsDeps {
  const request = createRequest(state, changed);
  const transfer: OptionsVaultTransferClient = {
    async import() { return { format: 'json', scope: 'personal', phase: 'previewed', counts: { folders: 1, collections: 0, items: 3, attachments: 0 }, diagnostics: { errors: [], warnings: [], unsupported: [] }, organizationTargetRequired: false, hasUnknownOutcome: false, canCommit: true }; },
    async confirm() { state.calls.push({ type: 'import.confirm', result: 'completed' }); changed(); return { version: 1, type: 'import.result', transferId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', phase: 'completed', status: 'completed', counts: { committed: 4, rejected: 0, skipped: 0, outcomeUnknown: 0 }, mustSyncBeforeRetry: false }; },
    async inspectRecovery() { return state.recovery ? { count: 1, unresolvedUnknownCount: 1, reconcileRequiredCount: 0, omittedCount: 0, barriers: [{ transferId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', reason: 'outcome_unknown', reconciled: true, clearable: true }] } : { count: 0, unresolvedUnknownCount: 0, reconcileRequiredCount: 0, omittedCount: 0, barriers: [] }; },
    async clearRecovery() { state.recovery = false; state.calls.push({ type: 'recovery.clear', result: 'completed' }); changed(); return { version: 1, type: 'recovery.cleared', phase: 'completed', cleared: 1 }; },
    async export() { return { blob: new Blob(['{"fixture":true}'], { type: 'application/json' }), fileName: 'miyu-fixture.json', format: 'json' }; },
    cancel() {}, dispose() {},
  };
  return { request, createVaultTransferClient: () => transfer, requestOrigins: async () => true, extensionVersion: () => '0.0.2 · UI workbench', getCommands: async () => [{ name: 'autofill-focused', shortcut: 'Ctrl+Shift+F' }], openShortcutSettings: async () => undefined, subscribeSessionChanges: () => () => undefined };
}
