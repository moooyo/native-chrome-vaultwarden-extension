/** Development-only browser adapter. This module is never imported by an extension entry point. */
const values: Record<string, unknown> = {
  'miyu.locale': 'zh-CN', 'miyu.theme': 'light', 'miyu.density': 'comfortable',
};
const event = () => {
  const listeners = new Set<(...args: unknown[]) => unknown>();
  return {
    addListener: (listener: (...args: unknown[]) => unknown) => listeners.add(listener),
    removeListener: (listener: (...args: unknown[]) => unknown) => listeners.delete(listener),
    hasListener: (listener: (...args: unknown[]) => unknown) => listeners.has(listener),
  };
};
const storage = {
  get: async (keys?: string | string[] | Record<string, unknown>) => {
    if (!keys) return { ...values };
    const requested = typeof keys === 'string' ? [keys] : Array.isArray(keys) ? keys : Object.keys(keys);
    return Object.fromEntries(requested.map((key) => [key, values[key]]));
  },
  set: async (items: Record<string, unknown>) => { Object.assign(values, items); },
  remove: async () => undefined, clear: async () => undefined, setAccessLevel: async () => undefined,
};
const browser = {
  runtime: {
    id: 'miyu-production-ui-workbench',
    getURL: (path: string) => new URL('/' + path, location.origin).href,
    getManifest: () => ({ version: '0.0.2', name: 'MiYu' }),
    sendMessage: async () => ({ ok: false, error: { code: 'unavailable', message: '测试环境未配置该操作' } }),
    connect: () => ({ onMessage: event(), onDisconnect: event(), postMessage() {}, disconnect() {} }),
    openOptionsPage: async () => undefined, onMessage: event(), onConnect: event(), lastError: undefined,
  },
  storage: { local: storage, session: storage, sync: storage, onChanged: event() },
  tabs: {
    query: async () => [{ id: 7, url: 'https://github.example/login', title: 'GitHub Example' }],
    create: async () => undefined, sendMessage: async () => undefined,
    onActivated: event(), onUpdated: event(),
  },
  windows: { create: async () => undefined, getCurrent: async () => ({ id: 1 }) },
  permissions: { contains: async () => false, request: async () => false, remove: async () => true, onAdded: event(), onRemoved: event() },
  commands: { getAll: async () => [{ name: 'autofill-focused', shortcut: 'Ctrl+Shift+F' }] },
  alarms: { create: async () => undefined, clear: async () => true, onAlarm: event() },
  i18n: { getUILanguage: () => 'zh-CN', getMessage: (key: string) => key },
};
export default browser;
