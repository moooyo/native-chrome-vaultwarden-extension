import { detectLoginForms, type DetectedLoginForm } from './form-detection.js';
import { detectCardForms, detectIdentityForms, type DetectedFillForm } from './field-detection.js';
import type { AutofillCandidate, AutofillCredentials, FillItemCandidate, CardFillData, IdentityFillData, FillKind } from '../messaging/protocol.js';

export type FocusedTarget =
  | { kind: 'login'; form: DetectedLoginForm }
  | { kind: 'card'; form: DetectedFillForm }
  | { kind: 'identity'; form: DetectedFillForm }
  | { kind: 'none' };

export interface FillExclusion {
  /** Real login forms — a login form whose password field is actually a card CVC is dropped. */
  loginForms: DetectedLoginForm[];
  /** The username/password/totp fields of those login forms, to keep them out of card/identity detection. */
  exclude: Set<Element>;
}

/**
 * Single source of truth for the login/card/identity carve-out. Mirrors what attachPopovers did inline:
 * build the set of card CVC fields first, then treat a "login" form whose password IS a CVC as not-a-login.
 */
export function computeFillExclusion(root: ParentNode = document): FillExclusion {
  const cardCodeFields = new Set<Element>();
  for (const card of detectCardForms(root)) {
    const code = card.fields.get('code');
    if (code) cardCodeFields.add(code);
  }
  const loginForms: DetectedLoginForm[] = [];
  const exclude = new Set<Element>();
  for (const form of detectLoginForms(root)) {
    if (form.passwordInput && cardCodeFields.has(form.passwordInput)) continue; // a CVC, not a login
    loginForms.push(form);
    for (const el of [form.usernameInput, form.passwordInput, form.totpInput]) if (el) exclude.add(el);
  }
  return { loginForms, exclude };
}

/**
 * Determine which detected form the focused element belongs to. Precedence (identical to attachPopovers):
 * CVC carve-out (inside computeFillExclusion) → login → card → identity → none.
 */
export function resolveFocusedFill(activeEl: Element | null, root: ParentNode = document): FocusedTarget {
  if (!(activeEl instanceof HTMLInputElement || activeEl instanceof HTMLSelectElement)) return { kind: 'none' };
  const { loginForms, exclude } = computeFillExclusion(root);
  for (const form of loginForms) {
    if (activeEl === form.usernameInput || activeEl === form.passwordInput || activeEl === form.totpInput) {
      return { kind: 'login', form };
    }
  }
  for (const form of detectCardForms(root, exclude)) {
    for (const field of form.fields.values()) if (field === activeEl) return { kind: 'card', form };
  }
  for (const form of detectIdentityForms(root, exclude)) {
    for (const field of form.fields.values()) if (field === activeEl) return { kind: 'identity', form };
  }
  return { kind: 'none' };
}

export const NOTICE_FOCUS = 'Focus a login, card, or identity field, then use the shortcut';
export const NOTICE_PAGE_CHANGED = 'Page changed before autofill';

export type FillOutcome<T> = { ok: true; data: T } | { ok: false; message: string };

export interface FocusedFillDeps {
  frameUrl(): string;
  loginCandidates(frameUrl: string): Promise<FillOutcome<AutofillCandidate[]>>;
  loginCredentials(cipherId: string, frameUrl: string): Promise<FillOutcome<AutofillCredentials>>;
  fillItems(kind: FillKind): Promise<FillOutcome<FillItemCandidate[]>>;
  fillData(cipherId: string, kind: FillKind): Promise<FillOutcome<CardFillData | IdentityFillData>>;
  fillLogin(form: DetectedLoginForm, creds: AutofillCredentials): void;
  fillCard(form: DetectedFillForm, data: CardFillData): void;
  fillIdentity(form: DetectedFillForm, data: IdentityFillData): void;
  openPicker(formId: string): void;
  notify(message: string): void;
}

function loginFormLive(form: DetectedLoginForm): boolean {
  const fields = [form.usernameInput, form.passwordInput, form.totpInput].filter((f): f is HTMLInputElement => Boolean(f));
  return fields.length > 0 && fields.every((f) => f.isConnected);
}

function fillFormLive(form: DetectedFillForm): boolean {
  const fields = [...form.fields.values()];
  return fields.length > 0 && fields.every((f) => f.isConnected);
}

/** Resolve a focused target to an autofill action, reusing existing worker requests via injected deps. */
export async function runFocusedFill(target: FocusedTarget, deps: FocusedFillDeps): Promise<void> {
  if (target.kind === 'none') { deps.notify(NOTICE_FOCUS); return; }

  if (target.kind === 'login') {
    const frameUrl = deps.frameUrl();
    const cands = await deps.loginCandidates(frameUrl);
    if (!cands.ok) { deps.notify(cands.message); return; }
    if (cands.data.length === 0) { deps.notify('No matching logins'); return; }
    if (cands.data.length > 1) { deps.openPicker(target.form.id); return; }
    const creds = await deps.loginCredentials(cands.data[0]!.id, frameUrl);
    if (!creds.ok) { deps.notify(creds.message); return; }
    if (deps.frameUrl() !== frameUrl || !loginFormLive(target.form)) { deps.notify(NOTICE_PAGE_CHANGED); return; }
    deps.fillLogin(target.form, creds.data);
    return;
  }

  const kind = target.kind; // 'card' | 'identity'
  const items = await deps.fillItems(kind);
  if (!items.ok) { deps.notify(items.message); return; }
  if (items.data.length === 0) { deps.notify(kind === 'card' ? 'No saved cards' : 'No saved identities'); return; }
  if (items.data.length > 1) { deps.openPicker(target.form.id); return; }
  const data = await deps.fillData(items.data[0]!.id, kind);
  if (!data.ok) { deps.notify(data.message); return; }
  if (!fillFormLive(target.form)) { deps.notify(NOTICE_PAGE_CHANGED); return; }
  if (kind === 'card') deps.fillCard(target.form, data.data as CardFillData);
  else deps.fillIdentity(target.form, data.data as IdentityFillData);
}
