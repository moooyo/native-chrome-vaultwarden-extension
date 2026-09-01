export type SendDraftOwner = 'create' | `edit:${string}`;
export type SendDraftType = 'text' | 'file';
export type SendDraftPasswordMode = 'none' | 'keep' | 'set' | 'remove';

export interface SendDraftFile {
  name: string;
  size: number;
  type: string;
  lastModified: number;
}

export interface SendDraftValues {
  owner: SendDraftOwner;
  type: SendDraftType;
  name?: string;
  notes?: string;
  text?: string;
  file?: Pick<File, 'name' | 'size' | 'type' | 'lastModified'> | null | undefined;
  hidden?: boolean;
  disabled?: boolean;
  hideEmail?: boolean;
  passwordMode?: SendDraftPasswordMode;
  password?: string;
  expirationHours?: string | number | null;
  deletionHours?: string | number | null;
  maxAccessCount?: string | number | null;
}

export interface SendDraftSnapshot {
  owner: SendDraftOwner;
  type: SendDraftType;
  name: string;
  notes: string;
  text: string;
  file: SendDraftFile | null;
  hidden: boolean;
  disabled: boolean;
  hideEmail: boolean;
  passwordMode: SendDraftPasswordMode;
  password: string;
  expirationHours: number | null;
  deletionHours: number | null;
  maxAccessCount: number | null;
}

/** Normalize a Send form to the values that can affect its eventual request. */
export function normalizeSendDraft(values: SendDraftValues): SendDraftSnapshot {
  const passwordMode = values.passwordMode ?? 'none';
  return {
    owner: values.owner,
    type: values.type,
    name: (values.name ?? '').trim(),
    notes: values.notes ?? '',
    text: values.type === 'text' ? (values.text ?? '') : '',
    file: values.type === 'file' && values.file
      ? {
          name: values.file.name,
          size: values.file.size,
          type: values.file.type,
          lastModified: values.file.lastModified,
        }
      : null,
    hidden: values.type === 'text' && Boolean(values.hidden),
    disabled: Boolean(values.disabled),
    hideEmail: Boolean(values.hideEmail),
    passwordMode,
    password: passwordMode === 'set' ? (values.password ?? '') : '',
    expirationHours: normalizePositiveInteger(values.expirationHours),
    deletionHours: normalizePositiveInteger(values.deletionHours),
    maxAccessCount: normalizePositiveInteger(values.maxAccessCount),
  };
}

export function sendDraftHasEdits(
  baseline: SendDraftSnapshot | undefined,
  current: SendDraftSnapshot | undefined,
): boolean {
  if (!baseline || !current) return false;
  return baseline.owner !== current.owner
    || baseline.type !== current.type
    || baseline.name !== current.name
    || baseline.notes !== current.notes
    || baseline.text !== current.text
    || !sameFile(baseline.file, current.file)
    || baseline.hidden !== current.hidden
    || baseline.disabled !== current.disabled
    || baseline.hideEmail !== current.hideEmail
    || baseline.passwordMode !== current.passwordMode
    || baseline.password !== current.password
    || baseline.expirationHours !== current.expirationHours
    || baseline.deletionHours !== current.deletionHours
    || baseline.maxAccessCount !== current.maxAccessCount;
}

function normalizePositiveInteger(value: string | number | null | undefined): number | null {
  if (value === '' || value === null || value === undefined) return null;
  const parsed = typeof value === 'number' ? value : Number(value);
  return Number.isFinite(parsed) && parsed > 0 ? Math.trunc(parsed) : null;
}

function sameFile(left: SendDraftFile | null, right: SendDraftFile | null): boolean {
  if (!left || !right) return left === right;
  return left.name === right.name
    && left.size === right.size
    && left.type === right.type
    && left.lastModified === right.lastModified;
}
