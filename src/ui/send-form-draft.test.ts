import { describe, expect, it } from 'vitest';
import { normalizeSendDraft, sendDraftHasEdits, type SendDraftValues } from './send-form-draft.js';

describe('Send draft normalization', () => {
  it('compares every editable text-Send field after request-equivalent normalization', () => {
    const baselineValues: SendDraftValues = {
      owner: 'edit:send-a',
      type: 'text',
      name: '  Baseline  ',
      notes: 'private note',
      text: 'shared text',
      hidden: false,
      disabled: false,
      hideEmail: false,
      passwordMode: 'keep',
      expirationHours: '',
      deletionHours: '',
      maxAccessCount: '5',
    };
    const baseline = normalizeSendDraft(baselineValues);
    expect(sendDraftHasEdits(baseline, normalizeSendDraft({ ...baselineValues, name: 'Baseline' }))).toBe(false);

    const changes: SendDraftValues[] = [
      { ...baselineValues, owner: 'edit:send-b' },
      { ...baselineValues, name: 'Changed' },
      { ...baselineValues, notes: 'changed note' },
      { ...baselineValues, text: 'changed text' },
      { ...baselineValues, hidden: true },
      { ...baselineValues, disabled: true },
      { ...baselineValues, hideEmail: true },
      { ...baselineValues, passwordMode: 'remove' },
      { ...baselineValues, passwordMode: 'set', password: 'new password' },
      { ...baselineValues, expirationHours: '24' },
      { ...baselineValues, deletionHours: '48' },
      { ...baselineValues, maxAccessCount: '10' },
    ];
    for (const changed of changes) {
      expect(sendDraftHasEdits(baseline, normalizeSendDraft(changed))).toBe(true);
    }
  });

  it('tracks file identity and ignores fields that cannot affect the selected Send type', () => {
    const file = { name: 'a.txt', size: 10, type: 'text/plain', lastModified: 7 };
    const baseline = normalizeSendDraft({
      owner: 'create',
      type: 'file',
      file,
      text: 'inactive text',
      hidden: true,
      passwordMode: 'none',
      password: 'inactive password',
      maxAccessCount: '05.9',
    });
    const equivalent = normalizeSendDraft({
      owner: 'create',
      type: 'file',
      file: { ...file },
      text: 'different inactive text',
      hidden: false,
      passwordMode: 'none',
      maxAccessCount: 5,
    });
    expect(sendDraftHasEdits(baseline, equivalent)).toBe(false);
    expect(sendDraftHasEdits(baseline, normalizeSendDraft({
      owner: 'create',
      type: 'file',
      file: { ...file, size: 11 },
      maxAccessCount: 5,
    }))).toBe(true);
    expect(sendDraftHasEdits(baseline, normalizeSendDraft({
      owner: 'create',
      type: 'text',
      text: '',
      maxAccessCount: 5,
    }))).toBe(true);
  });
});
