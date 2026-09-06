import { describe, expect, it, vi } from 'vitest';
import { SessionGate } from './session-gate.js';
import { AccountLeaseGate } from '../core/session/account-gate.js';
import { EnterprisePolicyGate } from '../core/policy/effective-enterprise-policy.js';
import { createBinaryTransferProduction, type BinaryTransferProductionDependencies } from './binary-transfer-production.js';
import type { BinaryTransferExecution } from './binary-transfer-port-handler.js';
import type { VaultTimeoutActivityLease } from './vault-timeout-controller.js';

function fixture() {
  const sessionGate = new SessionGate('unlocked');
  const accountGate = new AccountLeaseGate();
  accountGate.initialize({ serverUrl: 'https://vault.example/', accountIdentity: 'user@example.com' });
  const policyGate = new EnterprisePolicyGate();
  let generation = 0;
  const publishPolicy = () => policyGate.replace({
    response: { profile: { id: 'user', email: 'user@example.com' }, ciphers: [], policiesNew: [] },
    accountLease: accountGate.capture(), rawGeneration: `raw-${++generation}`,
  });
  publishPolicy();
  const vault: BinaryTransferProductionDependencies['vault'] = {
    createFileSendBytes: async () => { throw new Error('Unexpected Send creation'); },
    addAttachmentBytes: async () => { throw new Error('Unexpected attachment creation'); },
    getAttachmentBytes: async () => { throw new Error('Unexpected attachment download'); },
  };
  let activity: VaultTimeoutActivityLease = {
    generation: 1, accountKey: 'https://vault.example/\nuser@example.com', sessionBindingId: 'session-1',
  };
  const captureActivity = vi.fn(() => activity);
  const recordActivity = vi.fn(async (_lease: VaultTimeoutActivityLease | undefined) => {});
  const settings = { getServerUrl: vi.fn(async (): Promise<string | undefined> => 'https://vault.example/') };
  const production = createBinaryTransferProduction({
    sessionGate, accountGate, policyGate, settings, vault,
    timeout: { captureActivity, recordActivity },
  });
  const finalAuthorities: Array<() => void> = [];
  const execution: BinaryTransferExecution = {
    signal: new AbortController().signal,
    assertCurrent: production.captureAuthority(),
    bindFinalAuthority: (assertCurrent) => finalAuthorities.push(assertCurrent),
    markCommitted: vi.fn(),
  };
  return {
    production, execution, vault, settings, sessionGate, policyGate, recordActivity, publishPolicy, finalAuthorities,
    advanceTimeout: () => { activity = { ...activity, generation: activity.generation + 1 }; return activity; },
  };
}

describe('binary transfer production authority', () => {
  it('hands a successful mutation to its new result policy without relaxing account ownership', async () => {
    const h = fixture();
    const admission = h.production.captureAdmissionAuthority();
    let renewedActivity: VaultTimeoutActivityLease | undefined;
    h.vault.addAttachmentBytes = async (_cipherId, _name, _bytes, _password, bind, assertCurrent) => {
      admission();
      assertCurrent?.();
      h.publishPolicy();
      renewedActivity = h.advanceTimeout();
      const finalPolicy = h.policyGate.capture();
      bind?.(() => { h.policyGate.assert(finalPolicy); });
      return { items: [], folders: [], collections: [], orgPermissions: [] };
    };
    const result = await h.production.execute({
      type: 'vault.addAttachment', cipherId: 'cipher', fileName: 'data.bin', expectedBytes: 3,
    }, new Uint8Array([1, 2, 3]), h.execution);
    expect(result.kind).toBe('result');
    expect(h.recordActivity).toHaveBeenCalledWith(renewedActivity);
    expect(admission).toThrow();
    expect(h.execution.assertCurrent).not.toThrow();
    expect(h.finalAuthorities).toHaveLength(1);
    expect(h.finalAuthorities[0]).not.toThrow();
    h.publishPolicy();
    expect(h.finalAuthorities[0]).toThrow();
  });

  it('rejects a server change before any Send mutation can be dispatched', async () => {
    const h = fixture();
    h.settings.getServerUrl.mockResolvedValue('https://another.example/');
    const create = vi.fn(h.vault.createFileSendBytes);
    h.vault.createFileSendBytes = create;
    await expect(h.production.execute({
      type: 'sends.createFile', input: { name: 'File' }, fileName: 'file.bin', expectedBytes: 1,
    }, new Uint8Array([1]), h.execution)).rejects.toMatchObject({ code: 'denied' });
    expect(create).not.toHaveBeenCalled();
    expect(h.execution.markCommitted).not.toHaveBeenCalled();
  });

  it('marks a committed attachment before fallible timeout bookkeeping', async () => {
    const h = fixture();
    h.vault.addAttachmentBytes = async () => ({ items: [], folders: [], collections: [], orgPermissions: [] });
    h.recordActivity.mockImplementation(async () => {
      expect(h.execution.markCommitted).toHaveBeenCalledOnce();
      throw new Error('Storage unavailable');
    });
    await expect(h.production.execute({
      type: 'vault.addAttachment', cipherId: 'cipher', fileName: 'data.bin', expectedBytes: 1,
    }, new Uint8Array([1]), h.execution)).rejects.toThrow('Storage unavailable');
  });

  it('erases downloaded bytes when lock wins during activity persistence', async () => {
    const h = fixture();
    const bytes = new Uint8Array([4, 5, 6]);
    h.vault.getAttachmentBytes = async () => ({ bytes, fileName: 'secret.bin' });
    h.recordActivity.mockImplementation(async () => {
      h.sessionGate.handleTransition({ phase: 'start', transitionId: 1, reason: 'lock', identityChanged: false });
    });
    await expect(h.production.execute({
      type: 'vault.getAttachment', cipherId: 'cipher', attachmentId: 'attachment',
    }, undefined, h.execution)).rejects.toMatchObject({ code: 'locked' });
    expect(bytes).toEqual(new Uint8Array(3));
    expect(h.execution.markCommitted).not.toHaveBeenCalled();
  });
});
