import { AppError } from '../core/errors.js';
import type { AccountLeaseGate } from '../core/session/account-gate.js';
import type { SessionLeaseGate } from '../core/session/session-manager.js';
import type { EnterprisePolicyGate } from '../core/policy/effective-enterprise-policy.js';
import type { VaultService } from '../core/vault/vault-service.js';
import type { BinaryTransferDependencies, BinaryTransferResult } from './binary-transfer-port-handler.js';
import type { VaultTimeoutController } from './vault-timeout-controller.js';

export interface BinaryTransferProductionDependencies {
  readonly sessionGate: SessionLeaseGate;
  readonly accountGate: Pick<AccountLeaseGate, 'capture' | 'assert'>;
  readonly policyGate: Pick<EnterprisePolicyGate, 'capture' | 'assert'>;
  readonly settings: { getServerUrl(): Promise<string | undefined> };
  readonly timeout: Pick<VaultTimeoutController, 'captureActivity' | 'recordActivity'>;
  readonly vault: Pick<VaultService, 'createFileSendBytes' | 'addAttachmentBytes' | 'getAttachmentBytes'>;
}

/** Keep transport ownership stable while each vault use case owns its policy and mutation fences. */
export function createBinaryTransferProduction(deps: BinaryTransferProductionDependencies): Pick<
  BinaryTransferDependencies, 'captureAuthority' | 'captureAdmissionAuthority' | 'execute'
> {
  return {
    captureAuthority() {
      const session = deps.sessionGate.capture();
      const account = deps.accountGate.capture();
      return () => {
        deps.sessionGate.assert(session);
        deps.accountGate.assert(account);
      };
    },
    captureAdmissionAuthority() {
      const account = deps.accountGate.capture();
      const policy = deps.policyGate.capture();
      const assertCurrent = (): void => {
        deps.accountGate.assert(account);
        deps.policyGate.assert(policy);
        if (policy.serverUrl !== account.serverUrl
            || policy.accountIdentity !== account.accountIdentity
            || policy.serverGeneration !== account.serverGeneration
            || policy.accountGeneration !== account.accountGeneration) {
          throw new AppError('denied', 'File transfer policy belongs to another account.');
        }
      };
      assertCurrent();
      return assertCurrent;
    },
    async execute(request, bytes, execution) {
      execution.assertCurrent();
      let activity = deps.timeout.captureActivity();
      let result: BinaryTransferResult;
      switch (request.type) {
        case 'sends.createFile': {
          if (!bytes) throw new AppError('error', 'File transfer data is unavailable.');
          const account = deps.accountGate.capture();
          const serverUrl = await deps.settings.getServerUrl();
          execution.assertCurrent();
          deps.accountGate.assert(account);
          if (!serverUrl || new URL(serverUrl).href !== new URL(account.serverUrl).href) {
            throw new AppError('denied', 'File transfer server changed.');
          }
          const send = await deps.vault.createFileSendBytes(
            request.input, bytes, request.fileName, serverUrl,
            execution.bindFinalAuthority, execution.assertCurrent,
          );
          execution.markCommitted();
          execution.assertCurrent();
          activity = deps.timeout.captureActivity();
          result = { kind: 'result', data: { send } };
          break;
        }
        case 'vault.addAttachment': {
          if (!bytes) throw new AppError('error', 'File transfer data is unavailable.');
          const listing = await deps.vault.addAttachmentBytes(
            request.cipherId, request.fileName, bytes, request.masterPassword,
            execution.bindFinalAuthority, execution.assertCurrent,
          );
          execution.markCommitted();
          execution.assertCurrent();
          activity = deps.timeout.captureActivity();
          result = { kind: 'result', data: listing };
          break;
        }
        case 'vault.getAttachment': {
          const attachment = await deps.vault.getAttachmentBytes(
            request.cipherId, request.attachmentId, request.masterPassword,
            execution.bindFinalAuthority, execution.assertCurrent,
          );
          result = { kind: 'download', ...attachment };
          break;
        }
      }
      try {
        await deps.timeout.recordActivity(activity);
        execution.assertCurrent();
        return result;
      } catch (error) {
        if (result.kind === 'download') result.bytes.fill(0);
        throw error;
      }
    },
  };
}
