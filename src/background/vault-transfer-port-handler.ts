import type {
  VaultTransferPreview,
  VaultTransferPreviewDiagnosticCode,
} from '../core/vault/vault-transfer-preview.js';
import type { VaultTransferSourceFormat } from '../core/vault/vault-transfer-source.js';
import type { VaultTransferExportTarget } from '../core/vault/vault-transfer-target.js';
import {
  MAX_VAULT_TRANSFER_PORT_CHUNK_BYTES,
  MAX_VAULT_TRANSFER_RECOVERY_BARRIERS,
  VAULT_TRANSFER_PORT_DIAGNOSTIC_CODES,
  VAULT_TRANSFER_PORT_NAME,
  VAULT_TRANSFER_PORT_VERSION,
  VaultTransferPortProtocolError,
  canClearVaultTransferRecovery,
  createVaultTransferPortErrorMessage,
  decodeVaultTransferPortChunk,
  encodeVaultTransferPortChunk,
  parseVaultTransferClientMessage,
  parseVaultTransferWorkerMessage,
  type VaultTransferClientMessage,
  type VaultTransferExportAckMessage,
  type VaultTransferExportFormat,
  type VaultTransferImportResultAckMessage,
  type VaultTransferPortDiagnosticCode,
  type VaultTransferPortErrorCode,
  type VaultTransferPortPhase,
  type VaultTransferPortPreviewModel,
  type VaultTransferPortSanitizedDiagnostic,
  type VaultTransferRecoveryStatusMessage,
  type VaultTransferWorkerMessage,
} from '../messaging/vault-transfer-port.js';
import {
  VaultTransferControllerError,
  type VaultTransferController,
  type VaultTransferControllerErrorCode,
  type VaultTransferExportChunkProducer,
} from './vault-transfer-controller.js';
import type { VaultReleaseGate, VaultReleaseLease } from './vault-release-gate.js';
import { bestEffortClientEvent } from './client-event-best-effort.js';

const OPTIONS_PAGE_PATH = '/ui/options/options.html';
const MAX_RESULT_COUNT = 1_000_000;

type Controller = Pick<
  VaultTransferController<unknown, unknown, unknown, unknown, unknown>,
  | 'beginImport'
  | 'appendImportChunk'
  | 'acknowledgeImportChunk'
  | 'sealAndInspectImport'
  | 'confirmImport'
  | 'commitConfirmedImport'
  | 'acknowledgeImportResult'
  | 'beginExport'
  | 'streamExport'
  | 'inspectReplayBarriers'
  | 'clearReplayBarrier'
  | 'disconnect'
>;

export interface VaultTransferPortEvent<Listener> {
  addListener(listener: Listener): void;
  removeListener?(listener: Listener): void;
}

export interface VaultTransferPortLike {
  readonly name: string;
  readonly sender?: {
    readonly id?: string;
    readonly url?: string;
    readonly documentId?: string;
  };
  readonly onMessage: VaultTransferPortEvent<(message: unknown) => void>;
  readonly onDisconnect: VaultTransferPortEvent<() => void>;
  postMessage(message: VaultTransferWorkerMessage): void;
  disconnect(): void;
}

interface PendingExportAcknowledgement {
  readonly transferId: string;
  readonly sequence: number;
  readonly generation: number;
  readonly resolve: () => void;
  readonly reject: (error: Error) => void;
}

type HandlerPhase = VaultTransferPortPhase | 'awaiting_result_ack';
type FastAcknowledgement = VaultTransferExportAckMessage | VaultTransferImportResultAckMessage;

interface PortState {
  active: boolean;
  generation: number;
  ordinaryMessagePending: boolean;
  phase: HandlerPhase;
  transferId: string | undefined;
  exportFormat: VaultTransferExportFormat | undefined;
  exportTarget: VaultTransferExportTarget | undefined;
  controllerDisconnected: boolean;
  importResultAcknowledgementPending: boolean;
  pendingExportAcknowledgement: PendingExportAcknowledgement | undefined;
  releaseSessionLease: VaultReleaseLease['sessionLease'] | undefined;
  tail: Promise<void>;
}

const DIAGNOSTIC_CODE_MAP: Readonly<Record<
  VaultTransferPreviewDiagnosticCode,
  VaultTransferPortDiagnosticCode
>> = Object.freeze({
  ambiguous_transfer_scope: 'malformed_input',
  archive_metadata_invalid: 'malformed_input',
  attachments_unsupported: 'attachment_unavailable',
  autofill_on_page_load_unsupported: 'unsupported_data',
  capability_policy_invalid: 'capability_blocked',
  collection_ids_limit_exceeded: 'limit_exceeded',
  collections_limit_exceeded: 'limit_exceeded',
  csv_cell_limit_exceeded: 'limit_exceeded',
  csv_columns_limit_exceeded: 'limit_exceeded',
  csv_format_is_lossy: 'unsupported_format',
  csv_rows_limit_exceeded: 'limit_exceeded',
  custom_fields_unsupported: 'unsupported_data',
  diagnostics_truncated: 'diagnostics_omitted',
  duplicate_collection_id: 'malformed_input',
  duplicate_csv_header: 'malformed_input',
  duplicate_folder_id: 'malformed_input',
  empty_input: 'malformed_input',
  encrypted_input_requires_decryption: 'unsupported_format',
  fields_limit_exceeded: 'limit_exceeded',
  folders_limit_exceeded: 'limit_exceeded',
  folders_unsupported: 'unsupported_data',
  format_mismatch: 'unsupported_format',
  input_too_large: 'limit_exceeded',
  inspection_invalid: 'malformed_input',
  inspection_resource_limit: 'limit_exceeded',
  invalid_encryption_marker: 'malformed_input',
  invalid_json_root: 'malformed_input',
  invalid_shape: 'malformed_input',
  item_dates_unsupported: 'unsupported_data',
  item_type_unsupported: 'unsupported_data',
  items_limit_exceeded: 'limit_exceeded',
  malformed_csv: 'malformed_input',
  malformed_json: 'malformed_input',
  missing_collection_reference: 'missing_reference',
  missing_folder_reference: 'missing_reference',
  missing_folders: 'malformed_input',
  missing_items: 'malformed_input',
  organization_target_required: 'organization_target_required',
  organization_import_atomicity_unavailable: 'capability_blocked',
  outcome_unknown: 'outcome_unknown',
  passkeys_limit_exceeded: 'limit_exceeded',
  passkeys_unsupported: 'unsupported_data',
  password_history_limit_exceeded: 'limit_exceeded',
  password_history_unsupported: 'unsupported_data',
  preview_options_invalid: 'malformed_input',
  reprompt_unsupported: 'unsupported_data',
  secure_note_type_unsupported: 'unsupported_data',
  server_managed_dates_dropped: 'other',
  ssh_linked_fields_unsupported: 'unsupported_data',
  string_limit_exceeded: 'limit_exceeded',
  transfer_diagnostic: 'other',
  transfer_notice: 'other',
  unknown_field: 'unknown_data',
  unknown_fields: 'unknown_data',
  unknown_item_type: 'unknown_data',
  unsupported_ir_version: 'unsupported_format',
  unsupported_known_data: 'unsupported_data',
  uri_match_unsupported: 'unsupported_data',
  uris_limit_exceeded: 'limit_exceeded',
});

/**
 * Owns the privileged options-page transfer channel. Each accepted Port may carry exactly one
 * transfer, and the Port itself keeps the MV3 worker alive while plaintext is staged in memory.
 */
export class VaultTransferPortHandler {
  constructor(
    private readonly controller: Controller,
    private readonly ready: PromiseLike<void> = Promise.resolve(),
    private readonly vaultReleaseGate?: Pick<
      VaultReleaseGate,
      'capture' | 'checkpoint' | 'assertAuthorities' | 'assert'
    > & Partial<Pick<VaultReleaseGate, 'settlePendingAction'>>,
    private readonly issuePersonalExportAck?: (documentId: string) => Promise<string | undefined>,
    private readonly issueOrganizationExportAck?: (
      documentId: string,
      organizationId: string,
    ) => Promise<string | undefined>,
  ) {}

  handle(port: VaultTransferPortLike, extensionBaseUrl: string, extensionId: string): boolean {
    if (!isTrustedOptionsPort(port, extensionBaseUrl, extensionId)) {
      safeDisconnectPort(port);
      return false;
    }

    const state: PortState = {
      active: true,
      generation: 1,
      ordinaryMessagePending: false,
      phase: 'idle',
      transferId: undefined,
      exportFormat: undefined,
      exportTarget: undefined,
      controllerDisconnected: false,
      importResultAcknowledgementPending: false,
      pendingExportAcknowledgement: undefined,
      releaseSessionLease: undefined,
      tail: Promise.resolve(this.ready),
    };

    const onMessage = (value: unknown): void => {
      if (!state.active) return;
      let message: VaultTransferClientMessage;
      try {
        message = parseVaultTransferClientMessage(value);
      } catch (error) {
        this.fail(port, state, error, onMessage, onDisconnect);
        return;
      }

      if (message.type === 'export.ack') {
        this.handleExportAcknowledgement(port, state, message, onMessage, onDisconnect);
        return;
      }
      if (message.type === 'import.result.ack') {
        this.handleImportResultAcknowledgement(port, state, message, onMessage, onDisconnect);
        return;
      }

      if (state.ordinaryMessagePending) {
        this.fail(
          port,
          state,
          new VaultTransferPortProtocolError('invalid_state'),
          onMessage,
          onDisconnect,
        );
        return;
      }

      const generation = state.generation;
      state.ordinaryMessagePending = true;
      state.tail = state.tail.then(async () => {
        if (!isCurrent(state, generation)) return;
        await this.handleOrdinaryMessage(port, state, message, generation, onMessage, onDisconnect);
      }).then(
        () => {
          if (isCurrent(state, generation)) state.ordinaryMessagePending = false;
        },
        async (error: unknown) => {
          await this.vaultReleaseGate?.settlePendingAction?.();
          if (isCurrent(state, generation)) {
            state.ordinaryMessagePending = false;
            this.fail(port, state, error, onMessage, onDisconnect);
          }
        },
      );
    };

    const onDisconnect = (): void => {
      this.close(port, state, onMessage, onDisconnect);
    };

    state.tail = state.tail.catch(() => {
      if (state.active) {
        this.fail(
          port,
          state,
          new VaultTransferPortProtocolError('internal_error'),
          onMessage,
          onDisconnect,
        );
      }
    });

    try {
      port.onMessage.addListener(onMessage);
      port.onDisconnect.addListener(onDisconnect);
    } catch {
      this.close(port, state, onMessage, onDisconnect);
      safeDisconnectPort(port);
      return false;
    }
    return true;
  }

  private async handleOrdinaryMessage(
    port: VaultTransferPortLike,
    state: PortState,
    message: Exclude<VaultTransferClientMessage, FastAcknowledgement>,
    generation: number,
    onMessage: (message: unknown) => void,
    onDisconnect: () => void,
  ): Promise<void> {
    switch (message.type) {
      case 'import.begin': {
        requirePhase(state, 'idle');
        const begun = this.controller.beginImport({ expectedTotalBytes: message.expectedTotalBytes });
        state.transferId = begun.transferId;
        state.phase = 'uploading';
        post(port, {
          version: VAULT_TRANSFER_PORT_VERSION,
          type: 'import.begun',
          transferId: begun.transferId,
          phase: 'uploading',
          maxChunkBytes: Math.min(begun.maxChunkBytes, MAX_VAULT_TRANSFER_PORT_CHUNK_BYTES),
          maxEncodedChunkChars: encodedLength(
            Math.min(begun.maxChunkBytes, MAX_VAULT_TRANSFER_PORT_CHUNK_BYTES),
          ),
        });
        return;
      }
      case 'import.chunk': {
        requireMatchingTransfer(state, message.transferId, 'uploading');
        let chunk: Uint8Array | undefined;
        try {
          chunk = decodeVaultTransferPortChunk(message.dataBase64, message.byteLength);
          const ack = this.controller.appendImportChunk(
            message.transferId,
            message.sequence,
            chunk,
          );
          if (ack.transferId !== message.transferId || ack.sequence !== message.sequence) {
            throw new VaultTransferPortProtocolError('invalid_sequence');
          }
          post(port, {
            version: VAULT_TRANSFER_PORT_VERSION,
            type: 'import.ack',
            transferId: message.transferId,
            phase: 'uploading',
            sequence: ack.sequence,
            nextSequence: ack.sequence + 1,
            byteLength: message.byteLength,
            totalBytes: ack.totalBytes,
          });
          this.controller.acknowledgeImportChunk(message.transferId, ack.sequence);
        } finally {
          chunk?.fill(0);
        }
        return;
      }
      case 'import.seal': {
        requireMatchingTransfer(state, message.transferId, 'uploading');
        state.phase = 'inspecting';
        const inspected = await this.controller.sealAndInspectImport(
          message.transferId,
          message.password,
        );
        if (!isCurrent(state, generation)) return;
        if (inspected.transferId !== message.transferId) {
          throw new VaultTransferPortProtocolError('invalid_state');
        }
        state.phase = 'previewed';
        post(port, {
          version: VAULT_TRANSFER_PORT_VERSION,
          type: 'import.preview',
          transferId: message.transferId,
          previewRevision: inspected.previewCapability,
          preview: sanitizePreview(inspected.preview, inspected.sourceFormat),
        });
        return;
      }
      case 'import.confirm': {
        requireMatchingTransfer(state, message.transferId, 'previewed');
        state.phase = 'committing';
        const confirmation = this.controller.confirmImport(message.transferId, message.previewRevision);
        if (confirmation.transferId !== message.transferId || confirmation.status !== 'confirmed') {
          throw new VaultTransferPortProtocolError('invalid_state');
        }
        const result = await this.controller.commitConfirmedImport(message.transferId);
        if (!isCurrent(state, generation)) return;
        if (result.transferId !== message.transferId) {
          throw new VaultTransferPortProtocolError('commit_failed');
        }
        state.phase = 'completed';
        post(port, {
          version: VAULT_TRANSFER_PORT_VERSION,
          type: 'import.result',
          transferId: message.transferId,
          phase: 'completed',
          status: result.status,
          counts: {
            committed: result.counts.committed,
            rejected: result.counts.rejected,
            skipped: result.counts.skipped,
            outcomeUnknown: result.counts.outcomeUnknown,
          },
          mustSyncBeforeRetry: result.requiresReconcile || result.counts.outcomeUnknown > 0,
        });
        state.phase = 'awaiting_result_ack';
        return;
      }
      case 'export.begin': {
        requirePhase(state, 'idle');
        state.releaseSessionLease = this.vaultReleaseGate?.capture().sessionLease;
        state.phase = 'exporting';
        state.exportFormat = message.format;
        state.exportTarget = message.target;
        const begun = await this.controller.beginExport({
          format: message.format,
          authorizationId: message.authorizationId,
          target: message.target,
          ...(message.format === 'encrypted-json' && message.filePassword !== undefined
            ? { filePassword: message.filePassword }
            : {}),
        });
        if (!isCurrent(state, generation)) {
          this.disconnectController(state, begun.transferId);
          return;
        }
        state.transferId = begun.transferId;
        if (begun.format !== message.format) {
          throw new VaultTransferPortProtocolError('export_failed');
        }
        post(port, {
          version: VAULT_TRANSFER_PORT_VERSION,
          type: 'export.begun',
          transferId: begun.transferId,
          format: message.format,
          phase: 'exporting',
          fileName: begun.filename,
          ...(begun.review ? { review: begun.review } : {}),
        });
        void this.streamExport(port, state, generation, onMessage, onDisconnect);
        return;
      }
      case 'recovery.inspect': {
        requirePhase(state, 'idle');
        state.phase = 'inspecting';
        const inspection = await this.controller.inspectReplayBarriers();
        if (!isCurrent(state, generation)) return;
        state.phase = 'completed';
        post(port, createRecoveryStatusMessage(inspection));
        return;
      }
      case 'recovery.clear': {
        requirePhase(state, 'idle');
        state.phase = 'inspecting';
        const inspection = await this.controller.inspectReplayBarriers();
        if (!isCurrent(state, generation)) return;
        const statusMessage = createRecoveryStatusMessage(inspection);
        if (!canClearVaultTransferRecovery(statusMessage.status)
          || !matchesRecoveryClearExpectation(
            statusMessage.status.barriers,
            message.expectedBarriers,
          )) {
          throw new VaultTransferPortProtocolError('recovery_not_clearable');
        }
        state.phase = 'committing';
        let cleared = 0;
        for (const barrier of message.expectedBarriers) {
          if (!isCurrent(state, generation)) return;
          await this.controller.clearReplayBarrier(barrier.transferId);
          if (!isCurrent(state, generation)) return;
          cleared += 1;
        }
        const clearedMessage = parseVaultTransferWorkerMessage({
          version: VAULT_TRANSFER_PORT_VERSION,
          type: 'recovery.cleared',
          phase: 'completed',
          cleared,
        });
        if (clearedMessage.type !== 'recovery.cleared') {
          throw new VaultTransferPortProtocolError('internal_error');
        }
        state.phase = 'completed';
        post(port, clearedMessage);
        return;
      }
      case 'cancel': {
        requireMatchingTransfer(state, message.transferId);
        this.close(port, state, onMessage, onDisconnect);
        safeDisconnectPort(port);
        return;
      }
    }
  }

  private async streamExport(
    port: VaultTransferPortLike,
    state: PortState,
    generation: number,
    onMessage: (message: unknown) => void,
    onDisconnect: () => void,
  ): Promise<void> {
    const transferId = state.transferId;
    const format = state.exportFormat;
    const target = state.exportTarget;
    if (transferId === undefined || format === undefined || target === undefined) {
      this.fail(port, state, new VaultTransferPortProtocolError('invalid_state'), onMessage, onDisconnect);
      return;
    }

    let chunkCount = 0;
    let totalBytes = 0;
    let clientEventAckId: string | undefined;
    try {
      const result = await this.controller.streamExport(transferId, async ({ format: streamFormat, producer }) => {
        if (streamFormat !== format) throw new VaultTransferPortProtocolError('export_failed');
        for (;;) {
          if (!isCurrent(state, generation)) throw new VaultTransferPortProtocolError('cancelled');
          const releaseLease = state.releaseSessionLease && this.vaultReleaseGate
            ? this.vaultReleaseGate.capture(state.releaseSessionLease)
            : undefined;
          const chunk = await producer.next();
          if (!isCurrent(state, generation)) throw new VaultTransferPortProtocolError('cancelled');
          if (chunk.done) {
            totalBytes = chunk.totalBytes;
            assertExportProducerCurrent(producer);
            const releaseProof = releaseLease && this.vaultReleaseGate
              ? await this.vaultReleaseGate.checkpoint(releaseLease)
              : undefined;
            if (releaseProof && this.vaultReleaseGate) {
              this.vaultReleaseGate.assertAuthorities(releaseProof, () => assertExportProducerCurrent(producer));
              this.vaultReleaseGate.assert(releaseProof);
            }
            const documentId = port.sender?.documentId;
            clientEventAckId = typeof documentId !== 'string'
              ? undefined
              : target.kind === 'personal'
                ? this.issuePersonalExportAck
                  ? await bestEffortClientEvent(() => this.issuePersonalExportAck!(documentId))
                  : undefined
                : this.issueOrganizationExportAck
                  ? await bestEffortClientEvent(() => this.issueOrganizationExportAck!(
                      documentId,
                      target.organizationId,
                    ))
                  : undefined;
            assertExportProducerCurrent(producer);
            if (releaseProof && this.vaultReleaseGate) {
              this.vaultReleaseGate.assertAuthorities(releaseProof, () => assertExportProducerCurrent(producer));
              this.vaultReleaseGate.assert(releaseProof);
            }
            return;
          }

          const encoded = { value: encodeVaultTransferPortChunk(chunk.bytes) };
          const acknowledgement = this.waitForExportAcknowledgement(
            state,
            transferId,
            chunk.sequence,
            generation,
          );
          try {
            producer.assertCurrent();
            const releaseProof = releaseLease && this.vaultReleaseGate
              ? await this.vaultReleaseGate.checkpoint(releaseLease)
              : undefined;
            if (!isCurrent(state, generation)) throw new VaultTransferPortProtocolError('cancelled');
            if (releaseProof && this.vaultReleaseGate) {
              this.vaultReleaseGate.assertAuthorities(releaseProof, () => producer.assertCurrent());
              this.vaultReleaseGate.assert(releaseProof);
            }
            post(port, {
              version: VAULT_TRANSFER_PORT_VERSION,
              type: 'export.chunk',
              transferId,
              format,
              phase: 'exporting',
              sequence: chunk.sequence,
              byteLength: chunk.bytes.byteLength,
              dataBase64: encoded.value,
            });
          } catch (error) {
            rejectPendingAcknowledgement(state, stableError('export_failed'));
            await acknowledgement.catch(() => undefined);
            throw error;
          } finally {
            clearEncodedReference(encoded);
          }

          await acknowledgement;
          if (!isCurrent(state, generation)) throw new VaultTransferPortProtocolError('cancelled');
          producer.acknowledge(chunk.sequence);
          chunkCount += 1;
        }
      });
      if (!isCurrent(state, generation)) return;
      if (
        result.transferId !== transferId
        || result.format !== format
        || result.totalBytes !== totalBytes
      ) {
        throw new VaultTransferPortProtocolError('export_failed');
      }
      if (!isCurrent(state, generation)) return;
      state.phase = 'completed';
      post(port, {
        version: VAULT_TRANSFER_PORT_VERSION,
        type: 'export.done',
        transferId,
        format,
        phase: 'completed',
        chunkCount,
        totalBytes,
        ...(clientEventAckId ? { clientEventAckId } : {}),
      });
    } catch (error) {
      await this.vaultReleaseGate?.settlePendingAction?.();
      if (isCurrent(state, generation)) {
        this.fail(port, state, error, onMessage, onDisconnect);
      }
    }
  }

  private waitForExportAcknowledgement(
    state: PortState,
    transferId: string,
    sequence: number,
    generation: number,
  ): Promise<void> {
    if (state.pendingExportAcknowledgement !== undefined) {
      throw new VaultTransferPortProtocolError('ack_required');
    }
    return new Promise<void>((resolve, reject) => {
      state.pendingExportAcknowledgement = {
        transferId,
        sequence,
        generation,
        resolve,
        reject,
      };
    });
  }

  private handleExportAcknowledgement(
    port: VaultTransferPortLike,
    state: PortState,
    message: VaultTransferExportAckMessage,
    onMessage: (message: unknown) => void,
    onDisconnect: () => void,
  ): void {
    const pending = state.pendingExportAcknowledgement;
    if (
      state.phase !== 'exporting'
      || !pending
      || pending.generation !== state.generation
      || pending.transferId !== message.transferId
      || pending.sequence !== message.sequence
    ) {
      this.fail(
        port,
        state,
        new VaultTransferPortProtocolError('invalid_sequence'),
        onMessage,
        onDisconnect,
      );
      return;
    }
    state.pendingExportAcknowledgement = undefined;
    pending.resolve();
  }

  private handleImportResultAcknowledgement(
    port: VaultTransferPortLike,
    state: PortState,
    message: VaultTransferImportResultAckMessage,
    onMessage: (message: unknown) => void,
    onDisconnect: () => void,
  ): void {
    if (state.phase !== 'awaiting_result_ack') {
      this.fail(
        port,
        state,
        new VaultTransferPortProtocolError('invalid_state'),
        onMessage,
        onDisconnect,
      );
      return;
    }
    if (
      state.transferId !== message.transferId
      || state.importResultAcknowledgementPending
    ) {
      this.fail(
        port,
        state,
        new VaultTransferPortProtocolError('invalid_sequence'),
        onMessage,
        onDisconnect,
      );
      return;
    }

    state.importResultAcknowledgementPending = true;
    const generation = state.generation;
    let acknowledgement: Promise<void>;
    try {
      acknowledgement = Promise.resolve(this.controller.acknowledgeImportResult(message.transferId));
    } catch (error) {
      this.fail(port, state, error, onMessage, onDisconnect);
      return;
    }
    void acknowledgement.then(
      () => {
        if (!isCurrent(state, generation)) return;
        state.importResultAcknowledgementPending = false;
        state.phase = 'completed';
        this.close(port, state, onMessage, onDisconnect);
        safeDisconnectPort(port);
      },
      (error: unknown) => {
        if (isCurrent(state, generation)) {
          this.fail(port, state, error, onMessage, onDisconnect);
        }
      },
    );
  }

  private fail(
    port: VaultTransferPortLike,
    state: PortState,
    error: unknown,
    onMessage: (message: unknown) => void,
    onDisconnect: () => void,
  ): void {
    if (!state.active) return;
    const code = errorCode(error);
    const transferId = state.transferId ?? null;
    const phase = state.phase;
    try {
      port.postMessage(createVaultTransferPortErrorMessage(code, transferId, wirePhase(phase)));
    } catch {
      // The Port is already unusable; teardown below remains authoritative.
    }
    this.close(port, state, onMessage, onDisconnect);
    safeDisconnectPort(port);
  }

  private close(
    port: VaultTransferPortLike,
    state: PortState,
    onMessage: (message: unknown) => void,
    onDisconnect: () => void,
  ): void {
    if (!state.active) return;
    state.active = false;
    state.generation += 1;
    state.ordinaryMessagePending = false;
    state.importResultAcknowledgementPending = false;
    rejectPendingAcknowledgement(state, stableError('cancelled'));
    removeListener(port.onMessage, onMessage);
    removeListener(port.onDisconnect, onDisconnect);
    this.disconnectController(state);
  }

  private disconnectController(state: PortState, lateTransferId?: string): void {
    if (state.controllerDisconnected) return;
    const transferId = lateTransferId ?? state.transferId;
    if (transferId === undefined) return;
    state.controllerDisconnected = true;
    try {
      Promise.resolve(this.controller.disconnect(transferId)).catch(() => undefined);
    } catch {
      // Teardown remains terminal even if a non-conforming adapter throws synchronously.
    }
  }
}

function matchesRecoveryClearExpectation(
  current: readonly { readonly transferId: string; readonly reason: string }[],
  expected: readonly { readonly transferId: string; readonly reason: string }[],
): boolean {
  if (current.length !== expected.length) return false;
  const ordered = [...current].sort((left, right) => (
    left.transferId < right.transferId ? -1 : left.transferId > right.transferId ? 1 : 0
  ));
  return ordered.every((barrier, index) => (
    barrier.transferId === expected[index]?.transferId
      && barrier.reason === expected[index]?.reason
  ));
}

function createRecoveryStatusMessage(
  inspection: Awaited<ReturnType<Controller['inspectReplayBarriers']>>,
): VaultTransferRecoveryStatusMessage {
  const message = parseVaultTransferWorkerMessage({
    version: VAULT_TRANSFER_PORT_VERSION,
    type: 'recovery.status',
    phase: 'completed',
    status: {
      count: inspection.count,
      unresolvedUnknownCount: inspection.unresolvedUnknownCount,
      reconcileRequiredCount: inspection.reconcileRequiredCount,
      omittedCount: inspection.omittedCount,
      barriers: inspection.barriers
        .slice(0, MAX_VAULT_TRANSFER_RECOVERY_BARRIERS + 1)
        .map((barrier) => ({
        transferId: barrier.transferId,
        reason: barrier.reason,
        reconciled: barrier.reconciled,
        clearable: barrier.clearable,
        })),
    },
  });
  if (message.type !== 'recovery.status') {
    throw new VaultTransferPortProtocolError('internal_error');
  }
  return message;
}

function sanitizePreview(
  preview: VaultTransferPreview,
  sourceFormat: VaultTransferSourceFormat,
): VaultTransferPortPreviewModel {
  return Object.freeze({
    format: sourceFormat,
    scope: preview.scope,
    phase: 'previewed',
    counts: Object.freeze({
      folders: preview.counts.folders,
      collections: preview.counts.collections,
      items: preview.counts.items,
      attachments: preview.counts.attachments,
    }),
    diagnostics: Object.freeze({
      errors: sanitizeDiagnosticGroup(preview.diagnostics.errors, 0),
      warnings: sanitizeDiagnosticGroup(
        preview.diagnostics.warnings,
        preview.diagnostics.omittedCount,
      ),
      unsupported: sanitizeDiagnosticGroup(preview.diagnostics.unsupported, 0),
    }),
    organizationTargetRequired: preview.organizationTargetRequired,
    hasUnknownOutcome: preview.hasUnknownOutcome,
    canCommit: preview.canCommit,
  });
}

function sanitizeDiagnosticGroup(
  diagnostics: readonly { readonly code: VaultTransferPreviewDiagnosticCode }[],
  omittedCount: number,
): readonly VaultTransferPortSanitizedDiagnostic[] {
  const counts = new Map<VaultTransferPortDiagnosticCode, number>();
  for (const diagnostic of diagnostics) {
    const code = DIAGNOSTIC_CODE_MAP[diagnostic.code] ?? 'other';
    counts.set(code, boundedDiagnosticCount((counts.get(code) ?? 0) + 1));
  }
  if (omittedCount > 0) {
    counts.set(
      'diagnostics_omitted',
      boundedDiagnosticCount((counts.get('diagnostics_omitted') ?? 0) + omittedCount),
    );
  }
  return Object.freeze(VAULT_TRANSFER_PORT_DIAGNOSTIC_CODES.flatMap((code) => {
    const count = counts.get(code);
    return count === undefined ? [] : [Object.freeze({ code, count })];
  }));
}

function boundedDiagnosticCount(value: number): number {
  if (!Number.isFinite(value) || value < 1) return 1;
  return Math.min(Math.floor(value), MAX_RESULT_COUNT);
}

function isTrustedOptionsPort(
  port: VaultTransferPortLike,
  extensionBaseUrl: string,
  extensionId: string,
): boolean {
  if (port.name !== VAULT_TRANSFER_PORT_NAME
    || typeof extensionId !== 'string'
    || extensionId.length === 0
    || port.sender?.id !== extensionId
    || typeof port.sender.url !== 'string') {
    return false;
  }
  let senderUrl: URL;
  let baseUrl: URL;
  try {
    senderUrl = new URL(port.sender.url);
    baseUrl = new URL(extensionBaseUrl);
  } catch {
    return false;
  }
  return senderUrl.protocol === baseUrl.protocol
    && senderUrl.host === baseUrl.host
    && senderUrl.username === ''
    && senderUrl.password === ''
    && baseUrl.username === ''
    && baseUrl.password === ''
    && senderUrl.pathname === OPTIONS_PAGE_PATH;
}

function requirePhase(state: PortState, phase: VaultTransferPortPhase): void {
  if (state.phase !== phase || state.transferId !== undefined) {
    throw new VaultTransferPortProtocolError('invalid_state');
  }
}

function requireMatchingTransfer(
  state: PortState,
  transferId: string,
  phase?: HandlerPhase,
): void {
  if (state.transferId !== transferId || (phase !== undefined && state.phase !== phase)) {
    throw new VaultTransferPortProtocolError('invalid_state');
  }
}

function errorCode(error: unknown): VaultTransferPortErrorCode {
  if (error instanceof VaultTransferPortProtocolError) return error.code;
  if (error instanceof VaultTransferControllerError) return controllerErrorCode(error.code);
  return 'internal_error';
}

function controllerErrorCode(code: VaultTransferControllerErrorCode): VaultTransferPortErrorCode {
  switch (code) {
    case 'capacity': return 'capacity';
    case 'not_found': return 'not_found';
    case 'expired': return 'expired';
    case 'lease_changed':
    case 'account_unavailable': return 'lease_changed';
    case 'invalid_state': return 'invalid_state';
    case 'invalid_sequence': return 'invalid_sequence';
    case 'ack_required': return 'ack_required';
    case 'invalid_chunk': return 'invalid_chunk';
    case 'chunk_too_large': return 'chunk_too_large';
    case 'too_many_chunks':
    case 'total_too_large':
    case 'resident_limit':
    case 'source_too_large':
    case 'input_too_large':
    case 'decrypted_input_too_large': return 'total_too_large';
    case 'size_mismatch': return 'size_mismatch';
    case 'preview_mismatch':
    case 'confirmation_mismatch': return 'preview_mismatch';
    case 'password_required': return 'password_required';
    case 'unexpected_password': return 'password_not_allowed';
    case 'preview_blocked':
    case 'invalid_request':
    case 'invalid_input':
    case 'empty_input':
    case 'invalid_utf8':
    case 'invalid_archive':
    case 'unsupported_encrypted_export':
    case 'decryption_failed': return 'inspection_failed';
    case 'commit_unavailable':
    case 'commit_failed':
    case 'commit_incomplete':
    case 'journal_failed': return 'commit_failed';
    case 'outcome_unknown': return 'outcome_unknown';
    case 'cancelled': return 'cancelled';
    case 'export_authorization_invalid': return 'export_authorization_invalid';
    case 'export_unavailable':
    case 'export_failed':
    case 'export_incomplete': return 'export_failed';
    case 'reconcile_unavailable':
    case 'reconcile_failed': return 'outcome_unknown';
    case 'digest_failed':
    case 'source_digest_mismatch':
    case 'deadline_exceeded': return 'internal_error';
  }
}

function isCurrent(state: PortState, generation: number): boolean {
  return state.active && state.generation === generation;
}

function wirePhase(phase: HandlerPhase): VaultTransferPortPhase {
  return phase === 'awaiting_result_ack' ? 'completed' : phase;
}

function post(port: VaultTransferPortLike, message: VaultTransferWorkerMessage): void {
  port.postMessage(message);
}

function rejectPendingAcknowledgement(state: PortState, error: Error): void {
  const pending = state.pendingExportAcknowledgement;
  state.pendingExportAcknowledgement = undefined;
  pending?.reject(error);
}

function stableError(code: VaultTransferPortErrorCode): VaultTransferPortProtocolError {
  return new VaultTransferPortProtocolError(code);
}

function assertExportProducerCurrent(producer: VaultTransferExportChunkProducer): void {
  try {
    producer.assertCurrent();
  } catch {
    throw stableError('export_failed');
  }
}

function encodedLength(byteLength: number): number {
  return Math.ceil(byteLength / 3) * 4;
}

function clearEncodedReference(encoded: { value: string }): void {
  encoded.value = '';
}

function removeListener<Listener>(
  event: VaultTransferPortEvent<Listener>,
  listener: Listener,
): void {
  try {
    event.removeListener?.(listener);
  } catch {
    // Listener teardown is best effort after trust-boundary shutdown.
  }
}

function safeDisconnectPort(port: VaultTransferPortLike): void {
  try {
    port.disconnect();
  } catch {
    // Already-disconnected ports need no further action.
  }
}
