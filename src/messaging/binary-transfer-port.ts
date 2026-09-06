import type { SendInput } from '../core/vault/sends.js';
import { decodeVaultTransferPortChunk, encodeVaultTransferPortChunk } from './vault-transfer-port.js';

export const BINARY_TRANSFER_PORT_NAME = 'vault-binary-v1';
export const BINARY_TRANSFER_PORT_VERSION = 1 as const;
export const MAX_BINARY_TRANSFER_CHUNK_BYTES = 256 * 1024;
export const MAX_BINARY_TRANSFER_BYTES = 128 * 1024 * 1024;
export const MAX_SEND_FILE_BYTES = 100 * 1024 * 1024;
export const MAX_ATTACHMENT_FILE_BYTES = MAX_BINARY_TRANSFER_BYTES - 65;
export const BINARY_TRANSFER_TIMEOUT_MS = 30_000;
export const BINARY_TRANSFER_TTL_MS = 10 * 60_000;

export type BinaryTransferRequest =
  | { type: 'sends.createFile'; input: SendInput; fileName: string; expectedBytes: number }
  | { type: 'vault.addAttachment'; cipherId: string; fileName: string; expectedBytes: number; masterPassword?: string }
  | { type: 'vault.getAttachment'; cipherId: string; attachmentId: string; masterPassword?: string };

type Envelope = { readonly version: 1 };
type Chunk = { readonly type: 'chunk'; readonly sequence: number; readonly byteLength: number; readonly dataBase64: string };
export type BinaryTransferClientMessage = Envelope & (
  | { readonly type: 'begin'; readonly request: BinaryTransferRequest }
  | Chunk
  | { readonly type: 'seal' | 'cancel' }
  | { readonly type: 'ack'; readonly sequence: number }
);
export type BinaryTransferWorkerMessage = Envelope & (
  | { readonly type: 'ready' }
  | { readonly type: 'ack'; readonly sequence: number }
  | { readonly type: 'result'; readonly data: unknown }
  | { readonly type: 'download'; readonly fileName: string; readonly totalBytes: number }
  | Chunk
  | { readonly type: 'done'; readonly chunkCount: number; readonly totalBytes: number }
  | { readonly type: 'error'; readonly error: { readonly code: string; readonly message: string } }
);

export class BinaryTransferError extends Error {
  constructor(readonly code: string, message = 'The file transfer could not be completed.') {
    super(message);
    this.name = 'BinaryTransferError';
  }
}

export const encodeBinaryTransferChunk = encodeVaultTransferPortChunk;
export const decodeBinaryTransferChunk = decodeVaultTransferPortChunk;

export function parseBinaryTransferClientMessage(value: unknown): BinaryTransferClientMessage {
  const message = envelope(value);
  switch (message.type) {
    case 'begin':
      keys(message, ['version', 'type', 'request']);
      return { version: 1, type: 'begin', request: parseRequest(message.request) };
    case 'chunk': return parseChunk(message);
    case 'seal': case 'cancel':
      keys(message, ['version', 'type']);
      return { version: 1, type: message.type };
    case 'ack':
      keys(message, ['version', 'type', 'sequence']);
      return { version: 1, type: 'ack', sequence: integer(message.sequence, MAX_BINARY_TRANSFER_BYTES) };
    default: return invalid();
  }
}

export function parseBinaryTransferWorkerMessage(value: unknown): BinaryTransferWorkerMessage {
  const message = envelope(value);
  switch (message.type) {
    case 'ready':
      keys(message, ['version', 'type']);
      return { version: 1, type: 'ready' };
    case 'ack':
      keys(message, ['version', 'type', 'sequence']);
      return { version: 1, type: 'ack', sequence: integer(message.sequence, MAX_BINARY_TRANSFER_BYTES) };
    case 'chunk': return parseChunk(message);
    case 'download':
      keys(message, ['version', 'type', 'fileName', 'totalBytes']);
      return { version: 1, type: 'download', fileName: string(message.fileName, 1_024), totalBytes: integer(message.totalBytes, MAX_BINARY_TRANSFER_BYTES) };
    case 'done':
      keys(message, ['version', 'type', 'chunkCount', 'totalBytes']);
      return { version: 1, type: 'done', chunkCount: integer(message.chunkCount, MAX_BINARY_TRANSFER_BYTES), totalBytes: integer(message.totalBytes, MAX_BINARY_TRANSFER_BYTES) };
    case 'result':
      keys(message, ['version', 'type', 'data']);
      return { version: 1, type: 'result', data: message.data };
    case 'error': {
      keys(message, ['version', 'type', 'error']);
      const error = record(message.error);
      keys(error, ['code', 'message']);
      return { version: 1, type: 'error', error: { code: string(error.code, 128), message: string(error.message, 1_024) } };
    }
    default: return invalid();
  }
}

function parseRequest(value: unknown): BinaryTransferRequest {
  const request = record(value);
  if (request.type === 'sends.createFile') {
    keys(request, ['type', 'input', 'fileName', 'expectedBytes']);
    return { type: request.type, input: parseSendInput(request.input), fileName: string(request.fileName, 255), expectedBytes: integer(request.expectedBytes, MAX_SEND_FILE_BYTES) };
  }
  if (request.type === 'vault.addAttachment') {
    keys(request, ['type', 'cipherId', 'fileName', 'expectedBytes'], ['masterPassword']);
    return { type: request.type, cipherId: string(request.cipherId, 1_024), fileName: string(request.fileName, 255), expectedBytes: integer(request.expectedBytes, MAX_ATTACHMENT_FILE_BYTES), ...password(request) };
  }
  if (request.type === 'vault.getAttachment') {
    keys(request, ['type', 'cipherId', 'attachmentId'], ['masterPassword']);
    return { type: request.type, cipherId: string(request.cipherId, 1_024), attachmentId: string(request.attachmentId, 1_024), ...password(request) };
  }
  return invalid();
}

function parseSendInput(value: unknown): SendInput {
  const input = record(value);
  keys(input, ['name'], ['notes', 'text', 'hidden', 'hideEmail', 'password', 'maxAccessCount', 'expirationHours', 'expirationDays', 'deletionHours', 'deletionDays']);
  const parsed: Record<string, unknown> = { name: string(input.name, 1_024) };
  for (const key of ['notes', 'text', 'password']) {
    if (Object.hasOwn(input, key)) parsed[key] = string(input[key], 16_384, true);
  }
  for (const key of ['hidden', 'hideEmail']) {
    if (Object.hasOwn(input, key)) {
      if (typeof input[key] !== 'boolean') invalid();
      parsed[key] = input[key];
    }
  }
  for (const key of ['maxAccessCount', 'expirationHours', 'expirationDays', 'deletionHours', 'deletionDays']) {
    if (Object.hasOwn(input, key)) {
      if (typeof input[key] !== 'number' || !Number.isFinite(input[key]) || input[key] < 0) invalid();
      parsed[key] = input[key];
    }
  }
  return parsed as unknown as SendInput;
}

function password(request: Record<string, unknown>): { masterPassword?: string } {
  return Object.hasOwn(request, 'masterPassword') ? { masterPassword: string(request.masterPassword, 1_024, true) } : {};
}

function parseChunk(message: Record<string, unknown>): Envelope & Chunk {
  keys(message, ['version', 'type', 'sequence', 'byteLength', 'dataBase64']);
  const byteLength = integer(message.byteLength, MAX_BINARY_TRANSFER_CHUNK_BYTES);
  if (byteLength === 0) invalid();
  const dataBase64 = string(message.dataBase64, Math.ceil(MAX_BINARY_TRANSFER_CHUNK_BYTES / 3) * 4);
  const decoded = decodeBinaryTransferChunk(dataBase64, byteLength);
  decoded.fill(0);
  return { version: 1, type: 'chunk', sequence: integer(message.sequence, MAX_BINARY_TRANSFER_BYTES), byteLength, dataBase64 };
}

function envelope(value: unknown): Record<string, unknown> {
  const message = record(value);
  if (message.version !== 1) invalid();
  return message;
}

function record(value: unknown): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) invalid();
  for (const key of Reflect.ownKeys(value)) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (typeof key !== 'string' || !descriptor?.enumerable || !('value' in descriptor)) invalid();
  }
  return value as Record<string, unknown>;
}

function keys(value: Record<string, unknown>, required: readonly string[], optional: readonly string[] = []): void {
  if (required.some((key) => !Object.hasOwn(value, key)) || Object.keys(value).some((key) => !required.includes(key) && !optional.includes(key))) invalid();
}

function string(value: unknown, limit: number, allowEmpty = false): string {
  if (typeof value !== 'string' || value.length > limit || (!allowEmpty && value.length === 0)) invalid();
  return value;
}

function integer(value: unknown, maximum: number): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0 || (value as number) > maximum) invalid();
  return value as number;
}

function invalid(): never {
  throw new BinaryTransferError('invalid_message', 'The file transfer message is invalid.');
}
