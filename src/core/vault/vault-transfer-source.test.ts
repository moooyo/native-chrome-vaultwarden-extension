import { beforeAll, describe, expect, it } from 'vitest';
import { zipSync, type Zippable } from 'fflate';
import { buildEncryptedExportJson } from './vault-io.js';
import {
  inspectVaultTransferSource,
  type VaultTransferSourceOk,
} from './vault-transfer-source.js';

const encoder = new TextEncoder();

function personalJson(items: unknown[] = []): string {
  return JSON.stringify({ encrypted: false, folders: [], items });
}

function bytes(value: string): Uint8Array {
  return encoder.encode(value);
}

function archive(
  entries: Record<string, Uint8Array>,
  level: 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 = 0,
): Uint8Array {
  const input = Object.create(null) as Zippable;
  for (const [path, data] of Object.entries(entries)) input[path] = data;
  return zipSync(input, { level, mtime: new Date('1980-01-02T00:00:00.000Z') });
}

function expectOk(result: Awaited<ReturnType<typeof inspectVaultTransferSource>>): VaultTransferSourceOk {
  expect(result.status).toBe('ok');
  if (result.status !== 'ok') throw new Error(`Expected ok, received ${result.status}`);
  return result;
}

describe('vault transfer source text inspection', () => {
  it('detects plaintext JSON and CSV from bytes without a caller-selected format', async () => {
    const json = expectOk(await inspectVaultTransferSource(bytes(personalJson([
      { type: 2, name: 'Runbook', secureNote: { type: 0 } },
    ]))));
    expect(json.format).toBe('json');
    expect(json.inspection.canCommit).toBe(true);
    expect(json.inspection.ir?.items[0]).toMatchObject({ kind: 'secureNote', name: 'Runbook' });
    expect(json).toMatchObject({ attachmentCount: 0, attachments: [], skippedAttachmentCount: 0 });

    const csv = expectOk(await inspectVaultTransferSource(bytes('name,type,login_username\nGitHub,login,octocat\n')));
    expect(csv.format).toBe('csv');
    expect(csv.inspection.canCommit).toBe(true);
    expect(csv.inspection.ir?.items[0]).toMatchObject({ kind: 'login', name: 'GitHub' });
  });

  it('keeps malformed JSON in the JSON inspector instead of reinterpreting it as CSV', async () => {
    const result = expectOk(await inspectVaultTransferSource(bytes('{"encrypted": false,')));
    expect(result.format).toBe('json');
    expect(result.inspection.canCommit).toBe(false);
    expect(result.inspection.diagnostics).toContainEqual(expect.objectContaining({ code: 'malformed_json' }));
  });

  it('classifies valid non-object JSON as JSON and lets the schema inspector reject it', async () => {
    const result = expectOk(await inspectVaultTransferSource(bytes('[]')));
    expect(result.format).toBe('json');
    expect(result.inspection.diagnostics).toContainEqual(expect.objectContaining({ code: 'invalid_json_root' }));
  });

  it('rejects malformed UTF-8 before JSON or CSV parsing', async () => {
    const result = await inspectVaultTransferSource(new Uint8Array([0x7b, 0x22, 0xff, 0x22, 0x7d]));
    expect(result).toEqual({ status: 'failed', code: 'invalid_utf8' });
  });

  it('returns only stable failures for invalid input and resource boundaries', async () => {
    await expect(inspectVaultTransferSource(null as unknown as Uint8Array)).resolves.toEqual({
      status: 'failed', code: 'invalid_input',
    });
    await expect(inspectVaultTransferSource(new Uint8Array())).resolves.toEqual({
      status: 'failed', code: 'empty_input',
    });
    await expect(inspectVaultTransferSource(bytes('abcd'), { limits: { maxSourceBytes: 3 } })).resolves.toEqual({
      status: 'failed', code: 'source_too_large',
    });
    await expect(inspectVaultTransferSource(bytes(personalJson()), { limits: { maxInputBytes: 1 } })).resolves.toEqual({
      status: 'failed', code: 'input_too_large',
    });
  });

  it('rejects invalid limit overrides as programmer errors', async () => {
    await expect(inspectVaultTransferSource(bytes(personalJson()), {
      limits: { maxSourceBytes: 0 },
    })).rejects.toThrow(RangeError);
    await expect(inspectVaultTransferSource(bytes(personalJson()), {
      limits: { archive: { maxCompressionRatio: Number.POSITIVE_INFINITY } },
    })).rejects.toThrow(RangeError);
  });
});

describe('vault transfer encrypted JSON inspection', () => {
  const password = 'correct horse';
  const plaintext = personalJson([{
    type: 2,
    name: 'Encrypted note',
    notes: 'x'.repeat(2_048),
    secureNote: { type: 0 },
  }]);
  let encrypted = '';

  beforeAll(async () => {
    encrypted = await buildEncryptedExportJson(
      plaintext,
      password,
      { kdf: 0, kdfIterations: 5_000 },
      {
        randomBytes: (length) => new Uint8Array(length).fill(0x42),
        newGuid: () => 'fixed-guid',
      },
    );
  });

  it('requests a password without retaining it or the encrypted source in the result', async () => {
    const result = await inspectVaultTransferSource(bytes(encrypted));
    expect(result).toEqual({ status: 'password_required', format: 'encrypted-json' });
    expect(JSON.stringify(result)).not.toContain(password);
    expect(JSON.stringify(result)).not.toContain('encKeyValidation_DO_NOT_EDIT');
  });

  it('decrypts with the existing Bitwarden export implementation and inspects the plaintext as JSON', async () => {
    const result = expectOk(await inspectVaultTransferSource(bytes(encrypted), { password }));
    expect(result.format).toBe('encrypted-json');
    expect(result.inspection.canCommit).toBe(true);
    expect(result.inspection.ir?.items[0]).toMatchObject({ name: 'Encrypted note', kind: 'secureNote' });
    expect(JSON.stringify(result)).not.toContain(password);
  });

  it('collapses wrong-password and malformed-envelope details to one stable failure', async () => {
    await expect(inspectVaultTransferSource(bytes(encrypted), { password: 'wrong' })).resolves.toEqual({
      status: 'failed', code: 'decryption_failed',
    });
    const malformed = bytes(JSON.stringify({
      encrypted: true,
      passwordProtected: true,
      salt: 'attacker-controlled-value',
      data: 'attacker-controlled-ciphertext',
    }));
    const result = await inspectVaultTransferSource(malformed, { password });
    expect(result).toEqual({ status: 'failed', code: 'decryption_failed' });
    expect(JSON.stringify(result)).not.toContain('attacker-controlled');
  });

  it('routes account-encrypted JSON only through the injected worker key boundary', async () => {
    const source = bytes(JSON.stringify({
      encrypted: true,
      encKeyValidation_DO_NOT_EDIT: '2.iv|ciphertext|mac',
      folders: [],
      items: [],
    }));
    await expect(inspectVaultTransferSource(source)).resolves.toEqual({
      status: 'failed', code: 'unsupported_encrypted_export',
    });

    const inspection = expectOk(await inspectVaultTransferSource(source, {
      inspectAccountEncrypted: async () => ({
        canCommit: true,
        ir: {
          version: 1,
          format: 'bitwarden-json',
          scope: 'personal',
          inputBytes: 1,
          folders: [],
          collections: [],
          items: [],
          folderRelationships: [],
          collectionRelationships: [],
          unknownFieldPaths: [],
        },
        diagnostics: [],
      }),
    }));
    expect(inspection.format).toBe('encrypted-json');
    expect(inspection.inspection.canCommit).toBe(true);
  });

  it('collapses account-key mismatch and authenticated-data damage to one stable failure', async () => {
    const source = bytes(JSON.stringify({
      encrypted: true,
      encKeyValidation_DO_NOT_EDIT: 'opaque',
      folders: [],
      items: [],
    }));
    await expect(inspectVaultTransferSource(source, {
      inspectAccountEncrypted: async () => null,
    })).resolves.toEqual({ status: 'failed', code: 'decryption_failed' });

    const revoked = new Error('authority revoked');
    await expect(inspectVaultTransferSource(source, {
      inspectAccountEncrypted: async () => { throw revoked; },
    })).rejects.toBe(revoked);
  });

  it('rejects a password supplied for a source that did not request one', async () => {
    await expect(inspectVaultTransferSource(bytes(personalJson()), { password })).resolves.toEqual({
      status: 'failed', code: 'unexpected_password',
    });
    await expect(inspectVaultTransferSource(bytes('name,type\nGitHub,login\n'), { password })).resolves.toEqual({
      status: 'failed', code: 'unexpected_password',
    });
  });

  it('applies maxInputBytes again after decryption instead of allowing the wrapper to bypass it', async () => {
    const encryptedBytes = bytes(encrypted);
    const result = await inspectVaultTransferSource(encryptedBytes, {
      password,
      limits: {
        maxSourceBytes: encryptedBytes.byteLength + 1,
        maxInputBytes: 128,
      },
    });
    expect(result).toEqual({ status: 'failed', code: 'decrypted_input_too_large' });
  });
});

describe('vault transfer ZIP inspection', () => {
  it('uses the ZIP signature and returns only archive-reader attachment mappings', async () => {
    const manifest = {
      format: 'miyu-vault-archive',
      version: 1,
      critical: ['format', 'version', 'attachments'],
      attachments: [{
        path: 'attachments/Item/mapped.txt',
        itemToken: 'manifest-item-token',
        attachmentId: 'manifest-attachment-id',
      }],
      skippedAttachments: [{
        itemToken: 'skipped-item-token',
        attachmentId: 'skipped-attachment-id',
        reason: 'Unavailable at export time',
      }],
    };
    const source = archive({
      'data.json': bytes(personalJson()),
      'miyu-manifest.json': bytes(JSON.stringify(manifest)),
      'attachments/Item/mapped.txt': bytes('mapped'),
      'attachments/PathLooksLikeItem/PathLooksLikeAttachment': bytes('unmapped'),
    });
    const original = source.slice();

    const result = expectOk(await inspectVaultTransferSource(source));
    expect(result.format).toBe('zip');
    expect(result.inspection.canCommit).toBe(true);
    expect(result.attachmentCount).toBe(2);
    expect(result.skippedAttachmentCount).toBe(1);
    expect(result.attachments).toEqual([
      {
        path: 'attachments/Item/mapped.txt',
        byteLength: 6,
        itemToken: 'manifest-item-token',
        attachmentId: 'manifest-attachment-id',
      },
      {
        path: 'attachments/PathLooksLikeItem/PathLooksLikeAttachment',
        byteLength: 8,
      },
    ]);
    expect(source).toEqual(original);
  });

  it('applies strict UTF-8 decoding to ZIP data.json after archive validation', async () => {
    const invalidDataJson = new Uint8Array([
      ...bytes('{"encrypted":false,"items":[],"value":"'),
      0xff,
      ...bytes('"}'),
    ]);
    const result = await inspectVaultTransferSource(archive({ 'data.json': invalidDataJson }));
    expect(result).toEqual({ status: 'failed', code: 'invalid_utf8' });
  });

  it('supports password-protected data.json while keeping ZIP as the outer format', async () => {
    const encrypted = await buildEncryptedExportJson(
      personalJson(),
      'zip-password',
      { kdf: 0, kdfIterations: 5_000 },
      {
        randomBytes: (length) => new Uint8Array(length).fill(0x24),
        newGuid: () => 'zip-guid',
      },
    );
    const source = archive({ 'data.json': bytes(encrypted) });

    await expect(inspectVaultTransferSource(source)).resolves.toEqual({
      status: 'password_required', format: 'zip',
    });
    const result = expectOk(await inspectVaultTransferSource(source, { password: 'zip-password' }));
    expect(result.format).toBe('zip');
    expect(result.inspection.canCommit).toBe(true);
  });

  it('rejects a password on an ordinary ZIP so callers must honor the password-required handshake', async () => {
    const source = archive({ 'data.json': bytes(personalJson()) });
    await expect(inspectVaultTransferSource(source, { password: 'stale-password' })).resolves.toEqual({
      status: 'failed', code: 'unexpected_password',
    });
  });

  it('does not let archive overrides raise the source-specific extraction budget', async () => {
    const compressed = archive({
      'data.json': bytes(personalJson()),
      'attachments/Item/repeated.txt': bytes('0123456789abcdef'.repeat(512)),
    }, 9);
    expect(compressed.byteLength).toBeLessThan(2_048);

    const result = await inspectVaultTransferSource(compressed, {
      limits: {
        maxSourceBytes: 2_048,
        archive: {
          maxTotalUncompressedBytes: 64 * 1024 * 1024,
          maxEntryUncompressedBytes: 64 * 1024 * 1024,
          maxCompressionRatio: 10_000,
        },
      },
    });
    expect(result).toEqual({ status: 'failed', code: 'invalid_archive' });
  });

  it('returns no hostile archive diagnostics or paths when ZIP validation fails', async () => {
    const invalid = archive({
      'data.json': bytes(personalJson()),
      '../attacker-controlled.txt': bytes('secret'),
    });
    const result = await inspectVaultTransferSource(invalid);
    expect(result).toEqual({ status: 'failed', code: 'invalid_archive' });
    expect(JSON.stringify(result)).not.toContain('attacker-controlled');

    await expect(inspectVaultTransferSource(new Uint8Array([0x50, 0x4b, 0x03, 0x04, 1, 2]))).resolves.toEqual({
      status: 'failed', code: 'invalid_archive',
    });
  });
});
