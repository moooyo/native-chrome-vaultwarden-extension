import { describe, expect, it, vi } from 'vitest';
import {
  DEFAULT_MAX_VAULT_TRANSFER_BYTES,
  DEFAULT_MAX_VAULT_TRANSFER_CHUNK_BYTES,
  DEFAULT_MAX_VAULT_TRANSFER_RESIDENT_BYTES,
  DEFAULT_MAX_VAULT_TRANSFER_SESSIONS,
  DEFAULT_VAULT_TRANSFER_SESSION_TTL_MS,
  MAX_VAULT_TRANSFER_BYTES,
  MAX_VAULT_TRANSFER_CHUNK_BYTES,
  MAX_VAULT_TRANSFER_CHUNKS,
  MAX_VAULT_TRANSFER_RESIDENT_BYTES,
  MAX_VAULT_TRANSFER_SESSIONS,
  MAX_VAULT_TRANSFER_SESSION_TTL_MS,
  VaultTransferSessionManager,
  type VaultTransferLeases,
} from './vault-transfer-session.js';

interface MutableLeaseState {
  account: number;
  session: number;
  enterprisePolicy: number;
}

interface FixtureOptions {
  readonly ttlMs?: number;
  readonly maxSessions?: number;
  readonly maxTotalBytes?: number;
  readonly maxChunkBytes?: number;
  readonly maxChunks?: number;
  readonly maxResidentBytes?: number;
  readonly inspectionDeadlineMs?: number;
  readonly confirmedAccessDeadlineMs?: number;
}

function createFixture(options: FixtureOptions = {}): {
  readonly manager: VaultTransferSessionManager<number, number, number>;
  readonly leases: MutableLeaseState;
  readonly setNow: (value: number) => void;
  readonly assertLeasesCurrent: ReturnType<typeof vi.fn>;
} {
  let now = 1_000;
  let nextId = 1;
  const leases: MutableLeaseState = { account: 1, session: 1, enterprisePolicy: 1 };
  const assertLeasesCurrent = vi.fn((captured: VaultTransferLeases<number, number, number>) => (
    captured.account === leases.account
    && captured.session === leases.session
    && captured.enterprisePolicy === leases.enterprisePolicy
  ));
  const manager = new VaultTransferSessionManager<number, number, number>({
    captureLeases: () => ({ ...leases }),
    assertLeasesCurrent,
    now: () => now,
    createId: () => `00000000-0000-4000-8000-${String(nextId++).padStart(12, '0')}`,
    ...(options.ttlMs === undefined ? {} : { ttlMs: options.ttlMs }),
    ...(options.maxSessions === undefined ? {} : { maxSessions: options.maxSessions }),
    ...(options.maxTotalBytes === undefined ? {} : { maxTotalBytes: options.maxTotalBytes }),
    ...(options.maxChunkBytes === undefined ? {} : { maxChunkBytes: options.maxChunkBytes }),
    ...(options.maxChunks === undefined ? {} : { maxChunks: options.maxChunks }),
    ...(options.maxResidentBytes === undefined ? {} : { maxResidentBytes: options.maxResidentBytes }),
    ...(options.inspectionDeadlineMs === undefined ? {} : { inspectionDeadlineMs: options.inspectionDeadlineMs }),
    ...(options.confirmedAccessDeadlineMs === undefined
      ? {}
      : { confirmedAccessDeadlineMs: options.confirmedAccessDeadlineMs }),
  });
  return {
    manager,
    leases,
    setNow(value: number) {
      now = value;
    },
    assertLeasesCurrent,
  };
}

async function uploadAndInspect(
  manager: VaultTransferSessionManager<number, number, number>,
  bytes = new Uint8Array([1, 2, 3, 4]),
): Promise<{ readonly transferId: string; readonly previewRevision: string }> {
  const begun = manager.begin({ direction: 'import', expectedTotalBytes: bytes.byteLength });
  const ack = manager.append(begun.transferId, 0, bytes);
  manager.acknowledge(begun.transferId, ack.sequence);
  await manager.seal(begun.transferId);
  const inspected = await manager.inspect(begun.transferId, () => ({ canCommit: true }));
  return {
    transferId: begun.transferId,
    previewRevision: inspected.previewRevision,
  };
}

describe('VaultTransferSessionManager', () => {
  it('runs upload, explicit ACK, seal, inspection, single-use confirmation, and completion', async () => {
    const { manager } = createFixture({ maxChunkBytes: 2, maxTotalBytes: 8 });
    const sourceA = new Uint8Array([1, 2]);
    const sourceB = new Uint8Array([3, 4]);
    const begun = manager.begin({ direction: 'import', expectedTotalBytes: 4 });

    const firstAck = manager.append(begun.transferId, 0, sourceA);
    expect(firstAck).toEqual({
      transferId: begun.transferId,
      sequence: 0,
      totalBytes: 2,
      requiresAcknowledgement: true,
    });
    manager.acknowledge(begun.transferId, 0);
    manager.append(begun.transferId, 1, sourceB);
    manager.acknowledge(begun.transferId, 1);

    sourceA.fill(9);
    sourceB.fill(9);
    const sealed = await manager.seal(begun.transferId);
    expect(sealed).toEqual({
      transferId: begun.transferId,
      sourceDigest: '9f64a747e1b97f131fabb6b447296c9b6f0201e79fb3c5356e6c77e89b6a806a',
      totalBytes: 4,
    });

    let scratch: Readonly<Uint8Array> | undefined;
    const inspected = await manager.inspect(begun.transferId, (input) => {
      scratch = input.bytes;
      expect(input).toMatchObject({
        direction: 'import',
        sourceDigest: sealed.sourceDigest,
        totalBytes: 4,
      });
      expect(Array.from(input.bytes)).toEqual([1, 2, 3, 4]);
      return { canCommit: true, itemCount: 1 };
    });
    expect(inspected.preview).toEqual({ canCommit: true, itemCount: 1 });
    expect(scratch).toBeDefined();
    expect(Array.from(scratch ?? [])).toEqual([0, 0, 0, 0]);
    expect(manager.status(begun.transferId)?.phase).toBe('previewed');

    const confirmed = manager.confirm(begun.transferId, inspected.previewRevision);
    expect(confirmed).not.toHaveProperty('bytes');
    expect(confirmed).not.toHaveProperty('leases');
    let confirmedScratch: Readonly<Uint8Array> | undefined;
    await expect(manager.withConfirmedBytes(
      begun.transferId,
      confirmed.confirmationId,
      (input) => {
        confirmedScratch = input.bytes;
        expect(Array.from(input.bytes)).toEqual([1, 2, 3, 4]);
        (input.bytes as Uint8Array)[0] = 99;
        return 'committed';
      },
    )).resolves.toBe('committed');
    expect(Array.from(confirmedScratch ?? [])).toEqual([0, 0, 0, 0]);
    expect(manager.status(begun.transferId)?.phase).toBe('confirmed');

    expect(manager.complete(begun.transferId, confirmed.confirmationId)).toEqual(sealed);
    expect(manager.status(begun.transferId)).toBeUndefined();
    expect(manager.residentBytes).toBe(0);
  });

  it('keeps the next chunk behind an explicit ACK and destroys plaintext on backpressure violation', () => {
    const { manager } = createFixture({ maxChunkBytes: 4, maxTotalBytes: 8 });
    const begun = manager.begin({ direction: 'import' });
    const source = new Uint8Array([7, 8]);

    manager.append(begun.transferId, 0, source);
    expect(() => manager.append(begun.transferId, 1, new Uint8Array([9]))).toThrowError(
      expect.objectContaining({ code: 'ack_required' }),
    );
    expect(manager.status(begun.transferId)).toBeUndefined();
    expect(Array.from(source)).toEqual([7, 8]);
  });

  it.each([
    ['skipped sequence', 2, 0],
    ['wrong ACK', 0, 1],
  ])('destroys a session on %s', (_name, appendSequence, ackSequence) => {
    const { manager } = createFixture();
    const begun = manager.begin({ direction: 'import' });

    if (appendSequence === 0) {
      manager.append(begun.transferId, appendSequence, new Uint8Array([1]));
      expect(() => manager.acknowledge(begun.transferId, ackSequence)).toThrowError(
        expect.objectContaining({ code: 'invalid_sequence' }),
      );
    } else {
      expect(() => manager.append(
        begun.transferId,
        appendSequence,
        new Uint8Array([1]),
      )).toThrowError(expect.objectContaining({ code: 'invalid_sequence' }));
    }
    expect(manager.status(begun.transferId)).toBeUndefined();
  });

  it('destroys a session when an acknowledged sequence is repeated', () => {
    const { manager } = createFixture();
    const begun = manager.begin({ direction: 'import' });
    manager.append(begun.transferId, 0, new Uint8Array([1]));
    manager.acknowledge(begun.transferId, 0);

    expect(() => manager.append(begun.transferId, 0, new Uint8Array([2]))).toThrowError(
      expect.objectContaining({ code: 'invalid_sequence' }),
    );
    expect(manager.status(begun.transferId)).toBeUndefined();
  });

  it('rejects a repeated ACK and a repeated seal without retaining the transfer', async () => {
    const first = createFixture().manager;
    const firstId = first.begin({ direction: 'import' }).transferId;
    first.append(firstId, 0, new Uint8Array([1]));
    first.acknowledge(firstId, 0);
    expect(() => first.acknowledge(firstId, 0)).toThrowError(
      expect.objectContaining({ code: 'invalid_sequence' }),
    );
    expect(first.status(firstId)).toBeUndefined();

    const second = createFixture().manager;
    const secondId = second.begin({ direction: 'export' }).transferId;
    await second.seal(secondId);
    await expect(second.seal(secondId)).rejects.toMatchObject({ code: 'invalid_state' });
    expect(second.status(secondId)).toBeUndefined();
  });

  it('enforces declared, per-chunk, and aggregate byte limits', async () => {
    const oversizedChunk = createFixture({ maxChunkBytes: 2, maxTotalBytes: 4 }).manager;
    const chunkId = oversizedChunk.begin({ direction: 'import' }).transferId;
    expect(() => oversizedChunk.append(chunkId, 0, new Uint8Array(3))).toThrowError(
      expect.objectContaining({ code: 'chunk_too_large' }),
    );
    expect(oversizedChunk.status(chunkId)).toBeUndefined();

    const aggregate = createFixture({ maxChunkBytes: 3, maxTotalBytes: 4 }).manager;
    const aggregateId = aggregate.begin({ direction: 'import' }).transferId;
    aggregate.append(aggregateId, 0, new Uint8Array(3));
    aggregate.acknowledge(aggregateId, 0);
    expect(() => aggregate.append(aggregateId, 1, new Uint8Array(2))).toThrowError(
      expect.objectContaining({ code: 'total_too_large' }),
    );
    expect(aggregate.status(aggregateId)).toBeUndefined();

    const declared = createFixture({ maxChunkBytes: 4, maxTotalBytes: 4 }).manager;
    const declaredId = declared.begin({ direction: 'import', expectedTotalBytes: 3 }).transferId;
    declared.append(declaredId, 0, new Uint8Array(2));
    declared.acknowledge(declaredId, 0);
    await expect(declared.seal(declaredId)).rejects.toMatchObject({ code: 'size_mismatch' });
    expect(declared.status(declaredId)).toBeUndefined();
  });

  it('caps one-byte chunks independently of the payload byte limit', () => {
    const { manager } = createFixture({
      maxTotalBytes: 16,
      maxChunkBytes: 16,
      maxChunks: 2,
    });
    const begun = manager.begin({ direction: 'import' });
    manager.append(begun.transferId, 0, new Uint8Array([1]));
    manager.acknowledge(begun.transferId, 0);
    manager.append(begun.transferId, 1, new Uint8Array([2]));
    manager.acknowledge(begun.transferId, 1);

    expect(() => manager.append(begun.transferId, 2, new Uint8Array([3]))).toThrowError(
      expect.objectContaining({ code: 'too_many_chunks' }),
    );
    expect(manager.status(begun.transferId)).toBeUndefined();
    expect(manager.residentBytes).toBe(0);
  });

  it('enforces one resident-memory budget across concurrent sessions', () => {
    const { manager } = createFixture({
      maxSessions: 3,
      maxTotalBytes: 4,
      maxChunkBytes: 4,
      maxResidentBytes: 8,
    });
    const first = manager.begin({ direction: 'import' });
    const second = manager.begin({ direction: 'import' });
    const third = manager.begin({ direction: 'import' });
    manager.append(first.transferId, 0, new Uint8Array(4));
    manager.acknowledge(first.transferId, 0);
    manager.append(second.transferId, 0, new Uint8Array(4));
    manager.acknowledge(second.transferId, 0);

    expect(() => manager.append(third.transferId, 0, new Uint8Array(1))).toThrowError(
      expect.objectContaining({ code: 'resident_limit' }),
    );
    expect(manager.status(first.transferId)?.totalBytes).toBe(4);
    expect(manager.status(second.transferId)?.totalBytes).toBe(4);
    expect(manager.status(third.transferId)).toBeUndefined();
    expect(manager.residentBytes).toBe(8);
    expect(manager.cancel(first.transferId)).toBe(true);
    expect(manager.cancel(second.transferId)).toBe(true);
    expect(manager.residentBytes).toBe(0);
  });

  it('accounts for duplicate residency while sealing and inspecting', async () => {
    const sealing = createFixture({
      maxSessions: 2,
      maxTotalBytes: 4,
      maxChunkBytes: 4,
      maxResidentBytes: 8,
    }).manager;
    const sealingId = sealing.begin({ direction: 'import' }).transferId;
    sealing.append(sealingId, 0, new Uint8Array(4));
    sealing.acknowledge(sealingId, 0);
    const sealingCompetitor = sealing.begin({ direction: 'import' }).transferId;
    sealing.append(sealingCompetitor, 0, new Uint8Array(1));
    sealing.acknowledge(sealingCompetitor, 0);
    await expect(sealing.seal(sealingId)).rejects.toMatchObject({ code: 'resident_limit' });
    expect(sealing.residentBytes).toBe(1);
    sealing.cancel(sealingCompetitor);
    expect(sealing.residentBytes).toBe(0);

    const inspecting = createFixture({
      maxSessions: 2,
      maxTotalBytes: 4,
      maxChunkBytes: 4,
      maxResidentBytes: 8,
    }).manager;
    const inspectingId = inspecting.begin({ direction: 'import' }).transferId;
    inspecting.append(inspectingId, 0, new Uint8Array(3));
    inspecting.acknowledge(inspectingId, 0);
    await inspecting.seal(inspectingId);
    const otherId = inspecting.begin({ direction: 'import' }).transferId;
    inspecting.append(otherId, 0, new Uint8Array(3));
    inspecting.acknowledge(otherId, 0);
    expect(inspecting.residentBytes).toBe(6);
    await expect(inspecting.inspect(inspectingId, () => ({ canCommit: true })))
      .rejects.toMatchObject({ code: 'resident_limit' });
    expect(inspecting.status(inspectingId)).toBeUndefined();
    expect(inspecting.residentBytes).toBe(3);
    inspecting.cancel(otherId);
    expect(inspecting.residentBytes).toBe(0);
  });

  it('supports an intentionally empty transfer while rejecting empty chunks', async () => {
    const { manager } = createFixture({ maxTotalBytes: 4 });
    const empty = manager.begin({ direction: 'export', expectedTotalBytes: 0 });
    const sealed = await manager.seal(empty.transferId);
    expect(sealed.totalBytes).toBe(0);

    const invalid = manager.begin({ direction: 'import' });
    expect(() => manager.append(invalid.transferId, 0, new Uint8Array())).toThrowError(
      expect.objectContaining({ code: 'invalid_chunk' }),
    );
    expect(manager.status(invalid.transferId)).toBeUndefined();
  });

  it('consumes the pending session before checking the preview revision', async () => {
    const { manager } = createFixture();
    const prepared = await uploadAndInspect(manager);

    expect(() => manager.confirm(
      prepared.transferId,
      'ffffffff-ffff-4fff-8fff-ffffffffffff',
    )).toThrowError(expect.objectContaining({ code: 'preview_mismatch' }));
    expect(manager.status(prepared.transferId)).toBeUndefined();
    expect(() => manager.confirm(prepared.transferId, prepared.previewRevision)).toThrowError(
      expect.objectContaining({ code: 'not_found' }),
    );
  });

  it('treats repeated confirmation as a fail-closed violation and zeroes confirmed plaintext', async () => {
    const { manager } = createFixture();
    const prepared = await uploadAndInspect(manager);
    const confirmed = manager.confirm(prepared.transferId, prepared.previewRevision);
    let release!: () => void;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    let entered!: () => void;
    const callbackEntered = new Promise<void>((resolve) => {
      entered = resolve;
    });
    let scratch: Readonly<Uint8Array> | undefined;
    const accessing = manager.withConfirmedBytes(
      prepared.transferId,
      confirmed.confirmationId,
      async (input) => {
        scratch = input.bytes;
        entered();
        await gate;
      },
    );
    await callbackEntered;

    expect(() => manager.confirm(prepared.transferId, prepared.previewRevision)).toThrowError(
      expect.objectContaining({ code: 'not_found' }),
    );
    expect(Array.from(scratch ?? [])).toEqual([0, 0, 0, 0]);
    release();
    await expect(accessing).rejects.toMatchObject({ code: 'not_found' });
    expect(manager.status(prepared.transferId)).toBeUndefined();
    expect(manager.residentBytes).toBe(0);
  });

  it.each(['account', 'session', 'enterprisePolicy'] as const)(
    'destroys pending plaintext when the %s lease changes',
    async (lease) => {
      const fixture = createFixture();
      const prepared = await uploadAndInspect(fixture.manager);
      fixture.leases[lease] += 1;

      expect(() => fixture.manager.status(prepared.transferId)).toThrowError(
        expect.objectContaining({ code: 'lease_changed' }),
      );
      expect(fixture.manager.status(prepared.transferId)).toBeUndefined();
    },
  );

  it('zeroes confirmed plaintext when a lease changes before a commit boundary', async () => {
    const fixture = createFixture();
    const prepared = await uploadAndInspect(fixture.manager);
    const confirmed = fixture.manager.confirm(prepared.transferId, prepared.previewRevision);
    fixture.leases.enterprisePolicy += 1;

    await expect(fixture.manager.withConfirmedBytes(
      prepared.transferId,
      confirmed.confirmationId,
      () => undefined,
    )).rejects.toMatchObject({ code: 'lease_changed' });
    expect(fixture.manager.status(prepared.transferId)).toBeUndefined();
    expect(fixture.manager.residentBytes).toBe(0);
  });

  it('accounts for confirmed callback scratch against the cross-session resident budget', async () => {
    const fixture = createFixture({
      maxSessions: 2,
      maxTotalBytes: 4,
      maxChunkBytes: 4,
      maxResidentBytes: 8,
    });
    const prepared = await uploadAndInspect(fixture.manager, new Uint8Array([1, 2, 3]));
    const confirmed = fixture.manager.confirm(prepared.transferId, prepared.previewRevision);
    const competitor = fixture.manager.begin({ direction: 'import' });
    fixture.manager.append(competitor.transferId, 0, new Uint8Array(3));
    fixture.manager.acknowledge(competitor.transferId, 0);
    const callback = vi.fn();

    await expect(fixture.manager.withConfirmedBytes(
      prepared.transferId,
      confirmed.confirmationId,
      callback,
    )).rejects.toMatchObject({ code: 'resident_limit' });
    expect(callback).not.toHaveBeenCalled();
    expect(fixture.manager.status(prepared.transferId)).toBeUndefined();
    expect(fixture.manager.residentBytes).toBe(3);
    fixture.manager.cancel(competitor.transferId);
    expect(fixture.manager.residentBytes).toBe(0);
  });

  it('uses a fixed TTL, sweeps pending and confirmed sessions, and zeroes confirmed bytes', async () => {
    const fixture = createFixture({ ttlMs: 10 });
    const pending = fixture.manager.begin({ direction: 'import' });
    fixture.setNow(1_009);
    expect(fixture.manager.status(pending.transferId)?.phase).toBe('uploading');
    fixture.setNow(1_010);
    expect(fixture.manager.sweepExpired()).toBe(1);
    expect(fixture.manager.status(pending.transferId)).toBeUndefined();

    fixture.setNow(2_000);
    const prepared = await uploadAndInspect(fixture.manager);
    const confirmed = fixture.manager.confirm(prepared.transferId, prepared.previewRevision);
    fixture.setNow(2_010);
    expect(fixture.manager.sweepExpired()).toBe(1);
    expect(confirmed).not.toHaveProperty('bytes');
    expect(fixture.manager.residentBytes).toBe(0);
  });

  it('enforces capacity but makes expired slots available to begin', () => {
    const fixture = createFixture({ maxSessions: 1, ttlMs: 10 });
    const first = fixture.manager.begin({ direction: 'import' });
    expect(() => fixture.manager.begin({ direction: 'export' })).toThrowError(
      expect.objectContaining({ code: 'capacity' }),
    );

    fixture.setNow(1_010);
    const replacement = fixture.manager.begin({ direction: 'export' });
    expect(replacement.transferId).not.toBe(first.transferId);
    expect(fixture.manager.status(first.transferId)).toBeUndefined();
  });

  it('evicts stale leases before applying capacity to a new account session', async () => {
    const fixture = createFixture({ maxSessions: 1 });
    const prepared = await uploadAndInspect(fixture.manager);
    const confirmed = fixture.manager.confirm(prepared.transferId, prepared.previewRevision);
    fixture.leases.account += 1;

    const replacement = fixture.manager.begin({ direction: 'import' });
    expect(replacement.transferId).not.toBe(prepared.transferId);
    expect(confirmed).not.toHaveProperty('bytes');
    expect(fixture.manager.residentBytes).toBe(0);
  });

  it('destroys the transfer and clears the scratch copy when inspection fails', async () => {
    const { manager } = createFixture();
    const begun = manager.begin({ direction: 'import' });
    manager.append(begun.transferId, 0, new Uint8Array([4, 5, 6]));
    manager.acknowledge(begun.transferId, 0);
    await manager.seal(begun.transferId);
    let scratch: Readonly<Uint8Array> | undefined;

    await expect(manager.inspect(begun.transferId, (input) => {
      scratch = input.bytes;
      throw new Error('inspection failed');
    })).rejects.toThrow('inspection failed');
    expect(Array.from(scratch ?? [])).toEqual([0, 0, 0]);
    expect(manager.status(begun.transferId)).toBeUndefined();
  });

  it('cancels an in-flight async inspection and clears both internal and scratch buffers', async () => {
    const { manager } = createFixture();
    const begun = manager.begin({ direction: 'import' });
    manager.append(begun.transferId, 0, new Uint8Array([8, 9]));
    manager.acknowledge(begun.transferId, 0);
    await manager.seal(begun.transferId);
    let release!: () => void;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    let entered!: () => void;
    const callbackEntered = new Promise<void>((resolve) => {
      entered = resolve;
    });
    let scratch: Readonly<Uint8Array> | undefined;
    const inspecting = manager.inspect(begun.transferId, async (input) => {
      scratch = input.bytes;
      entered();
      await gate;
      return { canCommit: true };
    });
    await callbackEntered;

    expect(manager.cancel(begun.transferId)).toBe(true);
    expect(Array.from(scratch ?? [])).toEqual([0, 0]);
    expect(manager.residentBytes).toBe(0);
    release();
    await expect(inspecting).rejects.toMatchObject({ code: 'not_found' });
    expect(Array.from(scratch ?? [])).toEqual([0, 0]);
  });

  it('times out a non-settling inspector and synchronously clears its retained scratch', async () => {
    const { manager } = createFixture({ inspectionDeadlineMs: 10 });
    const begun = manager.begin({ direction: 'import' });
    manager.append(begun.transferId, 0, new Uint8Array([5, 6]));
    manager.acknowledge(begun.transferId, 0);
    await manager.seal(begun.transferId);
    vi.useFakeTimers();
    try {
      let entered!: () => void;
      const callbackEntered = new Promise<void>((resolve) => {
        entered = resolve;
      });
      let scratch: Readonly<Uint8Array> | undefined;
      const inspecting = manager.inspect(begun.transferId, async (input) => {
        scratch = input.bytes;
        entered();
        await new Promise<void>(() => undefined);
        return { canCommit: true };
      });
      await callbackEntered;

      const rejection = expect(inspecting).rejects.toMatchObject({ code: 'deadline_exceeded' });
      await vi.advanceTimersByTimeAsync(10);
      await rejection;
      expect(Array.from(scratch ?? [])).toEqual([0, 0]);
      expect(manager.status(begun.transferId)).toBeUndefined();
      expect(manager.residentBytes).toBe(0);
    } finally {
      vi.useRealTimers();
    }
  });

  it('times out a non-settling confirmed callback and clears its scratch', async () => {
    const fixture = createFixture({ confirmedAccessDeadlineMs: 10 });
    const prepared = await uploadAndInspect(fixture.manager);
    const confirmed = fixture.manager.confirm(prepared.transferId, prepared.previewRevision);
    vi.useFakeTimers();
    try {
      let entered!: () => void;
      const callbackEntered = new Promise<void>((resolve) => {
        entered = resolve;
      });
      let scratch: Readonly<Uint8Array> | undefined;
      const accessing = fixture.manager.withConfirmedBytes(
        prepared.transferId,
        confirmed.confirmationId,
        async (input) => {
          scratch = input.bytes;
          entered();
          await new Promise<void>(() => undefined);
        },
      );
      await callbackEntered;

      const rejection = expect(accessing).rejects.toMatchObject({ code: 'deadline_exceeded' });
      await vi.advanceTimersByTimeAsync(10);
      await rejection;
      expect(Array.from(scratch ?? [])).toEqual([0, 0, 0, 0]);
      expect(fixture.manager.residentBytes).toBe(0);
    } finally {
      vi.useRealTimers();
    }
  });

  it('destroys confirmed plaintext on a wrong completion token and makes cancel idempotent', async () => {
    const { manager } = createFixture();
    const prepared = await uploadAndInspect(manager);
    manager.confirm(prepared.transferId, prepared.previewRevision);

    expect(() => manager.complete(
      prepared.transferId,
      'ffffffff-ffff-4fff-8fff-ffffffffffff',
    )).toThrowError(expect.objectContaining({ code: 'confirmation_mismatch' }));
    expect(manager.cancel(prepared.transferId)).toBe(false);
    expect(manager.residentBytes).toBe(0);
  });

  it('clears every pending and active callback buffer before account-level teardown returns', async () => {
    const { manager } = createFixture({ maxSessions: 3 });
    const prepared = await uploadAndInspect(manager);
    const confirmed = manager.confirm(prepared.transferId, prepared.previewRevision);
    const pending = manager.begin({ direction: 'export' });
    manager.append(pending.transferId, 0, new Uint8Array([8, 9]));
    let release!: () => void;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    let entered!: () => void;
    const callbackEntered = new Promise<void>((resolve) => {
      entered = resolve;
    });
    let scratch: Readonly<Uint8Array> | undefined;
    const accessing = manager.withConfirmedBytes(
      prepared.transferId,
      confirmed.confirmationId,
      async (input) => {
        scratch = input.bytes;
        entered();
        await gate;
      },
    );
    await callbackEntered;

    expect(manager.clearAll()).toBe(2);
    expect(Array.from(scratch ?? [])).toEqual([0, 0, 0, 0]);
    expect(manager.residentBytes).toBe(0);
    release();
    await expect(accessing).rejects.toMatchObject({ code: 'not_found' });
    expect(manager.status(prepared.transferId)).toBeUndefined();
    expect(manager.status(pending.transferId)).toBeUndefined();
    expect(manager.clearAll()).toBe(0);
  });

  it('revalidates leases at complete after the one-use callback settles', async () => {
    const fixture = createFixture();
    const prepared = await uploadAndInspect(fixture.manager);
    const confirmed = fixture.manager.confirm(prepared.transferId, prepared.previewRevision);
    await fixture.manager.withConfirmedBytes(
      prepared.transferId,
      confirmed.confirmationId,
      () => 'done',
    );
    fixture.leases.session += 1;

    expect(() => fixture.manager.complete(
      prepared.transferId,
      confirmed.confirmationId,
    )).toThrowError(expect.objectContaining({ code: 'lease_changed' }));
    expect(fixture.manager.status(prepared.transferId)).toBeUndefined();
    expect(fixture.manager.residentBytes).toBe(0);
  });

  it('revalidates the fixed TTL at complete after the callback settles', async () => {
    const fixture = createFixture({ ttlMs: 10 });
    const prepared = await uploadAndInspect(fixture.manager);
    const confirmed = fixture.manager.confirm(prepared.transferId, prepared.previewRevision);
    await fixture.manager.withConfirmedBytes(
      prepared.transferId,
      confirmed.confirmationId,
      () => undefined,
    );
    fixture.setNow(1_010);

    expect(() => fixture.manager.complete(
      prepared.transferId,
      confirmed.confirmationId,
    )).toThrowError(expect.objectContaining({ code: 'expired' }));
    expect(fixture.manager.residentBytes).toBe(0);
  });

  it('makes concurrent completion invalidate and clear an active confirmed callback', async () => {
    const { manager } = createFixture();
    const prepared = await uploadAndInspect(manager);
    const confirmed = manager.confirm(prepared.transferId, prepared.previewRevision);
    let release!: () => void;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    let entered!: () => void;
    const callbackEntered = new Promise<void>((resolve) => {
      entered = resolve;
    });
    let scratch: Readonly<Uint8Array> | undefined;
    const accessing = manager.withConfirmedBytes(
      prepared.transferId,
      confirmed.confirmationId,
      async (input) => {
        scratch = input.bytes;
        entered();
        await gate;
      },
    );
    await callbackEntered;

    expect(() => manager.complete(prepared.transferId, confirmed.confirmationId)).toThrowError(
      expect.objectContaining({ code: 'invalid_state' }),
    );
    expect(Array.from(scratch ?? [])).toEqual([0, 0, 0, 0]);
    expect(manager.residentBytes).toBe(0);
    release();
    await expect(accessing).rejects.toMatchObject({ code: 'not_found' });
  });

  it('validates configuration, declared sizes, IDs, clocks, and low total-byte defaults', () => {
    const defaults = createFixture().manager.begin({ direction: 'import' });
    expect(defaults).toMatchObject({
      maxChunkBytes: DEFAULT_MAX_VAULT_TRANSFER_CHUNK_BYTES,
      maxTotalBytes: DEFAULT_MAX_VAULT_TRANSFER_BYTES,
      maxChunks: 512,
    });

    const lowLimit = createFixture({ maxTotalBytes: 8 }).manager.begin({ direction: 'import' });
    expect(lowLimit.maxChunkBytes).toBe(8);

    expect(() => createFixture().manager.begin({
      direction: 'import',
      expectedTotalBytes: -1,
    })).toThrow(RangeError);
    expect(() => createFixture().manager.status('not-a-uuid')).toThrow(TypeError);
    expect(() => new VaultTransferSessionManager({
      captureLeases: () => ({ account: 1, session: 1, enterprisePolicy: 1 }),
      assertLeasesCurrent: () => true,
      now: () => -1,
    }).begin({ direction: 'import' })).toThrow(RangeError);

    const base = {
      captureLeases: () => ({ account: 1, session: 1, enterprisePolicy: 1 }),
      assertLeasesCurrent: () => true,
    };
    expect(() => new VaultTransferSessionManager({ ...base, ttlMs: 0 })).toThrow(RangeError);
    expect(() => new VaultTransferSessionManager({
      ...base,
      ttlMs: MAX_VAULT_TRANSFER_SESSION_TTL_MS + 1,
    })).toThrow(RangeError);
    expect(() => new VaultTransferSessionManager({ ...base, maxSessions: 0 })).toThrow(RangeError);
    expect(() => new VaultTransferSessionManager({
      ...base,
      maxSessions: MAX_VAULT_TRANSFER_SESSIONS + 1,
    })).toThrow(RangeError);
    expect(() => new VaultTransferSessionManager({
      ...base,
      maxTotalBytes: MAX_VAULT_TRANSFER_BYTES + 1,
    })).toThrow(RangeError);
    expect(() => new VaultTransferSessionManager({
      ...base,
      maxChunkBytes: MAX_VAULT_TRANSFER_CHUNK_BYTES + 1,
    })).toThrow(RangeError);
    expect(() => new VaultTransferSessionManager({
      ...base,
      maxTotalBytes: 8,
      maxChunkBytes: 2,
      maxChunks: 3,
    })).toThrow(RangeError);
    expect(() => new VaultTransferSessionManager({
      ...base,
      maxChunks: MAX_VAULT_TRANSFER_CHUNKS + 1,
    })).toThrow(RangeError);
    expect(() => new VaultTransferSessionManager({
      ...base,
      maxResidentBytes: MAX_VAULT_TRANSFER_RESIDENT_BYTES + 1,
    })).toThrow(RangeError);
    expect(() => new VaultTransferSessionManager({
      ...base,
      maxTotalBytes: 8,
      maxChunkBytes: 8,
      maxResidentBytes: 15,
    })).toThrow(RangeError);
    expect(() => new VaultTransferSessionManager({
      ...base,
      inspectionDeadlineMs: 0,
    })).toThrow(RangeError);
    expect(DEFAULT_VAULT_TRANSFER_SESSION_TTL_MS).toBeGreaterThan(0);
    expect(DEFAULT_MAX_VAULT_TRANSFER_SESSIONS).toBeGreaterThan(0);
    expect(DEFAULT_MAX_VAULT_TRANSFER_RESIDENT_BYTES).toBe(128 * 1024 * 1024);
  });

  it('fails begin when the captured lease is already stale or the ID generator is invalid', () => {
    const stale = new VaultTransferSessionManager({
      captureLeases: () => ({ account: 1, session: 1, enterprisePolicy: 1 }),
      assertLeasesCurrent: () => false,
    });
    expect(() => stale.begin({ direction: 'import' })).toThrowError(
      expect.objectContaining({ code: 'lease_changed' }),
    );

    const invalidId = new VaultTransferSessionManager({
      captureLeases: () => ({ account: 1, session: 1, enterprisePolicy: 1 }),
      assertLeasesCurrent: () => true,
      createId: () => 'predictable',
    });
    expect(() => invalidId.begin({ direction: 'import' })).toThrow(TypeError);
  });

  it('keeps transfer, preview, and confirmation capability identifiers distinct', async () => {
    const first = '00000000-0000-4000-8000-000000000001';
    const second = '00000000-0000-4000-8000-000000000002';
    const third = '00000000-0000-4000-8000-000000000003';
    const generated = [first, first, second, second, first, third];
    const manager = new VaultTransferSessionManager({
      captureLeases: () => ({ account: 1, session: 1, enterprisePolicy: 1 }),
      assertLeasesCurrent: () => true,
      createId: () => generated.shift() ?? third,
    });

    const begun = manager.begin({ direction: 'import', expectedTotalBytes: 0 });
    await manager.seal(begun.transferId);
    const inspected = await manager.inspect(begun.transferId, () => ({ canCommit: true }));
    const confirmed = manager.confirm(begun.transferId, inspected.previewRevision);

    expect(begun.transferId).toBe(first);
    expect(inspected.previewRevision).toBe(second);
    expect(confirmed.confirmationId).toBe(third);
  });
});
