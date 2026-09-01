import { describe, expect, it } from 'vitest';
import {
  ClientEventType,
  MAX_CLIENT_EVENT_BATCH_EVENTS,
  MAX_CLIENT_EVENT_BATCH_UTF8_BYTES,
  clientEventDateTimestamp,
  parseClientEvent,
  serializeClientEventBatch,
  toClientEventWire,
} from './client-event.js';

const DATE = '2026-08-31T10:20:30.123Z';
const CIPHER_ID = '11111111-1111-4111-8111-111111111111';
const ORGANIZATION_ID = '22222222-2222-4222-8222-222222222222';

describe('client event model', () => {
  it('pins the supported client-generated event types to the official wire values', () => {
    expect(ClientEventType).toEqual({
      User_ClientExportedVault: 1007,
      Cipher_ClientViewed: 1107,
      Cipher_ClientToggledPasswordVisible: 1108,
      Cipher_ClientToggledHiddenFieldVisible: 1109,
      Cipher_ClientToggledCardCodeVisible: 1110,
      Cipher_ClientCopiedPassword: 1111,
      Cipher_ClientCopiedHiddenField: 1112,
      Cipher_ClientCopiedCardCode: 1113,
      Cipher_ClientAutofilled: 1114,
      Cipher_ClientToggledCardNumberVisible: 1117,
      Cipher_ClientToggledTOTPSeedVisible: 1118,
      Organization_ClientExportedVault: 1602,
      Organization_ItemOrganization_Accepted: 1618,
      Organization_ItemOrganization_Declined: 1619,
    });
    expect(MAX_CLIENT_EVENT_BATCH_EVENTS).toBe(50);
    expect(MAX_CLIENT_EVENT_BATCH_UTF8_BYTES).toBe(32 * 1024);
  });

  it('enforces the field shape associated with each event family', () => {
    expect(parseClientEvent({ type: 1007, date: DATE })).toEqual({ type: 1007, date: DATE });
    expect(parseClientEvent({
      type: 1602,
      date: DATE,
      organizationId: ORGANIZATION_ID,
    })).toEqual({ type: 1602, date: DATE, organizationId: ORGANIZATION_ID });
    expect(parseClientEvent({
      type: 1618,
      date: DATE,
      organizationId: ORGANIZATION_ID,
    })).toEqual({ type: 1618, date: DATE, organizationId: ORGANIZATION_ID });
    expect(parseClientEvent({
      type: 1619,
      date: DATE,
      organizationId: ORGANIZATION_ID,
    })).toEqual({ type: 1619, date: DATE, organizationId: ORGANIZATION_ID });
    expect(parseClientEvent({
      type: 1114,
      date: DATE,
      cipherId: CIPHER_ID,
      organizationId: ORGANIZATION_ID,
    })).toEqual({
      type: 1114,
      date: DATE,
      cipherId: CIPHER_ID,
      organizationId: ORGANIZATION_ID,
    });
  });

  it.each([
    { type: 1100, date: DATE, cipherId: CIPHER_ID, organizationId: ORGANIZATION_ID },
    { type: 1007, date: DATE, organizationId: ORGANIZATION_ID },
    { type: 1602, date: DATE },
    { type: 1618, date: DATE, organizationId: ORGANIZATION_ID, cipherId: CIPHER_ID },
    { type: 1111, date: DATE, cipherId: CIPHER_ID },
    { type: 1111, date: DATE, cipherId: CIPHER_ID, organizationId: ORGANIZATION_ID, source: 'popup' },
    {
      type: 1111,
      date: DATE,
      cipherId: 'AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA',
      organizationId: ORGANIZATION_ID,
    },
    { type: 1111, date: '2026-08-31T10:20:30Z', cipherId: CIPHER_ID, organizationId: ORGANIZATION_ID },
  ])('rejects unsupported, incomplete, noncanonical, or trigger-bearing input %#', (input) => {
    expect(() => parseClientEvent(input)).toThrow(TypeError);
  });

  it('returns a frozen wire projection containing no queue or trigger metadata', () => {
    const input = {
      type: ClientEventType.Cipher_ClientViewed,
      date: DATE,
      cipherId: CIPHER_ID,
      organizationId: ORGANIZATION_ID,
    } as const;
    const wire = toClientEventWire(input);

    expect(Object.isFrozen(wire)).toBe(true);
    expect(Object.keys(wire)).toEqual(['type', 'date', 'cipherId', 'organizationId']);
    expect(JSON.parse(serializeClientEventBatch([wire]))).toEqual([input]);
  });

  it('accepts only a nonempty dense batch of at most 50 events', () => {
    const event = { type: ClientEventType.User_ClientExportedVault, date: DATE } as const;
    expect(() => serializeClientEventBatch([])).toThrow(RangeError);
    expect(() => serializeClientEventBatch(
      Array.from({ length: MAX_CLIENT_EVENT_BATCH_EVENTS + 1 }, () => event),
    )).toThrow(RangeError);

    const sparse = new Array(1) as unknown[];
    expect(() => serializeClientEventBatch(sparse)).toThrow(TypeError);
    expect(JSON.parse(serializeClientEventBatch(
      Array.from({ length: MAX_CLIENT_EVENT_BATCH_EVENTS }, () => event),
    ))).toHaveLength(MAX_CLIENT_EVENT_BATCH_EVENTS);
  });

  it('parses only canonical millisecond ISO dates', () => {
    expect(clientEventDateTimestamp(DATE)).toBe(Date.parse(DATE));
    expect(() => clientEventDateTimestamp('2026-02-30T00:00:00.000Z')).toThrow(TypeError);
  });
});
