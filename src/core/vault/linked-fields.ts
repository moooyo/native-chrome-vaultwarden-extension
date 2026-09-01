import type { KnownCipherType } from './models.js';

export type LinkedFieldSource =
  | 'username'
  | 'password'
  | 'cardholderName'
  | 'number'
  | 'brand'
  | 'expMonth'
  | 'expYear'
  | 'code'
  | 'title'
  | 'firstName'
  | 'middleName'
  | 'fullName'
  | 'lastName'
  | 'company'
  | 'email'
  | 'phone'
  | 'address1'
  | 'address2'
  | 'address3'
  | 'city'
  | 'state'
  | 'postalCode'
  | 'country'
  | 'ssn'
  | 'passportNumber'
  | 'licenseNumber';

export interface LinkedFieldOption {
  readonly id: number;
  readonly source: LinkedFieldSource;
}

const LOGIN_LINKED_FIELDS: readonly LinkedFieldOption[] = Object.freeze([
  Object.freeze({ id: 100, source: 'username' }),
  Object.freeze({ id: 101, source: 'password' }),
]);

const CARD_LINKED_FIELDS: readonly LinkedFieldOption[] = Object.freeze([
  Object.freeze({ id: 300, source: 'cardholderName' }),
  Object.freeze({ id: 305, source: 'number' }),
  Object.freeze({ id: 304, source: 'brand' }),
  Object.freeze({ id: 301, source: 'expMonth' }),
  Object.freeze({ id: 302, source: 'expYear' }),
  Object.freeze({ id: 303, source: 'code' }),
]);

const IDENTITY_LINKED_FIELDS: readonly LinkedFieldOption[] = Object.freeze([
  Object.freeze({ id: 400, source: 'title' }),
  Object.freeze({ id: 416, source: 'firstName' }),
  Object.freeze({ id: 401, source: 'middleName' }),
  Object.freeze({ id: 418, source: 'fullName' }),
  Object.freeze({ id: 417, source: 'lastName' }),
  Object.freeze({ id: 413, source: 'username' }),
  Object.freeze({ id: 409, source: 'company' }),
  Object.freeze({ id: 412, source: 'ssn' }),
  Object.freeze({ id: 414, source: 'passportNumber' }),
  Object.freeze({ id: 415, source: 'licenseNumber' }),
  Object.freeze({ id: 410, source: 'email' }),
  Object.freeze({ id: 411, source: 'phone' }),
  Object.freeze({ id: 402, source: 'address1' }),
  Object.freeze({ id: 403, source: 'address2' }),
  Object.freeze({ id: 404, source: 'address3' }),
  Object.freeze({ id: 405, source: 'city' }),
  Object.freeze({ id: 406, source: 'state' }),
  Object.freeze({ id: 407, source: 'postalCode' }),
  Object.freeze({ id: 408, source: 'country' }),
]);

const NO_LINKED_FIELDS: readonly LinkedFieldOption[] = Object.freeze([]);

/** Official Bitwarden linked-field choices in the same order as its cipher editor. */
export function linkedFieldOptionsForCipherType(type: KnownCipherType): readonly LinkedFieldOption[] {
  if (type === 1) return LOGIN_LINKED_FIELDS;
  if (type === 3) return CARD_LINKED_FIELDS;
  if (type === 4) return IDENTITY_LINKED_FIELDS;
  return NO_LINKED_FIELDS;
}

export function isSupportedLinkedFieldId(type: KnownCipherType, value: unknown): value is number {
  return typeof value === 'number'
    && Number.isInteger(value)
    && linkedFieldOptionsForCipherType(type).some((option) => option.id === value);
}
