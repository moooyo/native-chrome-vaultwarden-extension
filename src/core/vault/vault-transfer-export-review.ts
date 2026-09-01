export const VAULT_TRANSFER_EXPORT_WARNING_CODES = Object.freeze([
  'card_items_omitted',
  'identity_items_omitted',
  'ssh_key_items_omitted',
  'new_item_types_omitted',
  'other_items_omitted',
  'attachments_omitted',
  'passkeys_omitted',
  'password_history_omitted',
  'fields_flattened',
  'login_metadata_omitted',
  'secure_note_metadata_omitted',
  'unknown_data_omitted',
  'diagnostics_omitted',
] as const);

export type VaultTransferExportWarningCode =
  (typeof VAULT_TRANSFER_EXPORT_WARNING_CODES)[number];

/** Bounded, value-free disclosure that is safe to send to an unprivileged download surface. */
export interface VaultTransferExportWarning {
  readonly code: VaultTransferExportWarningCode;
  readonly count: number;
}

export interface VaultTransferExportReview {
  readonly exportedItemCount: number;
  readonly omittedItemCount: number;
  readonly warnings: readonly VaultTransferExportWarning[];
}
