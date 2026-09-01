import type { KdfConfig } from '../crypto/kdf.js';
import type {
  MasterPasswordEvidence,
  MasterPasswordPolicy,
} from '../policy/master-password-policy.js';

import type { InteractiveTwoFactorOwner } from './interactive-two-factor.js';
import type { DuoProviderSeed } from './duo-two-factor.js';

export const PENDING_LOGIN_CONTINUATION_TTL_MS = 5 * 60_000;

export type PendingLoginContinuationStage = 'newDeviceVerification' | 'twoFactor';

export interface PendingLoginFido2Metadata {
  /** Canonical provider options JSON. Re-parse it to recreate the one-shot in-memory binding. */
  readonly connectorData: string;
  /** Fixed same-server connector URL; launch tab identity is deliberately not persisted. */
  readonly connectorUrl: string;
}

export interface PendingSsoLoginGrant {
  /** Public random binding to the outer browser SSO attempt; never authorizes a token exchange. */
  readonly ssoAttemptId: string;
  readonly ssoAttemptGeneration: number;
  /** One-time authorization code retained only while the Identity token grant is incomplete. */
  readonly code: string;
  readonly codeVerifier: string;
  readonly redirectUri: string;
  readonly identityUrl: string;
  readonly emailTwoFactorMode: 'vaultwarden-device' | 'bitwarden-session';
  /** Authentication factor for requesting an email 2FA code without a master password hash. */
  readonly emailTwoFactorSessionToken?: string;
}

/** Internal, secret-free proof that an outer SSO claim handed off to a resumable 2FA continuation. */
export interface PendingSsoHandoff {
  readonly attemptId: string;
  readonly attemptGeneration: number;
  readonly serverUrl: string;
  readonly identityUrl: string;
  readonly email: string;
}

export interface PendingLoginContinuationData {
  readonly stage: PendingLoginContinuationStage;
  readonly email: string;
  /** Exactly one grant is present. Both variants may exist only in storage.session. */
  readonly masterPasswordHash?: string;
  readonly sso?: PendingSsoLoginGrant;
  readonly kdf: KdfConfig;
  readonly providers: readonly number[];
  readonly twoFactorToken?: string;
  readonly fido2?: PendingLoginFido2Metadata;
  readonly duo?: readonly DuoProviderSeed[];
  /** Secret-free facts captured before the plaintext password leaves scope. */
  readonly passwordEvidence?: MasterPasswordEvidence;
  /** Monotonically combined Identity policy from every completed grant stage. */
  readonly masterPasswordPolicy?: MasterPasswordPolicy;
  /** Once observed, an administrative reset requirement can never be downgraded. */
  readonly forcePasswordReset?: true;
}

export interface PendingLoginContinuationOwner {
  readonly generation: number;
  readonly attemptId: string;
  readonly serverUrl: string;
  readonly email: string;
}

export interface ActivePendingLoginContinuation {
  readonly status: 'active';
  readonly owner: PendingLoginContinuationOwner;
  readonly createdAt: number;
  readonly expiresAt: number;
  readonly data?: PendingLoginContinuationData;
  /** Secret-free marker for a stage that also depends on an in-memory OTP/assertion. */
  readonly memoryOnly?: true;
}

export interface ClaimedPendingLoginContinuation {
  readonly status: 'claimed';
  readonly owner: PendingLoginContinuationOwner;
  readonly createdAt: number;
  readonly expiresAt: number;
  readonly claimedAt: number;
  readonly data?: PendingLoginContinuationData;
  readonly memoryOnly?: true;
}

export interface UnknownPendingLoginOutcome {
  readonly status: 'outcome_unknown';
  readonly owner: PendingLoginContinuationOwner;
  readonly createdAt: number;
  readonly expiresAt: number;
  readonly terminalAt: number;
}

export type PendingLoginContinuationSnapshot =
  | ActivePendingLoginContinuation
  | ClaimedPendingLoginContinuation
  | UnknownPendingLoginOutcome;

export interface PendingLoginContinuationStore {
  read(): Promise<PendingLoginContinuationSnapshot | undefined>;
  write(
    serverUrl: string,
    data: PendingLoginContinuationData,
  ): Promise<ActivePendingLoginContinuation>;
  claim(
    owner: PendingLoginContinuationOwner,
  ): Promise<ClaimedPendingLoginContinuation | undefined>;
  release(
    owner: PendingLoginContinuationOwner,
    data: PendingLoginContinuationData,
  ): Promise<ActivePendingLoginContinuation | undefined>;
  redact(
    owner: PendingLoginContinuationOwner,
  ): Promise<ActivePendingLoginContinuation | undefined>;
  releaseMarker(
    owner: PendingLoginContinuationOwner,
  ): Promise<ActivePendingLoginContinuation | undefined>;
  markOutcomeUnknown(
    owner: PendingLoginContinuationOwner,
  ): Promise<UnknownPendingLoginOutcome | undefined>;
  clear(owner: PendingLoginContinuationOwner): Promise<boolean>;
  /** Lifecycle cleanup for any generation descended from one stable random attempt. */
  clearAttempt(owner: PendingLoginContinuationOwner): Promise<boolean>;
}

export type PendingLoginPublicStatus =
  | { readonly status: 'none' }
  | {
      readonly status: 'newDeviceVerification';
      readonly attemptId: number;
      readonly continuationId: string;
      readonly expiresAt: number;
    }
  | {
      readonly status: 'twoFactor';
      readonly attemptId: number;
      readonly continuationId: string;
      readonly providers: readonly number[];
      readonly fido2?: { readonly owner: InteractiveTwoFactorOwner };
      readonly expiresAt: number;
    }
  | {
      readonly status: 'outcome_unknown';
      readonly serverOrigin: string;
      readonly email: string;
      readonly createdAt: number;
      readonly expiresAt: number;
      readonly terminalAt: number;
    };
