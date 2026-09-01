import { AppError } from '../core/errors.js';
import { websitePasskeyOriginMatchPattern } from './website-passkey-browser.js';

const PERMISSION_ERROR_MESSAGE = 'Website passkey host permission is unavailable.';

export interface WebsitePasskeyPermissionLease {
  readonly generation: number;
  readonly originPattern: string;
}

export interface WebsitePasskeyPermissionGateDeps {
  readonly permissions: {
    contains(details: { readonly origins: readonly [string] }): PromiseLike<boolean>;
  };
}

/** Revocable proof that Chrome still grants host access to one browser-authoritative origin. */
export class WebsitePasskeyPermissionGate {
  readonly #issued = new WeakSet<object>();
  readonly #permissions: WebsitePasskeyPermissionGateDeps['permissions'];
  #generation = 0;

  constructor(deps: WebsitePasskeyPermissionGateDeps) {
    this.#permissions = deps.permissions;
  }

  async capture(browserUrl: string): Promise<WebsitePasskeyPermissionLease> {
    const generation = this.#generation;
    if (
      typeof browserUrl !== 'string'
      || browserUrl.length === 0
      || browserUrl.trim() !== browserUrl
      || containsControlCharacter(browserUrl)
    ) throw permissionError();
    const originPattern = websitePasskeyOriginMatchPattern(browserUrl);
    if (!originPattern) throw permissionError();

    let granted: boolean;
    try {
      granted = await this.#permissions.contains({ origins: [originPattern] });
    } catch {
      throw permissionError();
    }
    if (granted !== true || generation !== this.#generation) throw permissionError();

    const lease = Object.freeze({ generation, originPattern });
    this.#issued.add(lease);
    return lease;
  }

  assert(lease: WebsitePasskeyPermissionLease): void {
    if (
      typeof lease !== 'object'
      || lease === null
      || !this.#issued.has(lease)
      || lease.generation !== this.#generation
      || websitePasskeyOriginMatchPattern(lease.originPattern) !== lease.originPattern
    ) {
      throw permissionError();
    }
  }

  /** Revoke every issued proof after either a permissions.onAdded or permissions.onRemoved event. */
  invalidate(): void {
    this.#generation += 1;
  }
}

function permissionError(): AppError {
  return new AppError('denied', PERMISSION_ERROR_MESSAGE);
}

function containsControlCharacter(value: string): boolean {
  return [...value].some((character) => {
    const codePoint = character.codePointAt(0) ?? 0;
    return codePoint <= 31 || codePoint === 127;
  });
}
