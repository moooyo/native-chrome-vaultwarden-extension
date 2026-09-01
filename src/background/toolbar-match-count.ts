import type { SessionState } from '../core/session/session-manager.js';

export interface ToolbarMatchContribution {
  readonly tabId: number;
  readonly url: string;
  readonly count: number;
}

export interface ToolbarMatchCountDeps {
  readonly hasHostAccess: (url: string) => Promise<boolean>;
  readonly countMatches: (
    url: string,
    bindFinalAuthority: (assertCurrent: () => void) => void,
  ) => Promise<number>;
  readonly publish: (contribution: ToolbarMatchContribution) => void | PromiseLike<void>;
  readonly forget?: (tabId: number) => void;
  readonly logger?: { warn(event: 'toolbar_match_count_failed'): void };
}

export interface ToolbarMatchTab {
  readonly id: number;
  readonly url: string;
}

/**
 * Produces count-only contributions for one browser-owned top-level URL. It never inspects document
 * fields or frames, and a missing host permission publishes an immediate zero instead of retaining
 * a count from a previous site.
 */
export class ToolbarMatchCountController {
  readonly #generations = new Map<number, number>();
  #epoch = 0;

  constructor(private readonly deps: ToolbarMatchCountDeps) {}

  async refresh(
    tab: ToolbarMatchTab,
    authState: SessionState,
    enabled: boolean,
  ): Promise<void> {
    const source = toolbarMatchSource(tab);
    const generation = (this.#generations.get(source.id) ?? 0) + 1;
    const epoch = this.#epoch;
    this.#generations.set(source.id, generation);
    const current = (): boolean => this.#epoch === epoch
      && this.#generations.get(source.id) === generation;
    const publish = async (count: number): Promise<void> => {
      if (!current()) return;
      await this.deps.publish(Object.freeze({ tabId: source.id, url: source.url, count }));
    };

    await publish(0);
    if (!current() || authState !== 'unlocked' || !enabled || !isHttpUrl(source.url)) return;

    try {
      const permitted = await this.deps.hasHostAccess(source.url);
      if (!current() || !permitted) return;
      let assertAuthority: (() => void) | undefined;
      const count = await this.deps.countMatches(source.url, (assertCurrent) => {
        assertAuthority = assertCurrent;
      });
      if (!current() || !assertAuthority || !validCount(count)) return;
      assertAuthority();
      await publish(count);
      if (current()) assertAuthority();
    } catch {
      if (current()) this.#report('toolbar_match_count_failed');
    }
  }

  revokeTab(tabId: number): void {
    if (!Number.isSafeInteger(tabId) || tabId < 0) return;
    this.#generations.set(tabId, (this.#generations.get(tabId) ?? 0) + 1);
    this.deps.forget?.(tabId);
  }

  revokeAll(): void {
    this.#epoch += 1;
    this.#generations.clear();
  }

  #report(event: 'toolbar_match_count_failed'): void {
    try { this.deps.logger?.warn(event); } catch { /* Diagnostics are best-effort. */ }
  }
}

function toolbarMatchSource(tab: ToolbarMatchTab): ToolbarMatchTab {
  if (!Number.isSafeInteger(tab?.id) || tab.id < 0) {
    throw new TypeError('Toolbar match source is invalid');
  }
  const url = typeof tab.url === 'string' && tab.url.length <= 16_384 ? tab.url : '';
  return Object.freeze({ id: tab.id, url });
}

function isHttpUrl(value: string): boolean {
  try {
    const url = new URL(value);
    return (url.protocol === 'https:' || url.protocol === 'http:')
      && !url.username && !url.password && url.href === value;
  } catch {
    return false;
  }
}

function validCount(value: unknown): value is number {
  return Number.isSafeInteger(value) && (value as number) >= 0;
}
