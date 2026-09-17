/**
 * Deterministic avatar/tile styling for vault items. Blue and slate tones keep personal items
 * within the vault palette; initials provide identification without implying item risk or status.
 * A seed keeps each item stable. Pure — no globals, safe in any context.
 */

/** Muted blue and slate backgrounds with enough contrast for small white initials. */
const TILE_COLORS: readonly string[] = [
  '#315D8E',
  '#3B6389',
  '#456984',
  '#426282',
  '#536A80',
  '#365F95',
];

/** Stable non-cryptographic hash (djb2) → index into the palette. */
export function tileColor(seed: string): string {
  let hash = 5381;
  for (let i = 0; i < seed.length; i++) {
    hash = ((hash << 5) + hash + seed.charCodeAt(i)) >>> 0;
  }
  return TILE_COLORS[hash % TILE_COLORS.length]!;
}

/** First letter/number of a name, uppercased; falls back to a bullet for empty/symbol-only names. */
export function tileInitial(name: string): string {
  const match = name.match(/[\p{L}\p{N}]/u);
  return match ? match[0]!.toUpperCase() : '•';
}
