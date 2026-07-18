/**
 * Deterministic avatar/tile styling for vault items. The design uses hand-picked brand colors for
 * its demo data; real items get a stable color derived from a seed (item id or name) so the same
 * item always renders the same tile. Pure — no globals, safe in any context.
 */

/** A curated set of saturated tile backgrounds (white text sits on all of them at AA). */
const TILE_COLORS: readonly string[] = [
  '#0B6BC2', // blue
  '#0F7B4F', // green
  '#7C5CBF', // violet
  '#C2571A', // orange
  '#B4275E', // magenta
  '#3B6EA5', // steel
  '#946B00', // amber
  '#0B57D0', // Google blue
  '#5C5C5C', // graphite
  '#B23B3B', // red
  '#2E7D6B', // pine
  '#6D4AA6', // grape
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
