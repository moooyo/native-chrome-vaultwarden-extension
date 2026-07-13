/*
 * Generates the extension icon set (16/32/48/128) with no external dependencies.
 *
 * The mark is the Warden shield: an indigo gradient rounded square with a white
 * shield and an indigo check. Each size is rendered at 4× and box-downsampled for
 * clean anti-aliased edges, so the toolbar icon stays crisp on HiDPI displays
 * where Chrome reaches for the 32px asset. Re-run with `node tools/gen-icons.mjs`.
 */
import { deflateSync } from 'node:zlib';
import { writeFileSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';

const OUT = 'src/icons';
const SIZES = [16, 32, 48, 128];
const SS = 4; // supersampling factor

// Colors (sRGB)
const BG_TOP = [79, 70, 229];
const BG_BOT = [67, 56, 202];
const WHITE = [255, 255, 255];
const CHECK = [67, 56, 202];

const SHIELD = [
  [0.5, 0.2], [0.72, 0.27], [0.72, 0.5], [0.66, 0.66],
  [0.5, 0.8], [0.34, 0.66], [0.28, 0.5], [0.28, 0.27],
];
const CHECK_PTS = [[0.42, 0.5], [0.48, 0.57], [0.6, 0.43]];
const CHECK_HALF = 0.028;

function lerp(a, b, t) { return a + (b - a) * t; }

function pointInPolygon(x, y, poly) {
  let inside = false;
  for (let i = 0, j = poly.length - 1; i < poly.length; j = i++) {
    const [xi, yi] = poly[i];
    const [xj, yj] = poly[j];
    if ((yi > y) !== (yj > y) && x < ((xj - xi) * (y - yi)) / (yj - yi) + xi) inside = !inside;
  }
  return inside;
}

function distToSegments(x, y, pts) {
  let min = Infinity;
  for (let i = 0; i < pts.length - 1; i++) {
    const [ax, ay] = pts[i];
    const [bx, by] = pts[i + 1];
    const dx = bx - ax, dy = by - ay;
    const len2 = dx * dx + dy * dy || 1e-9;
    let t = ((x - ax) * dx + (y - ay) * dy) / len2;
    t = Math.max(0, Math.min(1, t));
    const px = ax + t * dx, py = ay + t * dy;
    min = Math.min(min, Math.hypot(x - px, y - py));
  }
  return min;
}

/** Inside a rounded square with corner radius r (all in 0..1 space). */
function inRoundedSquare(x, y, r) {
  const cx = Math.min(Math.max(x, r), 1 - r);
  const cy = Math.min(Math.max(y, r), 1 - r);
  return Math.hypot(x - cx, y - cy) <= r;
}

/** Color of one sub-sample at normalized (x,y); returns [r,g,b,a] 0..255. */
function sample(x, y) {
  if (!inRoundedSquare(x, y, 0.22)) return [0, 0, 0, 0];
  const bg = [
    Math.round(lerp(BG_TOP[0], BG_BOT[0], y)),
    Math.round(lerp(BG_TOP[1], BG_BOT[1], y)),
    Math.round(lerp(BG_TOP[2], BG_BOT[2], y)),
  ];
  if (distToSegments(x, y, CHECK_PTS) <= CHECK_HALF && pointInPolygon(x, y, SHIELD)) {
    return [...CHECK, 255];
  }
  if (pointInPolygon(x, y, SHIELD)) return [...WHITE, 255];
  return [...bg, 255];
}

function renderRGBA(size) {
  const buf = Buffer.alloc(size * size * 4);
  for (let py = 0; py < size; py++) {
    for (let px = 0; px < size; px++) {
      let r = 0, g = 0, b = 0, a = 0;
      for (let sy = 0; sy < SS; sy++) {
        for (let sx = 0; sx < SS; sx++) {
          const nx = (px + (sx + 0.5) / SS) / size;
          const ny = (py + (sy + 0.5) / SS) / size;
          const [sr, sg, sb, sa] = sample(nx, ny);
          // premultiply for correct edge blending
          r += sr * sa; g += sg * sa; b += sb * sa; a += sa;
        }
      }
      const n = SS * SS;
      const alpha = a / n;
      const i = (py * size + px) * 4;
      if (alpha === 0) { buf[i] = buf[i + 1] = buf[i + 2] = buf[i + 3] = 0; continue; }
      buf[i] = Math.round(r / a);
      buf[i + 1] = Math.round(g / a);
      buf[i + 2] = Math.round(b / a);
      buf[i + 3] = Math.round(alpha);
    }
  }
  return buf;
}

// ---- minimal PNG encoder ----
const CRC_TABLE = (() => {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[n] = c >>> 0;
  }
  return t;
})();

function crc32(buf) {
  let c = 0xffffffff;
  for (let i = 0; i < buf.length; i++) c = CRC_TABLE[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

function chunk(type, data) {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length, 0);
  const typeBuf = Buffer.from(type, 'ascii');
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(Buffer.concat([typeBuf, data])), 0);
  return Buffer.concat([len, typeBuf, data, crc]);
}

function encodePNG(rgba, size) {
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(size, 0);
  ihdr.writeUInt32BE(size, 4);
  ihdr[8] = 8;  // bit depth
  ihdr[9] = 6;  // color type RGBA
  // 10,11,12 = 0 (deflate, no filter on header, no interlace)

  const stride = size * 4;
  const raw = Buffer.alloc((stride + 1) * size);
  for (let y = 0; y < size; y++) {
    raw[y * (stride + 1)] = 0; // filter type 0
    rgba.copy(raw, y * (stride + 1) + 1, y * stride, y * stride + stride);
  }
  const idat = deflateSync(raw, { level: 9 });

  return Buffer.concat([
    Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]),
    chunk('IHDR', ihdr),
    chunk('IDAT', idat),
    chunk('IEND', Buffer.alloc(0)),
  ]);
}

mkdirSync(OUT, { recursive: true });
for (const size of SIZES) {
  const png = encodePNG(renderRGBA(size), size);
  writeFileSync(join(OUT, `icon${size}.png`), png);
  console.log(`wrote ${OUT}/icon${size}.png (${png.length} bytes)`);
}
