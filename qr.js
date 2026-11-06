'use strict';
// Pure-JS QR renderer: no native canvas, so it is light on RAM and has no install scripts.
// Uses `qrcode` for the matrix and `pngjs` for PNG encode/decode.
const QRCode = require('qrcode');
const { PNG } = require('pngjs');

const BRAND = [0x58, 0x65, 0xf2];
const INK = [0x0b, 0x0d, 0x12];
const WHITE = [255, 255, 255];
const clamp01 = (v) => (v < 0 ? 0 : v > 1 ? 1 : v);

const makeImage = (w, h) => ({ w, h, d: Buffer.alloc(w * h * 4) });

// non-premultiplied "source over" blend of colour c with alpha a onto pixel (x, y)
function put(img, x, y, c, a) {
  if (a <= 0 || x < 0 || y < 0 || x >= img.w || y >= img.h) return;
  const i = (y * img.w + x) * 4, d = img.d;
  const da = d[i + 3] / 255;
  const oa = a + da * (1 - a);
  if (oa <= 0) return;
  for (let k = 0; k < 3; k++) d[i + k] = Math.round((c[k] * a + d[i + k] * da * (1 - a)) / oa);
  d[i + 3] = Math.round(oa * 255);
}

// anti-aliased rounded rectangle (signed distance field)
function fillRR(img, x, y, w, h, r, c) {
  r = Math.min(r, w / 2, h / 2);
  const cx = x + w / 2, cy = y + h / 2, hx = w / 2 - r, hy = h / 2 - r;
  for (let py = Math.floor(y) - 1; py <= Math.ceil(y + h) + 1; py++) {
    for (let px = Math.floor(x) - 1; px <= Math.ceil(x + w) + 1; px++) {
      const qx = Math.abs(px + 0.5 - cx) - hx, qy = Math.abs(py + 0.5 - cy) - hy;
      const dist = Math.hypot(Math.max(qx, 0), Math.max(qy, 0)) + Math.min(Math.max(qx, qy), 0) - r;
      put(img, px, py, c, clamp01(0.5 - dist));
    }
  }
}

function fillCircle(img, cx, cy, rad, c) {
  for (let py = Math.floor(cy - rad) - 1; py <= Math.ceil(cy + rad) + 1; py++) {
    for (let px = Math.floor(cx - rad) - 1; px <= Math.ceil(cx + rad) + 1; px++) {
      put(img, px, py, c, clamp01(0.5 - (Math.hypot(px + 0.5 - cx, py + 0.5 - cy) - rad)));
    }
  }
}

function ring(img, cx, cy, rad, lw, c) {
  const o = rad + lw;
  for (let py = Math.floor(cy - o) - 1; py <= Math.ceil(cy + o) + 1; py++) {
    for (let px = Math.floor(cx - o) - 1; px <= Math.ceil(cx + o) + 1; px++) {
      put(img, px, py, c, clamp01(0.5 - (Math.abs(Math.hypot(px + 0.5 - cx, py + 0.5 - cy) - rad) - lw / 2)));
    }
  }
}

function sample(src, u, v) {
  const x0 = Math.floor(u), y0 = Math.floor(v), fx = u - x0, fy = v - y0;
  const at = (x, y) => {
    x = Math.min(src.width - 1, Math.max(0, x)); y = Math.min(src.height - 1, Math.max(0, y));
    const i = (y * src.width + x) * 4;
    return [src.data[i], src.data[i + 1], src.data[i + 2], src.data[i + 3]];
  };
  const a = at(x0, y0), b = at(x0 + 1, y0), c = at(x0, y0 + 1), d = at(x0 + 1, y0 + 1);
  return a.map((_, k) => (a[k] * (1 - fx) + b[k] * fx) * (1 - fy) + (c[k] * (1 - fx) + d[k] * fx) * fy);
}

function drawLogo(img, cx, cy, d, src) {
  const rad = d / 2;
  for (let py = Math.floor(cy - rad) - 1; py <= Math.ceil(cy + rad) + 1; py++) {
    for (let px = Math.floor(cx - rad) - 1; px <= Math.ceil(cx + rad) + 1; px++) {
      const cov = clamp01(0.5 - (Math.hypot(px + 0.5 - cx, py + 0.5 - cy) - rad));
      if (cov <= 0) continue;
      const u = ((px + 0.5 - (cx - rad)) / d) * src.width - 0.5;
      const v = ((py + 0.5 - (cy - rad)) / d) * src.height - 0.5;
      const s = sample(src, u, v);
      put(img, px, py, s, cov * (s[3] / 255));
    }
  }
}

function drawFallbackLogo(img, cx, cy, d) {
  fillCircle(img, cx, cy, d / 2, BRAND);
  const w = d * 0.52, h = d * 0.38;
  fillRR(img, cx - w / 2, cy - h / 2, w, h, d * 0.07, WHITE);
  fillCircle(img, cx + w * 0.26, cy, d * 0.045, BRAND);
}

/** isDark(r, c) -> bool for an n x n matrix. logo = decoded PNG ({width,height,data}) or null. Returns PNG Buffer. */
function renderMatrix(isDark, n, logo) {
  const quiet = 3;
  const cell = Math.max(8, Math.floor(560 / (n + quiet * 2)));
  const pad = 24;
  const W = (n + quiet * 2) * cell + pad * 2;
  const img = makeImage(W, W);
  fillRR(img, 0, 0, W, W, 40, WHITE);

  const ox = pad + quiet * cell;
  const mid = W / 2;
  const logoD = Math.round(n * cell * 0.22);          // small enough for error-correction level H
  const clearR = logoD / 2 + cell * 1.5;
  const isFinder = (r, c) => (r < 7 && c < 7) || (r < 7 && c >= n - 7) || (r >= n - 7 && c < 7);

  for (let r = 0; r < n; r++) {
    for (let c = 0; c < n; c++) {
      if (!isDark(r, c) || isFinder(r, c)) continue;
      const x = ox + c * cell, y = ox + r * cell;
      if (Math.hypot(x + cell / 2 - mid, y + cell / 2 - mid) < clearR) continue; // leave room for the logo
      fillRR(img, x + cell * 0.06, y + cell * 0.06, cell * 0.88, cell * 0.88, cell * 0.32, INK);
    }
  }
  for (const [r, c] of [[0, 0], [0, n - 7], [n - 7, 0]]) {
    const x = ox + c * cell, y = ox + r * cell;
    fillRR(img, x, y, 7 * cell, 7 * cell, cell * 1.8, INK);
    fillRR(img, x + cell, y + cell, 5 * cell, 5 * cell, cell * 1.2, WHITE);
    fillRR(img, x + 2 * cell, y + 2 * cell, 3 * cell, 3 * cell, cell * 0.9, BRAND);
  }

  fillCircle(img, mid, mid, logoD / 2 + cell * 0.7, WHITE); // halo
  if (logo) drawLogo(img, mid, mid, logoD, logo);
  else drawFallbackLogo(img, mid, mid, logoD);
  ring(img, mid, mid, logoD / 2, cell * 0.35, BRAND);

  const png = new PNG({ width: W, height: W });
  img.d.copy(png.data);
  return PNG.sync.write(png);
}

/** @param {string} text @param {Buffer|null} logoBuffer PNG bytes for the centre logo, or null for the built-in glyph */
async function renderQr(text, logoBuffer) {
  const qr = QRCode.create(text, { errorCorrectionLevel: 'H' });
  let logo = null;
  if (logoBuffer) { try { logo = PNG.sync.read(logoBuffer); } catch { /* not a PNG: use glyph */ } }
  return renderMatrix((r, c) => !!qr.modules.get(r, c), qr.modules.size, logo);
}

module.exports = { renderQr, renderMatrix };
