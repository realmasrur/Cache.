'use strict';
const QRCode = require('qrcode');
const { createCanvas, loadImage } = require('@napi-rs/canvas');

const BRAND = '#5865f2';
const INK = '#0b0d12';

function rr(g, x, y, w, h, r) {
  r = Math.min(r, w / 2, h / 2);
  g.beginPath();
  g.moveTo(x + r, y);
  g.arcTo(x + w, y, x + w, y + h, r);
  g.arcTo(x + w, y + h, x, y + h, r);
  g.arcTo(x, y + h, x, y, r);
  g.arcTo(x, y, x + w, y, r);
  g.closePath();
}

// Simple built-in wallet glyph, used when no logo / avatar is available.
function drawFallbackLogo(g, cx, cy, d) {
  g.fillStyle = BRAND;
  g.beginPath(); g.arc(cx, cy, d / 2, 0, Math.PI * 2); g.fill();
  const w = d * 0.52, h = d * 0.38;
  g.fillStyle = '#ffffff';
  rr(g, cx - w / 2, cy - h / 2, w, h, d * 0.07); g.fill();
  g.fillStyle = BRAND;
  g.beginPath(); g.arc(cx + w * 0.26, cy, d * 0.045, 0, Math.PI * 2); g.fill();
}

/**
 * Renders `text` as a QR (error correction H) with a round logo in the centre.
 * @param {string} text
 * @param {Buffer|null} logoBuffer  PNG/JPG/WEBP bytes, or null for the built-in glyph
 * @returns {Promise<Buffer>} PNG
 */
async function renderQr(text, logoBuffer) {
  const qr = QRCode.create(text, { errorCorrectionLevel: 'H' });
  const n = qr.modules.size;
  const quiet = 3;
  const cell = Math.max(8, Math.floor(560 / (n + quiet * 2)));
  const inner = (n + quiet * 2) * cell;
  const pad = 24;
  const W = inner + pad * 2;

  const canvas = createCanvas(W, W);
  const g = canvas.getContext('2d');
  g.fillStyle = '#ffffff';
  rr(g, 0, 0, W, W, 40); g.fill();

  const ox = pad + quiet * cell;
  const cx = W / 2;
  const logoD = Math.round(n * cell * 0.22);        // ~5% of the code area, well inside H-level recovery
  const clearR = logoD / 2 + cell * 1.5;

  const isFinder = (r, c) => (r < 7 && c < 7) || (r < 7 && c >= n - 7) || (r >= n - 7 && c < 7);
  const inLogoZone = (r, c) => Math.hypot(ox + c * cell + cell / 2 - cx, ox + r * cell + cell / 2 - cx) < clearR;

  // data modules as rounded dots
  g.fillStyle = INK;
  for (let r = 0; r < n; r++) {
    for (let c = 0; c < n; c++) {
      if (!qr.modules.get(r, c) || isFinder(r, c) || inLogoZone(r, c)) continue;
      rr(g, ox + c * cell + cell * 0.06, ox + r * cell + cell * 0.06, cell * 0.88, cell * 0.88, cell * 0.32);
      g.fill();
    }
  }

  // finder patterns as rounded concentric squares
  for (const [r, c] of [[0, 0], [0, n - 7], [n - 7, 0]]) {
    const x = ox + c * cell, y = ox + r * cell;
    g.fillStyle = INK; rr(g, x, y, 7 * cell, 7 * cell, cell * 1.8); g.fill();
    g.fillStyle = '#ffffff'; rr(g, x + cell, y + cell, 5 * cell, 5 * cell, cell * 1.2); g.fill();
    g.fillStyle = BRAND; rr(g, x + 2 * cell, y + 2 * cell, 3 * cell, 3 * cell, cell * 0.9); g.fill();
  }

  // centre logo: white halo, circular clip, brand ring
  g.fillStyle = '#ffffff';
  g.beginPath(); g.arc(cx, cx, logoD / 2 + cell * 0.7, 0, Math.PI * 2); g.fill();

  let drawn = false;
  if (logoBuffer) {
    try {
      const img = await loadImage(logoBuffer);
      g.save();
      g.beginPath(); g.arc(cx, cx, logoD / 2, 0, Math.PI * 2); g.clip();
      g.drawImage(img, cx - logoD / 2, cx - logoD / 2, logoD, logoD);
      g.restore();
      drawn = true;
    } catch { /* fall through to glyph */ }
  }
  if (!drawn) drawFallbackLogo(g, cx, cx, logoD);

  g.strokeStyle = BRAND;
  g.lineWidth = cell * 0.35;
  g.beginPath(); g.arc(cx, cx, logoD / 2, 0, Math.PI * 2); g.stroke();

  return canvas.toBuffer('image/png');
}

module.exports = { renderQr };
