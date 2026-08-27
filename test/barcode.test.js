import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';

import { encodeQR, qrToSvg } from '../public/lib/qrcode.js';
import { encodePDF417, pdf417ToSvg } from '../public/lib/pdf417.js';

const digest = (modules) =>
  createHash('sha256').update(modules.map((row) => Array.from(row).join('')).join('\n')).digest('hex').slice(0, 16);

test('QR: known symbol matches the reference encoder output', () => {
  // Byte-for-byte identical to python-qrcode for the same version/ECC/mask.
  const qr = encodeQR('HELLO WORLD', { ecc: 'M', mask: 2 });
  assert.equal(qr.version, 1);
  assert.equal(qr.size, 21);
  assert.equal(digest(qr.modules), '4a00c00a60fcf7c1');
});

test('QR: version grows with payload and stays within capacity', () => {
  const sizes = [10, 100, 400, 1200].map((length) => encodeQR('a'.repeat(length), { ecc: 'M' }).version);
  assert.deepEqual(sizes, [1, 6, 15, 29]);
  assert.throws(() => encodeQR('a'.repeat(3000), { ecc: 'H' }), /too long/);
});

test('QR: finder patterns and timing rows are in place', () => {
  const { modules, size } = encodeQR('finder-check', { ecc: 'Q' });
  for (const [cx, cy] of [[3, 3], [size - 4, 3], [3, size - 4]]) {
    assert.equal(modules[cy][cx], 1, 'finder centre is dark');
    assert.equal(modules[cy - 1][cx], 1, 'finder ring is dark');
    assert.equal(modules[cy - 2][cx], 0, 'separator ring is light');
  }
  for (let i = 8; i < size - 8; i++) assert.equal(modules[6][i], i % 2 === 0 ? 1 : 0, 'timing pattern alternates');
});

test('QR: svg path covers every dark module', () => {
  const qr = encodeQR('svg', { ecc: 'L' });
  const svg = qrToSvg(qr, { quietZone: 4 });
  const dark = qr.modules.flatMap((row) => Array.from(row)).filter(Boolean).length;
  assert.equal(svg.path.split('M').length - 1, dark);
  assert.equal(svg.width, qr.size + 8);
});

test('PDF417: layout follows the requested columns and error correction level', () => {
  const symbol = encodePDF417('PASS-TOKEN-12345', { columns: 4, ecLevel: 2 });
  assert.equal(symbol.columns, 4);
  assert.equal(symbol.ecLevel, 2);
  assert.equal(symbol.codewords.length, symbol.rows * symbol.columns);
  assert.equal(symbol.codewords[0], symbol.rows * symbol.columns - (1 << 3), 'length descriptor counts data words');
  assert.equal(symbol.width, 17 * (symbol.columns + 2) + 18 + 1);
  for (const row of symbol.modules) {
    assert.equal(row[0], 1, 'every row starts with the start pattern bar');
    assert.equal(row[row.length - 1], 1, 'every row ends with the closing bar');
  }
});

test('PDF417: error correction words match the reference implementation', () => {
  const symbol = encodePDF417('PASS', { columns: 2, ecLevel: 3 });
  // Data words [4, 900, 450, 558] with 16 EC words, cross-checked against pdf417gen 0.8.1.
  assert.deepEqual(symbol.codewords.slice(0, 4), [4, 900, 450, 558]);
  assert.deepEqual(
    symbol.codewords.slice(-16),
    [830, 354, 353, 276, 452, 640, 349, 916, 431, 489, 658, 527, 731, 204, 470, 262],
  );
});

test('PDF417: byte compaction handles non-ASCII payloads', () => {
  const symbol = encodePDF417('Пропуск №42', { columns: 6, ecLevel: 3 });
  assert.ok([901, 924].includes(symbol.codewords[1]), 'switches to byte compaction');
  assert.ok(symbol.rows >= 3 && symbol.rows <= 90);
});

test('PDF417: svg output is wider than it is tall for a typical token', () => {
  const symbol = encodePDF417('v'.repeat(118), { columns: 10, ecLevel: 4 });
  const svg = pdf417ToSvg(symbol, { rowHeight: 3 });
  assert.ok(svg.width > svg.height, 'symbol stays scannable on a phone screen');
});
