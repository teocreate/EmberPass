/**
 * PDF417 encoder (ISO/IEC 15438). Text and Byte compaction, ECC levels 0-8.
 * Zero dependencies. Works both in the browser and in Node (ES module).
 *
 * encodePDF417("text", { columns: 8, ecLevel: 4 })
 *   -> { rows, columns, width, height, modules }
 * `modules` is an array of rows, each a Uint8Array of 0 (light) / 1 (dark).
 */

import { PDF417_PATTERNS, PDF417_START, PDF417_STOP } from './pdf417-codes.js';

const MODE_LATCH_TEXT = 900;
const MODE_LATCH_BYTE = 901;
const MODE_LATCH_BYTE_6 = 924; // byte compaction when the length is a multiple of 6
const PAD_CODEWORD = 900;

const MAX_CODEWORDS = 928;
const MAX_DATA_CODEWORDS = 925; // 928 - 1 length descriptor - minimum 2 ECC

/* ----------------------------- Text compaction ----------------------------- */

const ALPHA = 0;
const LOWER = 1;
const MIXED = 2;
const PUNCT = 3;

const SUBMODE_CHARS = [
  'ABCDEFGHIJKLMNOPQRSTUVWXYZ ',
  'abcdefghijklmnopqrstuvwxyz ',
  '0123456789&\r\t,:#-.$/+%*=^',
  ';<>@[\\]_`~!\r\t,:\n-.$/"|*()?{}\'',
];
// Index 26 in mixed mode is a space; it is not part of the ordered char list above.
const MIXED_SPACE = 26;

function submodeValue(submode, char) {
  if (submode === MIXED && char === ' ') return MIXED_SPACE;
  const index = SUBMODE_CHARS[submode].indexOf(char);
  if (submode <= LOWER) return index === -1 ? -1 : index; // 0-25 letters, 26 space
  if (submode === MIXED) return index >= 0 && index <= 24 ? index : -1;
  return index >= 0 && index <= 28 ? index : -1;
}

function isTextEncodable(text) {
  return Array.from(text).every((c) => SUBMODE_CHARS.some((_, m) => submodeValue(m, c) !== -1));
}

/** Encodes text into interim 5-bit values, switching submodes as needed. */
function textValues(text) {
  const values = [];
  let submode = ALPHA;
  const chars = Array.from(text);

  for (let i = 0; i < chars.length; i++) {
    const char = chars[i];
    const direct = submodeValue(submode, char);
    if (direct !== -1) {
      values.push(direct);
      continue;
    }

    // Single-character shift into punctuation keeps the current latch.
    const punctValue = submodeValue(PUNCT, char);
    if (submode !== PUNCT && punctValue !== -1 && submodeValue(MIXED, char) === -1) {
      const next = chars[i + 1];
      const nextNeedsPunct = next !== undefined && submodeValue(PUNCT, next) !== -1 && submodeValue(submode, next) === -1;
      if (!nextNeedsPunct) {
        values.push(29, punctValue); // PS
        continue;
      }
    }

    // Single uppercase letter while latched to lowercase: shift instead of latching.
    if (submode === LOWER && submodeValue(ALPHA, char) !== -1) {
      const next = chars[i + 1];
      if (next === undefined || submodeValue(LOWER, next) !== -1) {
        values.push(27, submodeValue(ALPHA, char)); // AS
        continue;
      }
    }

    const target = [ALPHA, LOWER, MIXED, PUNCT].find((m) => submodeValue(m, char) !== -1);
    values.push(...latch(submode, target));
    submode = target;
    values.push(submodeValue(submode, char));
  }

  if (values.length % 2 === 1) values.push(29); // pad with PS/AL
  const codewords = [];
  for (let i = 0; i < values.length; i += 2) codewords.push(values[i] * 30 + values[i + 1]);
  return codewords;
}

function latch(from, to) {
  if (from === to) return [];
  switch (from) {
    case ALPHA:
      return to === LOWER ? [27] : to === MIXED ? [28] : [28, 25];
    case LOWER:
      return to === MIXED ? [28] : to === PUNCT ? [28, 25] : [28, 28];
    case MIXED:
      return to === LOWER ? [27] : to === PUNCT ? [25] : [28];
    case PUNCT:
      return to === ALPHA ? [29] : to === LOWER ? [29, 27] : [29, 28];
    default:
      throw new Error('unreachable submode');
  }
}

/* ----------------------------- Byte compaction ----------------------------- */

function byteValues(bytes) {
  const codewords = [];
  const fullGroups = Math.floor(bytes.length / 6);
  codewords.push(bytes.length % 6 === 0 && bytes.length > 0 ? MODE_LATCH_BYTE_6 : MODE_LATCH_BYTE);

  for (let g = 0; g < fullGroups; g++) {
    let value = 0n;
    for (let i = 0; i < 6; i++) value = value * 256n + BigInt(bytes[g * 6 + i]);
    const group = [];
    for (let i = 0; i < 5; i++) {
      group.unshift(Number(value % 900n));
      value /= 900n;
    }
    codewords.push(...group);
  }
  // Trailing bytes are encoded one codeword per byte.
  for (let i = fullGroups * 6; i < bytes.length; i++) codewords.push(bytes[i]);
  return codewords;
}

function utf8Bytes(text) {
  if (typeof TextEncoder !== 'undefined') return new TextEncoder().encode(text);
  return Uint8Array.from(Buffer.from(text, 'utf8'));
}

/* --------------------- Reed-Solomon error correction (GF 929) --------------------- */

const MODULUS = 929;

/**
 * Builds the generator polynomial of the given degree: the product of (x - 3^i) for
 * i = 1..degree over GF(929). Returns the coefficients of x^0..x^(degree-1); the
 * leading coefficient is always 1 and is implied. Computing these makes the large
 * per-level factor tables from the spec unnecessary.
 */
function generatorPolynomial(degree) {
  let poly = [1];
  let root = 1;
  for (let i = 0; i < degree; i++) {
    root = (root * 3) % MODULUS;
    const negRoot = MODULUS - root;
    const next = new Array(poly.length + 1).fill(0);
    for (let j = 0; j < poly.length; j++) {
      next[j] = (next[j] + poly[j] * negRoot) % MODULUS;
      next[j + 1] = (next[j + 1] + poly[j]) % MODULUS;
    }
    poly = next;
  }
  return poly.slice(0, degree);
}

function computeEcc(dataCodewords, eccCount) {
  const factors = generatorPolynomial(eccCount);
  const ecc = new Array(eccCount).fill(0);
  for (const codeword of dataCodewords) {
    const t = (codeword + ecc[eccCount - 1]) % MODULUS;
    for (let j = eccCount - 1; j > 0; j--) {
      ecc[j] = (ecc[j - 1] + MODULUS - (t * factors[j]) % MODULUS) % MODULUS;
    }
    ecc[0] = (MODULUS - (t * factors[0]) % MODULUS) % MODULUS;
  }
  return ecc.map((c) => (c === 0 ? 0 : MODULUS - c)).reverse();
}

/* -------------------------------- Symbol layout -------------------------------- */

/** Picks the smallest ECC level the spec recommends for a given data size. */
export function recommendedEcLevel(dataCount) {
  if (dataCount <= 40) return 2;
  if (dataCount <= 160) return 3;
  if (dataCount <= 320) return 4;
  return 5;
}

function highLevelEncode(text) {
  if (isTextEncodable(text)) return [MODE_LATCH_TEXT, ...textValues(text)];
  return byteValues(utf8Bytes(text));
}

/**
 * Encodes text as a PDF417 symbol.
 * @param {string} text
 * @param {{columns?: number, ecLevel?: number, rowHeight?: number}} options
 */
export function encodePDF417(text, options = {}) {
  const payload = highLevelEncode(text);
  const ecLevel = options.ecLevel === undefined ? recommendedEcLevel(payload.length) : options.ecLevel;
  if (ecLevel < 0 || ecLevel > 8) throw new RangeError('ecLevel must be 0..8');
  const eccCount = 1 << (ecLevel + 1);

  let columns = options.columns || 0;
  if (!columns) {
    // Aim for a roughly 3:1 symbol; clamp into the legal 1..30 data column range.
    columns = Math.min(30, Math.max(1, Math.round(Math.sqrt((payload.length + eccCount + 1) / 3))));
  }
  if (columns < 1 || columns > 30) throw new RangeError('columns must be 1..30');

  const total = payload.length + 1 + eccCount;
  if (total > MAX_CODEWORDS || payload.length + 1 > MAX_DATA_CODEWORDS) {
    throw new RangeError('data too long for a single PDF417 symbol');
  }
  const rows = Math.ceil(total / columns);
  if (rows < 3 || rows > 90) {
    throw new RangeError(`resulting symbol needs ${rows} rows, which is outside the legal 3..90 range`);
  }

  const dataCount = rows * columns - eccCount;
  const data = [dataCount, ...payload];
  while (data.length < dataCount) data.push(PAD_CODEWORD);
  data[0] = dataCount; // length descriptor counts data codewords including itself

  const codewords = [...data, ...computeEcc(data, eccCount)];

  const width = 17 * (columns + 2) + 18 + 1; // start + left + data + right + stop + final bar
  const modules = [];
  for (let r = 0; r < rows; r++) {
    const cluster = r % 3;
    const row = new Uint8Array(width);
    let x = 0;
    const put = (pattern, length) => {
      for (let i = length - 1; i >= 0; i--) row[x++] = (pattern >> i) & 1;
    };

    put(PDF417_START, 17);
    put(PDF417_PATTERNS[cluster][rowIndicator(r, rows, columns, ecLevel, 'left')], 17);
    for (let c = 0; c < columns; c++) put(PDF417_PATTERNS[cluster][codewords[r * columns + c]], 17);
    put(PDF417_PATTERNS[cluster][rowIndicator(r, rows, columns, ecLevel, 'right')], 17);
    put(PDF417_STOP, 18);
    row[x] = 1; // closing bar

    modules.push(row);
  }

  return { rows, columns, ecLevel, width, height: rows, codewords, modules };
}

function rowIndicator(row, rows, columns, ecLevel, side) {
  const base = 30 * Math.floor(row / 3);
  const a = Math.floor((rows - 1) / 3);
  const b = ecLevel * 3 + ((rows - 1) % 3);
  const c = columns - 1;
  const order = side === 'left' ? [a, b, c] : [c, a, b];
  return base + order[row % 3];
}

/** Renders a PDF417 symbol as an SVG path (1 unit per module, rowHeight units tall rows). */
export function pdf417ToSvg(symbol, { rowHeight = 3, quietZone = 2 } = {}) {
  let path = '';
  for (let y = 0; y < symbol.rows; y++) {
    const row = symbol.modules[y];
    let x = 0;
    while (x < row.length) {
      if (!row[x]) {
        x++;
        continue;
      }
      let run = 0;
      while (x + run < row.length && row[x + run]) run++;
      path += `M${x + quietZone} ${y * rowHeight + quietZone}h${run}v${rowHeight}h-${run}z`;
      x += run;
    }
  }
  return { width: symbol.width + quietZone * 2, height: symbol.rows * rowHeight + quietZone * 2, path };
}
