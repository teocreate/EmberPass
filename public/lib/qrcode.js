/**
 * QR Code encoder (ISO/IEC 18004), byte mode, versions 1-40, ECC L/M/Q/H.
 * Zero dependencies. Works both in the browser and in Node (ES module).
 *
 * encodeQR("text") -> { size, version, ecc, mask, modules }
 * `modules` is an array of rows, each row a Uint8Array of 0 (light) / 1 (dark).
 */

const ECC_LEVELS = { L: 0, M: 1, Q: 2, H: 3 };
// Format-info bit pattern per ECC level (not the same order as the index above).
const ECC_FORMAT_BITS = { L: 1, M: 0, Q: 3, H: 2 };

// Number of error-correction codewords per block, indexed [eccIndex][version].
const ECC_CODEWORDS_PER_BLOCK = [
  // 1   2   3   4   5   6   7   8   9  10  11  12  13  14  15  16  17  18  19  20  21  22  23  24  25  26  27  28  29  30  31  32  33  34  35  36  37  38  39  40
  [7, 10, 15, 20, 26, 18, 20, 24, 30, 18, 20, 24, 26, 30, 22, 24, 28, 30, 28, 28, 28, 28, 30, 30, 26, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30], // L
  [10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24, 28, 28, 26, 26, 26, 26, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28], // M
  [13, 22, 18, 26, 18, 24, 18, 22, 20, 24, 28, 26, 24, 20, 30, 24, 28, 28, 26, 30, 28, 30, 30, 30, 30, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30], // Q
  [17, 28, 22, 16, 22, 28, 26, 26, 24, 28, 24, 28, 22, 24, 24, 30, 28, 28, 26, 28, 30, 24, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30], // H
];

// Number of error-correction blocks, indexed [eccIndex][version].
const NUM_ECC_BLOCKS = [
  [1, 1, 1, 1, 1, 2, 2, 2, 2, 4, 4, 4, 4, 4, 6, 6, 6, 6, 7, 8, 8, 9, 9, 10, 12, 12, 12, 13, 14, 15, 16, 17, 18, 19, 19, 20, 21, 22, 24, 25], // L
  [1, 1, 1, 2, 2, 4, 4, 4, 5, 5, 5, 8, 9, 9, 10, 10, 11, 13, 14, 16, 17, 17, 18, 20, 21, 23, 25, 26, 28, 29, 31, 33, 35, 37, 38, 40, 43, 45, 47, 49], // M
  [1, 1, 2, 2, 4, 4, 6, 6, 8, 8, 8, 10, 12, 16, 12, 17, 16, 18, 21, 20, 23, 23, 25, 27, 29, 34, 34, 35, 38, 40, 43, 45, 48, 51, 53, 56, 59, 62, 65, 68], // Q
  [1, 1, 2, 4, 4, 4, 5, 6, 8, 8, 11, 11, 16, 16, 18, 16, 19, 21, 25, 25, 25, 34, 30, 32, 35, 37, 40, 42, 45, 48, 51, 54, 57, 60, 63, 66, 70, 74, 77, 81], // H
];

/** Total number of data+ECC modules (bits) available in a version, excluding function patterns. */
function rawDataModules(version) {
  let result = (16 * version + 128) * version + 64;
  if (version >= 2) {
    const numAlign = Math.floor(version / 7) + 2;
    result -= (25 * numAlign - 10) * numAlign - 55;
    if (version >= 7) result -= 36;
  }
  return result;
}

function dataCodewords(version, ecc) {
  const i = ECC_LEVELS[ecc];
  return (
    Math.floor(rawDataModules(version) / 8) -
    ECC_CODEWORDS_PER_BLOCK[i][version - 1] * NUM_ECC_BLOCKS[i][version - 1]
  );
}

function alignmentPositions(version) {
  if (version === 1) return [];
  const numAlign = Math.floor(version / 7) + 2;
  const step =
    version === 32 ? 26 : Math.floor((version * 4 + numAlign * 2 + 1) / (numAlign * 2 - 2)) * 2;
  const positions = [6];
  for (let pos = version * 4 + 10; positions.length < numAlign; pos -= step) positions.splice(1, 0, pos);
  return positions;
}

/* ---------------------------- Galois field GF(256) --------------------------- */

function gfMultiply(x, y) {
  let z = 0;
  for (let i = 7; i >= 0; i--) {
    z = (z << 1) ^ ((z >>> 7) * 0x11d);
    z ^= ((y >>> i) & 1) * x;
  }
  return z & 0xff;
}

function rsDivisor(degree) {
  const result = new Uint8Array(degree);
  result[degree - 1] = 1;
  let root = 1;
  for (let i = 0; i < degree; i++) {
    for (let j = 0; j < degree; j++) {
      result[j] = gfMultiply(result[j], root);
      if (j + 1 < degree) result[j] ^= result[j + 1];
    }
    root = gfMultiply(root, 0x02);
  }
  return result;
}

function rsRemainder(data, divisor) {
  const result = new Uint8Array(divisor.length);
  for (const byte of data) {
    const factor = byte ^ result[0];
    result.copyWithin(0, 1);
    result[result.length - 1] = 0;
    for (let i = 0; i < divisor.length; i++) result[i] ^= gfMultiply(divisor[i], factor);
  }
  return result;
}

/* -------------------------------- Bit buffer -------------------------------- */

class BitBuffer {
  constructor() {
    this.bits = [];
  }
  append(value, length) {
    for (let i = length - 1; i >= 0; i--) this.bits.push((value >>> i) & 1);
  }
  get length() {
    return this.bits.length;
  }
  toBytes() {
    const bytes = new Uint8Array(Math.ceil(this.bits.length / 8));
    this.bits.forEach((bit, i) => {
      bytes[i >>> 3] |= bit << (7 - (i & 7));
    });
    return bytes;
  }
}

function utf8Bytes(text) {
  if (typeof TextEncoder !== 'undefined') return new TextEncoder().encode(text);
  return Uint8Array.from(Buffer.from(text, 'utf8'));
}

/** Builds the data codeword stream (mode + length + payload + padding). */
function buildCodewords(bytes, version, ecc) {
  const capacity = dataCodewords(version, ecc);
  const buffer = new BitBuffer();
  buffer.append(0b0100, 4); // byte mode
  buffer.append(bytes.length, version <= 9 ? 8 : 16);
  for (const byte of bytes) buffer.append(byte, 8);

  const capacityBits = capacity * 8;
  buffer.append(0, Math.min(4, capacityBits - buffer.length)); // terminator
  buffer.append(0, (8 - (buffer.length % 8)) % 8); // pad to byte boundary

  const data = new Uint8Array(capacity);
  data.set(buffer.toBytes());
  for (let i = buffer.length / 8, pad = 0xec; i < capacity; i++, pad ^= 0xec ^ 0x11) data[i] = pad;
  return data;
}

/** Splits data into blocks, appends ECC to each, and interleaves them. */
function addEccAndInterleave(data, version, ecc) {
  const eccIndex = ECC_LEVELS[ecc];
  const numBlocks = NUM_ECC_BLOCKS[eccIndex][version - 1];
  const blockEccLen = ECC_CODEWORDS_PER_BLOCK[eccIndex][version - 1];
  const rawCodewords = Math.floor(rawDataModules(version) / 8);
  const numShortBlocks = numBlocks - (rawCodewords % numBlocks);
  const shortBlockDataLen = Math.floor(rawCodewords / numBlocks) - blockEccLen;

  const divisor = rsDivisor(blockEccLen);
  const blocks = [];
  for (let i = 0, offset = 0; i < numBlocks; i++) {
    const len = shortBlockDataLen + (i < numShortBlocks ? 0 : 1);
    const chunk = data.subarray(offset, offset + len);
    offset += len;
    const block = Array.from(chunk);
    if (i < numShortBlocks) block.push(0); // placeholder keeps blocks rectangular
    blocks.push(block.concat(Array.from(rsRemainder(chunk, divisor))));
  }

  const result = [];
  for (let i = 0; i < blocks[0].length; i++) {
    for (let j = 0; j < blocks.length; j++) {
      if (i !== shortBlockDataLen || j >= numShortBlocks) result.push(blocks[j][i]);
    }
  }
  return Uint8Array.from(result);
}

/* --------------------------------- Matrix ---------------------------------- */

class Matrix {
  constructor(version) {
    this.version = version;
    this.size = version * 4 + 17;
    this.modules = Array.from({ length: this.size }, () => new Uint8Array(this.size));
    this.functional = Array.from({ length: this.size }, () => new Uint8Array(this.size));
  }

  setFunction(x, y, dark) {
    this.modules[y][x] = dark ? 1 : 0;
    this.functional[y][x] = 1;
  }

  drawFunctionPatterns(ecc) {
    const size = this.size;
    for (let i = 0; i < size; i++) {
      this.setFunction(6, i, i % 2 === 0);
      this.setFunction(i, 6, i % 2 === 0);
    }
    this.drawFinder(3, 3);
    this.drawFinder(size - 4, 3);
    this.drawFinder(3, size - 4);

    const positions = alignmentPositions(this.version);
    const last = positions.length - 1;
    for (let i = 0; i <= last; i++) {
      for (let j = 0; j <= last; j++) {
        if ((i === 0 && j === 0) || (i === 0 && j === last) || (i === last && j === 0)) continue;
        this.drawAlignment(positions[i], positions[j]);
      }
    }

    this.drawFormatBits(ecc, 0); // placeholder, rewritten once the mask is chosen
    this.drawVersionBits();
  }

  drawFinder(cx, cy) {
    for (let dy = -4; dy <= 4; dy++) {
      for (let dx = -4; dx <= 4; dx++) {
        const dist = Math.max(Math.abs(dx), Math.abs(dy));
        const x = cx + dx;
        const y = cy + dy;
        if (x >= 0 && x < this.size && y >= 0 && y < this.size) {
          this.setFunction(x, y, dist !== 2 && dist !== 4);
        }
      }
    }
  }

  drawAlignment(cx, cy) {
    for (let dy = -2; dy <= 2; dy++) {
      for (let dx = -2; dx <= 2; dx++) {
        this.setFunction(cx + dx, cy + dy, Math.max(Math.abs(dx), Math.abs(dy)) !== 1);
      }
    }
  }

  drawFormatBits(ecc, mask) {
    const size = this.size;
    const data = (ECC_FORMAT_BITS[ecc] << 3) | mask;
    let rem = data;
    for (let i = 0; i < 10; i++) rem = (rem << 1) ^ ((rem >>> 9) * 0x537);
    const bits = (((data << 10) | rem) ^ 0x5412) & 0x7fff;
    const bit = (i) => ((bits >>> i) & 1) !== 0;

    for (let i = 0; i <= 5; i++) this.setFunction(8, i, bit(i));
    this.setFunction(8, 7, bit(6));
    this.setFunction(8, 8, bit(7));
    this.setFunction(7, 8, bit(8));
    for (let i = 9; i < 15; i++) this.setFunction(14 - i, 8, bit(i));

    for (let i = 0; i < 8; i++) this.setFunction(size - 1 - i, 8, bit(i));
    for (let i = 8; i < 15; i++) this.setFunction(8, size - 15 + i, bit(i));
    this.setFunction(8, size - 8, true); // always-dark module
  }

  drawVersionBits() {
    if (this.version < 7) return;
    let rem = this.version;
    for (let i = 0; i < 12; i++) rem = (rem << 1) ^ ((rem >>> 11) * 0x1f25);
    const bits = (this.version << 12) | rem;
    for (let i = 0; i < 18; i++) {
      const bit = ((bits >>> i) & 1) !== 0;
      const a = this.size - 11 + (i % 3);
      const b = Math.floor(i / 3);
      this.setFunction(a, b, bit);
      this.setFunction(b, a, bit);
    }
  }

  drawCodewords(data) {
    let i = 0;
    for (let right = this.size - 1; right >= 1; right -= 2) {
      if (right === 6) right = 5; // skip the vertical timing column
      for (let vert = 0; vert < this.size; vert++) {
        for (let j = 0; j < 2; j++) {
          const x = right - j;
          const upward = ((right + 1) & 2) === 0;
          const y = upward ? this.size - 1 - vert : vert;
          if (!this.functional[y][x] && i < data.length * 8) {
            this.modules[y][x] = (data[i >>> 3] >>> (7 - (i & 7))) & 1;
            i++;
          }
        }
      }
    }
  }

  applyMask(mask) {
    for (let y = 0; y < this.size; y++) {
      for (let x = 0; x < this.size; x++) {
        if (this.functional[y][x]) continue;
        let invert;
        switch (mask) {
          case 0: invert = (x + y) % 2 === 0; break;
          case 1: invert = y % 2 === 0; break;
          case 2: invert = x % 3 === 0; break;
          case 3: invert = (x + y) % 3 === 0; break;
          case 4: invert = (Math.floor(x / 3) + Math.floor(y / 2)) % 2 === 0; break;
          case 5: invert = ((x * y) % 2) + ((x * y) % 3) === 0; break;
          case 6: invert = (((x * y) % 2) + ((x * y) % 3)) % 2 === 0; break;
          case 7: invert = (((x + y) % 2) + ((x * y) % 3)) % 2 === 0; break;
          default: throw new RangeError('mask out of range');
        }
        if (invert) this.modules[y][x] ^= 1;
      }
    }
  }

  /** Penalty score used to pick the mask that produces the most readable symbol. */
  penaltyScore() {
    const size = this.size;
    let score = 0;

    const scanLine = (get) => {
      let runColor = get(0);
      let runLength = 1;
      const history = [];
      for (let i = 1; i < size; i++) {
        const color = get(i);
        if (color === runColor) {
          runLength++;
        } else {
          if (runLength >= 5) score += 3 + (runLength - 5);
          history.push(runLength);
          runColor = color;
          runLength = 1;
        }
      }
      if (runLength >= 5) score += 3 + (runLength - 5);
      history.push(runLength);
      return history;
    };

    const finderLike = (line, get) => {
      // 1:1:3:1:1 ratio surrounded by 4 light modules, in either direction.
      const bits = [];
      for (let i = 0; i < size; i++) bits.push(get(i));
      const pattern = [1, 0, 1, 1, 1, 0, 1];
      for (let i = 0; i + 6 < size; i++) {
        let ok = true;
        for (let j = 0; j < 7; j++) if (bits[i + j] !== pattern[j]) { ok = false; break; }
        if (!ok) continue;
        const before = bits.slice(Math.max(0, i - 4), i);
        const after = bits.slice(i + 7, i + 11);
        const light = (arr, need) => arr.length >= need && arr.every((b) => b === 0);
        if (light(before, 4) || light(after, 4)) score += 40;
      }
      void line;
    };

    for (let y = 0; y < size; y++) {
      const get = (x) => this.modules[y][x];
      finderLike(scanLine(get), get);
    }
    for (let x = 0; x < size; x++) {
      const get = (y) => this.modules[y][x];
      finderLike(scanLine(get), get);
    }

    for (let y = 0; y < size - 1; y++) {
      for (let x = 0; x < size - 1; x++) {
        const c = this.modules[y][x];
        if (c === this.modules[y][x + 1] && c === this.modules[y + 1][x] && c === this.modules[y + 1][x + 1]) {
          score += 3;
        }
      }
    }

    let dark = 0;
    for (const row of this.modules) for (const m of row) dark += m;
    const total = size * size;
    const k = Math.floor(Math.abs(dark * 20 - total * 10) / total); // == |percent-50|/5
    score += k * 10;
    return score;
  }
}

/**
 * Encodes text as a QR symbol.
 * @param {string} text
 * @param {{ecc?: 'L'|'M'|'Q'|'H', minVersion?: number, maxVersion?: number, mask?: number}} options
 */
export function encodeQR(text, options = {}) {
  const ecc = options.ecc || 'M';
  if (!(ecc in ECC_LEVELS)) throw new RangeError(`unknown ECC level: ${ecc}`);
  const minVersion = options.minVersion || 1;
  const maxVersion = options.maxVersion || 40;
  const bytes = utf8Bytes(text);

  let version = 0;
  for (let v = minVersion; v <= maxVersion; v++) {
    const headerBits = 4 + (v <= 9 ? 8 : 16);
    if (headerBits + bytes.length * 8 <= dataCodewords(v, ecc) * 8) {
      version = v;
      break;
    }
  }
  if (!version) throw new RangeError('data too long for the requested QR version range');

  const matrix = new Matrix(version);
  matrix.drawFunctionPatterns(ecc);
  matrix.drawCodewords(addEccAndInterleave(buildCodewords(bytes, version, ecc), version, ecc));

  let mask = options.mask;
  if (mask === undefined || mask === null) {
    let best = Infinity;
    for (let m = 0; m < 8; m++) {
      matrix.applyMask(m);
      matrix.drawFormatBits(ecc, m);
      const score = matrix.penaltyScore();
      if (score < best) {
        best = score;
        mask = m;
      }
      matrix.applyMask(m); // undo (XOR is its own inverse)
    }
  }
  matrix.applyMask(mask);
  matrix.drawFormatBits(ecc, mask);

  return { size: matrix.size, version, ecc, mask, modules: matrix.modules };
}

/** Renders a QR symbol as an SVG path string (1 unit per module, plus quiet zone). */
export function qrToSvg(qr, { quietZone = 4, moduleSize = 1 } = {}) {
  const dim = (qr.size + quietZone * 2) * moduleSize;
  let path = '';
  for (let y = 0; y < qr.size; y++) {
    for (let x = 0; x < qr.size; x++) {
      if (qr.modules[y][x]) {
        path += `M${(x + quietZone) * moduleSize} ${(y + quietZone) * moduleSize}h${moduleSize}v${moduleSize}h-${moduleSize}z`;
      }
    }
  }
  return { width: dim, height: dim, path };
}
