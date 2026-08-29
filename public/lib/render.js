import { encodeQR, qrToSvg } from './qrcode.js';

const SVG_NS = 'http://www.w3.org/2000/svg';

function svgElement(width, height, path, label) {
  const svg = document.createElementNS(SVG_NS, 'svg');
  svg.setAttribute('viewBox', `0 0 ${width} ${height}`);
  svg.setAttribute('role', 'img');
  svg.setAttribute('aria-label', label);
  svg.setAttribute('shape-rendering', 'crispEdges');

  const background = document.createElementNS(SVG_NS, 'rect');
  background.setAttribute('width', String(width));
  background.setAttribute('height', String(height));
  background.setAttribute('fill', '#ffffff');
  svg.appendChild(background);

  const shape = document.createElementNS(SVG_NS, 'path');
  shape.setAttribute('d', path);
  shape.setAttribute('fill', '#000000');
  svg.appendChild(shape);
  return svg;
}

// The PDF417 encoder is only fetched where the format is switched on, so a
// deployment without turnstile hardware never downloads it.
let pdf417Module = null;
export async function loadFormat(format) {
  if (format !== 'pdf417' || pdf417Module) return;
  pdf417Module = await import('./pdf417.js');
}

/** Draws a token into `container` as a QR or PDF417 symbol. */
export function renderBarcode(container, token, format) {
  container.replaceChildren();
  if (format === 'pdf417' && pdf417Module) {
    const { encodePDF417, pdf417ToSvg } = pdf417Module;
    // Few columns on purpose. A wide, short symbol looks tidier but packs the modules
    // too tightly to survive a phone camera: measured against blur and a few degrees
    // of tilt, 10 columns failed where 4 held - the modules are simply wider, and the
    // taller rows give the decoder more to sample vertically.
    const symbol = encodePDF417(token, { columns: 4, ecLevel: 4 });
    const { width, height, path } = pdf417ToSvg(symbol, { rowHeight: 4, quietZone: 2 });
    container.appendChild(svgElement(width, height, path, 'PDF417 код пропуска'));
    return { format, version: `${symbol.columns}x${symbol.rows}` };
  }
  const qr = encodeQR(token, { ecc: 'M' });
  const { width, height, path } = qrToSvg(qr, { quietZone: 4 });
  container.appendChild(svgElement(width, height, path, 'QR код пропуска'));
  return { format: 'qr', version: `v${qr.version}` };
}
