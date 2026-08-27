import { encodeQR, qrToSvg } from './qrcode.js';
import { encodePDF417, pdf417ToSvg } from './pdf417.js';

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

/** Draws a token into `container` as a QR or PDF417 symbol. */
export function renderBarcode(container, token, format) {
  container.replaceChildren();
  if (format === 'pdf417') {
    // A wide, short symbol scans better off a phone screen than a tall one.
    const symbol = encodePDF417(token, { columns: 10, ecLevel: 4 });
    const { width, height, path } = pdf417ToSvg(symbol, { rowHeight: 3, quietZone: 2 });
    container.appendChild(svgElement(width, height, path, 'PDF417 код пропуска'));
    return { format, version: `${symbol.columns}x${symbol.rows}` };
  }
  const qr = encodeQR(token, { ecc: 'M' });
  const { width, height, path } = qrToSvg(qr, { quietZone: 4 });
  container.appendChild(svgElement(width, height, path, 'QR код пропуска'));
  return { format: 'qr', version: `v${qr.version}` };
}
