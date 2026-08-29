/**
 * Reading a code from the camera, two ways.
 *
 * BarcodeDetector is native, fast and handles both QR and PDF417 - but Safari does
 * not implement it, so on an iPhone the scanner would simply not work. There the
 * frames are decoded in JavaScript instead, with a vendored jsQR. That path is
 * QR-only: there is no pure-JS PDF417 decoder here, and the holder app can switch
 * its code to QR with one tap.
 */

const VENDOR_URL = '/staff/lib/vendor/jsqr.min.js';
const MAX_FRAME_WIDTH = 640; // decoding a full-resolution frame is needlessly slow

let vendorPromise = null;

function loadVendorDecoder() {
  if (!vendorPromise) {
    vendorPromise = new Promise((resolve, reject) => {
      const script = document.createElement('script');
      script.src = VENDOR_URL;
      script.onload = () => (window.jsQR ? resolve(window.jsQR) : reject(new Error('декодер загрузился без jsQR')));
      script.onerror = () => reject(new Error('не удалось загрузить декодер QR'));
      document.head.appendChild(script);
    });
  }
  return vendorPromise;
}

async function nativeScanner() {
  const supported = await window.BarcodeDetector.getSupportedFormats();
  const formats = ['qr_code', 'pdf417'].filter((format) => supported.includes(format));
  if (!formats.length) return null;
  const detector = new window.BarcodeDetector({ formats });
  return {
    kind: 'native',
    formats,
    async detect(video) {
      const codes = await detector.detect(video);
      return codes.map((code) => code.rawValue);
    },
  };
}

async function fallbackScanner() {
  const jsQR = await loadVendorDecoder();
  const canvas = document.createElement('canvas');
  const context = canvas.getContext('2d', { willReadFrequently: true });

  return {
    kind: 'jsqr',
    formats: ['qr_code'],
    async detect(video) {
      const width = video.videoWidth;
      const height = video.videoHeight;
      if (!width || !height) return [];

      const scale = Math.min(1, MAX_FRAME_WIDTH / width);
      canvas.width = Math.round(width * scale);
      canvas.height = Math.round(height * scale);
      context.drawImage(video, 0, 0, canvas.width, canvas.height);
      const frame = context.getImageData(0, 0, canvas.width, canvas.height);

      const result = jsQR(frame.data, frame.width, frame.height, { inversionAttempts: 'dontInvert' });
      return result?.data ? [result.data] : [];
    },
    /** Exposed so the decode path can be exercised without a camera. */
    decodeImageData(frame) {
      const result = jsQR(frame.data, frame.width, frame.height, { inversionAttempts: 'dontInvert' });
      return result?.data ?? null;
    },
  };
}

/** Picks the best available way to read codes, or throws if there is none. */
export async function createScanner() {
  if ('BarcodeDetector' in window) {
    try {
      const native = await nativeScanner();
      if (native) return native;
    } catch {
      // A present but unusable BarcodeDetector still leaves the fallback.
    }
  }
  return fallbackScanner();
}

export function describeScanner(scanner) {
  if (scanner.kind === 'native') {
    return scanner.formats.includes('pdf417')
      ? 'Наведите камеру на код пропуска (QR или PDF417)'
      : 'Наведите камеру на QR-код пропуска';
  }
  return 'Наведите камеру на QR-код пропуска (PDF417 в этом браузере не читается)';
}
