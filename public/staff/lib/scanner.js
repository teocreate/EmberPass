/**
 * Reading a code from the camera, two ways.
 *
 * BarcodeDetector is native and fast, but Safari does not implement it, so on an
 * iPhone the scanner would simply not work. There the frames go to a vendored
 * WebAssembly build of ZXing instead, which reads both formats - the same engine
 * this project's encoders were verified against. It costs a one-time 1.1 MB
 * download, so it is fetched only where it is needed and cached afterwards.
 */

const VENDOR_URL = '/staff/lib/vendor/zxing/index.js';
const WASM_URL = '/staff/lib/vendor/zxing/zxing_reader.wasm';
// PDF417 modules are far narrower than a QR module, so the frame has to keep more
// detail than a QR scan needs. Measured at 14 ms per frame at this width, against a
// 320 ms scan interval - the resolution is nearly free, the failed reads were not.
const MAX_FRAME_WIDTH = 1280;

let vendorPromise = null;

/** Loads the WebAssembly decoder once. Its .wasm sits next to the module by design. */
export function loadVendorDecoder() {
  if (!vendorPromise) {
    vendorPromise = import(VENDOR_URL)
      .then((module) => {
        // Left alone the module fetches its .wasm from a CDN, which the page's
        // content security policy forbids - and which would put a gate scanner at the
        // mercy of someone else's uptime. Point it at our own copy.
        module.prepareZXingModule({ overrides: { locateFile: () => WASM_URL }, fireImmediately: true });
        return module;
      })
      .catch((error) => {
        vendorPromise = null; // let a later attempt retry after a failed download
        throw new Error(`не удалось загрузить декодер: ${error.message}`);
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
  const { readBarcodes } = await loadVendorDecoder();
  const canvas = document.createElement('canvas');
  const context = canvas.getContext('2d', { willReadFrequently: true });
  const options = {
    formats: ['QRCode', 'PDF417'],
    tryHarder: true,
    tryRotate: true,
    tryInvert: false, // a code on a phone screen is never inverted
    maxNumberOfSymbols: 1,
  };

  const decode = async (frame) => {
    const results = await readBarcodes(frame, options);
    return results.filter((result) => result.isValid !== false && result.text).map((result) => result.text);
  };

  return {
    kind: 'wasm',
    formats: ['qr_code', 'pdf417'],
    async detect(video) {
      const width = video.videoWidth;
      const height = video.videoHeight;
      if (!width || !height) return [];

      const scale = Math.min(1, MAX_FRAME_WIDTH / width);
      canvas.width = Math.round(width * scale);
      canvas.height = Math.round(height * scale);
      context.drawImage(video, 0, 0, canvas.width, canvas.height);
      return decode(context.getImageData(0, 0, canvas.width, canvas.height));
    },
    /** Exposed so the decode path can be exercised without a camera. */
    decodeImageData: decode,
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
  return scanner.formats.includes('pdf417')
    ? 'Наведите камеру на код пропуска (QR или PDF417)'
    : 'Наведите камеру на QR-код пропуска';
}
