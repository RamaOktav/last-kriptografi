/**
 * stego.js — Secret Note
 * Steganografi gambar LSB (Red/Green/Blue) dengan delimiter 1111111111111110 (0xFF 0xFE).
 * Pesan di-encode UTF-8 (byte 0xFF tidak pernah muncul di UTF-8), sehingga delimiter aman.
 * embedLSBWithTrace juga mengembalikan data "Pixel Bit Inspector".
 */
'use strict';

const STEGO_DELIMITER = '1111111111111110';

function loadImageFromFile(file) {
  return new Promise((resolve, reject) => {
    const url = URL.createObjectURL(file);
    const img = new Image();
    img.onload = () => resolve(img);
    img.onerror = () => reject(new Error('Gagal memuat gambar.'));
    img.src = url;
  });
}

function _drawToCanvas(img) {
  const w = img.naturalWidth || img.width, h = img.naturalHeight || img.height;
  const canvas = document.createElement('canvas');
  canvas.width = w;
  canvas.height = h;
  const ctx = canvas.getContext('2d', { willReadFrequently: true });
  // Latar putih opak: mencegah perubahan RGB akibat alpha premultiplied
  ctx.fillStyle = '#fff';
  ctx.fillRect(0, 0, w, h);
  ctx.drawImage(img, 0, 0);
  return { canvas, ctx, w, h };
}

/** Kapasitas maksimum pesan (byte) untuk sebuah gambar. */
function stegoCapacity(img) {
  const w = img.naturalWidth || img.width, h = img.naturalHeight || img.height;
  return Math.max(0, Math.floor((w * h * 3 - STEGO_DELIMITER.length) / 8));
}

/** @returns {{dataUrl:string, trace:object}} */
function embedLSBWithTrace(imageElement, secretMessage) {
  const { canvas, ctx, w, h } = _drawToCanvas(imageElement);
  const imageData = ctx.getImageData(0, 0, w, h);
  const px = imageData.data;
  const bytes = new TextEncoder().encode(secretMessage);
  let bits = '';
  for (const b of bytes) bits += b.toString(2).padStart(8, '0');
  const messageBitLen = bits.length;
  bits += STEGO_DELIMITER;
  if (bits.length > w * h * 3) throw new Error(`Pesan terlalu panjang. Kapasitas gambar: ${stegoCapacity(imageElement)} byte.`);

  // Sampel 2 piksel pertama (sebelum)
  const samplePx = Math.min(2, w * h);
  const before = [];
  for (let p = 0; p < samplePx; p++) before.push([px[p * 4], px[p * 4 + 1], px[p * 4 + 2]]);

  let bi = 0;
  for (let i = 0; i < px.length && bi < bits.length; i++) {
    if (i % 4 === 3) continue; // lewati alpha
    px[i] = (px[i] & 0xFE) | Number(bits[bi++]);
  }

  const pixels = [];
  for (let p = 0; p < samplePx; p++) {
    pixels.push({
      index: p,
      before: before[p],
      after: [px[p * 4], px[p * 4 + 1], px[p * 4 + 2]],
      bits: [bits[p * 3], bits[p * 3 + 1], bits[p * 3 + 2]],
    });
  }
  ctx.putImageData(imageData, 0, 0);

  const trace = {
    width: w, height: h,
    messageBytes: bytes.length,
    messageBitLen,
    totalBitLen: bits.length,
    capacityBits: w * h * 3,
    capacityBytes: stegoCapacity(imageElement),
    firstChars: Array.from(secretMessage).slice(0, 6).map(c => ({ char: c, bin: Array.from(new TextEncoder().encode(c)).map(b => b.toString(2).padStart(8, '0')).join(' ') })),
    delimiter: STEGO_DELIMITER,
    pixels,
  };
  return { dataUrl: canvas.toDataURL('image/png'), trace };
}

/** @returns {string} data URL PNG stego-image */
const embedLSB = (imageElement, secretMessage) => embedLSBWithTrace(imageElement, secretMessage).dataUrl;

/** @returns {string} pesan rahasia */
function extractLSB(imageElement) {
  const { ctx, w, h } = _drawToCanvas(imageElement);
  const px = ctx.getImageData(0, 0, w, h).data;
  const bytes = [];
  let cur = 0, n = 0;
  for (let i = 0; i < px.length; i++) {
    if (i % 4 === 3) continue;
    cur = (cur << 1) | (px[i] & 1);
    if (++n === 8) {
      if (cur === 0xFF) { // awal delimiter (0xFF 0xFE); 0xFF tidak mungkin muncul di UTF-8
        return new TextDecoder().decode(new Uint8Array(bytes));
      }
      bytes.push(cur);
      cur = 0; n = 0;
    }
  }
  throw new Error('Tidak ditemukan pesan tersembunyi (delimiter tidak ada).');
}
