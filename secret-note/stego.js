/**
 * stego.js — Secret Note
 * Steganografi Citra LSB (Red/Green/Blue) dengan Delimiter 1111111111111110 (0xFF 0xFE)
 * serta Optimasi & Kamuflase Ukuran Berkas (Adaptive 24-bit RGB PNG Encoder + Exact Byte-Size Matching).
 *
 * Fitur Utama:
 *   1. Adaptive 24-bit RGB / 32-bit RGBA PNG Encoder (menggunakan PNG Row Filtering + Deflate)
 *      sehingga tidak membengkak akibat channel Alpha mubazir bawaan canvas.toDataURL().
 *   2. Exact Byte-Size Camouflage: menyamakan ukuran byte berkas PNG sebelum & sesudah penyisipan
 *      menggunakan ancillary chunk PNG standar (CRC32 valid), sehingga selisih ukuran berkas
 *      menjadi 0 byte (identik) atau sangat minimal terhadap berkas asli.
 */
'use strict';

const STEGO_DELIMITER = '1111111111111110';
const PNG_SIGNATURE = new Uint8Array([137, 80, 78, 71, 13, 10, 26, 10]);

// ── Tabel & Fungsi CRC32 (Standar ISO 3309 / PNG Specification) ──────────────
const _CRC_TABLE = (() => {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) {
      c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1);
    }
    t[n] = c >>> 0;
  }
  return t;
})();

function crc32(bytes) {
  let c = 0xFFFFFFFF;
  for (let i = 0; i < bytes.length; i++) {
    c = _CRC_TABLE[(c ^ bytes[i]) & 0xFF] ^ (c >>> 8);
  }
  return (c ^ 0xFFFFFFFF) >>> 0;
}

function _u32be(n) {
  return new Uint8Array([
    (n >>> 24) & 0xFF,
    (n >>> 16) & 0xFF,
    (n >>> 8) & 0xFF,
    n & 0xFF,
  ]);
}

function _makeChunk(typeStr, dataBytes) {
  const type = new Uint8Array(4);
  for (let i = 0; i < 4; i++) type[i] = typeStr.charCodeAt(i);
  const len = _u32be(dataBytes.length);
  const crcInput = new Uint8Array(4 + dataBytes.length);
  crcInput.set(type, 0);
  crcInput.set(dataBytes, 4);
  const crc = _u32be(crc32(crcInput));

  const out = new Uint8Array(12 + dataBytes.length);
  out.set(len, 0);
  out.set(crcInput, 4);
  out.set(crc, 8 + dataBytes.length);
  return out;
}

function _paethPredictor(a, b, c) {
  const p = a + b - c;
  const pa = Math.abs(p - a);
  const pb = Math.abs(p - b);
  const pc = Math.abs(p - c);
  if (pa <= pb && pa <= pc) return a;
  if (pb <= pc) return b;
  return c;
}

/** Kompresi zlib stream (RFC 1950) menggunakan CompressionStream('deflate'). */
async function _deflateZlib(rawBytes) {
  if (typeof CompressionStream === 'function') {
    const cs = new CompressionStream('deflate');
    const writer = cs.writable.getWriter();
    writer.write(rawBytes);
    writer.close();
    const chunks = [];
    const reader = cs.readable.getReader();
    let total = 0;
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      chunks.push(value);
      total += value.length;
    }
    const out = new Uint8Array(total);
    let offset = 0;
    for (const ch of chunks) {
      out.set(ch, offset);
      offset += ch.length;
    }
    return out;
  }
  return null;
}

/**
 * Mengkodekan ImageData menjadi PNG biner yang dioptimalkan:
 *   • Otomatis memilih 24-bit RGB (3 byte/px) bila semua piksel opak, atau 32-bit RGBA bila ada alpha.
 *   • Menggunakan Adaptive PNG Row Filtering (Sub / Up / Paeth) agar ukuran berkas minimal.
 */
async function encodeOptimizedPNG(imageData, w, h) {
  const px = imageData.data;
  let hasAlpha = false;
  for (let i = 3; i < px.length; i += 4) {
    if (px[i] < 255) { hasAlpha = true; break; }
  }

  const bpp = hasAlpha ? 4 : 3;
  const colorType = hasAlpha ? 6 : 2; // 2 = Truecolor RGB, 6 = RGBA
  const rowBytes = w * bpp;
  const rawScanlines = new Uint8Array((rowBytes + 1) * h);

  let prevRow = new Uint8Array(rowBytes);
  const curRow = new Uint8Array(rowBytes);
  const fSub = new Uint8Array(rowBytes);
  const fUp = new Uint8Array(rowBytes);
  const fPaeth = new Uint8Array(rowBytes);

  for (let y = 0; y < h; y++) {
    // Salin baris piksel ke curRow (RGB atau RGBA)
    if (bpp === 3) {
      let src = y * w * 4;
      let dst = 0;
      for (let x = 0; x < w; x++) {
        curRow[dst++] = px[src];
        curRow[dst++] = px[src + 1];
        curRow[dst++] = px[src + 2];
        src += 4;
      }
    } else {
      curRow.set(px.subarray(y * w * 4, (y + 1) * w * 4));
    }

    // Evaluasi filter Sub (1), Up (2), dan Paeth (4) menggunakan heuristik minimum sum of absolute differences
    let sumSub = 0, sumUp = 0, sumPaeth = 0;
    for (let i = 0; i < rowBytes; i++) {
      const x = curRow[i];
      const a = i >= bpp ? curRow[i - bpp] : 0;
      const b = prevRow[i];
      const c = i >= bpp ? prevRow[i - bpp] : 0;

      const vSub = (x - a) & 0xFF;
      const vUp = (x - b) & 0xFF;
      const vPaeth = (x - _paethPredictor(a, b, c)) & 0xFF;

      fSub[i] = vSub;
      fUp[i] = vUp;
      fPaeth[i] = vPaeth;

      sumSub += vSub < 128 ? vSub : 256 - vSub;
      sumUp += vUp < 128 ? vUp : 256 - vUp;
      sumPaeth += vPaeth < 128 ? vPaeth : 256 - vPaeth;
    }

    const outOffset = y * (rowBytes + 1);
    if (sumPaeth <= sumSub && sumPaeth <= sumUp) {
      rawScanlines[outOffset] = 4;
      rawScanlines.set(fPaeth, outOffset + 1);
    } else if (sumUp <= sumSub) {
      rawScanlines[outOffset] = 2;
      rawScanlines.set(fUp, outOffset + 1);
    } else {
      rawScanlines[outOffset] = 1;
      rawScanlines.set(fSub, outOffset + 1);
    }

    prevRow.set(curRow);
  }

  const compressed = await _deflateZlib(rawScanlines);
  if (!compressed) {
    // Fallback jika browser tidak mendukung CompressionStream
    const c = document.createElement('canvas');
    c.width = w; c.height = h;
    c.getContext('2d').putImageData(imageData, 0, 0);
    const b64 = c.toDataURL('image/png').split(',')[1];
    const bin = atob(b64);
    const arr = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
    return arr;
  }

  // Bangun chunk IHDR (13 byte)
  const ihdr = new Uint8Array(13);
  ihdr.set(_u32be(w), 0);
  ihdr.set(_u32be(h), 4);
  ihdr[8] = 8; // bit depth 8
  ihdr[9] = colorType;
  ihdr[10] = 0; // compression
  ihdr[11] = 0; // filter
  ihdr[12] = 0; // interlace

  const cIHDR = _makeChunk('IHDR', ihdr);
  const cIDAT = _makeChunk('IDAT', compressed);
  const cIEND = _makeChunk('IEND', new Uint8Array(0));

  const png = new Uint8Array(PNG_SIGNATURE.length + cIHDR.length + cIDAT.length + cIEND.length);
  let pos = 0;
  png.set(PNG_SIGNATURE, pos); pos += PNG_SIGNATURE.length;
  png.set(cIHDR, pos); pos += cIHDR.length;
  png.set(cIDAT, pos); pos += cIDAT.length;
  png.set(cIEND, pos);
  return png;
}

/**
 * Menyisipkan ancillary chunk PNG netral ('caMo') tepat sebelum IEND (12 byte terakhir)
 * sehingga total ukuran berkas PNG menjadi tepat sama dengan targetByteLength.
 */
function padPngToExactSize(pngBytes, targetByteLength) {
  const diff = targetByteLength - pngBytes.length;
  if (diff < 12) return pngBytes;
  const payloadLen = diff - 12; // 4B length + 4B type + 4B CRC = 12B
  const padData = new Uint8Array(payloadLen);
  // Isi dengan pola deterministik bersih (0x00) agar tidak mencurigakan
  const padChunk = _makeChunk('caMo', padData);
  const iendOffset = pngBytes.length - 12;

  const out = new Uint8Array(targetByteLength);
  out.set(pngBytes.subarray(0, iendOffset), 0);
  out.set(padChunk, iendOffset);
  out.set(pngBytes.subarray(iendOffset), iendOffset + padChunk.length);
  return out;
}

/**
 * Menyamakan ukuran dua berkas PNG hingga identik ke satuan byte (0 byte difference).
 * Jika originalPngSize diberikan dan >= ukuran keduanya + 12, keduanya juga disamakan ke originalPngSize.
 */
function equalizePngPairSizes(coverPngBytes, stegoPngBytes, originalPngSize = 0) {
  const maxEncoded = Math.max(coverPngBytes.length, stegoPngBytes.length);
  let target = maxEncoded;

  if (originalPngSize >= maxEncoded + 12 || originalPngSize === maxEncoded) {
    target = originalPngSize;
  } else {
    const gap = Math.abs(coverPngBytes.length - stegoPngBytes.length);
    if (gap > 0 && gap < 12) {
      target = maxEncoded + 12;
    }
  }

  return {
    coverBytes: padPngToExactSize(coverPngBytes, target),
    stegoBytes: padPngToExactSize(stegoPngBytes, target),
    targetBytes: target,
  };
}

function uint8ToDataUrl(bytes, mime = 'image/png') {
  let bin = '';
  for (let i = 0; i < bytes.length; i += 8192) {
    bin += String.fromCharCode(...bytes.subarray(i, i + 8192));
  }
  return `data:${mime};base64,${btoa(bin)}`;
}

// ── Pembaca Gambar & Canvas ──────────────────────────────────────────────────
function loadImageFromFile(file) {
  return new Promise((resolve, reject) => {
    const url = URL.createObjectURL(file);
    const img = new Image();
    img.onload = () => {
      img._fileSize = file.size;
      img._fileType = file.type || '';
      img._fileName = file.name || 'cover.png';
      resolve(img);
    };
    img.onerror = () => reject(new Error('Gagal memuat citra.'));
    img.src = url;
  });
}

function _drawToCanvas(img) {
  const w = img.naturalWidth || img.width;
  const h = img.naturalHeight || img.height;
  const canvas = document.createElement('canvas');
  canvas.width = w;
  canvas.height = h;
  const ctx = canvas.getContext('2d', { willReadFrequently: true });
  ctx.drawImage(img, 0, 0);
  return { canvas, ctx, w, h };
}

/** Kapasitas maksimum pesan (byte) untuk sebuah gambar. */
function stegoCapacity(img) {
  const w = img.naturalWidth || img.width;
  const h = img.naturalHeight || img.height;
  return Math.max(0, Math.floor((w * h * 3 - STEGO_DELIMITER.length) / 8));
}

/**
 * Menyisipkan pesan ke LSB kanal RGB, mengoptimalkan kompresi PNG 24-bit/32-bit,
 * dan menyamakan ukuran byte berkas agar identik (tidak terdeteksi dari selisih ukuran file).
 * @returns {Promise<{dataUrl:string, stegoBlob:Blob, coverNormalizedBlob:Blob, trace:object}>}
 */
async function embedLSBWithTrace(imageElement, secretMessage) {
  const { ctx, w, h } = _drawToCanvas(imageElement);
  const coverImageData = ctx.getImageData(0, 0, w, h);
  const stegoImageData = ctx.getImageData(0, 0, w, h);
  const px = stegoImageData.data;

  // Pastikan piksel tempat pesan disisipkan memiliki alpha = 255 agar nilai RGB tidak berubah oleh premultiplied alpha browser
  const bytes = new TextEncoder().encode(secretMessage);
  let bits = '';
  for (const b of bytes) bits += b.toString(2).padStart(8, '0');
  const messageBitLen = bits.length;
  bits += STEGO_DELIMITER;
  if (bits.length > w * h * 3) {
    throw new Error(`Pesan terlalu panjang. Kapasitas maksimum citra: ${stegoCapacity(imageElement)} byte.`);
  }

  const samplePx = Math.min(2, w * h);
  const before = [];
  for (let p = 0; p < samplePx; p++) {
    before.push([px[p * 4], px[p * 4 + 1], px[p * 4 + 2]]);
  }

  let bi = 0;
  for (let i = 0; i < px.length && bi < bits.length; i++) {
    if (i % 4 === 3) {
      px[i] = 255;
      continue;
    }
    px[i] = (px[i] & 0xFE) | Number(bits[bi++]);
    if (i % 4 === 2) px[i + 1] = 255;
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

  // Encode cover & stego dengan Adaptive 24-bit RGB / 32-bit RGBA PNG Encoder
  const rawCoverPng = await encodeOptimizedPNG(coverImageData, w, h);
  const rawStegoPng = await encodeOptimizedPNG(stegoImageData, w, h);

  const isOrigPng = (imageElement._fileType || '').includes('png') || /\.png$/i.test(imageElement._fileName || '');
  const origFileSize = imageElement._fileSize || 0;

  // Samakan ukuran byte secara presisi
  const equalized = equalizePngPairSizes(rawCoverPng, rawStegoPng, isOrigPng ? origFileSize : 0);
  const stegoBytes = equalized.stegoBytes;
  const coverBytes = equalized.coverBytes;

  const referenceSize = (isOrigPng && origFileSize === stegoBytes.length) ? origFileSize : coverBytes.length;
  const sizeDiff = stegoBytes.length - referenceSize;

  const trace = {
    width: w,
    height: h,
    messageBytes: bytes.length,
    messageBitLen,
    totalBitLen: bits.length,
    capacityBits: w * h * 3,
    capacityBytes: stegoCapacity(imageElement),
    origUploadBytes: origFileSize,
    isOrigPng,
    rawCoverPngBytes: rawCoverPng.length,
    rawStegoPngBytes: rawStegoPng.length,
    coverFinalBytes: coverBytes.length,
    stegoFinalBytes: stegoBytes.length,
    sizeDiffBytes: sizeDiff,
    firstChars: Array.from(secretMessage).slice(0, 6).map(c => ({
      char: c,
      bin: Array.from(new TextEncoder().encode(c)).map(b => b.toString(2).padStart(8, '0')).join(' '),
    })),
    delimiter: STEGO_DELIMITER,
    pixels,
  };

  return {
    dataUrl: uint8ToDataUrl(stegoBytes, 'image/png'),
    stegoBlob: new Blob([stegoBytes], { type: 'image/png' }),
    coverNormalizedBlob: new Blob([coverBytes], { type: 'image/png' }),
    trace,
  };
}

/** Wrapper untuk kompatibilitas. */
async function embedLSB(imageElement, secretMessage) {
  return (await embedLSBWithTrace(imageElement, secretMessage)).dataUrl;
}

/** Mengekstrak pesan rahasia dari piksel LSB hingga menemukan delimiter 16-bit. */
function extractLSB(imageElement) {
  const { ctx, w, h } = _drawToCanvas(imageElement);
  const px = ctx.getImageData(0, 0, w, h).data;
  const bytes = [];
  let cur = 0, n = 0;
  for (let i = 0; i < px.length; i++) {
    if (i % 4 === 3) continue;
    cur = (cur << 1) | (px[i] & 1);
    if (++n === 8) {
      if (cur === 0xFF) {
        return new TextDecoder().decode(new Uint8Array(bytes));
      }
      bytes.push(cur);
      cur = 0;
      n = 0;
    }
  }
  throw new Error('Tidak ditemukan pesan tersembunyi pada citra ini (delimiter tidak ditemukan).');
}
