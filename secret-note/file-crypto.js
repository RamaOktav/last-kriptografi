/**
 * file-crypto.js — Secret Note
 * Enkripsi berkas dengan RC4 (stream cipher), berbeda dari algoritma teks (Vigenère + AES).
 * Dilengkapi trace KSA / PRGA / XOR untuk visualisasi presentasi.
 *
 * Format plaintext sebelum dienkripsi RC4:
 *   "RC4F"(4B magic) | nameLen(uint16 BE) | nama file (UTF-8) | data file
 * Magic dipakai untuk mendeteksi kunci yang salah saat dekripsi.
 */
'use strict';

const FILE_MAGIC = [0x52, 0x43, 0x34, 0x46]; // "RC4F"
const MAX_FILE_BYTES = 50 * 1024 * 1024;
const RC4_TRACE_SAMPLE = 16;
const RC4_TRACE_ROWS = 10;

/**
 * RC4: KSA + PRGA. Simetris — enkripsi dan dekripsi memakai fungsi yang sama.
 * @param {boolean} withTrace  jika true, kembalikan {out, trace}
 */
function rc4Core(keyBytes, data, withTrace) {
  if (!keyBytes.length) throw new Error('Kunci RC4 tidak boleh kosong.');
  const S = new Uint8Array(256);
  for (let i = 0; i < 256; i++) S[i] = i;
  const trace = withTrace ? { keyBytes: Array.from(keyBytes), sBefore: Array.from(S.slice(0, RC4_TRACE_SAMPLE)), keystream: [], rows: [] } : null;
  // KSA
  let j = 0;
  for (let i = 0; i < 256; i++) {
    j = (j + S[i] + keyBytes[i % keyBytes.length]) & 255;
    [S[i], S[j]] = [S[j], S[i]];
  }
  if (trace) trace.sAfter = Array.from(S.slice(0, RC4_TRACE_SAMPLE));
  // PRGA
  const out = new Uint8Array(data.length);
  let a = 0, b = 0;
  for (let n = 0; n < data.length; n++) {
    a = (a + 1) & 255;
    b = (b + S[a]) & 255;
    [S[a], S[b]] = [S[b], S[a]];
    const ks = S[(S[a] + S[b]) & 255];
    out[n] = data[n] ^ ks;
    if (trace && n < RC4_TRACE_SAMPLE) trace.keystream.push(ks);
    if (trace && n < RC4_TRACE_ROWS) trace.rows.push({ index: n, input: data[n], keystream: ks, output: out[n] });
  }
  return withTrace ? { out, trace } : out;
}

const rc4 = (keyBytes, data) => rc4Core(keyBytes, data, false);

/** Membaca File sebagai ArrayBuffer memakai FileReader. */
function readFileAsArrayBuffer(file) {
  return new Promise((resolve, reject) => {
    const fr = new FileReader();
    fr.onload = () => resolve(fr.result);
    fr.onerror = () => reject(fr.error);
    fr.readAsArrayBuffer(file);
  });
}

/** @returns {Promise<{bytes:Uint8Array, trace:object}>} */
async function encryptFileRC4(file, password) {
  if (file.size > MAX_FILE_BYTES) throw new Error('Ukuran file melebihi 50 MB.');
  const data = new Uint8Array(await readFileAsArrayBuffer(file));
  const name = strToBytes(file.name);
  const plain = new Uint8Array(6 + name.length + data.length);
  plain.set(FILE_MAGIC, 0);
  plain[4] = (name.length >> 8) & 255;
  plain[5] = name.length & 255;
  plain.set(name, 6);
  plain.set(data, 6 + name.length);
  const { out, trace } = rc4Core(strToBytes(password), plain, true);
  trace.package = { magic: 'RC4F', nameLen: name.length, name: file.name, dataLen: data.length, totalLen: plain.length };
  return { bytes: out, trace };
}

/** @returns {Promise<{name:string,data:Uint8Array,trace:object}>} */
async function decryptFileRC4(file, password) {
  const enc = new Uint8Array(await readFileAsArrayBuffer(file));
  const { out: plain, trace } = rc4Core(strToBytes(password), enc, true);
  if (plain.length < 6 || FILE_MAGIC.some((m, i) => plain[i] !== m)) {
    throw new Error('Dekripsi gagal: kunci salah atau bukan file .enc yang valid.');
  }
  const nameLen = (plain[4] << 8) | plain[5];
  if (6 + nameLen > plain.length) throw new Error('File rusak.');
  const name = new TextDecoder().decode(plain.slice(6, 6 + nameLen));
  const data = plain.slice(6 + nameLen);
  trace.package = { magic: 'RC4F', nameLen, name, dataLen: data.length, totalLen: plain.length };
  return { name, data, trace };
}

/** Memicu unduhan Blob. */
function downloadBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}
