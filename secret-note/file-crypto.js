/**
 * file-crypto.js — Secret Note
 * Module enkripsi & dekripsi file menggunakan Web Crypto API (AES-256-GCM).
 * File diproses sebagai ArrayBuffer di browser — tidak ada upload ke server.
 *
 * Format payload terenkripsi:
 *   [salt (16B) | iv (12B) | filenameLength (4B, uint32) | filename (UTF-8) | ciphertext]
 *
 * Semua file tersimpan di localStorage sebagai base64, bersama metadata:
 *   { id, originalName, encryptedType, size, encryptedAt, payloadB64 }
 */

'use strict';

// ── Konstanta ─────────────────────────────────────────────────────────────────
const FILE_SALT_BYTES = 16;
const FILE_IV_BYTES   = 12;
const MAX_FILE_BYTES  = 50 * 1024 * 1024; // 50 MB

// ── Helpers ───────────────────────────────────────────────────────────────────

/**
 * Mengkonversi ArrayBuffer menjadi string base64.
 * @param {ArrayBuffer} buffer
 * @returns {string}
 */
function bufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let bin = '';
  // Gunakan chunk agar tidak overflow call stack pada file besar
  const chunkSize = 8192;
  for (let i = 0; i < bytes.length; i += chunkSize) {
    bin += String.fromCharCode(...bytes.subarray(i, i + chunkSize));
  }
  return btoa(bin);
}

/**
 * Mengkonversi string base64 menjadi ArrayBuffer.
 * @param {string} b64
 * @returns {ArrayBuffer}
 */
function base64ToBuffer(b64) {
  const bin   = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes.buffer;
}

/**
 * Menurunkan CryptoKey dari kata sandi + salt (PBKDF2 → AES-256-GCM).
 * Menggunakan fungsi yang sama persis dengan crypto.js untuk konsistensi.
 * @param {string}     password
 * @param {Uint8Array} salt
 * @returns {Promise<CryptoKey>}
 */
async function deriveFileKey(password, salt) {
  const baseKey = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(password),
    { name: 'PBKDF2' },
    false,
    ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: 200_000, hash: 'SHA-256' },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

// ── API Publik ────────────────────────────────────────────────────────────────

/**
 * Mengenkripsi sebuah File dan menyimpannya ke localStorage.
 * Memanggil onProgress(percent) secara berkala selama proses berlangsung.
 *
 * @param {File}     file         - File yang akan dienkripsi
 * @param {string}   password     - Kata sandi master
 * @param {Function} onProgress   - Callback progress (0–100)
 * @returns {Promise<Object>}     - Metadata file terenkripsi
 */
async function encryptFile(file, password, onProgress = () => {}) {
  if (file.size > MAX_FILE_BYTES) {
    throw new Error(`Ukuran file melebihi batas ${MAX_FILE_BYTES / 1024 / 1024} MB.`);
  }

  onProgress(10);

  // Baca file sebagai ArrayBuffer
  const fileBuffer = await file.arrayBuffer();
  onProgress(30);

  // Siapkan salt & iv
  const salt = crypto.getRandomValues(new Uint8Array(FILE_SALT_BYTES));
  const iv   = crypto.getRandomValues(new Uint8Array(FILE_IV_BYTES));
  const key  = await deriveFileKey(password, salt);
  onProgress(50);

  // Encode nama file agar bisa dipulihkan saat dekripsi
  const filenameBytes  = new TextEncoder().encode(file.name);
  const filenameLenBuf = new Uint8Array(4);
  new DataView(filenameLenBuf.buffer).setUint32(0, filenameBytes.length, false);

  // Gabungkan: filenameLength | filename | fileContent
  const plainCombined = new Uint8Array(
    4 + filenameBytes.length + fileBuffer.byteLength
  );
  plainCombined.set(filenameLenBuf,    0);
  plainCombined.set(filenameBytes,     4);
  plainCombined.set(new Uint8Array(fileBuffer), 4 + filenameBytes.length);

  // Enkripsi
  const cipherBuf   = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    plainCombined
  );
  onProgress(80);

  // Bangun payload akhir: salt | iv | ciphertext
  const cipherBytes = new Uint8Array(cipherBuf);
  const payload     = new Uint8Array(FILE_SALT_BYTES + FILE_IV_BYTES + cipherBytes.length);
  payload.set(salt,        0);
  payload.set(iv,          FILE_SALT_BYTES);
  payload.set(cipherBytes, FILE_SALT_BYTES + FILE_IV_BYTES);

  const payloadB64 = bufferToBase64(payload.buffer);
  onProgress(95);

  // Metadata yang disimpan (tanpa data plaintext)
  const meta = {
    id:            crypto.randomUUID(),
    originalName:  file.name,
    mimeType:      file.type || 'application/octet-stream',
    size:          file.size,
    encryptedAt:   new Date().toISOString(),
    payloadB64:    payloadB64,
  };

  // Simpan ke localStorage
  const stored = getStoredFiles();
  stored.push(meta);
  localStorage.setItem('sn_files', JSON.stringify(stored));

  onProgress(100);
  return meta;
}

/**
 * Mendekripsi file dan memicu download di browser.
 *
 * @param {string} fileId    - ID file yang tersimpan
 * @param {string} password  - Kata sandi master
 * @returns {Promise<void>}
 */
async function decryptAndDownloadFile(fileId, password) {
  const stored = getStoredFiles();
  const meta   = stored.find(f => f.id === fileId);
  if (!meta) throw new Error('File tidak ditemukan.');

  const payload    = new Uint8Array(base64ToBuffer(meta.payloadB64));
  const salt       = payload.slice(0, FILE_SALT_BYTES);
  const iv         = payload.slice(FILE_SALT_BYTES, FILE_SALT_BYTES + FILE_IV_BYTES);
  const cipherData = payload.slice(FILE_SALT_BYTES + FILE_IV_BYTES);

  const key = await deriveFileKey(password, salt);

  let plainBuf;
  try {
    plainBuf = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, cipherData);
  } catch {
    throw new Error('Dekripsi gagal: kata sandi salah atau file rusak.');
  }

  // Ekstrak nama file dari payload
  const plain          = new Uint8Array(plainBuf);
  const filenameLen    = new DataView(plain.buffer).getUint32(0, false);
  const filenameBytes  = plain.slice(4, 4 + filenameLen);
  const originalName   = new TextDecoder().decode(filenameBytes);
  const fileData       = plain.slice(4 + filenameLen);

  // Buat URL sementara dan trigger download
  const blob = new Blob([fileData], { type: meta.mimeType });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement('a');
  a.href     = url;
  a.download = originalName;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  // Bebaskan memory setelah 60 detik
  setTimeout(() => URL.revokeObjectURL(url), 60_000);
}

/**
 * Menghapus file terenkripsi dari localStorage berdasarkan ID.
 * @param {string} fileId
 */
function deleteEncryptedFile(fileId) {
  const stored  = getStoredFiles().filter(f => f.id !== fileId);
  localStorage.setItem('sn_files', JSON.stringify(stored));
}

/**
 * Mengambil seluruh metadata file dari localStorage.
 * @returns {Array<Object>}
 */
function getStoredFiles() {
  try {
    return JSON.parse(localStorage.getItem('sn_files') || '[]');
  } catch {
    return [];
  }
}

/**
 * Memformat ukuran file menjadi string yang mudah dibaca (KB, MB, dll).
 * @param {number} bytes
 * @returns {string}
 */
function formatFileSize(bytes) {
  if (bytes < 1024)           return `${bytes} B`;
  if (bytes < 1024 * 1024)    return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(2)} MB`;
}
