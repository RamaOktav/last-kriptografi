/**
 * crypto.js — Secret Note
 * Module enkripsi & dekripsi teks menggunakan Web Crypto API (AES-256-GCM).
 * Semua operasi berjalan sepenuhnya di browser, tidak ada data dikirim ke server.
 *
 * Alur enkripsi:
 *   plaintext  →  derive key (PBKDF2)  →  AES-256-GCM encrypt  →  base64 payload
 *
 * Alur dekripsi:
 *   base64 payload  →  extract salt+iv  →  derive key  →  AES-256-GCM decrypt  →  plaintext
 */

'use strict';

// ── Konstanta ────────────────────────────────────────────────────────────────
const PBKDF2_ITERATIONS = 200_000;  // Iterasi PBKDF2 (keamanan vs kecepatan)
const SALT_BYTES        = 16;       // 128-bit salt
const IV_BYTES          = 12;       // 96-bit IV (direkomendasikan untuk GCM)
const KEY_BITS          = 256;      // AES-256

/**
 * Mengkonversi string menjadi Uint8Array (UTF-8).
 * @param {string} str
 * @returns {Uint8Array}
 */
function strToBytes(str) {
  return new TextEncoder().encode(str);
}

/**
 * Mengkonversi Uint8Array menjadi string base64.
 * @param {Uint8Array} bytes
 * @returns {string}
 */
function bytesToBase64(bytes) {
  return btoa(String.fromCharCode(...bytes));
}

/**
 * Mengkonversi string base64 menjadi Uint8Array.
 * @param {string} b64
 * @returns {Uint8Array}
 */
function base64ToBytes(b64) {
  return Uint8Array.from(atob(b64), c => c.charCodeAt(0));
}

/**
 * Mengimpor kata sandi sebagai CryptoKey untuk digunakan di PBKDF2.
 * @param {string} password
 * @returns {Promise<CryptoKey>}
 */
async function importPasswordKey(password) {
  return crypto.subtle.importKey(
    'raw',
    strToBytes(password),
    { name: 'PBKDF2' },
    false,          // tidak bisa diekstrak
    ['deriveKey']
  );
}

/**
 * Menurunkan kunci AES-256-GCM dari kata sandi + salt menggunakan PBKDF2.
 * @param {string}     password
 * @param {Uint8Array} salt
 * @returns {Promise<CryptoKey>}
 */
async function deriveKey(password, salt) {
  const baseKey = await importPasswordKey(password);
  return crypto.subtle.deriveKey(
    {
      name:       'PBKDF2',
      salt:       salt,
      iterations: PBKDF2_ITERATIONS,
      hash:       'SHA-256',
    },
    baseKey,
    { name: 'AES-GCM', length: KEY_BITS },
    false,
    ['encrypt', 'decrypt']
  );
}

/**
 * Mengenkripsi plaintext dengan kata sandi.
 * Menghasilkan payload base64: [salt (16B) | iv (12B) | ciphertext].
 *
 * @param {string} plaintext   - Teks yang akan dienkripsi
 * @param {string} password    - Kata sandi master
 * @returns {Promise<string>}  - Payload terenkripsi dalam format base64
 */
async function encryptText(plaintext, password) {
  const salt       = crypto.getRandomValues(new Uint8Array(SALT_BYTES));
  const iv         = crypto.getRandomValues(new Uint8Array(IV_BYTES));
  const key        = await deriveKey(password, salt);
  const cipherBuf  = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    strToBytes(plaintext)
  );

  // Gabungkan: salt | iv | ciphertext
  const cipherBytes = new Uint8Array(cipherBuf);
  const payload     = new Uint8Array(SALT_BYTES + IV_BYTES + cipherBytes.length);
  payload.set(salt,       0);
  payload.set(iv,         SALT_BYTES);
  payload.set(cipherBytes, SALT_BYTES + IV_BYTES);

  return bytesToBase64(payload);
}

/**
 * Mendekripsi payload base64 kembali menjadi plaintext.
 *
 * @param {string} payloadB64  - Payload terenkripsi (base64)
 * @param {string} password    - Kata sandi master
 * @returns {Promise<string>}  - Teks asli
 * @throws {Error}             - Jika kata sandi salah atau data rusak
 */
async function decryptText(payloadB64, password) {
  const payload    = base64ToBytes(payloadB64);
  const salt       = payload.slice(0, SALT_BYTES);
  const iv         = payload.slice(SALT_BYTES, SALT_BYTES + IV_BYTES);
  const cipherData = payload.slice(SALT_BYTES + IV_BYTES);

  const key = await deriveKey(password, salt);

  try {
    const plainBuf = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv },
      key,
      cipherData
    );
    return new TextDecoder().decode(plainBuf);
  } catch {
    // AES-GCM gagal dekripsi = kata sandi salah atau data korup
    throw new Error('Dekripsi gagal: kata sandi salah atau data rusak.');
  }
}

/**
 * Membuat hash SHA-256 dari kata sandi untuk verifikasi login.
 * Hash disimpan di localStorage, BUKAN kata sandi aslinya.
 *
 * @param {string} password
 * @returns {Promise<string>} - Hash dalam hex
 */
async function hashPassword(password) {
  const buf  = await crypto.subtle.digest('SHA-256', strToBytes(password));
  return Array.from(new Uint8Array(buf))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Memverifikasi apakah kata sandi cocok dengan hash tersimpan.
 *
 * @param {string} password       - Kata sandi yang dimasukkan pengguna
 * @param {string} storedHash     - Hash SHA-256 yang tersimpan
 * @returns {Promise<boolean>}
 */
async function verifyPassword(password, storedHash) {
  const hash = await hashPassword(password);
  return hash === storedHash;
}
