/**
 * crypto.js — Secret Note
 * SHA-256, Vigenère (klasik), AES-256-GCM (modern) dan Super-Enkripsi dua lapis,
 * lengkap dengan "trace" langkah demi langkah untuk visualisasi presentasi.
 *   Enkripsi : Plaintext -> Vigenère -> AES-256-GCM -> Base64
 *   Dekripsi : Base64 -> AES-256-GCM -> Vigenère decrypt -> Plaintext
 */
'use strict';

const PBKDF2_ITERATIONS = 100000;
const AES_SALT_BYTES = 16;
const AES_IV_BYTES = 12;
const AES_TAG_BYTES = 16;

const strToBytes = (s) => new TextEncoder().encode(s);

function bytesToBase64(bytes) {
  let bin = '';
  for (let i = 0; i < bytes.length; i += 8192) bin += String.fromCharCode(...bytes.subarray(i, i + 8192));
  return btoa(bin);
}

function base64ToBytes(b64) {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

/** Hash SHA-256 (hex) dari string atau byte array. */
async function hashSHA256(data) {
  const input = typeof data === 'string' ? strToBytes(data) : data;
  const buf = await crypto.subtle.digest('SHA-256', input);
  return bytesToHex(new Uint8Array(buf));
}

// ── Vigenère (ASCII printable 32..126, karakter lain dibiarkan) ──────────────
const VIG_START = 32;
const VIG_RANGE = 95;

/**
 * @returns {{text:string, steps:Array}} steps: tiap karakter beserta detail pergeseran
 */
function _vigenereCore(text, key, dir) {
  if (!key) throw new Error('Kunci Vigenère tidak boleh kosong.');
  const keyChars = Array.from(key);
  const shifts = keyChars.map(c => c.charCodeAt(0) % VIG_RANGE);
  let ki = 0;
  let out = '';
  const steps = [];
  for (const ch of text) {
    const code = ch.codePointAt(0);
    if (code >= VIG_START && code < VIG_START + VIG_RANGE) {
      const idx = ki++ % shifts.length;
      const shift = shifts[idx] * dir;
      const n = (((code - VIG_START + shift) % VIG_RANGE) + VIG_RANGE) % VIG_RANGE;
      const res = String.fromCharCode(n + VIG_START);
      out += res;
      steps.push({ char: ch, code, keyChar: keyChars[idx], keyShift: shifts[idx], resChar: res, resCode: n + VIG_START, skipped: false });
    } else {
      out += ch;
      steps.push({ char: ch, code, keyChar: '', keyShift: 0, resChar: ch, resCode: code, skipped: true });
    }
  }
  return { text: out, steps };
}

const vigenereEncryptTrace = (p, k) => _vigenereCore(p, k, 1);
const vigenereDecryptTrace = (c, k) => _vigenereCore(c, k, -1);
const vigenereEncrypt = (plaintext, key) => _vigenereCore(plaintext, key, 1).text;
const vigenereDecrypt = (ciphertext, key) => _vigenereCore(ciphertext, key, -1).text;

// ── AES-256-GCM (kunci diturunkan dengan PBKDF2) ─────────────────────────────
async function _deriveBits(password, salt) {
  const base = await crypto.subtle.importKey('raw', strToBytes(password), 'PBKDF2', false, ['deriveBits']);
  return new Uint8Array(await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' }, base, 256));
}
const _aesKeyFromBits = (bits) => crypto.subtle.importKey('raw', bits, 'AES-GCM', false, ['encrypt', 'decrypt']);

/** Output Base64: [salt(16) | iv(12) | ciphertext+tag] + detail langkah. */
async function aesEncryptTrace(plaintext, key) {
  if (!key) throw new Error('Kunci AES tidak boleh kosong.');
  const salt = crypto.getRandomValues(new Uint8Array(AES_SALT_BYTES));
  const iv = crypto.getRandomValues(new Uint8Array(AES_IV_BYTES));
  const keyBits = await _deriveBits(key, salt);
  const k = await _aesKeyFromBits(keyBits);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, k, strToBytes(plaintext)));
  const payload = new Uint8Array(salt.length + iv.length + ct.length);
  payload.set(salt, 0);
  payload.set(iv, salt.length);
  payload.set(ct, salt.length + iv.length);
  return {
    b64: bytesToBase64(payload),
    iterations: PBKDF2_ITERATIONS,
    saltHex: bytesToHex(salt),
    ivHex: bytesToHex(iv),
    keyHex: bytesToHex(keyBits),
    ctHex: bytesToHex(ct.slice(0, ct.length - AES_TAG_BYTES)),
    tagHex: bytesToHex(ct.slice(ct.length - AES_TAG_BYTES)),
    inputLen: strToBytes(plaintext).length,
    payloadLen: payload.length,
  };
}

async function aesDecryptTrace(ciphertextB64, key) {
  if (!key) throw new Error('Kunci AES tidak boleh kosong.');
  let payload;
  try { payload = base64ToBytes(ciphertextB64.trim()); } catch { throw new Error('Ciphertext bukan Base64 yang valid.'); }
  if (payload.length < AES_SALT_BYTES + AES_IV_BYTES + AES_TAG_BYTES) throw new Error('Ciphertext terlalu pendek / rusak.');
  const salt = payload.slice(0, AES_SALT_BYTES);
  const iv = payload.slice(AES_SALT_BYTES, AES_SALT_BYTES + AES_IV_BYTES);
  const data = payload.slice(AES_SALT_BYTES + AES_IV_BYTES);
  const keyBits = await _deriveBits(key, salt);
  const k = await _aesKeyFromBits(keyBits);
  let plain;
  try {
    plain = new TextDecoder().decode(await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, k, data));
  } catch {
    throw new Error('Dekripsi AES gagal: kunci salah atau data rusak.');
  }
  return {
    plain,
    iterations: PBKDF2_ITERATIONS,
    saltHex: bytesToHex(salt),
    ivHex: bytesToHex(iv),
    keyHex: bytesToHex(keyBits),
    ctHex: bytesToHex(data.slice(0, data.length - AES_TAG_BYTES)),
    tagHex: bytesToHex(data.slice(data.length - AES_TAG_BYTES)),
    payloadLen: payload.length,
  };
}

const aesEncrypt = async (plaintext, key) => (await aesEncryptTrace(plaintext, key)).b64;
const aesDecrypt = async (ciphertextB64, key) => (await aesDecryptTrace(ciphertextB64, key)).plain;

// ── Super-Enkripsi ───────────────────────────────────────────────────────────
/** @returns {{plaintext, vigText, vigSteps, aes}} */
async function superEncryptTrace(plaintext, vigenereKey, aesKey) {
  const vig = vigenereEncryptTrace(plaintext, vigenereKey);
  const aes = await aesEncryptTrace(vig.text, aesKey);
  return { plaintext, vigText: vig.text, vigSteps: vig.steps, aes };
}

/** @returns {{aes, vigCipher, vigSteps, plain}} */
async function superDecryptTrace(ciphertext, vigenereKey, aesKey) {
  const aes = await aesDecryptTrace(ciphertext, aesKey);
  const vig = vigenereDecryptTrace(aes.plain, vigenereKey);
  return { aes, vigCipher: aes.plain, vigSteps: vig.steps, plain: vig.text };
}

async function superEncrypt(text, vigenereKey, aesKey) {
  const r = await superEncryptTrace(text, vigenereKey, aesKey);
  return { vigenere: r.vigText, aes: r.aes.b64 };
}

async function superDecrypt(ciphertext, vigenereKey, aesKey) {
  const r = await superDecryptTrace(ciphertext, vigenereKey, aesKey);
  return { vigenere: r.vigCipher, plain: r.plain };
}
