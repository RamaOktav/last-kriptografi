/**
 * db.js — Secret Note
 * Dual-Engine Storage Layer:
 *   1. Primary : SQLite Server API (/api/...) -> menyimpan langsung ke file SQLite secret-note.db
 *                dan dapat diinspeksi melalui Web GUI http://localhost:3000/db-admin
 *   2. Fallback: IndexedDB (SecretNoteCryptoDB) apabila dibuka melalui static server biasa.
 */
'use strict';

const DB_NAME = 'SecretNoteCryptoDB';
const DB_VERSION = 2;
const DB_STORES = ['users', 'blockchain_ledger', 'vault_text', 'vault_files'];

let _idb = null;
let _useServer = null; // true = SQLite backend, false = IndexedDB fallback

function _bufToB64(buffer) {
  const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  let bin = '';
  for (let i = 0; i < bytes.length; i += 8192) {
    bin += String.fromCharCode(...bytes.subarray(i, i + 8192));
  }
  return btoa(bin);
}

function _b64ToBuf(b64) {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out.buffer;
}

async function _api(path, opts = {}) {
  const res = await fetch(path, {
    headers: { 'Content-Type': 'application/json' },
    ...opts,
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
  return data;
}

function _openIDB() {
  if (_idb) return Promise.resolve(_idb);
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = (e) => {
      const db = req.result;
      if (e.oldVersion < 2) {
        for (const name of Array.from(db.objectStoreNames)) db.deleteObjectStore(name);
      }
      if (!db.objectStoreNames.contains('users')) db.createObjectStore('users', { keyPath: 'username' });
      if (!db.objectStoreNames.contains('blockchain_ledger')) db.createObjectStore('blockchain_ledger', { keyPath: 'index' });
      if (!db.objectStoreNames.contains('vault_text')) {
        db.createObjectStore('vault_text', { keyPath: 'id', autoIncrement: true }).createIndex('username', 'username');
      }
      if (!db.objectStoreNames.contains('vault_files')) {
        db.createObjectStore('vault_files', { keyPath: 'id', autoIncrement: true }).createIndex('username', 'username');
      }
    };
    req.onsuccess = () => { _idb = req.result; resolve(_idb); };
    req.onerror = () => reject(req.error);
  });
}

function _tx(store, mode, fn) {
  return _openIDB().then(db => new Promise((resolve, reject) => {
    const tx = db.transaction(store, mode);
    const result = fn(tx.objectStore(store));
    tx.oncomplete = () => resolve(result && 'result' in result ? result.result : undefined);
    tx.onerror = () => reject(tx.error);
    tx.onabort = () => reject(tx.error);
  }));
}

/** Inisialisasi koneksi storage (deteksi SQLite server terlebih dahulu). */
async function initDB() {
  if (_useServer !== null) return _useServer;
  try {
    const ping = await fetch('/api/ping', { cache: 'no-store' });
    if (ping.ok) {
      _useServer = true;
      return true;
    }
  } catch { /* fallback ke IndexedDB */ }
  _useServer = false;
  await _openIDB();
  return false;
}

function isUsingSqliteServer() {
  return _useServer === true;
}

// ── Users ────────────────────────────────────────────────────────────────────
async function registerUser(user) {
  await initDB();
  if (_useServer) return _api('/api/users', { method: 'POST', body: JSON.stringify(user) });
  try {
    return await _tx('users', 'readwrite', s => s.add(user));
  } catch (e) {
    throw new Error(e && e.name === 'ConstraintError' ? `Username "${user.username}" sudah terdaftar.` : (e.message || e));
  }
}

async function getUser(username) {
  await initDB();
  if (_useServer) return _api(`/api/users/${encodeURIComponent(username)}`);
  return _tx('users', 'readonly', s => s.get(username));
}

async function getAllUsers() {
  await initDB();
  if (_useServer) return _api('/api/users');
  return _tx('users', 'readonly', s => s.getAll());
}

// ── Vault Text (Terisolasi per user) ─────────────────────────────────────────
async function saveVaultText(record) {
  await initDB();
  if (_useServer) return _api('/api/vault-text', { method: 'POST', body: JSON.stringify(record) });
  return _tx('vault_text', 'readwrite', s => s.put(record));
}

async function getVaultTextsByUser(username) {
  await initDB();
  if (_useServer) return _api(`/api/vault-text?username=${encodeURIComponent(username)}`);
  return _tx('vault_text', 'readonly', s => s.index('username').getAll(username));
}

async function deleteVaultText(id, username) {
  await initDB();
  if (_useServer) return _api(`/api/vault-text/${id}?username=${encodeURIComponent(username || '')}`, { method: 'DELETE' });
  return _tx('vault_text', 'readwrite', s => s.delete(id));
}

// ── Vault Files (Terisolasi per user) ────────────────────────────────────────
async function saveVaultFile(record) {
  await initDB();
  if (_useServer) {
    const payload = {
      username: record.username,
      originalName: record.originalName,
      size: record.size,
      sha256: record.sha256,
      createdAt: record.createdAt,
      dataB64: _bufToB64(record.data),
    };
    return _api('/api/vault-files', { method: 'POST', body: JSON.stringify(payload) });
  }
  return _tx('vault_files', 'readwrite', s => s.put(record));
}

async function getVaultFilesByUser(username) {
  await initDB();
  if (_useServer) return _api(`/api/vault-files?username=${encodeURIComponent(username)}`);
  return _tx('vault_files', 'readonly', s => s.index('username').getAll(username));
}

async function getVaultFile(id) {
  await initDB();
  if (_useServer) {
    const r = await _api(`/api/vault-files/${id}`);
    return { ...r, data: _b64ToBuf(r.dataB64) };
  }
  return _tx('vault_files', 'readonly', s => s.get(id));
}

async function deleteVaultFile(id) {
  await initDB();
  if (_useServer) return _api(`/api/vault-files/${id}`, { method: 'DELETE' });
  return _tx('vault_files', 'readwrite', s => s.delete(id));
}

// ── Blockchain Ledger ────────────────────────────────────────────────────────
async function addBlockToDB(block) {
  await initDB();
  if (_useServer) return _api('/api/blockchain', { method: 'POST', body: JSON.stringify(block) });
  return _tx('blockchain_ledger', 'readwrite', s => s.put({ ...block }));
}

async function getAllBlocksFromDB() {
  await initDB();
  if (_useServer) return _api('/api/blockchain');
  const rows = await _tx('blockchain_ledger', 'readonly', s => s.getAll());
  return rows.sort((a, b) => a.index - b.index);
}

// ── Inspector & Reset ────────────────────────────────────────────────────────
async function getAllDatabaseData() {
  await initDB();
  if (_useServer) return _api('/api/dump');
  const out = {};
  for (const s of DB_STORES) out[s] = await _tx(s, 'readonly', st => st.getAll());
  return out;
}

async function clearAllDatabaseData() {
  await initDB();
  if (_useServer) return _api('/api/reset', { method: 'POST' });
  for (const s of DB_STORES) await _tx(s, 'readwrite', st => st.clear());
}
