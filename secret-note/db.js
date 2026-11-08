/**
 * db.js — Secret Note
 * Database client-side multi-user berbasis IndexedDB (SecretNoteCryptoDB).
 * Dapat diinspeksi via DevTools (F12 > Application > IndexedDB) atau Database Inspector di Tab 5.
 *
 * Object stores:
 *   users             keyPath 'username'  { username, pinHash, dongleSerial, faceDescriptor, createdAt }
 *   vault_text        keyPath 'id' (auto) { id, username, ciphertext, createdAt }        index: username
 *   vault_files       keyPath 'id' (auto) { id, username, originalName, size, data, sha256, createdAt }  index: username
 *   blockchain_ledger keyPath 'index'     { index, timestamp, username, data, previousHash, hash }
 */
'use strict';

const DB_NAME = 'SecretNoteCryptoDB';
const DB_VERSION = 2;
const DB_STORES = ['users', 'blockchain_ledger', 'vault_text', 'vault_files'];

let _db = null;

/** Membuka koneksi database dan membuat skema. Upgrade dari v1 (single-user) mereset skema lama. */
function initDB() {
  if (_db) return Promise.resolve(_db);
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = (e) => {
      const db = req.result;
      if (e.oldVersion < 2) {
        // Skema v1 (single-user, blok tanpa username) tidak kompatibel → buat ulang
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
    req.onsuccess = () => { _db = req.result; resolve(_db); };
    req.onerror = () => reject(req.error);
    req.onblocked = () => reject(new Error('Database sedang dipakai tab lain. Tutup tab lain lalu muat ulang.'));
  });
}

function _tx(store, mode, fn) {
  return initDB().then(db => new Promise((resolve, reject) => {
    const tx = db.transaction(store, mode);
    const result = fn(tx.objectStore(store));
    tx.oncomplete = () => resolve(result && 'result' in result ? result.result : undefined);
    tx.onerror = () => reject(tx.error);
    tx.onabort = () => reject(tx.error);
  }));
}

const dbPut = (store, value) => _tx(store, 'readwrite', s => s.put(value));
const dbAdd = (store, value) => _tx(store, 'readwrite', s => s.add(value));
const dbGetAll = (store) => _tx(store, 'readonly', s => s.getAll());
const dbGet = (store, key) => _tx(store, 'readonly', s => s.get(key));
const dbDelete = (store, key) => _tx(store, 'readwrite', s => s.delete(key));
const dbClear = (store) => _tx(store, 'readwrite', s => s.clear());
const dbGetByIndex = (store, index, value) => _tx(store, 'readonly', s => s.index(index).getAll(value));

// ── Users ────────────────────────────────────────────────────────────────────
/** Mendaftarkan user baru. Gagal jika username sudah ada. */
async function registerUser(user) {
  try { await dbAdd('users', user); }
  catch (e) { throw new Error(e && e.name === 'ConstraintError' ? `Username "${user.username}" sudah terdaftar.` : (e.message || e)); }
}
const getUser = (username) => dbGet('users', username);
const getAllUsers = () => dbGetAll('users');

// ── Vault (terisolasi per user) ──────────────────────────────────────────────
const saveVaultText = (record) => dbPut('vault_text', record);
const getVaultTextsByUser = (username) => dbGetByIndex('vault_text', 'username', username);
const saveVaultFile = (record) => dbPut('vault_files', record);
const getVaultFilesByUser = (username) => dbGetByIndex('vault_files', 'username', username);
const getVaultFile = (id) => dbGet('vault_files', id);
const deleteVaultFile = (id) => dbDelete('vault_files', id);

// ── Blockchain ───────────────────────────────────────────────────────────────
const addBlockToDB = (block) => dbPut('blockchain_ledger', { ...block });
const getAllBlocksFromDB = async () => (await dbGetAll('blockchain_ledger')).sort((a, b) => a.index - b.index);

// ── Inspector ────────────────────────────────────────────────────────────────
/** Snapshot seluruh database { storeName: [records] }. */
async function getAllDatabaseData() {
  const out = {};
  for (const s of DB_STORES) out[s] = await dbGetAll(s);
  return out;
}

/** Menghapus seluruh data pada semua object store. */
async function clearAllDatabaseData() {
  for (const s of DB_STORES) await dbClear(s);
}
