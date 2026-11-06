/**
 * db.js — Secret Note
 * Database client-side berbasis IndexedDB (SecretNoteCryptoDB).
 * Dapat diinspeksi via DevTools (F12 > Application > IndexedDB) atau Database Inspector di Tab 5.
 */
'use strict';

const DB_NAME = 'SecretNoteCryptoDB';
const DB_VERSION = 1;
const DB_STORES = ['blockchain_ledger', 'vault_text', 'vault_files', 'auth_store'];

let _db = null;

/** Membuka koneksi database dan membuat object store bila belum ada. */
function initDB() {
  if (_db) return Promise.resolve(_db);
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains('blockchain_ledger')) db.createObjectStore('blockchain_ledger', { keyPath: 'index' });
      if (!db.objectStoreNames.contains('vault_text')) db.createObjectStore('vault_text', { keyPath: 'id', autoIncrement: true });
      if (!db.objectStoreNames.contains('vault_files')) db.createObjectStore('vault_files', { keyPath: 'id', autoIncrement: true });
      if (!db.objectStoreNames.contains('auth_store')) db.createObjectStore('auth_store', { keyPath: 'key' });
    };
    req.onsuccess = () => { _db = req.result; resolve(_db); };
    req.onerror = () => reject(req.error);
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
const dbGetAll = (store) => _tx(store, 'readonly', s => s.getAll());
const dbGet = (store, key) => _tx(store, 'readonly', s => s.get(key));
const dbDelete = (store, key) => _tx(store, 'readwrite', s => s.delete(key));
const dbClear = (store) => _tx(store, 'readwrite', s => s.clear());

const addBlockToDB = (block) => dbPut('blockchain_ledger', { ...block });
const getAllBlocksFromDB = async () => (await dbGetAll('blockchain_ledger')).sort((a, b) => a.index - b.index);
const saveVaultText = (record) => dbPut('vault_text', record);
const getVaultTexts = () => dbGetAll('vault_text');
const saveVaultFile = (record) => dbPut('vault_files', record);
const getVaultFiles = () => dbGetAll('vault_files');
const deleteVaultFile = (id) => dbDelete('vault_files', id);
const setAuth = (key, value) => dbPut('auth_store', { key, value });
const getAuth = async (key) => { const r = await dbGet('auth_store', key); return r ? r.value : null; };

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
