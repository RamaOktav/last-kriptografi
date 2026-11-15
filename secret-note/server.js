/**
 * server.js — Secret Note Local Server & SQLite Engine
 * Menyajikan aplikasi utama di http://localhost:3000
 * serta Web GUI Database Admin di http://localhost:3000/db-admin
 * Menggunakan modul bawaan Node.js (node:sqlite, http, fs, path) — tanpa dependency eksternal.
 */
'use strict';

const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const { DatabaseSync } = require('node:sqlite');

const PORT = Number(process.env.PORT) || 3000;
const ROOT_DIR = __dirname;
const DB_PATH = path.join(ROOT_DIR, 'secret-note.db');

// ── Inisialisasi SQLite Database ─────────────────────────────────────────────
const db = new DatabaseSync(DB_PATH);
db.exec(`
  PRAGMA journal_mode = WAL;
  PRAGMA foreign_keys = ON;

  CREATE TABLE IF NOT EXISTS users (
    username        TEXT PRIMARY KEY,
    pin_hash        TEXT NOT NULL,
    dongle_serial   TEXT NOT NULL,
    face_descriptor TEXT,
    created_at      TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS vault_text (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    username    TEXT NOT NULL,
    title       TEXT NOT NULL DEFAULT 'Catatan Rahasia',
    ciphertext  TEXT NOT NULL,
    created_at  TEXT NOT NULL
  );
  CREATE INDEX IF NOT EXISTS idx_vault_text_user ON vault_text(username);

  CREATE TABLE IF NOT EXISTS vault_files (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT NOT NULL,
    original_name TEXT NOT NULL,
    size          INTEGER NOT NULL,
    sha256        TEXT NOT NULL,
    data          BLOB NOT NULL,
    created_at    TEXT NOT NULL
  );
  CREATE INDEX IF NOT EXISTS idx_vault_files_user ON vault_files(username);

  CREATE TABLE IF NOT EXISTS blockchain_ledger (
    idx           INTEGER PRIMARY KEY,
    timestamp     TEXT NOT NULL,
    username      TEXT NOT NULL,
    data          TEXT NOT NULL,
    previous_hash TEXT NOT NULL,
    hash          TEXT NOT NULL
  );
`);

// ── Helper HTTP & JSON ───────────────────────────────────────────────────────
const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.weights': 'text/plain; charset=x-user-defined',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
};

function sendJson(res, status, payload) {
  const body = JSON.stringify(payload);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
  });
  res.end(body);
}

function readBody(req, maxBytes = 70 * 1024 * 1024) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let len = 0;
    req.on('data', (chunk) => {
      len += chunk.length;
      if (len > maxBytes) {
        reject(new Error('Payload terlalu besar.'));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      try {
        const raw = Buffer.concat(chunks).toString('utf8');
        resolve(raw ? JSON.parse(raw) : {});
      } catch {
        reject(new Error('Body JSON tidak valid.'));
      }
    });
    req.on('error', reject);
  });
}

// ── Konversi Baris SQL <-> Objek Aplikasi ────────────────────────────────────
function rowToUser(r) {
  if (!r) return null;
  return {
    username: r.username,
    pinHash: r.pin_hash,
    dongleSerial: r.dongle_serial,
    faceDescriptor: r.face_descriptor ? JSON.parse(r.face_descriptor) : null,
    createdAt: r.created_at,
  };
}

function rowToText(r) {
  return {
    id: r.id,
    username: r.username,
    title: r.title,
    ciphertext: r.ciphertext,
    createdAt: r.created_at,
  };
}

function rowToFile(r, includeData = false) {
  const out = {
    id: r.id,
    username: r.username,
    originalName: r.original_name,
    size: r.size,
    sha256: r.sha256,
    createdAt: r.created_at,
  };
  if (includeData && r.data) {
    out.dataB64 = Buffer.from(r.data).toString('base64');
  }
  return out;
}

function rowToBlock(r) {
  let parsed = r.data;
  try { parsed = JSON.parse(r.data); } catch { /* biarkan string */ }
  return {
    index: r.idx,
    timestamp: r.timestamp,
    username: r.username,
    data: parsed,
    previousHash: r.previous_hash,
    hash: r.hash,
  };
}

function getAllSnapshot() {
  const users = db.prepare('SELECT * FROM users ORDER BY created_at ASC').all().map(rowToUser);
  const blockchain_ledger = db.prepare('SELECT * FROM blockchain_ledger ORDER BY idx ASC').all().map(rowToBlock);
  const vault_text = db.prepare('SELECT * FROM vault_text ORDER BY id DESC').all().map(rowToText);
  const vault_files = db.prepare('SELECT id, username, original_name, size, sha256, created_at FROM vault_files ORDER BY id DESC').all().map(r => ({
    ...rowToFile(r, false),
    data: `<BLOB ${r.size} bytes>`,
  }));
  return { users, blockchain_ledger, vault_text, vault_files };
}

// ── Halaman Web GUI Database Admin (/db-admin) ───────────────────────────────
const DB_ADMIN_HTML = `<!DOCTYPE html>
<html lang="id">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>SQLite Studio — Secret Note DB Admin</title>
  <link rel="preconnect" href="https://fonts.googleapis.com" />
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet" />
  <style>
    :root {
      --bg: #09090b;
      --surface: #121215;
      --card: #18181b;
      --border: #27272a;
      --text: #f4f4f5;
      --muted: #a1a1aa;
      --accent: #10b981;
      --amber: #f59e0b;
      --danger: #ef4444;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      background: var(--bg);
      color: var(--text);
      font-family: 'Inter', system-ui, sans-serif;
      font-size: 14px;
      min-height: 100vh;
      display: flex;
      flex-direction: column;
    }
    header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 12px 24px;
      background: var(--surface);
      border-bottom: 1px solid var(--border);
    }
    .brand {
      display: flex;
      align-items: center;
      gap: 10px;
      font-weight: 600;
      letter-spacing: -0.01em;
    }
    .pill {
      font-family: 'JetBrains Mono', monospace;
      font-size: 11px;
      padding: 3px 8px;
      border-radius: 4px;
      background: rgba(16, 185, 129, 0.12);
      color: var(--accent);
      border: 1px solid rgba(16, 185, 129, 0.3);
    }
    .layout {
      display: grid;
      grid-template-columns: 250px 1fr;
      flex: 1;
      min-height: 0;
    }
    aside {
      background: var(--surface);
      border-right: 1px solid var(--border);
      padding: 16px;
      display: flex;
      flex-direction: column;
      gap: 6px;
    }
    .side-label {
      font-size: 11px;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.06em;
      color: var(--muted);
      margin: 8px 0 4px;
    }
    .tbl-btn {
      display: flex;
      align-items: center;
      justify-content: space-between;
      width: 100%;
      background: transparent;
      border: 1px solid transparent;
      color: var(--text);
      padding: 8px 10px;
      border-radius: 6px;
      cursor: pointer;
      font-family: 'JetBrains Mono', monospace;
      font-size: 12.5px;
      text-align: left;
    }
    .tbl-btn:hover { background: var(--card); border-color: var(--border); }
    .tbl-btn.active {
      background: rgba(16, 185, 129, 0.1);
      border-color: rgba(16, 185, 129, 0.35);
      color: var(--accent);
    }
    .count {
      font-size: 11px;
      color: var(--muted);
      background: var(--bg);
      padding: 1px 6px;
      border-radius: 4px;
      border: 1px solid var(--border);
    }
    main {
      padding: 20px 24px;
      overflow: auto;
      display: flex;
      flex-direction: column;
      gap: 18px;
    }
    .card {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 16px;
      display: flex;
      flex-direction: column;
      gap: 12px;
    }
    .row { display: flex; gap: 8px; flex-wrap: wrap; align-items: center; justify-content: space-between; }
    .btn {
      background: var(--card);
      color: var(--text);
      border: 1px solid var(--border);
      padding: 7px 12px;
      border-radius: 6px;
      font-size: 12.5px;
      font-weight: 500;
      cursor: pointer;
      text-decoration: none;
      display: inline-flex;
      align-items: center;
      gap: 6px;
    }
    .btn:hover { border-color: #52525b; }
    .btn.primary { background: var(--accent); color: #052e16; border-color: var(--accent); font-weight: 600; }
    .btn.danger { color: var(--danger); border-color: rgba(239,68,68,0.35); }
    textarea {
      width: 100%;
      background: var(--bg);
      border: 1px solid var(--border);
      color: var(--text);
      border-radius: 6px;
      padding: 10px 12px;
      font-family: 'JetBrains Mono', monospace;
      font-size: 12.5px;
      resize: vertical;
    }
    textarea:focus { outline: none; border-color: var(--accent); }
    .table-wrap {
      overflow: auto;
      border: 1px solid var(--border);
      border-radius: 6px;
      background: var(--bg);
      max-height: 440px;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      font-family: 'JetBrains Mono', monospace;
      font-size: 12px;
    }
    th, td {
      padding: 8px 10px;
      border-bottom: 1px solid var(--border);
      text-align: left;
      vertical-align: top;
      max-width: 420px;
      word-break: break-all;
    }
    th {
      background: var(--card);
      color: var(--muted);
      font-weight: 600;
      position: sticky;
      top: 0;
    }
    tr:hover td { background: rgba(255,255,255,0.02); }
    pre.schema {
      margin: 0;
      padding: 10px 12px;
      background: var(--bg);
      border: 1px solid var(--border);
      border-radius: 6px;
      font-family: 'JetBrains Mono', monospace;
      font-size: 11.5px;
      color: var(--muted);
      overflow-x: auto;
    }
    .preset-bar { display: flex; gap: 6px; flex-wrap: wrap; }
    .muted { color: var(--muted); font-size: 12px; }
  </style>
</head>
<body>
  <header>
    <div class="brand">
      <span>SQLite Web Console</span>
      <span class="pill">secret-note.db</span>
      <span class="muted" id="dbFileSize"></span>
    </div>
    <div class="row">
      <a class="btn" href="/">← Kembali ke Aplikasi Brankas</a>
      <a class="btn" href="/api/download-db">Unduh File .db</a>
      <button class="btn" id="btnExportJson">Export JSON</button>
      <button class="btn danger" id="btnResetDb">Reset Database</button>
    </div>
  </header>

  <div class="layout">
    <aside>
      <div class="side-label">Tabel SQLite</div>
      <div id="tableList"></div>
      <div class="side-label" style="margin-top:16px">Contoh Query</div>
      <button class="tbl-btn" data-sql="SELECT username, dongle_serial, substr(pin_hash,1,16)||'…' AS pin_sha256, created_at FROM users;">Daftar User</button>
      <button class="tbl-btn" data-sql="SELECT id, username, title, substr(ciphertext,1,44)||'…' AS ciphertext_b64, created_at FROM vault_text ORDER BY id DESC;">Isi Vault Teks</button>
      <button class="tbl-btn" data-sql="SELECT id, username, original_name, size, substr(sha256,1,20)||'…' AS sha256, length(data) AS blob_bytes, created_at FROM vault_files ORDER BY id DESC;">Isi Vault File</button>
      <button class="tbl-btn" data-sql="SELECT idx, timestamp, username, data, substr(previous_hash,1,16)||'…' AS prev_hash, substr(hash,1,16)||'…' AS hash FROM blockchain_ledger ORDER BY idx ASC;">Blockchain Ledger</button>
    </aside>

    <main>
      <div class="card">
        <div class="row">
          <strong>SQL Query Runner</strong>
          <span class="muted">Mendukung perintah SELECT, PRAGMA, dan EXPLAIN pada file SQLite lokal</span>
        </div>
        <textarea id="sqlInput" rows="3">SELECT * FROM users;</textarea>
        <div class="row">
          <span id="queryMeta" class="muted">Siap menjalankan query.</span>
          <button class="btn primary" id="btnRunSql">Jalankan Query (Ctrl+Enter)</button>
        </div>
      </div>

      <div class="card">
        <div class="row">
          <strong id="resultTitle">Hasil Query</strong>
          <button class="btn" id="btnRefresh">Segarkan Data</button>
        </div>
        <pre class="schema" id="schemaBox"></pre>
        <div class="table-wrap">
          <table id="resultTable"></table>
        </div>
      </div>
    </main>
  </div>

  <script>
    const $ = id => document.getElementById(id);
    const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
    let activeTable = 'users';

    const TABLE_QUERIES = {
      users: "SELECT username, pin_hash, dongle_serial, substr(face_descriptor, 1, 60) || '…' AS face_descriptor_128d, created_at FROM users;",
      vault_text: "SELECT id, username, title, ciphertext, created_at FROM vault_text ORDER BY id DESC;",
      vault_files: "SELECT id, username, original_name, size, sha256, '<BLOB ' || length(data) || ' bytes>' AS data_blob, created_at FROM vault_files ORDER BY id DESC;",
      blockchain_ledger: "SELECT idx, timestamp, username, data, previous_hash, hash FROM blockchain_ledger ORDER BY idx ASC;"
    };

    async function loadOverview() {
      const r = await fetch('/api/sql', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ overview: true })
      }).then(x => x.json());
      $('dbFileSize').textContent = r.dbBytes ? '(' + (r.dbBytes / 1024).toFixed(1) + ' KB)' : '';
      $('tableList').innerHTML = (r.tables || []).map(t => \`
        <button class="tbl-btn \${t.name === activeTable ? 'active' : ''}" data-table="\${esc(t.name)}">
          <span>\${esc(t.name)}</span>
          <span class="count">\${t.count}</span>
        </button>\`).join('');
      $('tableList').querySelectorAll('[data-table]').forEach(b => {
        b.onclick = () => {
          activeTable = b.dataset.table;
          const t = (r.tables || []).find(x => x.name === activeTable);
          $('schemaBox').textContent = t ? t.sql : '';
          $('sqlInput').value = TABLE_QUERIES[activeTable] || ('SELECT * FROM ' + activeTable + ';');
          loadOverview();
          runQuery();
        };
      });
      const cur = (r.tables || []).find(x => x.name === activeTable);
      if (cur) $('schemaBox').textContent = cur.sql;
    }

    async function runQuery() {
      const sql = $('sqlInput').value.trim();
      if (!sql) return;
      const t0 = performance.now();
      const res = await fetch('/api/sql', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ sql })
      }).then(x => x.json());
      const dt = (performance.now() - t0).toFixed(1);
      if (res.error) {
        $('queryMeta').textContent = 'Error: ' + res.error;
        $('resultTable').innerHTML = '<tr><td>' + esc(res.error) + '</td></tr>';
        return;
      }
      const rows = res.rows || [];
      $('queryMeta').textContent = rows.length + ' baris dikembalikan dalam ' + dt + ' ms';
      if (!rows.length) {
        $('resultTable').innerHTML = '<tr><td class="muted">(Tidak ada baris data)</td></tr>';
        return;
      }
      const cols = Object.keys(rows[0]);
      $('resultTable').innerHTML = '<tr>' + cols.map(c => '<th>' + esc(c) + '</th>').join('') + '</tr>'
        + rows.map(row => '<tr>' + cols.map(c => {
          const val = row[c];
          const str = typeof val === 'object' && val !== null ? JSON.stringify(val) : String(val ?? '');
          return '<td>' + esc(str.length > 260 ? str.slice(0, 260) + '…' : str) + '</td>';
        }).join('') + '</tr>').join('');
    }

    document.querySelectorAll('[data-sql]').forEach(b => {
      b.onclick = () => { $('sqlInput').value = b.dataset.sql; runQuery(); };
    });
    $('btnRunSql').onclick = runQuery;
    $('btnRefresh').onclick = () => { loadOverview(); runQuery(); };
    $('sqlInput').addEventListener('keydown', e => { if (e.ctrlKey && e.key === 'Enter') runQuery(); });
    $('btnExportJson').onclick = async () => {
      const data = await fetch('/api/dump').then(x => x.json());
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = 'secret-note-sqlite-dump.json';
      a.click();
    };
    $('btnResetDb').onclick = async () => {
      if (!confirm('Kosongkan seluruh tabel di secret-note.db?')) return;
      await fetch('/api/reset', { method: 'POST' });
      loadOverview();
      runQuery();
    };

    loadOverview().then(() => {
      $('sqlInput').value = TABLE_QUERIES.users;
      runQuery();
    });
  </script>
</body>
</html>`;

// ── Router HTTP & API ────────────────────────────────────────────────────────
const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
    const pathname = url.pathname;

    // 1. Halaman Web GUI Database Admin
    if (req.method === 'GET' && pathname === '/db-admin') {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(DB_ADMIN_HTML);
      return;
    }

    // 2. Unduh file fisik secret-note.db
    if (req.method === 'GET' && pathname === '/api/download-db') {
      const buf = fs.readFileSync(DB_PATH);
      res.writeHead(200, {
        'Content-Type': 'application/vnd.sqlite3',
        'Content-Disposition': 'attachment; filename="secret-note.db"',
      });
      res.end(buf);
      return;
    }

    // 3. Ping / Status Engine
    if (req.method === 'GET' && pathname === '/api/ping') {
      sendJson(res, 200, { ok: true, engine: 'SQLite (secret-note.db)' });
      return;
    }

    // 4. Users API
    if (pathname === '/api/users' && req.method === 'GET') {
      const rows = db.prepare('SELECT * FROM users ORDER BY created_at ASC').all().map(rowToUser);
      sendJson(res, 200, rows);
      return;
    }
    if (pathname.startsWith('/api/users/') && req.method === 'GET') {
      const uname = decodeURIComponent(pathname.slice('/api/users/'.length));
      const row = db.prepare('SELECT * FROM users WHERE username = ?').get(uname);
      sendJson(res, 200, rowToUser(row));
      return;
    }
    if (pathname === '/api/users' && req.method === 'POST') {
      const u = await readBody(req);
      const exists = db.prepare('SELECT username FROM users WHERE username = ?').get(u.username);
      if (exists) {
        sendJson(res, 409, { error: `Username "${u.username}" sudah terdaftar.` });
        return;
      }
      db.prepare(`
        INSERT INTO users (username, pin_hash, dongle_serial, face_descriptor, created_at)
        VALUES (?, ?, ?, ?, ?)
      `).run(
        u.username,
        u.pinHash,
        u.dongleSerial,
        u.faceDescriptor ? JSON.stringify(u.faceDescriptor) : null,
        u.createdAt || new Date().toISOString()
      );
      sendJson(res, 201, { ok: true });
      return;
    }

    // 5. Vault Text API (Terisolasi per username)
    if (pathname === '/api/vault-text' && req.method === 'GET') {
      const uname = url.searchParams.get('username') || '';
      const rows = db.prepare('SELECT * FROM vault_text WHERE username = ? ORDER BY id DESC').all(uname).map(rowToText);
      sendJson(res, 200, rows);
      return;
    }
    if (pathname === '/api/vault-text' && req.method === 'POST') {
      const body = await readBody(req);
      const info = db.prepare(`
        INSERT INTO vault_text (username, title, ciphertext, created_at)
        VALUES (?, ?, ?, ?)
      `).run(
        body.username,
        body.title || 'Catatan Terenkripsi',
        body.ciphertext,
        body.createdAt || new Date().toISOString()
      );
      sendJson(res, 201, { id: Number(info.lastInsertRowid) });
      return;
    }
    if (pathname.startsWith('/api/vault-text/') && req.method === 'DELETE') {
      const id = Number(pathname.slice('/api/vault-text/'.length));
      const uname = url.searchParams.get('username');
      if (uname) db.prepare('DELETE FROM vault_text WHERE id = ? AND username = ?').run(id, uname);
      else db.prepare('DELETE FROM vault_text WHERE id = ?').run(id);
      sendJson(res, 200, { ok: true });
      return;
    }

    // 6. Vault Files API (Terisolasi per username)
    if (pathname === '/api/vault-files' && req.method === 'GET') {
      const uname = url.searchParams.get('username') || '';
      const rows = db.prepare('SELECT id, username, original_name, size, sha256, created_at FROM vault_files WHERE username = ? ORDER BY id DESC').all(uname).map(r => rowToFile(r, false));
      sendJson(res, 200, rows);
      return;
    }
    if (pathname.startsWith('/api/vault-files/') && req.method === 'GET') {
      const id = Number(pathname.slice('/api/vault-files/'.length));
      const row = db.prepare('SELECT * FROM vault_files WHERE id = ?').get(id);
      if (!row) { sendJson(res, 404, { error: 'File tidak ditemukan.' }); return; }
      sendJson(res, 200, rowToFile(row, true));
      return;
    }
    if (pathname === '/api/vault-files' && req.method === 'POST') {
      const body = await readBody(req);
      const buf = Buffer.from(body.dataB64, 'base64');
      const info = db.prepare(`
        INSERT INTO vault_files (username, original_name, size, sha256, data, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
      `).run(
        body.username,
        body.originalName,
        body.size ?? buf.length,
        body.sha256,
        buf,
        body.createdAt || new Date().toISOString()
      );
      sendJson(res, 201, { id: Number(info.lastInsertRowid) });
      return;
    }
    if (pathname.startsWith('/api/vault-files/') && req.method === 'DELETE') {
      const id = Number(pathname.slice('/api/vault-files/'.length));
      db.prepare('DELETE FROM vault_files WHERE id = ?').run(id);
      sendJson(res, 200, { ok: true });
      return;
    }

    // 7. Blockchain Ledger API
    if (pathname === '/api/blockchain' && req.method === 'GET') {
      const rows = db.prepare('SELECT * FROM blockchain_ledger ORDER BY idx ASC').all().map(rowToBlock);
      sendJson(res, 200, rows);
      return;
    }
    if (pathname === '/api/blockchain' && req.method === 'POST') {
      const b = await readBody(req);
      db.prepare(`
        INSERT OR REPLACE INTO blockchain_ledger (idx, timestamp, username, data, previous_hash, hash)
        VALUES (?, ?, ?, ?, ?, ?)
      `).run(
        b.index,
        b.timestamp,
        b.username || 'SYSTEM',
        typeof b.data === 'string' ? b.data : JSON.stringify(b.data),
        b.previousHash,
        b.hash
      );
      sendJson(res, 201, { ok: true });
      return;
    }

    // 8. Dump, SQL Console, & Reset
    if (pathname === '/api/dump' && req.method === 'GET') {
      sendJson(res, 200, getAllSnapshot());
      return;
    }
    if (pathname === '/api/sql' && req.method === 'POST') {
      const body = await readBody(req);
      if (body.overview) {
        const tables = db.prepare(`
          SELECT name, sql FROM sqlite_master
          WHERE type='table' AND name NOT LIKE 'sqlite_%'
          ORDER BY name ASC
        `).all().map(t => {
          const c = db.prepare(`SELECT COUNT(*) AS cnt FROM "${t.name}"`).get();
          return { name: t.name, sql: t.sql, count: c ? c.cnt : 0 };
        });
        const stat = fs.existsSync(DB_PATH) ? fs.statSync(DB_PATH).size : 0;
        sendJson(res, 200, { tables, dbBytes: stat });
        return;
      }
      const sql = String(body.sql || '').trim();
      if (!/^(SELECT|PRAGMA|EXPLAIN)\b/i.test(sql)) {
        sendJson(res, 400, { error: 'Hanya perintah SELECT, PRAGMA, atau EXPLAIN yang diizinkan di konsol inspeksi.' });
        return;
      }
      const rows = db.prepare(sql).all().map(r => {
        const clean = {};
        for (const [k, v] of Object.entries(r)) {
          clean[k] = v instanceof Uint8Array ? `<BLOB ${v.byteLength} bytes>` : v;
        }
        return clean;
      });
      sendJson(res, 200, { rows });
      return;
    }
    if (pathname === '/api/reset' && req.method === 'POST') {
      db.exec(`
        DELETE FROM vault_text;
        DELETE FROM vault_files;
        DELETE FROM users;
        DELETE FROM blockchain_ledger;
      `);
      sendJson(res, 200, { ok: true });
      return;
    }

    // 9. Static File Server (secret-note/)
    const relPath = pathname === '/' ? '/index.html' : pathname;
    const safePath = path.normalize(relPath).replace(/^(\.\.[/\\])+/, '');
    const fullPath = path.join(ROOT_DIR, safePath);
    if (!fullPath.startsWith(ROOT_DIR) || !fs.existsSync(fullPath) || fs.statSync(fullPath).isDirectory()) {
      res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end('404 Not Found');
      return;
    }
    const ext = path.extname(fullPath).toLowerCase();
    res.writeHead(200, {
      'Content-Type': MIME_TYPES[ext] || 'application/octet-stream',
      'Cache-Control': 'no-cache',
    });
    fs.createReadStream(fullPath).pipe(res);
  } catch (err) {
    sendJson(res, 500, { error: err.message || String(err) });
  }
});

server.listen(PORT, () => {
  console.log(`Secret Note Server & SQLite berjalan di:`);
  console.log(`  • Aplikasi Brankas : http://localhost:${PORT}`);
  console.log(`  • SQLite Web Admin : http://localhost:${PORT}/db-admin`);
  console.log(`  • File Database    : ${DB_PATH}`);
});
