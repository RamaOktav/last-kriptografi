/**
 * app.js — Secret Note
 * Blockchain ledger + controller semua tab. Persistensi lewat db.js (IndexedDB).
 */
'use strict';

const $ = (id) => document.getElementById(id);
const esc = (s) => String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

// ══ BLOCKCHAIN ═══════════════════════════════════════════════════════════════
class Block {
  constructor(index, timestamp, data, previousHash = '') {
    this.index = index;
    this.timestamp = timestamp;
    this.data = data;
    this.previousHash = previousHash;
    this.hash = '';
  }
  async calculateHash() {
    return hashSHA256(this.index + '|' + this.timestamp + '|' + JSON.stringify(this.data) + '|' + this.previousHash);
  }
  /** Factory async karena SHA-256 Web Crypto bersifat asynchronous. */
  static async create(index, timestamp, data, previousHash = '') {
    const b = new Block(index, timestamp, data, previousHash);
    b.hash = await b.calculateHash();
    return b;
  }
  static async fromRecord(r) {
    const b = new Block(r.index, r.timestamp, r.data, r.previousHash);
    b.hash = r.hash;
    return b;
  }
}

class Blockchain {
  constructor() { this.chain = []; }
  async createGenesisBlock() { return Block.create(0, new Date().toISOString(), { action: 'GENESIS', detail: 'Secret Note Ledger' }, '0'); }
  getLatestBlock() { return this.chain[this.chain.length - 1]; }
  async addBlock(newBlock) {
    newBlock.previousHash = this.getLatestBlock().hash;
    newBlock.hash = await newBlock.calculateHash();
    this.chain.push(newBlock);
    await addBlockToDB(newBlock);
    return newBlock;
  }
  async isChainValid() {
    for (let i = 0; i < this.chain.length; i++) {
      const cur = this.chain[i];
      if (cur.hash !== await cur.calculateHash()) return { valid: false, at: i };
      if (i > 0 && cur.previousHash !== this.chain[i - 1].hash) return { valid: false, at: i };
    }
    return { valid: true };
  }
  async load() {
    const recs = await getAllBlocksFromDB();
    this.chain = [];
    for (const r of recs) this.chain.push(await Block.fromRecord(r));
    if (!this.chain.length) {
      const g = await this.createGenesisBlock();
      this.chain.push(g);
      await addBlockToDB(g);
    }
  }
}

const ledger = new Blockchain();

/** Catat aksi sukses ke blockchain. */
async function logAction(action, detail) {
  await ledger.addBlock(new Block(ledger.chain.length, new Date().toISOString(), { action, detail }));
  renderChain();
}

// ══ UTIL UI ══════════════════════════════════════════════════════════════════
let toastTimer;
function toast(msg, isErr = false) {
  const t = $('toast');
  t.textContent = msg;
  t.className = 'toast show' + (isErr ? ' err' : '');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.remove('show'), 3200);
}
function setStatus(id, msg, kind = '') { const e = $(id); e.textContent = msg; e.className = 'status ' + kind; }
const fmtBytes = (n) => n < 1024 ? n + ' B' : n < 1048576 ? (n / 1024).toFixed(1) + ' KB' : (n / 1048576).toFixed(2) + ' MB';
async function guard(btn, fn) {
  btn.disabled = true;
  try { await fn(); } catch (e) { toast(e.message || String(e), true); console.error(e); } finally { btn.disabled = false; }
}

// ══ TAB NAV & SESSION ════════════════════════════════════════════════════════
let loggedIn = false;
function showTab(name) {
  if (!loggedIn && name !== 'login') { toast('Login terlebih dahulu di Gatekeeper.', true); return; }
  document.querySelectorAll('.tab').forEach(t => t.classList.toggle('active', t.dataset.tab === name));
  document.querySelectorAll('.panel').forEach(p => p.classList.toggle('active', p.id === 'tab-' + name));
  if (name === 'ledger') { renderChain(); renderDb(); }
  if (name === 'text') renderVaultText();
  if (name === 'file') renderVaultFiles();
  if (name !== 'login') stopFaceScan();
}
function setSession(state) {
  loggedIn = state;
  $('sessionBadge').textContent = state ? 'TERBUKA' : 'TERKUNCI';
  $('sessionBadge').className = 'badge ' + (state ? 'ok' : 'bad');
  $('btnLogout').classList.toggle('hidden', !state);
  document.querySelectorAll('.tab').forEach(t => { if (t.dataset.tab !== 'login') t.classList.toggle('locked', !state); });
}

// ══ TAB 1: GATEKEEPER ════════════════════════════════════════════════════════
let dongleOk = false, faceOk = false, faceMode = 'asli';

async function refreshFaceState() {
  const d = await getAuth('face_descriptor');
  $('btnFaceReg').disabled = !!d;
  setStatus('faceStatus', d ? 'Wajah terdaftar. Klik "Verifikasi Wajah".' : 'Belum ada wajah terdaftar. Klik "Daftarkan Wajah".', d ? 'ok' : '');
}

function updateLoginHint() {
  if (dongleOk && faceOk) setStatus('loginStatus', 'Faktor ① & ② lolos. Masukkan PIN.', 'ok');
  else setStatus('loginStatus', 'Selesaikan faktor ① dan ② lebih dulu');
}

async function refreshSetupCard() {
  const pin = await getAuth('pin_hash');
  $('setupCard').classList.toggle('hidden', !!pin);
}

function bindLogin() {
  $('btnSetup').onclick = () => guard($('btnSetup'), async () => {
    const pin = $('setupPin').value;
    if (pin.length < 4) throw new Error('PIN minimal 4 karakter.');
    await setAuth('pin_hash', await hashSHA256(pin));
    const { blob, serial } = await generateDongle();
    await setAuth('dongle_serial', serial);
    downloadBlob(blob, 'secret-dongle.key');
    $('setupPin').value = '';
    await logAction('REGISTER', `Akun terdaftar, dongle ${serial}`);
    await refreshSetupCard();
    toast('Terdaftar. Simpan secret-dongle.key di flashdisk, lalu upload di faktor ①.');
  });

  $('dongleFile').onchange = async (e) => {
    const r = await checkDongle(e.target.files[0]);
    dongleOk = r.valid;
    setStatus('dongleStatus', r.valid ? `✔ ${r.reason} (${r.serial})` : `✖ ${r.reason}`, r.valid ? 'ok' : 'err');
    updateLoginHint();
  };

  const faceMsg = m => setStatus('faceStatus', m);
  const faceFail = (e) => {
    stopFaceScan();
    setStatus('faceStatus', '✖ ' + (e.message || e) + ' — jika perangkat bermasalah, aktifkan mode simulasi.', 'err');
    throw e;
  };

  $('btnFaceReg').onclick = async () => {
    await guard($('btnFaceReg'), async () => {
      if ($('faceSim').checked) throw new Error('Mode simulasi aktif: registrasi wajah asli tidak diperlukan.');
      try {
        const d = await registerFaceDescriptor($('faceVideo'), $('faceCanvas'), faceMsg);
        stopFaceScan();
        await logAction('FACE_REGISTER', `Descriptor 128-d tersimpan (norm=${Math.sqrt(d.reduce((s, v) => s + v * v, 0)).toFixed(3)})`);
        setStatus('faceStatus', '✔ Wajah terdaftar (128-d descriptor disimpan di IndexedDB).', 'ok');
        toast('Wajah berhasil didaftarkan.');
      } catch (e) { faceFail(e); }
    });
    await refreshFaceState();
  };

  $('btnFace').onclick = () => guard($('btnFace'), async () => {
    faceOk = false;
    $('faceDist').textContent = '';
    if ($('faceSim').checked) {
      await initFaceScan($('faceVideo'), $('faceCanvas'), faceMsg);
      faceOk = true; faceMode = 'simulasi';
      setStatus('faceStatus', '⚠ Lolos via MODE SIMULASI (bukan biometrik asli).', 'ok');
    } else {
      try {
        const r = await verifyFaceBiometric($('faceVideo'), $('faceCanvas'), faceMsg);
        $('faceDist').textContent = `Jarak Euclidean = ${r.distance.toFixed(4)} (batas ≤ ${FACE_MATCH_THRESHOLD}) · kemiripan ${r.similarity.toFixed(1)}%`;
        if (!r.ok) throw new Error(`Wajah tidak cocok (jarak ${r.distance.toFixed(3)} > ${FACE_MATCH_THRESHOLD}).`);
        faceOk = true; faceMode = 'asli';
        setStatus('faceStatus', '✔ Wajah dikenali (biometrik asli).', 'ok');
      } catch (e) { faceFail(e); }
    }
    updateLoginHint();
  });
  $('faceSim').onchange = () => { faceOk = false; updateLoginHint(); };

  $('btnLogin').onclick = () => guard($('btnLogin'), async () => {
    const stored = await getAuth('pin_hash');
    if (!stored) throw new Error('Belum ada akun. Lakukan registrasi dahulu.');
    if (!dongleOk) throw new Error('Dongle belum valid.');
    if (!faceOk) throw new Error('Scan wajah belum selesai.');
    if ((await hashSHA256($('loginPin').value)) !== stored) throw new Error('PIN salah.');
    $('loginPin').value = '';
    stopFaceScan();
    setSession(true);
    await logAction('LOGIN', `Login 3 faktor berhasil (wajah: ${faceMode})`);
    toast('Akses diberikan.');
    showTab('text');
  });

  $('btnLogout').onclick = () => {
    setSession(false);
    dongleOk = faceOk = false;
    $('dongleFile').value = '';
    setStatus('dongleStatus', 'Belum diverifikasi');
    $('faceDist').textContent = '';
    refreshFaceState();
    updateLoginHint();
    showTab('login');
  };
}

// ══ TAB 2: SUPER-ENCRYPTION ══════════════════════════════════════════════════
let lastCipher = null;
function bindText() {
  $('btnTextEnc').onclick = () => guard($('btnTextEnc'), async () => {
    const text = $('textInput').value;
    if (!text) throw new Error('Teks kosong.');
    const r = await superEncryptTrace(text, $('vigKey').value, $('aesKey').value);
    $('textLayer1').value = r.vigText;
    $('textOutput').value = r.aes.b64;
    lastCipher = r.aes.b64;
    $('textSteps').innerHTML = renderEncryptSteps(r, $('vigKey').value, $('aesKey').value);
    await logAction('SUPER_ENCRYPT', `Teks ${text.length} char, SHA256(cipher)=${(await hashSHA256(r.aes.b64)).slice(0, 16)}…`);
    toast('Enkripsi dua lapis berhasil.');
  });
  $('btnTextDec').onclick = () => guard($('btnTextDec'), async () => {
    const r = await superDecryptTrace($('textInput').value, $('vigKey').value, $('aesKey').value);
    $('textLayer1').value = r.vigCipher;
    $('textOutput').value = r.plain;
    $('textSteps').innerHTML = renderDecryptSteps(r, $('vigKey').value);
    toast('Dekripsi berhasil.');
  });
  $('btnTextSave').onclick = () => guard($('btnTextSave'), async () => {
    if (!lastCipher) throw new Error('Enkripsi teks terlebih dahulu.');
    await saveVaultText({ ciphertext: lastCipher, createdAt: new Date().toISOString() });
    await renderVaultText();
    toast('Disimpan ke vault.');
  });
}
async function renderVaultText() {
  const items = await getVaultTexts();
  $('vaultTextList').innerHTML = items.length ? items.map(i => `<div class="item"><span>#${i.id} · ${esc(i.createdAt)} · ${esc(i.ciphertext.slice(0, 40))}…</span><button class="btn small" data-load="${i.id}">Muat</button></div>`).join('') : '<span class="muted">Kosong</span>';
  $('vaultTextList').querySelectorAll('[data-load]').forEach(b => b.onclick = () => {
    const it = items.find(x => x.id == b.dataset.load);
    $('textInput').value = it.ciphertext;
    toast('Ciphertext dimuat ke input. Isi kunci lalu Dekripsi.');
  });
}

// ══ TAB 3: FILE CRYPTO ═══════════════════════════════════════════════════════
let selectedFile = null, fileResult = null;
function pickFile(f) {
  selectedFile = f;
  setStatus('fileInfo', f ? `${f.name} (${fmtBytes(f.size)})` : 'Belum ada file', f ? 'ok' : '');
}
function bindFile() {
  const dz = $('dropzone');
  dz.onclick = () => $('fileInput').click();
  $('fileInput').onchange = e => pickFile(e.target.files[0]);
  dz.ondragover = e => { e.preventDefault(); dz.classList.add('over'); };
  dz.ondragleave = () => dz.classList.remove('over');
  dz.ondrop = e => { e.preventDefault(); dz.classList.remove('over'); pickFile(e.dataTransfer.files[0]); };

  const showResult = (blob, name, msg) => {
    fileResult = { blob, name };
    $('btnFileDownload').classList.remove('hidden');
    setStatus('fileResult', msg, 'ok');
  };
  $('btnFileEnc').onclick = () => guard($('btnFileEnc'), async () => {
    if (!selectedFile) throw new Error('Pilih file terlebih dahulu.');
    if (!$('fileKey').value) throw new Error('Kunci RC4 kosong.');
    const { bytes: enc, trace } = await encryptFileRC4(selectedFile, $('fileKey').value);
    const hash = await hashSHA256(enc);
    await saveVaultFile({ originalName: selectedFile.name, size: enc.length, createdAt: new Date().toISOString(), sha256: hash, data: enc.buffer });
    await logAction('FILE_ENCRYPT_RC4', `${selectedFile.name} (${fmtBytes(selectedFile.size)}), SHA256(enc)=${hash.slice(0, 16)}…`);
    $('fileSteps').innerHTML = renderRc4Steps(trace, true);
    showResult(new Blob([enc], { type: 'application/octet-stream' }), selectedFile.name + '.enc', `Terenkripsi → ${selectedFile.name}.enc (${fmtBytes(enc.length)})`);
    renderVaultFiles();
  });
  $('btnFileDec').onclick = () => guard($('btnFileDec'), async () => {
    if (!selectedFile) throw new Error('Pilih file .enc terlebih dahulu.');
    if (!$('fileKey').value) throw new Error('Kunci RC4 kosong.');
    const r = await decryptFileRC4(selectedFile, $('fileKey').value);
    $('fileSteps').innerHTML = renderRc4Steps(r.trace, false);
    showResult(new Blob([r.data]), r.name, `Terdekripsi → ${r.name} (${fmtBytes(r.data.length)})`);
  });
  $('btnFileDownload').onclick = () => fileResult && downloadBlob(fileResult.blob, fileResult.name);
}
async function renderVaultFiles() {
  const items = await getVaultFiles();
  $('vaultFileList').innerHTML = items.length ? items.map(i => `<div class="item"><span>#${i.id} · ${esc(i.originalName)}.enc · ${fmtBytes(i.size)}</span><span><button class="btn small" data-dl="${i.id}">Download</button> <button class="btn small danger" data-del="${i.id}">Hapus</button></span></div>`).join('') : '<span class="muted">Kosong</span>';
  $('vaultFileList').querySelectorAll('[data-dl]').forEach(b => b.onclick = () => {
    const it = items.find(x => x.id == b.dataset.dl);
    downloadBlob(new Blob([it.data]), it.originalName + '.enc');
  });
  $('vaultFileList').querySelectorAll('[data-del]').forEach(b => b.onclick = async () => { await deleteVaultFile(Number(b.dataset.del)); renderVaultFiles(); });
}

// ══ TAB 4: STEGANOGRAFI ══════════════════════════════════════════════════════
let stegoDataUrl = null;
function bindStego() {
  $('coverFile').onchange = async e => {
    const f = e.target.files[0]; if (!f) return;
    $('coverImg').src = (await loadImageFromFile(f)).src;
    $('coverImg').classList.remove('hidden');
    $('coverImg').onload = () => setStatus('coverInfo', `${$('coverImg').naturalWidth}×${$('coverImg').naturalHeight} px — kapasitas ±${fmtBytes(stegoCapacity($('coverImg')))}`, 'ok');
  };
  $('btnEmbed').onclick = () => guard($('btnEmbed'), async () => {
    if ($('coverImg').classList.contains('hidden')) throw new Error('Upload cover image dahulu.');
    const msg = $('stegoMsg').value;
    if (!msg) throw new Error('Pesan kosong.');
    const { dataUrl, trace } = embedLSBWithTrace($('coverImg'), msg);
    stegoDataUrl = dataUrl;
    $('stegoSteps').innerHTML = renderStegoSteps(trace);
    $('stegoOut').src = stegoDataUrl;
    $('stegoOut').classList.remove('hidden');
    $('btnStegoDownload').classList.remove('hidden');
    await logAction('STEGO_EMBED', `Pesan ${msg.length} char disisipkan, SHA256(msg)=${(await hashSHA256(msg)).slice(0, 16)}…`);
    toast('Pesan berhasil disisipkan.');
  });
  $('btnStegoDownload').onclick = () => {
    const a = document.createElement('a'); a.href = stegoDataUrl; a.download = 'stego-image.png'; a.click();
  };
  $('stegoFile').onchange = async e => {
    const f = e.target.files[0]; if (!f) return;
    $('stegoIn').src = (await loadImageFromFile(f)).src;
    $('stegoIn').classList.remove('hidden');
  };
  $('btnExtract').onclick = () => guard($('btnExtract'), async () => {
    if ($('stegoIn').classList.contains('hidden')) throw new Error('Upload stego image (.png) dahulu.');
    $('stegoExtracted').value = extractLSB($('stegoIn'));
    toast('Pesan diekstrak.');
  });
}

// ══ TAB 5: LEDGER & DB INSPECTOR ═════════════════════════════════════════════
async function renderChain() {
  const res = await ledger.isChainValid();
  const badge = $('chainBadge');
  badge.textContent = res.valid ? `✔ VALID · ${ledger.chain.length} blok` : `✖ TAMPERED (blok #${res.at})`;
  badge.className = 'badge ' + (res.valid ? 'ok' : 'bad');
  $('chainView').innerHTML = ledger.chain.map((b, i) => `
    <div class="block ${!res.valid && i >= res.at ? 'bad' : ''}">
      <b>Block #${b.index}</b> · ${esc(b.timestamp)}<br>
      <b>Data:</b> ${esc(JSON.stringify(b.data))}<br>
      <b>Prev:</b> <span class="hash">${esc(b.previousHash)}</span><br>
      <b>Hash:</b> <span class="hash">${esc(b.hash)}</span>
    </div>`).join('');
}

function dbReplacer(k, v) {
  if (v instanceof ArrayBuffer) return `<binary ${v.byteLength} bytes>`;
  if (v instanceof Uint8Array) return `<binary ${v.length} bytes>`;
  return v;
}
async function renderDb() {
  const store = $('dbStore').value;
  const all = await getAllDatabaseData();
  $('dbStats').textContent = Object.entries(all).map(([k, v]) => `${k}: ${v.length}`).join('  |  ');
  const rows = all[store] || [];
  const cols = [...new Set(rows.flatMap(r => Object.keys(r)))];
  $('dbTable').innerHTML = rows.length
    ? `<tr>${cols.map(c => `<th>${esc(c)}</th>`).join('')}</tr>` + rows.map(r => `<tr>${cols.map(c => {
        const v = r[c];
        let s = typeof v === 'object' && v !== null ? JSON.stringify(v, dbReplacer) : String(v ?? '');
        return `<td>${esc(s.length > 200 ? s.slice(0, 200) + '…' : s)}</td>`;
      }).join('')}</tr>`).join('')
    : '<tr><td>(kosong)</td></tr>';
}

function bindLedger() {
  $('dbStore').innerHTML = DB_STORES.map(s => `<option>${s}</option>`).join('');
  $('dbStore').onchange = renderDb;
  $('btnDbRefresh').onclick = renderDb;
  $('btnValidate').onclick = async () => { await renderChain(); toast((await ledger.isChainValid()).valid ? 'Rantai valid.' : 'Rantai tidak valid!', !(await ledger.isChainValid()).valid); };
  $('btnTamper').onclick = async () => {
    if (ledger.chain.length < 2) { toast('Butuh minimal 2 blok.', true); return; }
    ledger.chain[1].data = { action: 'TAMPERED', detail: 'data dimanipulasi' };
    await renderChain();
    toast('Blok #1 dimodifikasi di memori (DB tidak berubah).', true);
  };
  $('btnReloadChain').onclick = async () => { await ledger.load(); await renderChain(); toast('Rantai dimuat ulang dari database.'); };
  $('btnDbExport').onclick = async () => {
    const all = await getAllDatabaseData();
    downloadBlob(new Blob([JSON.stringify(all, dbReplacer, 2)], { type: 'application/json' }), 'secretnote-db-dump.json');
  };
  $('btnDbReset').onclick = async () => {
    if (!confirm('Hapus SELURUH data (akun, ledger, vault)? Anda perlu registrasi ulang.')) return;
    await clearAllDatabaseData();
    location.reload();
  };
}

// ══ RENDERER STEP-BY-STEP ════════════════════════════════════════════════════
const MAX_ROWS = 20;
const short = (h, n = 96) => h.length > n ? h.slice(0, n) + `… (${h.length / 2} byte)` : h;
const hx = (v) => v.toString(16).padStart(2, '0');
const bin8 = (v) => v.toString(2).padStart(8, '0');
const stepBox = (n, title, body) => `<div class="step"><div class="step-n">${n}</div><div class="step-b"><h4>${title}</h4>${body}</div></div>`;
const kv = (label, val) => `<div class="kv"><span>${label}</span><code>${esc(val)}</code></div>`;
const note = (t) => `<p>${t}</p>`;
const table = (head, rows) => `<div class="mini-wrap"><table class="mini"><tr>${head.map(h => `<th>${h}</th>`).join('')}</tr>${rows.map(r => `<tr>${r.map(c => `<td>${c}</td>`).join('')}</tr>`).join('')}</table></div>`;
const vis = (s) => s === ' ' ? '␣' : esc(s);

function vigTable(steps, dir) {
  const rows = steps.slice(0, MAX_ROWS).map(s => s.skipped
    ? [vis(s.char), s.code, '—', '—', 'tidak diproses', vis(s.resChar), s.resCode]
    : [vis(s.char), s.code, vis(s.keyChar), s.keyShift,
       `(${s.code}−32 ${dir > 0 ? '+' : '−'} ${s.keyShift}) mod 95 + 32`, vis(s.resChar), s.resCode]);
  const more = steps.length > MAX_ROWS ? note(`Menampilkan ${MAX_ROWS} dari ${steps.length} karakter.`) : '';
  return table(['Char', 'ASCII', 'Key', 'Shift', 'Rumus', 'Hasil', 'ASCII'], rows) + more;
}

function aesParams(a, maskedKey) {
  return kv('PBKDF2', `HMAC-SHA256, ${a.iterations.toLocaleString()} iterasi, passphrase "${maskedKey}"`)
    + kv('Salt (16 B)', a.saltHex) + kv('Derived Key (256 b)', a.keyHex) + kv('IV (12 B)', a.ivHex);
}

const pkgBar = (a) => `<div class="pkg"><span class="p1">Salt 16B</span><span class="p2">IV 12B</span><span class="p3">Ciphertext ${a.ctHex.length / 2}B</span><span class="p4">Tag 16B</span></div>`;

function renderEncryptSteps(r, vigKey, aesKey) {
  const a = r.aes;
  return [
    stepBox(1, 'Input', kv('Plaintext', r.plaintext) + kv('Kunci Vigenère', vigKey) + kv('Kunci AES', '•'.repeat(aesKey.length) + ` (${aesKey.length} karakter)`) + kv('Panjang', `${r.plaintext.length} karakter / ${a.inputLen} byte`)),
    stepBox(2, 'Lapis 1 — Vigenère Cipher (klasik)', note('Tiap karakter ASCII 32–126 digeser sebesar nilai kunci (diulang): C = (P − 32 + K) mod 95 + 32.') + vigTable(r.vigSteps, 1) + kv('Hasil perantara', r.vigText)),
    stepBox(3, 'Lapis 2 — AES-256-GCM (modern)', note('Kunci 256-bit diturunkan dari passphrase memakai PBKDF2 + salt acak, lalu AES-GCM dengan IV acak menghasilkan ciphertext + tag autentikasi.') + aesParams(a, '•'.repeat(aesKey.length)) + kv('Ciphertext (hex)', short(a.ctHex)) + kv('Auth Tag (16 B)', a.tagHex)),
    stepBox(4, 'Packaging → Base64', note('Payload = Salt | IV | Ciphertext | Tag, lalu di-encode Base64 (' + a.payloadLen + ' byte).') + pkgBar(a) + kv('Ciphertext akhir', a.b64)),
  ].join('');
}

function renderDecryptSteps(r, vigKey) {
  const a = r.aes;
  return [
    stepBox(1, 'Unpack Base64', note(`Base64 di-decode menjadi ${a.payloadLen} byte lalu dipisah:`) + pkgBar(a) + kv('Salt', a.saltHex) + kv('IV', a.ivHex) + kv('Auth Tag', a.tagHex)),
    stepBox(2, 'Lapis 2 (dibalik) — AES-256-GCM Decrypt', note('Kunci diturunkan ulang dari passphrase + salt yang sama. Tag diverifikasi; jika kunci salah / data diubah, dekripsi gagal.') + kv('PBKDF2', `HMAC-SHA256, ${a.iterations.toLocaleString()} iterasi`) + kv('Derived Key (256 b)', a.keyHex) + kv('Ciphertext (hex)', short(a.ctHex)) + kv('Hasil (Vigenère cipher)', r.vigCipher)),
    stepBox(3, `Lapis 1 (dibalik) — Vigenère Decrypt (kunci "${esc(vigKey)}")`, note('P = (C − 32 − K) mod 95 + 32.') + vigTable(r.vigSteps, -1)),
    stepBox(4, 'Plaintext', kv('Plaintext', r.plain)),
  ].join('');
}

function renderRc4Steps(t, encrypt) {
  const arr = (a) => a.map(hx).join(' ');
  const inLabel = encrypt ? 'Plaintext' : 'Ciphertext', outLabel = encrypt ? 'Ciphertext' : 'Plaintext';
  const p = t.package;
  return [
    stepBox(1, 'KSA — Key Scheduling Algorithm', note('S-Box diinisialisasi S[i]=i, lalu diacak 256 putaran: j = (j + S[i] + key[i mod len]) mod 256; swap(S[i], S[j]).') + kv('Kunci (byte)', arr(t.keyBytes)) + kv('S[0..15] sebelum', arr(t.sBefore)) + kv('S[0..15] sesudah', arr(t.sAfter))),
    stepBox(2, 'PRGA — Keystream Generator', note('Tiap byte: i++, j += S[i], swap(S[i],S[j]), K = S[(S[i]+S[j]) mod 256].') + kv('Keystream 16 byte', arr(t.keystream))),
    stepBox(3, `XOR Bitwise — ${inLabel} ⊕ Keystream = ${outLabel}`, note(`10 byte pertama dari paket (diawali header "RC4F").`) + table(['#', `${inLabel} hex`, 'biner', 'Keystream', 'biner', `${outLabel} hex`, 'biner'],
      t.rows.map(r => [r.index, hx(r.input), bin8(r.input), hx(r.keystream), bin8(r.keystream), hx(r.output), bin8(r.output)]))),
    stepBox(4, encrypt ? 'Packaging file .enc' : 'Unpack paket', `<div class="pkg"><span class="p1">Magic "${p.magic}" 4B</span><span class="p2">Nama len ${p.nameLen} → 2B</span><span class="p3">Nama "${esc(p.name)}" ${p.nameLen}B</span><span class="p4">Data ${p.dataLen}B</span></div>` + kv('Total', `${p.totalLen} byte (seluruhnya dienkripsi RC4)`)),
  ].join('');
}

function bitsLsb(v, changed) {
  const b = bin8(v);
  return `${b.slice(0, 7)}<span class="lsb ${changed ? '' : 'same'}">${b[7]}</span>`;
}

function renderStegoSteps(t) {
  const ratio = ((t.totalBitLen / t.capacityBits) * 100).toFixed(3);
  const pixRows = [];
  t.pixels.forEach(p => ['R', 'G', 'B'].forEach((ch, i) => {
    const changed = (p.before[i] & 1) !== (p.after[i] & 1);
    pixRows.push([`#${p.index} ${ch}`, p.before[i], bitsLsb(p.before[i], false), `<b>${p.bits[i]}</b>`, p.after[i], bitsLsb(p.after[i], changed), changed ? 'berubah' : 'tetap']);
  }));
  return [
    stepBox(1, 'Pesan → Bit', note('Pesan di-encode UTF-8, tiap byte menjadi 8 bit, lalu ditutup delimiter.') + table(['Char', 'Biner'], t.firstChars.map(c => [vis(c.char), c.bin])) + kv('Delimiter', t.delimiter) + kv('Total bit', `${t.messageBitLen} (pesan) + ${t.delimiter.length} (delimiter) = ${t.totalBitLen}`)),
    stepBox(2, 'Pixel Bit Inspector — LSB sebelum vs sesudah', note('Bit terakhir (LSB, disorot) tiap kanal R/G/B diganti dengan bit pesan. Perubahan maksimal ±1 sehingga tidak terlihat mata.') + table(['Piksel/Kanal', 'Sebelum', 'Biner', 'Bit pesan', 'Sesudah', 'Biner', 'Status'], pixRows)),
    stepBox(3, 'Kapasitas & Output', kv('Dimensi', `${t.width}×${t.height} px`) + kv('Kapasitas', `${t.capacityBits} bit (${t.capacityBytes} byte)`) + kv('Terpakai', `${t.totalBitLen} bit (${ratio}%)`) + note('Disimpan sebagai PNG (lossless) agar bit LSB tidak rusak oleh kompresi.')),
  ].join('');
}

// ══ INIT ═════════════════════════════════════════════════════════════════════
document.addEventListener('DOMContentLoaded', async () => {
  document.querySelectorAll('.tab').forEach(t => t.onclick = () => showTab(t.dataset.tab));
  bindLogin(); bindText(); bindFile(); bindStego(); bindLedger();
  try {
    await initDB();
    await ledger.load();
    await refreshSetupCard();
    await refreshFaceState();
    renderChain();
  } catch (e) {
    toast('Gagal inisialisasi database: ' + e.message, true);
    console.error(e);
  }
});
