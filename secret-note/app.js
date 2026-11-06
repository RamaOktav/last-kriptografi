/**
 * app.js — Secret Note
 * Multi-User Orchestration, Dual-Mode USB Dongle (with Auto-Lock on Eject),
 * Real Face Biometrics, Vigenère Klasik A-Z Mod 26 Tracer, & Blockchain Ledger.
 */
'use strict';

const $ = (id) => document.getElementById(id);
const esc = (s) => String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

// ══ STATE SESSI & MULTI-USER ═════════════════════════════════════════════════
let currentActiveUser = null;
let loggedIn = false;

// ══ BLOCKCHAIN ═══════════════════════════════════════════════════════════════
class Block {
  constructor(index, timestamp, username, data, previousHash = '') {
    this.index = index;
    this.timestamp = timestamp;
    this.username = username || 'SYSTEM';
    this.data = data;
    this.previousHash = previousHash;
    this.hash = '';
  }
  async calculateHash() {
    return hashSHA256(this.index + '|' + this.timestamp + '|' + this.username + '|' + JSON.stringify(this.data) + '|' + this.previousHash);
  }
  static async create(index, timestamp, username, data, previousHash = '') {
    const b = new Block(index, timestamp, username, data, previousHash);
    b.hash = await b.calculateHash();
    return b;
  }
  static async fromRecord(r) {
    const b = new Block(r.index, r.timestamp, r.username || 'SYSTEM', r.data, r.previousHash);
    b.hash = r.hash;
    return b;
  }
}

class Blockchain {
  constructor() { this.chain = []; }
  async createGenesisBlock() {
    return Block.create(0, new Date().toISOString(), 'SYSTEM', { action: 'GENESIS', detail: 'Secret Note Multi-User Ledger' }, '0');
  }
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

/** Catat aksi sukses ke blockchain dengan identitas pelaku. */
async function logAction(action, detail, actor = null) {
  const user = actor || currentActiveUser || $('userSelect')?.value || 'SYSTEM';
  await ledger.addBlock(new Block(ledger.chain.length, new Date().toISOString(), user, { action, detail }));
  renderChain();
}

// ══ UTIL UI ══════════════════════════════════════════════════════════════════
let toastTimer;
function toast(msg, isErr = false) {
  const t = $('toast');
  t.textContent = msg;
  t.className = 'toast show' + (isErr ? ' err' : '');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.remove('show'), 3400);
}
function setStatus(id, msg, kind = '') { const e = $(id); if (!e) return; e.textContent = msg; e.className = 'status ' + kind; }
const fmtBytes = (n) => n < 1024 ? n + ' B' : n < 1048576 ? (n / 1024).toFixed(1) + ' KB' : (n / 1048576).toFixed(2) + ' MB';
async function guard(btn, fn) {
  btn.disabled = true;
  try { await fn(); } catch (e) { toast(e.message || String(e), true); console.error(e); } finally { btn.disabled = false; }
}

// ══ TAB NAV & SESSION ════════════════════════════════════════════════════════
function showTab(name) {
  if (!loggedIn && name !== 'login') { toast('Login terlebih dahulu di Gatekeeper.', true); return; }
  document.querySelectorAll('.tab').forEach(t => t.classList.toggle('active', t.dataset.tab === name));
  document.querySelectorAll('.panel').forEach(p => p.classList.toggle('active', p.id === 'tab-' + name));
  if (name === 'ledger') { renderChain(); renderDb(); }
  if (name === 'text') renderVaultText();
  if (name === 'file') renderVaultFiles();
  if (name !== 'login') stopFaceScan();
}

function setSession(state, username = null) {
  loggedIn = state;
  currentActiveUser = state ? username : null;
  $('sessionBadge').textContent = state ? '🟢 TERBUKA' : 'TERKUNCI';
  $('sessionBadge').className = 'badge ' + (state ? 'ok' : 'bad');
  $('userBadge').textContent = state ? `👤 User: ${username}` : '👤 —';
  $('userBadge').classList.toggle('hidden', !state);
  $('btnLogout').classList.toggle('hidden', !state);
  document.querySelectorAll('.tab').forEach(t => { if (t.dataset.tab !== 'login') t.classList.toggle('locked', !state); });
}

// ══ TAB 1: GATEKEEPER & MULTI-USER AUTH ══════════════════════════════════════
let selectedUser = null;
let dongleOk = false, faceOk = false, faceMode = 'asli', dongleModeUsed = 'usb';
let activeUsbHandle = null, activeUsbContent = null;
let regFaceDesc = null;

function getDongleMode() {
  const checked = document.querySelector('input[name="dongleMode"]:checked');
  return checked ? checked.value : 'usb';
}

function updateLoginHint() {
  if (!selectedUser) {
    setStatus('loginStatus', 'Pilih atau daftarkan akun terlebih dahulu');
    return;
  }
  if (dongleOk && faceOk) setStatus('loginStatus', `Faktor ① & ② lolos untuk "${selectedUser.username}". Masukkan PIN.`, 'ok');
  else setStatus('loginStatus', 'Selesaikan faktor ① (Dongle) dan ② (Wajah) lebih dulu');
}

function resetFactorStates() {
  stopUsbWatcher();
  stopFaceScan();
  dongleOk = false;
  faceOk = false;
  activeUsbHandle = null;
  activeUsbContent = null;
  $('dongleFile').value = '';
  $('faceDist').textContent = '';
  if (!selectedUser) {
    $('userInfo').textContent = 'Belum ada akun dipilih. Klik "Daftar User Baru" untuk membuat akun.';
    $('dongleNameHint').textContent = 'dongle-<user>.key';
    setStatus('dongleStatus', 'Pilih akun terlebih dahulu');
    setStatus('faceStatus', 'Pilih akun terlebih dahulu');
  } else {
    const hasFace = Array.isArray(selectedUser.faceDescriptor) && selectedUser.faceDescriptor.length === 128;
    $('userInfo').textContent = `Serial Dongle terdaftar: ${selectedUser.dongleSerial} · Biometrik Wajah: ${hasFace ? '128-d Vector Tersimpan' : 'Tidak ada (gunakan mode simulasi)'}`;
    $('dongleNameHint').textContent = dongleFileName(selectedUser.username);
    setStatus('dongleStatus', `Menunggu verifikasi ${dongleFileName(selectedUser.username)}`);
    setStatus('faceStatus', hasFace ? `Siap memverifikasi wajah "${selectedUser.username}".` : 'User ini didaftarkan tanpa wajah — centang Mode Simulasi.');
  }
  updateLoginHint();
}

async function refreshUserList(preferUsername = null) {
  const users = await getAllUsers();
  const sel = $('userSelect');
  if (!users.length) {
    sel.innerHTML = '<option value="">— Belum ada user terdaftar —</option>';
    selectedUser = null;
    resetFactorStates();
    return;
  }
  sel.innerHTML = users.map(u => `<option value="${esc(u.username)}">👤 ${esc(u.username)} (${esc(u.dongleSerial)})</option>`).join('');
  const target = preferUsername && users.some(u => u.username === preferUsername) ? preferUsername : users[0].username;
  sel.value = target;
  selectedUser = await getUser(target);
  resetFactorStates();
}

/** Callback otomatis saat USB flashdrive dicabut (Hardware Removal Policy). */
async function handleUsbEject(reason) {
  const who = currentActiveUser || (selectedUser && selectedUser.username) || 'USER';
  dongleOk = false;
  activeUsbHandle = null;
  activeUsbContent = null;
  if (loggedIn) {
    await logAction('AUTO_LOCK_USB_EJECT', reason, who);
    setSession(false);
    showTab('login');
  }
  resetFactorStates();
  const alertEl = $('lockAlert');
  alertEl.textContent = `🚨 HARDWARE TOKEN TERPUTUS (${who}): ${reason} — Sesi dikunci otomatis!`;
  alertEl.classList.remove('hidden');
  toast('USB Dongle terputus! Sesi dikunci otomatis.', true);
}

function bindLogin() {
  $('userSelect').onchange = async () => {
    $('lockAlert').classList.add('hidden');
    const uname = $('userSelect').value;
    selectedUser = uname ? await getUser(uname) : null;
    resetFactorStates();
  };

  // Switch mode dongle: USB Flashdrive vs Upload manual
  document.querySelectorAll('input[name="dongleMode"]').forEach(r => {
    r.onchange = () => {
      const m = getDongleMode();
      $('dongleUsbBox').classList.toggle('hidden', m !== 'usb');
      $('dongleUploadBox').classList.toggle('hidden', m !== 'upload');
      stopUsbWatcher();
      dongleOk = false;
      activeUsbHandle = null;
      activeUsbContent = null;
      $('dongleFile').value = '';
      if (selectedUser) setStatus('dongleStatus', `Menunggu verifikasi ${dongleFileName(selectedUser.username)}`);
      updateLoginHint();
    };
  });

  // Mode 1: Real USB Flashdrive Detection
  $('btnUsbConnect').onclick = () => guard($('btnUsbConnect'), async () => {
    $('lockAlert').classList.add('hidden');
    if (!selectedUser) throw new Error('Pilih atau daftarkan akun terlebih dahulu.');
    const r = await connectUsbDrive(selectedUser.username);
    dongleOk = r.valid;
    if (r.valid) {
      dongleModeUsed = 'usb';
      activeUsbHandle = r.fileHandle;
      activeUsbContent = r.content;
      setStatus('dongleStatus', `✔ USB "${r.driveName}" terhubung · ${r.serial} (Auto-Lock aktif)`, 'ok');
      startUsbWatcher(r.fileHandle, r.content, handleUsbEject);
    } else {
      setStatus('dongleStatus', `✖ ${r.reason}`, 'err');
    }
    updateLoginHint();
  });

  // Mode 2: Upload File Manual
  $('dongleFile').onchange = async (e) => {
    $('lockAlert').classList.add('hidden');
    if (!selectedUser) {
      setStatus('dongleStatus', '✖ Pilih akun terlebih dahulu.', 'err');
      return;
    }
    const r = await checkDongleFile(e.target.files[0], selectedUser.username);
    dongleOk = r.valid;
    if (r.valid) dongleModeUsed = 'upload';
    setStatus('dongleStatus', r.valid ? `✔ ${r.reason} (${r.serial}, mode upload)` : `✖ ${r.reason}`, r.valid ? 'ok' : 'err');
    updateLoginHint();
  };

  // Faktor 2: Biometrik Wajah
  const faceMsg = m => setStatus('faceStatus', m);
  const faceFail = (e) => {
    stopFaceScan();
    setStatus('faceStatus', '✖ ' + (e.message || e) + ' — jika perangkat bermasalah, aktifkan mode simulasi.', 'err');
    throw e;
  };

  $('btnFace').onclick = () => guard($('btnFace'), async () => {
    if (!selectedUser) throw new Error('Pilih akun terlebih dahulu.');
    faceOk = false;
    $('faceDist').textContent = '';
    if ($('faceSim').checked) {
      await initFaceScan($('faceVideo'), $('faceCanvas'), faceMsg);
      faceOk = true;
      faceMode = 'simulasi';
      setStatus('faceStatus', `⚠ Lolos via MODE SIMULASI untuk "${selectedUser.username}".`, 'ok');
    } else {
      try {
        const r = await verifyUserFace($('faceVideo'), $('faceCanvas'), selectedUser.faceDescriptor, faceMsg);
        $('faceDist').textContent = `Jarak Euclidean = ${r.distance.toFixed(4)} (batas ≤ ${FACE_MATCH_THRESHOLD}) · kemiripan ${r.similarity.toFixed(1)}%`;
        if (!r.ok) throw new Error(`Wajah tidak cocok dengan "${selectedUser.username}" (jarak ${r.distance.toFixed(3)} > ${FACE_MATCH_THRESHOLD}).`);
        faceOk = true;
        faceMode = 'asli';
        setStatus('faceStatus', `✔ Wajah cocok dengan "${selectedUser.username}" (biometrik asli).`, 'ok');
      } catch (e) { faceFail(e); }
    }
    updateLoginHint();
  });
  $('faceSim').onchange = () => { faceOk = false; updateLoginHint(); };

  // Faktor 3: Master PIN & Login
  $('btnLogin').onclick = () => guard($('btnLogin'), async () => {
    if (!selectedUser) throw new Error('Pilih akun terlebih dahulu.');
    if (!dongleOk) throw new Error('Faktor ① (Dongle) belum terverifikasi.');
    if (!faceOk) throw new Error('Faktor ② (Biometrik Wajah) belum terverifikasi.');
    const pinHash = await hashSHA256($('loginPin').value);
    if (pinHash !== selectedUser.pinHash) throw new Error('Master PIN salah.');
    $('loginPin').value = '';
    $('lockAlert').classList.add('hidden');
    stopFaceScan();
    setSession(true, selectedUser.username);
    if (dongleModeUsed === 'usb' && activeUsbHandle) {
      startUsbWatcher(activeUsbHandle, activeUsbContent, handleUsbEject);
    }
    await logAction('LOGIN', `Login 3 faktor berhasil (dongle: ${dongleModeUsed}, wajah: ${faceMode})`, selectedUser.username);
    toast(`Selamat datang, ${selectedUser.username}!`);
    showTab('text');
  });

  $('btnLogout').onclick = async () => {
    const who = currentActiveUser;
    stopUsbWatcher();
    setSession(false);
    resetFactorStates();
    if (who) await logAction('LOGOUT', 'User logout manual', who);
    showTab('login');
  };

  // ── Modal Registrasi User Baru ──
  const openRegModal = () => {
    regFaceDesc = null;
    $('regUser').value = '';
    $('regPin').value = '';
    $('regPin2').value = '';
    $('regFaceSkip').checked = false;
    setStatus('regFaceStatus', 'Belum direkam');
    $('regStatus').classList.add('hidden');
    $('regModal').classList.remove('hidden');
  };
  const closeRegModal = () => {
    stopFaceScan();
    $('regModal').classList.add('hidden');
  };

  $('btnOpenRegister').onclick = openRegModal;
  $('btnRegClose').onclick = closeRegModal;

  $('btnRegFace').onclick = () => guard($('btnRegFace'), async () => {
    if ($('regFaceSkip').checked) throw new Error('Hapus centang "Lewati wajah" untuk merekam wajah.');
    try {
      const desc = await scanFaceDescriptor($('regVideo'), $('regCanvas'), m => setStatus('regFaceStatus', m), {
        samples: 5, timeoutMs: 25000, verb: 'Merekam'
      });
      regFaceDesc = Array.from(desc);
      stopFaceScan();
      const norm = Math.sqrt(regFaceDesc.reduce((s, v) => s + v * v, 0)).toFixed(3);
      setStatus('regFaceStatus', `✔ Wajah terekam (128-d vector, norm=${norm})`, 'ok');
    } catch (e) {
      stopFaceScan();
      setStatus('regFaceStatus', '✖ ' + (e.message || e), 'err');
      throw e;
    }
  });

  $('btnRegSubmit').onclick = () => guard($('btnRegSubmit'), async () => {
    const username = $('regUser').value.trim().toLowerCase();
    if (!/^[a-z0-9_-]{3,20}$/.test(username)) {
      throw new Error('Username harus 3–20 karakter (huruf kecil a-z, angka, _ atau -).');
    }
    if (await getUser(username)) throw new Error(`Username "${username}" sudah digunakan.`);
    const pin = $('regPin').value;
    if (pin.length < 4) throw new Error('Master PIN minimal 4 karakter.');
    if (pin !== $('regPin2').value) throw new Error('Konfirmasi PIN tidak cocok.');
    if (!regFaceDesc && !$('regFaceSkip').checked) {
      throw new Error('Rekam wajah terlebih dahulu, atau centang "Lewati wajah".');
    }

    const dongle = await generateDongle(username);
    const saveMode = document.querySelector('input[name="regDongle"]:checked')?.value || 'download';
    let dongleNote = `file ${dongle.fileName} diunduh`;
    if (saveMode === 'usb') {
      try {
        const driveName = await writeDongleToUsb(dongle);
        dongleNote = `ditulis langsung ke USB "${driveName}/${dongle.fileName}"`;
      } catch (e) {
        // Fallback otomatis ke download bila penulisan ke USB gagal/dibatalkan
        downloadBlob(dongle.blob, dongle.fileName);
        dongleNote = `fallback download ${dongle.fileName} (${e.message})`;
      }
    } else {
      downloadBlob(dongle.blob, dongle.fileName);
    }

    const userRecord = {
      username,
      pinHash: await hashSHA256(pin),
      dongleSerial: dongle.serial,
      faceDescriptor: regFaceDesc,
      createdAt: new Date().toISOString(),
    };
    await registerUser(userRecord);
    await logAction('USER_REGISTER', `User "${username}" terdaftar · dongle ${dongle.serial} (${dongleNote}) · wajah: ${regFaceDesc ? '128-d' : 'dilewati'}`, username);
    closeRegModal();
    await refreshUserList(username);
    toast(`User "${username}" terdaftar (${dongleNote}).`);
  });
}

// ══ TAB 2: SUPER-ENCRYPTION (Vigenère Klasik A-Z Mod 26 + AES-256-GCM) ══════
let lastCipher = null;
function bindText() {
  $('btnTextEnc').onclick = () => guard($('btnTextEnc'), async () => {
    const text = $('textInput').value;
    if (!text) throw new Error('Teks kosong.');
    const r = await superEncryptTrace(text, $('vigKey').value, $('aesKey').value);
    $('textLayer1').value = r.vigText;
    $('textOutput').value = r.aes.b64;
    lastCipher = r.aes.b64;
    $('textSteps').innerHTML = renderEncryptSteps(r, r.vigKey, $('aesKey').value);
    await logAction('SUPER_ENCRYPT', `Teks ${text.length} char, SHA256(cipher)=${(await hashSHA256(r.aes.b64)).slice(0, 16)}…`);
    toast('Enkripsi dua lapis berhasil.');
  });
  $('btnTextDec').onclick = () => guard($('btnTextDec'), async () => {
    const r = await superDecryptTrace($('textInput').value, $('vigKey').value, $('aesKey').value);
    $('textLayer1').value = r.vigCipher;
    $('textOutput').value = r.plain;
    $('textSteps').innerHTML = renderDecryptSteps(r, r.vigKey);
    toast('Dekripsi berhasil.');
  });
  $('btnTextSave').onclick = () => guard($('btnTextSave'), async () => {
    if (!currentActiveUser) throw new Error('Anda belum login.');
    if (!lastCipher) throw new Error('Enkripsi teks terlebih dahulu.');
    await saveVaultText({ username: currentActiveUser, ciphertext: lastCipher, createdAt: new Date().toISOString() });
    await renderVaultText();
    toast(`Disimpan ke vault milik "${currentActiveUser}".`);
  });
}
async function renderVaultText() {
  if (!currentActiveUser) { $('vaultTextList').innerHTML = '<span class="muted">Login terlebih dahulu</span>'; return; }
  const items = await getVaultTextsByUser(currentActiveUser);
  $('vaultTextList').innerHTML = items.length
    ? items.map(i => `<div class="item"><span>#${i.id} · 👤 ${esc(i.username)} · ${esc(i.createdAt)} · ${esc(i.ciphertext.slice(0, 36))}…</span><button class="btn small" data-load="${i.id}">Muat</button></div>`).join('')
    : `<span class="muted">Vault teks milik "${esc(currentActiveUser)}" masih kosong.</span>`;
  $('vaultTextList').querySelectorAll('[data-load]').forEach(b => b.onclick = () => {
    const it = items.find(x => x.id == b.dataset.load);
    $('textInput').value = it.ciphertext;
    toast('Ciphertext dimuat ke input. Isi kunci lalu klik Dekripsi.');
  });
}

// ══ TAB 3: FILE CRYPTO (RC4) ═════════════════════════════════════════════════
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
    if (!currentActiveUser) throw new Error('Anda belum login.');
    if (!selectedFile) throw new Error('Pilih file terlebih dahulu.');
    if (!$('fileKey').value) throw new Error('Kunci RC4 kosong.');
    const { bytes: enc, trace } = await encryptFileRC4(selectedFile, $('fileKey').value);
    const hash = await hashSHA256(enc);
    await saveVaultFile({
      username: currentActiveUser,
      originalName: selectedFile.name,
      size: enc.length,
      createdAt: new Date().toISOString(),
      sha256: hash,
      data: enc.buffer,
    });
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
  if (!currentActiveUser) { $('vaultFileList').innerHTML = '<span class="muted">Login terlebih dahulu</span>'; return; }
  const items = await getVaultFilesByUser(currentActiveUser);
  $('vaultFileList').innerHTML = items.length
    ? items.map(i => `<div class="item"><span>#${i.id} · 👤 ${esc(i.username)} · ${esc(i.originalName)}.enc · ${fmtBytes(i.size)}</span><span><button class="btn small" data-dl="${i.id}">Download</button> <button class="btn small danger" data-del="${i.id}">Hapus</button></span></div>`).join('')
    : `<span class="muted">Vault file milik "${esc(currentActiveUser)}" masih kosong.</span>`;
  $('vaultFileList').querySelectorAll('[data-dl]').forEach(b => b.onclick = () => {
    const it = items.find(x => x.id == b.dataset.dl);
    downloadBlob(new Blob([it.data]), it.originalName + '.enc');
  });
  $('vaultFileList').querySelectorAll('[data-del]').forEach(b => b.onclick = async () => {
    await deleteVaultFile(Number(b.dataset.del));
    renderVaultFiles();
  });
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
      <b>Block #${b.index}</b> · 👤 <b>${esc(b.username)}</b> · ${esc(b.timestamp)}<br>
      <b>Data:</b> ${esc(JSON.stringify(b.data))}<br>
      <b>Prev:</b> <span class="hash">${esc(b.previousHash)}</span><br>
      <b>Hash:</b> <span class="hash">${esc(b.hash)}</span>
    </div>`).join('');
}

function dbReplacer(k, v) {
  if (v instanceof ArrayBuffer) return `<binary ${v.byteLength} bytes>`;
  if (v instanceof Uint8Array) return `<binary ${v.length} bytes>`;
  if (k === 'faceDescriptor' && Array.isArray(v)) return `<float32[128] [${v.slice(0, 3).map(n => Number(n).toFixed(4)).join(', ')}, …]>`;
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
        let s = typeof v === 'object' && v !== null ? JSON.stringify(v, (k, val) => dbReplacer(k || c, val)) : String(v ?? '');
        return `<td>${esc(s.length > 200 ? s.slice(0, 200) + '…' : s)}</td>`;
      }).join('')}</tr>`).join('')
    : '<tr><td>(kosong)</td></tr>';
}

function bindLedger() {
  $('dbStore').innerHTML = DB_STORES.map(s => `<option>${s}</option>`).join('');
  $('dbStore').onchange = renderDb;
  $('btnDbRefresh').onclick = renderDb;
  $('btnValidate').onclick = async () => {
    await renderChain();
    const ok = (await ledger.isChainValid()).valid;
    toast(ok ? 'Rantai valid.' : 'Rantai tidak valid!', !ok);
  };
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
    if (!confirm('Hapus SELURUH data (semua user, ledger, vault)?')) return;
    stopUsbWatcher();
    await clearAllDatabaseData();
    location.reload();
  };
}

// ══ RENDERER STEP-BY-STEP ════════════════════════════════════════════════════
const MAX_ROWS = 24;
const short = (h, n = 96) => h.length > n ? h.slice(0, n) + `… (${h.length / 2} byte)` : h;
const hx = (v) => v.toString(16).padStart(2, '0');
const bin8 = (v) => v.toString(2).padStart(8, '0');
const stepBox = (n, title, body) => `<div class="step"><div class="step-n">${n}</div><div class="step-b"><h4>${title}</h4>${body}</div></div>`;
const kv = (label, val) => `<div class="kv"><span>${label}</span><code>${esc(val)}</code></div>`;
const note = (t) => `<p>${t}</p>`;
const table = (head, rows) => `<div class="mini-wrap"><table class="mini"><tr>${head.map(h => `<th>${h}</th>`).join('')}</tr>${rows.map(r => `<tr>${r.map(c => `<td>${c}</td>`).join('')}</tr>`).join('')}</table></div>`;
const vis = (s) => s === ' ' ? '␣' : esc(s);

function vigTable(steps, dir) {
  const inCol = dir > 0 ? 'P (0..25)' : 'C (0..25)';
  const outCol = dir > 0 ? 'C (0..25)' : 'P (0..25)';
  const rows = steps.slice(0, MAX_ROWS).map(s => s.isAlpha
    ? [vis(s.char), s.p, vis(s.keyChar), s.keyShift,
       dir > 0 ? `(${s.p} + ${s.keyShift}) mod 26 = ${s.c}` : `(${s.p} − ${s.keyShift} + 26) mod 26 = ${s.c}`,
       vis(s.resChar), s.c]
    : [vis(s.char), '—', '—', '—', 'pass-through (non-alfabet)', vis(s.resChar), '—']);
  const more = steps.length > MAX_ROWS ? note(`Menampilkan ${MAX_ROWS} dari ${steps.length} karakter.`) : '';
  return table(['Huruf', inCol, 'Kunci', 'K (0..25)', 'Rumus Mod 26', 'Hasil', outCol], rows) + more;
}

function aesParams(a, maskedKey) {
  return kv('PBKDF2', `HMAC-SHA256, ${a.iterations.toLocaleString()} iterasi, passphrase "${maskedKey}"`)
    + kv('Salt (16 B)', a.saltHex) + kv('Derived Key (256 b)', a.keyHex) + kv('IV (12 B)', a.ivHex);
}

const pkgBar = (a) => `<div class="pkg"><span class="p1">Salt 16B</span><span class="p2">IV 12B</span><span class="p3">Ciphertext ${a.ctHex.length / 2}B</span><span class="p4">Tag 16B</span></div>`;

function renderEncryptSteps(r, vigKey, aesKey) {
  const a = r.aes;
  return [
    stepBox(1, 'Input', kv('Plaintext', r.plaintext) + kv('Kunci Vigenère (A–Z)', vigKey) + kv('Kunci AES', '•'.repeat(aesKey.length) + ` (${aesKey.length} karakter)`) + kv('Panjang', `${r.plaintext.length} karakter / ${a.inputLen} byte`)),
    stepBox(2, 'Lapis 1 — Vigenère Cipher Klasik (A–Z, Modulo 26)', note('Huruf alfabet dipetakan A=0 … Z=25 lalu digeser C = (P + K) mod 26. Karakter non-huruf (spasi, angka, simbol) di-bypass (pass-through) sesuai teori klasik.') + vigTable(r.vigSteps, 1) + kv('Hasil perantara', r.vigText)),
    stepBox(3, 'Lapis 2 — AES-256-GCM (Modern)', note('Kunci 256-bit diturunkan dari passphrase memakai PBKDF2 + salt acak, lalu seluruh teks perantara (termasuk angka/simbol) dienkripsi AES-GCM.') + aesParams(a, '•'.repeat(aesKey.length)) + kv('Ciphertext (hex)', short(a.ctHex)) + kv('Auth Tag (16 B)', a.tagHex)),
    stepBox(4, 'Packaging → Base64', note('Payload = Salt | IV | Ciphertext | Tag, lalu di-encode Base64 (' + a.payloadLen + ' byte).') + pkgBar(a) + kv('Ciphertext akhir', a.b64)),
  ].join('');
}

function renderDecryptSteps(r, vigKey) {
  const a = r.aes;
  return [
    stepBox(1, 'Unpack Base64', note(`Base64 di-decode menjadi ${a.payloadLen} byte lalu dipisah:`) + pkgBar(a) + kv('Salt', a.saltHex) + kv('IV', a.ivHex) + kv('Auth Tag', a.tagHex)),
    stepBox(2, 'Lapis 2 (dibalik) — AES-256-GCM Decrypt', note('Kunci diturunkan ulang dari passphrase + salt yang sama. Tag diverifikasi; jika kunci salah / data diubah, dekripsi gagal.') + kv('PBKDF2', `HMAC-SHA256, ${a.iterations.toLocaleString()} iterasi`) + kv('Derived Key (256 b)', a.keyHex) + kv('Ciphertext (hex)', short(a.ctHex)) + kv('Hasil (Vigenère cipher)', r.vigCipher)),
    stepBox(3, `Lapis 1 (dibalik) — Vigenère Klasik Decrypt (kunci "${esc(vigKey)}")`, note('Huruf dikembalikan dengan rumus P = (C − K + 26) mod 26; karakter non-huruf tetap.') + vigTable(r.vigSteps, -1)),
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
    await refreshUserList();
    renderChain();
  } catch (e) {
    toast('Gagal inisialisasi database: ' + e.message, true);
    console.error(e);
  }
});
