/**
 * app.js — Secret Note (Industrial Vault Edition)
 * Mengelola:
 *   • Gatekeeper Dongle-First 3FA (USB Hardware / File .key + Real Face Biometrics + PIN SHA-256)
 *   • Pemisahan layar Gatekeeper vs Workspace Brankas & Sanitasi Memori saat Kunci Brankas
 *   • Super-Enkripsi (Vigenère Klasik A-Z Mod 26 + AES-256-GCM dengan AAD Owner Binding)
 *   • Enkripsi Berkas RC4, Steganografi LSB, dan Blockchain Audit Ledger
 *   • Penyimpanan ke SQLite Server (secret-note.db) dengan fallback IndexedDB
 */
'use strict';

const $ = (id) => document.getElementById(id);
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, c => ({
  '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
}[c]));

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
    return hashSHA256(
      this.index + '|' + this.timestamp + '|' + this.username + '|' + JSON.stringify(this.data) + '|' + this.previousHash
    );
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
    return Block.create(0, new Date().toISOString(), 'SYSTEM', {
      action: 'GENESIS',
      detail: 'Inisialisasi Rantai Audit Brankas Secret Note',
    }, '0');
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

async function logAction(action, detail, actor = null) {
  const user = actor || currentActiveUser || (selectedUser && selectedUser.username) || 'SYSTEM';
  await ledger.addBlock(new Block(ledger.chain.length, new Date().toISOString(), user, { action, detail }));
  if (loggedIn) renderChain();
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

function setStatus(id, msg, kind = '') {
  const e = $(id);
  if (!e) return;
  e.textContent = msg;
  e.className = 'status' + (kind ? ' ' + kind : '');
}

const fmtBytes = (n) => n < 1024 ? n + ' B' : n < 1048576 ? (n / 1024).toFixed(1) + ' KB' : (n / 1048576).toFixed(2) + ' MB';

async function guard(btn, fn) {
  btn.disabled = true;
  try {
    await fn();
  } catch (e) {
    toast(e.message || String(e), true);
    console.error(e);
  } finally {
    btn.disabled = false;
  }
}

// ══ SANITASI MEMORI & WORKSPACE ══════════════════════════════════════════════
let lastCipher = null;
let selectedFile = null;
let fileResult = null;
let stegoDataUrl = null;
let stegoBlobOut = null;
let coverNormalizedBlobOut = null;

/** Membersihkan seluruh input, output, dan jejak kriptografi di layar saat berganti sesi. */
function clearWorkspaceState() {
  lastCipher = null;
  selectedFile = null;
  fileResult = null;
  stegoDataUrl = null;
  stegoBlobOut = null;
  coverNormalizedBlobOut = null;

  // Bersihkan editor teks
  $('noteTitle').value = '';
  $('textInput').value = '';
  $('vigKey').value = '';
  $('aesKey').value = '';
  $('textLayer1').value = '';
  $('textOutput').value = '';
  $('textSteps').innerHTML = '<span class="muted">Jalankan proses enkripsi atau dekripsi untuk menampilkan rincian perhitungan matematis.</span>';
  $('vaultTextList').innerHTML = '';

  // Bersihkan berkas RC4
  $('fileInput').value = '';
  $('fileKey').value = '';
  setStatus('fileInfo', 'Belum ada berkas dipilih');
  $('fileResult').classList.add('hidden');
  $('btnFileDownload').classList.add('hidden');
  $('fileSteps').innerHTML = '<span class="muted">Jalankan enkripsi atau dekripsi berkas untuk melihat permutasi S-Box dan tabel XOR byte.</span>';
  $('vaultFileList').innerHTML = '';

  // Bersihkan steganografi
  $('coverFile').value = '';
  $('coverImg').src = '';
  $('coverImg').classList.add('hidden');
  setStatus('coverInfo', 'Pilih citra sampul untuk menghitung kapasitas byte');
  $('stegoMsg').value = '';
  $('stegoOut').src = '';
  $('stegoOut').classList.add('hidden');
  $('btnStegoDownload').classList.add('hidden');
  $('btnCoverNormalizedDownload').classList.add('hidden');
  $('stegoSizeStatus').classList.add('hidden');
  $('stegoFile').value = '';
  $('stegoIn').src = '';
  $('stegoIn').classList.add('hidden');
  $('stegoExtracted').value = '';
  $('stegoSteps').innerHTML = '<span class="muted">Sisipkan pesan pada citra untuk melihat perubahan bit LSB pada 2 piksel pertama.</span>';
}

function showTab(name) {
  if (!loggedIn) return;
  document.querySelectorAll('.tab').forEach(t => t.classList.toggle('active', t.dataset.tab === name));
  document.querySelectorAll('.panel').forEach(p => p.classList.toggle('active', p.id === 'tab-' + name));
  if (name === 'text') renderVaultText();
  if (name === 'file') renderVaultFiles();
  if (name === 'ledger') { renderChain(); renderDb(); }
}

function setSession(state, username = null, usbActive = false) {
  loggedIn = state;
  currentActiveUser = state ? username : null;
  clearWorkspaceState();

  $('gatekeeperView').classList.toggle('hidden', state);
  $('workspaceView').classList.toggle('hidden', !state);

  if (state) {
    $('userBadge').textContent = `Akun: ${username}`;
    $('usbWatchBadge').classList.toggle('hidden', !usbActive);
    showTab('text');
  } else {
    $('userBadge').textContent = '—';
    $('usbWatchBadge').classList.add('hidden');
  }
}

// ══ GATEKEEPER : DONGLE-FIRST 3-FACTOR AUTHENTICATION ════════════════════════
let selectedUser = null;
let dongleOk = false;
let faceOk = false;
let faceMode = 'biometrik';
let dongleModeUsed = 'usb';
let activeUsbHandle = null;
let activeUsbContent = null;
let regFaceDesc = null;

function getDongleMode() {
  const checked = document.querySelector('input[name="dongleMode"]:checked');
  return checked ? checked.value : 'usb';
}

function updateGatekeeperProgress() {
  // Identitas banner
  const banner = $('detectedIdentityBar');
  const dot = $('identityDot');
  if (dongleOk && selectedUser) {
    banner.classList.add('verified');
    dot.classList.add('ok');
    $('identityText').textContent = `Akun "${selectedUser.username}" · Seri Kunci ${selectedUser.dongleSerial}`;
    $('btnResetAuth').classList.remove('hidden');
  } else {
    banner.classList.remove('verified');
    dot.classList.remove('ok');
    $('identityText').textContent = 'Belum ada kunci fisik yang terhubung';
    $('btnResetAuth').classList.add('hidden');
  }

  // Tahap 1
  $('cardFactor1').classList.toggle('done', dongleOk);
  $('badgeFactor1').textContent = dongleOk ? 'Terverifikasi' : 'Menunggu';
  $('badgeFactor1').className = 'factor-badge' + (dongleOk ? ' ok' : '');

  // Tahap 2
  $('btnFace').disabled = !dongleOk;
  $('cardFactor2').classList.toggle('done', faceOk);
  $('badgeFactor2').textContent = faceOk ? 'Terverifikasi' : (dongleOk ? 'Siap' : 'Menunggu');
  $('badgeFactor2').className = 'factor-badge' + (faceOk ? ' ok' : '');

  // Tahap 3
  const readyPin = dongleOk && faceOk;
  $('loginPin').disabled = !readyPin;
  $('btnLogin').disabled = !readyPin;
  $('badgeFactor3').textContent = readyPin ? 'Siap' : 'Menunggu';
  if (readyPin && selectedUser) {
    setStatus('loginStatus', `Tahap 01 & 02 selesai untuk "${selectedUser.username}". Masukkan PIN brankas.`, 'ok');
  } else {
    setStatus('loginStatus', 'Menunggu Tahap 01 dan 02 selesai');
  }
}

function resetGatekeeperState() {
  stopUsbWatcher();
  stopFaceScan();
  selectedUser = null;
  dongleOk = false;
  faceOk = false;
  activeUsbHandle = null;
  activeUsbContent = null;
  $('dongleFile').value = '';
  $('dongleFileLabel').textContent = 'Pilih File Kunci (.key)';
  $('loginPin').value = '';
  $('faceDist').textContent = '';
  const ctx = $('faceCanvas').getContext('2d');
  ctx.clearRect(0, 0, $('faceCanvas').width, $('faceCanvas').height);
  setStatus('dongleStatus', 'Hubungkan USB atau pilih file .key');
  setStatus('faceStatus', 'Selesaikan Tahap 01 terlebih dahulu');
  updateGatekeeperProgress();
}

function applyVerifiedDongle(r, mode) {
  dongleOk = true;
  faceOk = false;
  selectedUser = r.user;
  dongleModeUsed = mode;
  $('faceDist').textContent = '';

  const hasFace = Array.isArray(selectedUser.faceDescriptor) && selectedUser.faceDescriptor.length === 128;
  if (!hasFace) {
    $('faceSim').checked = true;
  }
  setStatus(
    'faceStatus',
    hasFace
      ? `Kunci milik "${selectedUser.username}" dikenali. Menyiapkan kamera untuk verifikasi wajah...`
      : `Akun "${selectedUser.username}" menggunakan mode simulasi wajah. Klik "Pindai Wajah".`
  );
  updateGatekeeperProgress();

  // Panaskan kamera & model AI lebih awal begitu Tahap 01 lolos agar Tahap 02 tidak ada delay
  preloadFaceModels();
  if (hasFace && !$('faceSim').checked) {
    _startCamera($('faceVideo')).then(() => {
      setStatus('faceStatus', `Kamera siap untuk "${selectedUser.username}". Klik "Pindai Wajah".`);
    }).catch(() => { /* jika belum diizinkan, akan diminta saat klik Pindai Wajah */ });
  }
}

/** Callback otomatis saat USB flashdrive dicabut pada tengah sesi. */
async function handleUsbEject(reason) {
  const who = currentActiveUser || (selectedUser && selectedUser.username) || 'USER';
  const wasLoggedIn = loggedIn;
  if (wasLoggedIn) {
    await logAction('AUTO_LOCK_USB_EJECT', reason, who);
    setSession(false);
  }
  resetGatekeeperState();
  const alertEl = $('lockAlert');
  alertEl.textContent = `Peringatan Keamanan (${who}): ${reason} Brankas telah dikunci secara otomatis.`;
  alertEl.classList.remove('hidden');
  toast('Kunci USB terputus — brankas dikunci otomatis.', true);
}

function bindLogin() {
  $('btnResetAuth').onclick = () => {
    $('lockAlert').classList.add('hidden');
    resetGatekeeperState();
  };

  // Pilihan mode Kunci Fisik (USB vs Upload)
  document.querySelectorAll('input[name="dongleMode"]').forEach(r => {
    r.onchange = () => {
      const m = getDongleMode();
      $('dongleUsbBox').classList.toggle('hidden', m !== 'usb');
      $('dongleUploadBox').classList.toggle('hidden', m !== 'upload');
      resetGatekeeperState();
    };
  });

  // Tahap 1A: Hubungkan Drive USB Fisik (Dongle-First)
  $('btnUsbConnect').onclick = () => guard($('btnUsbConnect'), async () => {
    $('lockAlert').classList.add('hidden');
    const r = await connectUsbDrive();
    if (!r.valid) {
      resetGatekeeperState();
      setStatus('dongleStatus', r.reason, 'err');
      return;
    }
    activeUsbHandle = r.fileHandle;
    activeUsbContent = r.content;
    setStatus('dongleStatus', `Drive "${r.driveName}" terhubung · Akun "${r.username}" (${r.serial})`, 'ok');
    applyVerifiedDongle(r, 'usb');
    startUsbWatcher(r.fileHandle, r.content, handleUsbEject);
  });

  // Tahap 1B: Unggah File .key Manual (Dongle-First)
  $('dongleFile').onchange = async (e) => {
    $('lockAlert').classList.add('hidden');
    const file = e.target.files[0];
    if (!file) return;
    $('dongleFileLabel').textContent = file.name;
    const r = await checkDongleFile(file);
    if (!r.valid) {
      resetGatekeeperState();
      setStatus('dongleStatus', r.reason, 'err');
      return;
    }
    setStatus('dongleStatus', `File kunci valid · Akun "${r.username}" (${r.serial})`, 'ok');
    applyVerifiedDongle(r, 'upload');
  };

  // Tahap 2: Verifikasi Wajah
  const faceMsg = m => setStatus('faceStatus', m);
  const faceFail = (e) => {
    cancelFaceScanLoop();
    setStatus('faceStatus', (e.message || e) + ' — centang simulasi apabila perangkat tanpa kamera.', 'err');
    throw e;
  };

  $('btnFace').onclick = () => guard($('btnFace'), async () => {
    if (!dongleOk || !selectedUser) throw new Error('Hubungkan kunci fisik pada Tahap 01 terlebih dahulu.');
    faceOk = false;
    $('faceDist').textContent = '';
    if ($('faceSim').checked) {
      await initFaceScan($('faceVideo'), $('faceCanvas'), faceMsg);
      faceOk = true;
      faceMode = 'simulasi';
      setStatus('faceStatus', `Verifikasi simulasi selesai untuk "${selectedUser.username}".`, 'ok');
    } else {
      try {
        const r = await verifyUserFace($('faceVideo'), $('faceCanvas'), selectedUser.faceDescriptor, faceMsg);
        $('faceDist').textContent = `Jarak Euclidean: ${r.distance.toFixed(4)} (batas <= ${FACE_MATCH_THRESHOLD}) · Kemiripan: ${r.similarity.toFixed(1)}%`;
        if (!r.ok) {
          throw new Error(`Wajah tidak cocok dengan pemilik kunci "${selectedUser.username}" (d=${r.distance.toFixed(3)}).`);
        }
        faceOk = true;
        faceMode = 'biometrik';
        setStatus('faceStatus', `Wajah cocok dengan pemilik kunci "${selectedUser.username}".`, 'ok');
      } catch (e) {
        faceFail(e);
      }
    }
    updateGatekeeperProgress();
    if (faceOk) $('loginPin').focus();
  });

  $('faceSim').onchange = () => {
    faceOk = false;
    updateGatekeeperProgress();
  };

  // Tahap 3: Verifikasi PIN & Buka Brankas
  const executeLogin = () => guard($('btnLogin'), async () => {
    if (!selectedUser || !dongleOk) throw new Error('Kunci fisik belum terverifikasi.');
    if (!faceOk) throw new Error('Verifikasi wajah belum selesai.');
    const pin = $('loginPin').value;
    if (!pin) throw new Error('Masukkan PIN brankas.');
    const pinHash = await hashSHA256(pin);
    if (pinHash !== selectedUser.pinHash) {
      throw new Error('PIN brankas tidak sesuai.');
    }

    const uname = selectedUser.username;
    const usbActive = dongleModeUsed === 'usb' && !!activeUsbHandle;
    $('loginPin').value = '';
    $('lockAlert').classList.add('hidden');
    stopFaceScan();

    setSession(true, uname, usbActive);
    if (usbActive) {
      startUsbWatcher(activeUsbHandle, activeUsbContent, handleUsbEject);
    }
    await logAction('LOGIN', `Brankas dibuka (kunci: ${dongleModeUsed}, wajah: ${faceMode})`, uname);
    toast(`Brankas "${uname}" berhasil dibuka.`);
  });

  $('btnLogin').onclick = executeLogin;
  $('loginPin').addEventListener('keydown', e => {
    if (e.key === 'Enter' && !$('btnLogin').disabled) executeLogin();
  });

  $('btnLogout').onclick = async () => {
    const who = currentActiveUser;
    stopUsbWatcher();
    setSession(false);
    resetGatekeeperState();
    if (who) await logAction('LOGOUT', 'Brankas dikunci oleh pengguna', who);
    toast('Brankas telah dikunci.');
  };

  // ── Modal Pendaftaran Brankas Baru ─────────────────────────────────────────
  const openRegModal = () => {
    regFaceDesc = null;
    $('regUser').value = '';
    $('regPin').value = '';
    $('regPin2').value = '';
    $('regFaceSkip').checked = false;
    setStatus('regFaceStatus', 'Menyiapkan kamera...');
    $('regStatus').classList.add('hidden');
    $('regModal').classList.remove('hidden');
    preloadFaceModels();
    _startCamera($('regVideo')).then(() => {
      setStatus('regFaceStatus', 'Kamera aktif — posisikan wajah lalu klik "Rekam Sampel Wajah".');
    }).catch(() => {
      setStatus('regFaceStatus', 'Klik "Rekam Sampel Wajah" untuk mengizinkan akses kamera.');
    });
  };
  const closeRegModal = () => {
    stopFaceScan();
    $('regModal').classList.add('hidden');
  };

  $('btnOpenRegister').onclick = openRegModal;
  $('btnRegClose').onclick = closeRegModal;

  $('btnRegFace').onclick = () => guard($('btnRegFace'), async () => {
    if ($('regFaceSkip').checked) {
      throw new Error('Hilangkan centang lewati perekaman terlebih dahulu.');
    }
    try {
      const desc = await scanFaceDescriptor($('regVideo'), $('regCanvas'), m => setStatus('regFaceStatus', m), {
        samples: 3,
        timeoutMs: 20000,
        verb: 'Merekam',
      });
      regFaceDesc = Array.from(desc);
      cancelFaceScanLoop();
      const norm = Math.sqrt(regFaceDesc.reduce((s, v) => s + v * v, 0)).toFixed(3);
      setStatus('regFaceStatus', `Vektor wajah 128-d berhasil direkam (norm=${norm}).`, 'ok');
    } catch (e) {
      cancelFaceScanLoop();
      setStatus('regFaceStatus', e.message || String(e), 'err');
      throw e;
    }
  });

  $('btnRegSubmit').onclick = () => guard($('btnRegSubmit'), async () => {
    const username = $('regUser').value.trim().toLowerCase();
    if (!/^[a-z0-9_-]{3,20}$/.test(username)) {
      throw new Error('Nama pengguna harus 3–20 karakter (huruf kecil a–z, angka, _ atau -).');
    }
    if (await getUser(username)) {
      throw new Error(`Nama pengguna "${username}" sudah terdaftar.`);
    }
    const pin = $('regPin').value;
    if (pin.length < 4) throw new Error('PIN brankas minimal 4 karakter.');
    if (pin !== $('regPin2').value) throw new Error('Konfirmasi PIN tidak cocok.');
    if (!regFaceDesc && !$('regFaceSkip').checked) {
      throw new Error('Rekam sampel wajah terlebih dahulu, atau centang opsi lewati perekaman.');
    }

    const dongle = await generateDongle(username);
    const saveMode = document.querySelector('input[name="regDongle"]:checked')?.value || 'download';
    let dongleNote = `file ${dongle.fileName} diunduh`;
    if (saveMode === 'usb') {
      try {
        const driveName = await writeDongleToUsb(dongle);
        dongleNote = `ditulis ke drive USB "${driveName}/${dongle.fileName}"`;
      } catch {
        downloadBlob(dongle.blob, dongle.fileName);
        dongleNote = `diunduh sebagai ${dongle.fileName}`;
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
    await logAction(
      'USER_REGISTER',
      `Brankas "${username}" dibuat · seri kunci ${dongle.serial} (${dongleNote})`,
      username
    );
    closeRegModal();
    toast(`Brankas "${username}" berhasil dibuat (${dongleNote}). Hubungkan kunci tersebut pada Tahap 01.`);
  });
}

// ══ PANEL 1: SUPER-ENCRYPTION (Vigenère Mod 26 + AES-256-GCM AAD) ════════════
function bindText() {
  $('btnNewNote').onclick = () => {
    lastCipher = null;
    $('noteTitle').value = '';
    $('textInput').value = '';
    $('textLayer1').value = '';
    $('textOutput').value = '';
    $('textSteps').innerHTML = '<span class="muted">Editor telah dibersihkan.</span>';
  };

  $('btnCopyTextOut').onclick = async () => {
    const val = $('textOutput').value;
    if (!val) { toast('Tidak ada output untuk disalin.', true); return; }
    await navigator.clipboard.writeText(val);
    toast('Output berhasil disalin ke clipboard.');
  };

  $('btnTextEnc').onclick = () => guard($('btnTextEnc'), async () => {
    if (!currentActiveUser) throw new Error('Sesi brankas tidak aktif.');
    const text = $('textInput').value;
    if (!text) throw new Error('Masukkan teks yang akan dienkripsi.');
    const r = await superEncryptTrace(text, $('vigKey').value, $('aesKey').value, currentActiveUser);
    $('textLayer1').value = r.vigText;
    $('textOutput').value = r.aes.b64;
    lastCipher = r.aes.b64;
    $('textSteps').innerHTML = renderEncryptSteps(r, r.vigKey, $('aesKey').value);
    await logAction(
      'SUPER_ENCRYPT',
      `Enkripsi teks (${text.length} karakter, AAD=${currentActiveUser}), SHA256=${(await hashSHA256(r.aes.b64)).slice(0, 16)}…`
    );
    toast('Enkripsi dua lapis selesai.');
  });

  $('btnTextDec').onclick = () => guard($('btnTextDec'), async () => {
    if (!currentActiveUser) throw new Error('Sesi brankas tidak aktif.');
    const r = await superDecryptTrace($('textInput').value, $('vigKey').value, $('aesKey').value, currentActiveUser);
    $('textLayer1').value = r.vigCipher;
    $('textOutput').value = r.plain;
    $('textSteps').innerHTML = renderDecryptSteps(r, r.vigKey);
    toast('Dekripsi dua lapis berhasil.');
  });

  $('btnTextSave').onclick = () => guard($('btnTextSave'), async () => {
    if (!currentActiveUser) throw new Error('Sesi brankas tidak aktif.');
    if (!lastCipher) throw new Error('Enkripsi catatan terlebih dahulu sebelum menyimpan ke brankas.');
    const title = $('noteTitle').value.trim() || `Catatan #${new Date().toLocaleTimeString('id-ID')}`;
    await saveVaultText({
      username: currentActiveUser,
      title,
      ciphertext: lastCipher,
      createdAt: new Date().toISOString(),
    });
    await renderVaultText();
    toast(`Catatan "${title}" disimpan ke brankas.`);
  });
}

async function renderVaultText() {
  if (!currentActiveUser) return;
  const items = await getVaultTextsByUser(currentActiveUser);
  if (!items.length) {
    $('vaultTextList').innerHTML = '<span class="muted small-text">Belum ada catatan tersimpan pada brankas ini.</span>';
    return;
  }
  $('vaultTextList').innerHTML = items.map(i => `
    <div class="vault-item">
      <div class="vault-item-top">
        <span class="vault-item-title">${esc(i.title || 'Catatan #' + i.id)}</span>
        <span class="vault-item-meta">#${i.id}</span>
      </div>
      <div class="vault-item-meta">${esc(i.ciphertext.slice(0, 42))}…</div>
      <div class="vault-item-meta">${esc(new Date(i.createdAt).toLocaleString('id-ID'))}</div>
      <div class="vault-item-actions">
        <button class="btn tiny" data-load="${i.id}">Muat ke Editor</button>
        <button class="btn tiny danger" data-del="${i.id}">Hapus</button>
      </div>
    </div>
  `).join('');

  $('vaultTextList').querySelectorAll('[data-load]').forEach(b => {
    b.onclick = () => {
      const it = items.find(x => x.id == b.dataset.load);
      if (!it) return;
      $('noteTitle').value = it.title || '';
      $('textInput').value = it.ciphertext;
      $('textLayer1').value = '';
      $('textOutput').value = '';
      toast('Ciphertext dimuat ke kolom masukan. Isi kedua kunci lalu klik "Dekripsi ke Plaintext".');
    };
  });

  $('vaultTextList').querySelectorAll('[data-del]').forEach(b => {
    b.onclick = async () => {
      await deleteVaultText(Number(b.dataset.del), currentActiveUser);
      renderVaultText();
      toast('Catatan dihapus dari brankas.');
    };
  });
}

// ══ PANEL 2: ENKRIPSI BERKAS (RC4) ═══════════════════════════════════════════
function pickFile(f) {
  selectedFile = f;
  setStatus('fileInfo', f ? `${f.name} (${fmtBytes(f.size)})` : 'Belum ada berkas dipilih', f ? 'ok' : '');
}

function bindFile() {
  const dz = $('dropzone');
  dz.onclick = () => $('fileInput').click();
  $('fileInput').onchange = e => pickFile(e.target.files[0]);
  dz.ondragover = e => { e.preventDefault(); dz.classList.add('over'); };
  dz.ondragleave = () => dz.classList.remove('over');
  dz.ondrop = e => {
    e.preventDefault();
    dz.classList.remove('over');
    pickFile(e.dataTransfer.files[0]);
  };

  const showResult = (blob, name, msg) => {
    fileResult = { blob, name };
    $('btnFileDownload').classList.remove('hidden');
    $('fileResult').classList.remove('hidden');
    setStatus('fileResult', msg, 'ok');
  };

  $('btnFileEnc').onclick = () => guard($('btnFileEnc'), async () => {
    if (!currentActiveUser) throw new Error('Sesi brankas tidak aktif.');
    if (!selectedFile) throw new Error('Pilih berkas terlebih dahulu.');
    if (!$('fileKey').value) throw new Error('Masukkan kunci RC4.');
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
    await logAction('FILE_ENCRYPT_RC4', `${selectedFile.name} (${fmtBytes(selectedFile.size)}), SHA256=${hash.slice(0, 16)}…`);
    $('fileSteps').innerHTML = renderRc4Steps(trace, true);
    showResult(new Blob([enc], { type: 'application/octet-stream' }), selectedFile.name + '.enc', `Berkas terenkripsi: ${selectedFile.name}.enc (${fmtBytes(enc.length)})`);
    renderVaultFiles();
    toast('Berkas dienkripsi dan disimpan ke brankas.');
  });

  $('btnFileDec').onclick = () => guard($('btnFileDec'), async () => {
    if (!selectedFile) throw new Error('Pilih berkas .enc yang akan didekripsi.');
    if (!$('fileKey').value) throw new Error('Masukkan kunci RC4.');
    const r = await decryptFileRC4(selectedFile, $('fileKey').value);
    $('fileSteps').innerHTML = renderRc4Steps(r.trace, false);
    showResult(new Blob([r.data]), r.name, `Berkas dipulihkan: ${r.name} (${fmtBytes(r.data.length)})`);
    toast(`Berkas "${r.name}" berhasil didekripsi.`);
  });

  $('btnFileDownload').onclick = () => fileResult && downloadBlob(fileResult.blob, fileResult.name);
}

async function renderVaultFiles() {
  if (!currentActiveUser) return;
  const items = await getVaultFilesByUser(currentActiveUser);
  if (!items.length) {
    $('vaultFileList').innerHTML = '<span class="muted small-text">Belum ada berkas .enc pada brankas ini.</span>';
    return;
  }
  $('vaultFileList').innerHTML = items.map(i => `
    <div class="vault-item">
      <div class="vault-item-top">
        <span class="vault-item-title">${esc(i.originalName)}.enc</span>
        <span class="vault-item-meta">${fmtBytes(i.size)}</span>
      </div>
      <div class="vault-item-meta">SHA256: ${esc((i.sha256 || '').slice(0, 20))}…</div>
      <div class="vault-item-actions">
        <button class="btn tiny" data-dl="${i.id}">Unduh .enc</button>
        <button class="btn tiny danger" data-del="${i.id}">Hapus</button>
      </div>
    </div>
  `).join('');

  $('vaultFileList').querySelectorAll('[data-dl]').forEach(b => {
    b.onclick = async () => {
      const full = await getVaultFile(Number(b.dataset.dl));
      if (!full) return;
      downloadBlob(new Blob([full.data]), full.originalName + '.enc');
    };
  });

  $('vaultFileList').querySelectorAll('[data-del]').forEach(b => {
    b.onclick = async () => {
      await deleteVaultFile(Number(b.dataset.del));
      renderVaultFiles();
      toast('Berkas dihapus dari brankas.');
    };
  });
}

// ══ PANEL 3: STEGANOGRAFI CITRA (LSB) ════════════════════════════════════════
function bindStego() {
  $('coverFile').onchange = async e => {
    const f = e.target.files[0];
    if (!f) return;
    const img = await loadImageFromFile(f);
    $('coverImg').src = img.src;
    $('coverImg').classList.remove('hidden');
    $('coverImg')._fileSize = f.size;
    $('coverImg')._fileType = f.type || '';
    $('coverImg')._fileName = f.name || 'cover.png';
    $('coverImg').onload = () => setStatus(
      'coverInfo',
      `${f.name} (${f.size.toLocaleString('id-ID')} byte) · Dimensi ${$('coverImg').naturalWidth}×${$('coverImg').naturalHeight} px · Kapasitas ${fmtBytes(stegoCapacity($('coverImg')))}`,
      'ok'
    );
  };

  $('btnEmbed').onclick = () => guard($('btnEmbed'), async () => {
    if ($('coverImg').classList.contains('hidden')) throw new Error('Pilih citra sampul terlebih dahulu.');
    const msg = $('stegoMsg').value;
    if (!msg) throw new Error('Masukkan pesan rahasia yang akan disisipkan.');
    const { dataUrl, stegoBlob, coverNormalizedBlob, trace } = await embedLSBWithTrace($('coverImg'), msg);
    stegoDataUrl = dataUrl;
    stegoBlobOut = stegoBlob;
    coverNormalizedBlobOut = coverNormalizedBlob;

    $('stegoSteps').innerHTML = renderStegoSteps(trace);
    $('stegoOut').src = stegoDataUrl;
    $('stegoOut').classList.remove('hidden');
    $('btnStegoDownload').classList.remove('hidden');
    $('btnCoverNormalizedDownload').classList.remove('hidden');
    $('stegoSizeStatus').classList.remove('hidden');

    const exactWithOrig = trace.isOrigPng && trace.origUploadBytes === trace.stegoFinalBytes;
    const statusText = exactWithOrig
      ? `Ukuran Stego-Image: ${trace.stegoFinalBytes.toLocaleString('id-ID')} byte — 100% IDENTIK (selisih 0 byte) dengan file PNG asli yang diunggah.`
      : `Ukuran Stego-Image & Sampul PNG Terstandarisasi: ${trace.stegoFinalBytes.toLocaleString('id-ID')} byte (selisih 0 byte / identik).`;
    setStatus('stegoSizeStatus', statusText, 'ok');

    await logAction('STEGO_EMBED', `Pesan ${msg.length} karakter disisipkan ke LSB (${trace.stegoFinalBytes} byte, delta=${trace.sizeDiffBytes}B), SHA256=${(await hashSHA256(msg)).slice(0, 16)}…`);
    toast('Pesan berhasil disisipkan dengan ukuran berkas teroptimasi.');
  });

  $('btnStegoDownload').onclick = () => {
    if (stegoBlobOut) {
      downloadBlob(stegoBlobOut, 'stego-image.png');
    } else if (stegoDataUrl) {
      const a = document.createElement('a');
      a.href = stegoDataUrl;
      a.download = 'stego-image.png';
      a.click();
    }
  };

  $('btnCoverNormalizedDownload').onclick = () => {
    if (coverNormalizedBlobOut) {
      downloadBlob(coverNormalizedBlobOut, 'cover-reference.png');
    }
  };

  $('stegoFile').onchange = async e => {
    const f = e.target.files[0];
    if (!f) return;
    $('stegoIn').src = (await loadImageFromFile(f)).src;
    $('stegoIn').classList.remove('hidden');
  };

  $('btnExtract').onclick = () => guard($('btnExtract'), async () => {
    if ($('stegoIn').classList.contains('hidden')) throw new Error('Pilih berkas Stego-Image (.png) terlebih dahulu.');
    $('stegoExtracted').value = extractLSB($('stegoIn'));
    toast('Pesan tersembunyi berhasil diekstrak.');
  });
}

// ══ PANEL 4: BLOCKCHAIN LEDGER & DATABASE INSPECTOR ══════════════════════════
async function renderChain() {
  const res = await ledger.isChainValid();
  const badge = $('chainBadge');
  badge.textContent = res.valid ? `TERVERIFIKASI · ${ledger.chain.length} BLOK` : `TERDETEKSI MANIPULASI (MULAI BLOK #${res.at})`;
  badge.className = 'badge ' + (res.valid ? 'ok' : 'bad');
  $('chainView').innerHTML = ledger.chain.map((b, i) => `
    <div class="block ${!res.valid && i >= res.at ? 'bad' : ''}">
      <div class="block-head">
        <span>BLOK #${b.index} · ${esc(b.username)}</span>
        <button class="btn ghost tiny" data-tamper-idx="${b.index}">Ubah Data Blok #${b.index}</button>
      </div>
      <div class="mono-meta">${esc(new Date(b.timestamp).toLocaleString('id-ID'))}</div>
      <div><b>Data:</b> <code>${esc(JSON.stringify(b.data))}</code></div>
      <div><b>Prev:</b> <span class="hash">${esc(b.previousHash)}</span></div>
      <div><b>Hash:</b> <span class="hash">${esc(b.hash)}</span></div>
    </div>`).join('');

  $('chainView').querySelectorAll('[data-tamper-idx]').forEach(btn => {
    btn.onclick = async () => {
      const idx = Number(btn.dataset.tamperIdx);
      const blk = ledger.chain[idx];
      if (!blk) return;
      const curDetail = (blk.data && blk.data.detail) || JSON.stringify(blk.data);
      const input = prompt(`Simulasi Manipulasi pada Blok #${idx} (milik ${blk.username}):\nMasukkan teks detail baru untuk mengubah isi blok ini di memori:`, curDetail + ' [DIUBAH PAKSA]');
      if (input === null) return;
      blk.data = {
        action: (blk.data && blk.data.action) ? `${blk.data.action}_TAMPERED` : 'TAMPERED',
        detail: input,
      };
      await renderChain();
      toast(`Blok #${idx} telah dimodifikasi. Perhatikan rantai mulai Blok #${idx} ke atas terdeteksi tidak valid!`, true);
    };
  });
}

function dbReplacer(k, v) {
  if (v instanceof ArrayBuffer) return `<BLOB ${v.byteLength} bytes>`;
  if (v instanceof Uint8Array) return `<BLOB ${v.length} bytes>`;
  if (k === 'faceDescriptor' && Array.isArray(v)) {
    return `<float32[128] [${v.slice(0, 3).map(n => Number(n).toFixed(4)).join(', ')}, …]>`;
  }
  return v;
}

async function renderDb() {
  const store = $('dbStore').value;
  const all = await getAllDatabaseData();
  $('dbStats').textContent = Object.entries(all).map(([k, v]) => `${k}: ${v.length} baris`).join('   ·   ');
  const rows = all[store] || [];
  const cols = [...new Set(rows.flatMap(r => Object.keys(r)))];
  $('dbTable').innerHTML = rows.length
    ? `<tr>${cols.map(c => `<th>${esc(c)}</th>`).join('')}</tr>` + rows.map(r => `<tr>${cols.map(c => {
        const v = r[c];
        const s = typeof v === 'object' && v !== null ? JSON.stringify(v, (k, val) => dbReplacer(k || c, val)) : String(v ?? '');
        return `<td>${esc(s.length > 180 ? s.slice(0, 180) + '…' : s)}</td>`;
      }).join('')}</tr>`).join('')
    : '<tr><td class="muted">(Tabel kosong)</td></tr>';
}

function bindLedger() {
  $('dbStore').innerHTML = DB_STORES.map(s => `<option value="${s}">${s}</option>`).join('');
  $('dbStore').onchange = renderDb;
  $('btnDbRefresh').onclick = renderDb;
  $('btnValidate').onclick = async () => {
    await renderChain();
    const ok = (await ledger.isChainValid()).valid;
    toast(ok ? 'Integritas seluruh blok terverifikasi.' : 'Peringatan: Rantai blok telah dimanipulasi!', !ok);
  };
  $('btnTamper').onclick = async () => {
    if (ledger.chain.length < 2) { toast('Minimal harus terdapat 2 blok untuk simulasi.', true); return; }
    ledger.chain[1].data = { action: 'TAMPERED', detail: 'Data blok diubah secara paksa di memori' };
    await renderChain();
    toast('Blok #1 dimodifikasi di memori — perhatikan status rantai berubah merah.', true);
  };
  $('btnReloadChain').onclick = async () => {
    await ledger.load();
    await renderChain();
    toast('Rantai blok dipulihkan dari database.');
  };
  $('btnDbExport').onclick = async () => {
    const all = await getAllDatabaseData();
    downloadBlob(new Blob([JSON.stringify(all, dbReplacer, 2)], { type: 'application/json' }), 'secret-note-db-export.json');
  };
  $('btnDbReset').onclick = async () => {
    if (!confirm('Kosongkan seluruh tabel database (users, vault_text, vault_files, blockchain_ledger)?')) return;
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
  return table(['Karakter', inCol, 'Kunci', 'K (0..25)', 'Rumus Modulo 26', 'Hasil', outCol], rows) + more;
}

function aesParams(a, maskedKey) {
  return kv('PBKDF2', `HMAC-SHA256, ${a.iterations.toLocaleString()} iterasi, passphrase "${maskedKey}"`)
    + kv('Salt (16 B)', a.saltHex)
    + kv('Derived Key (256 b)', a.keyHex)
    + kv('IV (12 B)', a.ivHex)
    + kv('Konteks Akun (AAD)', a.aadLabel);
}

const pkgBar = (a) => `<div class="pkg"><span class="p1">Salt 16B</span><span class="p2">IV 12B</span><span class="p3">Ciphertext ${a.ctHex.length / 2}B</span><span class="p4">GCM Tag 16B</span></div>`;

function renderEncryptSteps(r, vigKey, aesKey) {
  const a = r.aes;
  return [
    stepBox(1, 'Parameter Masukan', kv('Plaintext', r.plaintext) + kv('Kunci Vigenère (A–Z)', vigKey) + kv('Passphrase AES', '•'.repeat(aesKey.length) + ` (${aesKey.length} karakter)`) + kv('Ukuran Data', `${r.plaintext.length} karakter / ${a.inputLen} byte`)),
    stepBox(2, 'Tahap 1 — Vigenère Klasik (Alfabet A–Z, Modulo 26)', note('Setiap huruf alfabet dipetakan A=0 … Z=25 dan digeser dengan rumus C = (P + K) mod 26. Spasi, angka, dan tanda baca dilewatkan (pass-through) sesuai teori klasik.') + vigTable(r.vigSteps, 1) + kv('Output Tahap 1', r.vigText)),
    stepBox(3, 'Tahap 2 — AES-256-GCM + Pengikatan Konteks Akun (AAD)', note('Kunci 256-bit diturunkan menggunakan PBKDF2. Identitas akun aktif diikat sebagai Additional Authenticated Data (AAD) sehingga ciphertext tidak dapat didekripsi oleh akun lain.') + aesParams(a, '•'.repeat(aesKey.length)) + kv('Ciphertext (hex)', short(a.ctHex)) + kv('GCM Auth Tag (16 B)', a.tagHex)),
    stepBox(4, 'Pengemasan Payload Base64', note('Format paket biner: [Salt 16B | IV 12B | Ciphertext | GCM Tag 16B] (' + a.payloadLen + ' byte).') + pkgBar(a) + kv('Output Base64', a.b64)),
  ].join('');
}

function renderDecryptSteps(r, vigKey) {
  const a = r.aes;
  return [
    stepBox(1, 'Pembongkaran Paket Base64', note(`Payload Base64 diuraikan kembali menjadi ${a.payloadLen} byte:`) + pkgBar(a) + kv('Salt (16 B)', a.saltHex) + kv('IV (12 B)', a.ivHex) + kv('GCM Auth Tag (16 B)', a.tagHex)),
    stepBox(2, 'Tahap 2 (Dibalik) — Verifikasi Tag & Dekripsi AES-256-GCM', note('Kunci diturunkan ulang dengan salt yang sama. GCM memverifikasi keutuhan ciphertext sekaligus kesesuaian pemilik akun (AAD).') + kv('Konteks Akun (AAD)', a.aadLabel) + kv('Derived Key (256 b)', a.keyHex) + kv('Output AES (Vigenère)', r.vigCipher)),
    stepBox(3, `Tahap 1 (Dibalik) — Dekripsi Vigenère Modulo 26 (Kunci "${esc(vigKey)}")`, note('Huruf dikembalikan dengan rumus P = (C − K + 26) mod 26.') + vigTable(r.vigSteps, -1)),
    stepBox(4, 'Plaintext Terpulihkan', kv('Plaintext', r.plain)),
  ].join('');
}

function renderRc4Steps(t, encrypt) {
  const arr = (a) => a.map(hx).join(' ');
  const inLabel = encrypt ? 'Plaintext' : 'Ciphertext', outLabel = encrypt ? 'Ciphertext' : 'Plaintext';
  const p = t.package;
  return [
    stepBox(1, 'KSA — Key-Scheduling Algorithm', note('Array S[0..255] diinisialisasi S[i]=i, kemudian diacak 256 putaran menggunakan byte kunci: j = (j + S[i] + key[i mod len]) mod 256.') + kv('Byte Kunci', arr(t.keyBytes)) + kv('S[0..15] Awal', arr(t.sBefore)) + kv('S[0..15] Hasil KSA', arr(t.sAfter))),
    stepBox(2, 'PRGA — Pseudo-Random Generation Algorithm', note('Membangkitkan aliran kunci (keystream) byte demi byte untuk di-XOR dengan data berkas.') + kv('Keystream 16 Byte Pertama', arr(t.keystream))),
    stepBox(3, `Operasi Bitwise XOR — ${inLabel} ⊕ Keystream = ${outLabel}`, note('Sampel 10 byte pertama dari paket berkas:') + table(['Indeks', `${inLabel} (hex)`, 'Biner', 'Keystream', 'Biner', `${outLabel} (hex)`, 'Biner'],
      t.rows.map(r => [r.index, hx(r.input), bin8(r.input), hx(r.keystream), bin8(r.keystream), hx(r.output), bin8(r.output)]))),
    stepBox(4, encrypt ? 'Struktur Berkas .enc' : 'Pemulihan Header Berkas', `<div class="pkg"><span class="p1">Magic "${p.magic}" 4B</span><span class="p2">Panjang Nama 2B</span><span class="p3">Nama "${esc(p.name)}" (${p.nameLen}B)</span><span class="p4">Data ${p.dataLen}B</span></div>` + kv('Total Ukuran', `${p.totalLen} byte`)),
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
    pixRows.push([`Piksel #${p.index} (${ch})`, p.before[i], bitsLsb(p.before[i], false), `<b>${p.bits[i]}</b>`, p.after[i], bitsLsb(p.after[i], changed), changed ? 'LSB Berubah' : 'Tetap']);
  }));
  return [
    stepBox(1, 'Konversi Pesan ke Aliran Bit & Delimiter', note('Setiap karakter UTF-8 diubah ke 8 bit biner dan diakhiri penanda 16-bit (0xFFFE).') + table(['Karakter', 'Representasi Biner'], t.firstChars.map(c => [vis(c.char), c.bin])) + kv('Delimiter Penutup', t.delimiter) + kv('Jumlah Bit', `${t.messageBitLen} bit pesan + ${t.delimiter.length} bit delimiter = ${t.totalBitLen} bit`)),
    stepBox(2, 'Perbandingan Bit Piksel (Sebelum vs Sesudah)', note('Bit paling kanan (LSB) pada kanal R, G, dan B digantikan oleh bit pesan.') + table(['Kanal Piksel', 'Nilai Awal', 'Biner Awal', 'Bit Pesan', 'Nilai Akhir', 'Biner Akhir', 'Status'], pixRows)),
    stepBox(3, 'Kapasitas Citra & Kamuflase Ukuran Berkas (Anti-Deteksi)',
      kv('Resolusi Citra', `${t.width}×${t.height} piksel`)
      + kv('Kapasitas Total', `${t.capacityBits.toLocaleString('id-ID')} bit (${t.capacityBytes.toLocaleString('id-ID')} byte)`)
      + kv('Kapasitas Terpakai', `${t.totalBitLen} bit (${ratio}%)`)
      + kv('Ukuran Unggahan Asli', `${(t.origUploadBytes || 0).toLocaleString('id-ID')} byte (${t.isOrigPng ? 'PNG' : 'Non-PNG'})`)
      + kv('Ukuran Hasil Kompresi Mentah', `Sampul: ${t.rawCoverPngBytes.toLocaleString('id-ID')} B · Stego: ${t.rawStegoPngBytes.toLocaleString('id-ID')} B (selisih alami ${Math.abs(t.rawStegoPngBytes - t.rawCoverPngBytes)} B)`)
      + kv('Ukuran Akhir Terstandarisasi', `Sampul: ${t.coverFinalBytes.toLocaleString('id-ID')} byte · Stego: ${t.stegoFinalBytes.toLocaleString('id-ID')} byte (Selisih: ${t.sizeDiffBytes} byte / 0.000%)`)
      + note('Menggunakan Adaptive 24-bit RGB PNG Encoder (tanpa channel Alpha mubazir) dan penyamaan ukuran byte (Byte-Size Equalization) sehingga ukuran berkas sebelum dan sesudah penyisipan identik hingga ke satuan byte.')
    ),
  ].join('');
}

// ══ INIT ═════════════════════════════════════════════════════════════════════
document.addEventListener('DOMContentLoaded', async () => {
  document.querySelectorAll('.tab').forEach(t => t.onclick = () => showTab(t.dataset.tab));
  bindLogin();
  bindText();
  bindFile();
  bindStego();
  bindLedger();
  try {
    const usingSqlite = await initDB();
    $('storageEngineLabel').textContent = usingSqlite ? 'SQLite Engine (secret-note.db)' : 'IndexedDB Engine';
    await ledger.load();
    resetGatekeeperState();
    preloadFaceModels();
  } catch (e) {
    toast('Gagal menyiapkan database: ' + e.message, true);
    console.error(e);
  }
});
