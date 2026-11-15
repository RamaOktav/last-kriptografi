/**
 * face-scan.js — Secret Note
 * Gatekeeper Dongle-First Multi-User:
 *   (1) Dual-Mode USB Dongle — Dongle-First Identification (1 USB = 1 User)
 *       • Mode USB fisik : Memindai drive USB (File System Access API), menemukan file .key,
 *                          memverifikasi signature SHA-256, dan langsung mengenali pemilik akun.
 *                          Dilengkapi watcher yang mengunci brankas otomatis begitu USB dicabut.
 *       • Mode upload    : Mengunggah file .key dan langsung mengenali pemilik akun.
 *   (2) Biometrik Wajah Riil (face-api.js) — 128-d descriptor + Euclidean Distance (<= 0.50).
 */
'use strict';

const DONGLE_TYPE = 'SECRET-NOTE-DONGLE';
const USB_WATCH_INTERVAL = 2000;
const FACE_MATCH_THRESHOLD = 0.50;
const FACE_MODEL_URLS = ['./models', 'https://cdn.jsdelivr.net/npm/@vladmandic/face-api/model/'];

let faceStream = null;
let faceRaf = null;
let faceRunId = 0;
let faceModelsLoaded = false;
let usbWatchTimer = null;

// ══ DONGLE TOKEN (DONGLE-FIRST IDENTIFICATION) ═══════════════════════════════
const dongleFileName = (username) => `dongle-${username}.key`;
const isUsbApiSupported = () => typeof window.showDirectoryPicker === 'function';

async function _dongleSignature(serial, username, secret) {
  return hashSHA256(`${DONGLE_TYPE}|${serial}|${username}|${secret}`);
}

/** Membuat token dongle untuk satu user. @returns {{blob, serial, fileName, json}} */
async function generateDongle(username) {
  const serial = 'SN-' + bytesToHex(crypto.getRandomValues(new Uint8Array(6))).toUpperCase();
  const secret = bytesToHex(crypto.getRandomValues(new Uint8Array(24)));
  const token = {
    type: DONGLE_TYPE,
    version: 2,
    serial,
    username,
    secret,
    signature: await _dongleSignature(serial, username, secret),
  };
  const json = JSON.stringify(token, null, 2);
  return {
    blob: new Blob([json], { type: 'application/octet-stream' }),
    serial,
    fileName: dongleFileName(username),
    json,
  };
}

/**
 * Memvalidasi isi file .key dan mengidentifikasi pemilik akun secara langsung (tanpa dropdown).
 * @param {string} jsonStr
 * @returns {Promise<{valid:boolean, reason:string, username?:string, serial?:string, user?:object}>}
 */
async function verifyDonglePayload(jsonStr) {
  let t;
  try {
    t = JSON.parse(jsonStr);
  } catch {
    return { valid: false, reason: 'Format file kunci tidak valid (bukan JSON).' };
  }
  if (!t || t.type !== DONGLE_TYPE || !t.serial || !t.username || !t.secret || !t.signature) {
    return { valid: false, reason: 'Struktur kunci fisik tidak dikenali.' };
  }
  const expectedSig = await _dongleSignature(t.serial, t.username, t.secret);
  if (expectedSig !== t.signature) {
    return { valid: false, reason: 'Tanda tangan kriptografis (SHA-256) tidak cocok — file kunci telah dimodifikasi.' };
  }
  const user = await getUser(t.username);
  if (!user) {
    return { valid: false, reason: `Akun "${t.username}" pada kunci ini tidak ditemukan di database.` };
  }
  if (user.dongleSerial !== t.serial) {
    return { valid: false, reason: `Nomor seri kunci (${t.serial}) sudah tidak berlaku untuk akun "${t.username}".` };
  }
  return {
    valid: true,
    reason: 'Kunci fisik terverifikasi.',
    username: user.username,
    serial: t.serial,
    user,
  };
}

/** Mode 2: Unggah file .key manual -> otomatis identifikasi user. */
async function checkDongleFile(file) {
  if (!file) return { valid: false, reason: 'Tidak ada file dipilih.' };
  if (!file.name.toLowerCase().endsWith('.key')) {
    return { valid: false, reason: 'File kunci harus berekstensi .key' };
  }
  return verifyDonglePayload(await file.text());
}

/** Meminta akses folder/drive USB (memerlukan klik pengguna). */
async function pickUsbDrive(mode = 'read') {
  if (!isUsbApiSupported()) {
    throw new Error('Browser ini tidak mendukung Web File System Access API. Gunakan Chrome/Edge atau pilih mode Unggah File .key.');
  }
  try {
    return await window.showDirectoryPicker({ id: 'secretnote-usb', mode });
  } catch (e) {
    if (e.name === 'AbortError') throw new Error('Pemilihan drive USB dibatalkan.');
    throw new Error('Drive tidak dapat diakses: ' + e.message + ' — jika root drive diblokir oleh OS, buat folder di dalam USB (misal E:\\VAULT) dan pilih folder tersebut.');
  }
}

/** Mengumpulkan semua file .key dari direktori yang dipilih (dan subfolder SECRETNOTE/VAULT bila ada). */
async function _collectKeyFilesFromDir(dirHandle) {
  const candidates = [];
  async function scanDir(dh) {
    for await (const [name, handle] of dh.entries()) {
      if (handle.kind === 'file' && name.toLowerCase().endsWith('.key')) {
        candidates.push({ name, handle });
      }
    }
  }
  await scanDir(dirHandle);
  for (const subName of ['SECRETNOTE', 'VAULT']) {
    try {
      const sub = await dirHandle.getDirectoryHandle(subName);
      await scanDir(sub);
    } catch { /* abaikan jika tidak ada */ }
  }
  return candidates;
}

/**
 * Mode 1: Deteksi USB Flashdrive fisik -> pindai file .key dan identifikasi pemilik akun.
 */
async function connectUsbDrive() {
  const dirHandle = await pickUsbDrive('read');
  const keyFiles = await _collectKeyFilesFromDir(dirHandle);
  if (!keyFiles.length) {
    return {
      valid: false,
      reason: `Tidak ditemukan file .key di drive "${dirHandle.name}".`,
    };
  }
  let lastError = 'Tidak ada kunci yang cocok.';
  for (const item of keyFiles) {
    try {
      const content = await (await item.handle.getFile()).text();
      const res = await verifyDonglePayload(content);
      if (res.valid) {
        return {
          ...res,
          dirHandle,
          fileHandle: item.handle,
          fileName: item.name,
          content,
          driveName: dirHandle.name,
        };
      }
      lastError = `${item.name}: ${res.reason}`;
    } catch (e) {
      lastError = e.message || String(e);
    }
  }
  return { valid: false, reason: lastError };
}

/** Menulis token langsung ke flashdisk saat registrasi. */
async function writeDongleToUsb(dongle) {
  const dirHandle = await pickUsbDrive('readwrite');
  const fh = await dirHandle.getFileHandle(dongle.fileName, { create: true });
  const w = await fh.createWritable();
  await w.write(dongle.json);
  await w.close();
  return dirHandle.name;
}

/**
 * Watcher: tiap 2 detik membaca ulang token dari drive USB.
 * Jika drive dicabut / file hilang / isi berubah -> panggil onEject(reason).
 */
function startUsbWatcher(fileHandle, expectedContent, onEject) {
  stopUsbWatcher();
  let busy = false;
  usbWatchTimer = setInterval(async () => {
    if (busy) return;
    busy = true;
    try {
      const text = await (await fileHandle.getFile()).text();
      if (text !== expectedContent) {
        stopUsbWatcher();
        onEject('Isi file kunci pada USB mengalami perubahan.');
      }
    } catch {
      stopUsbWatcher();
      onEject('Drive USB dicabut atau koneksi perangkat terputus.');
    } finally {
      busy = false;
    }
  }, USB_WATCH_INTERVAL);
}

function stopUsbWatcher() {
  if (usbWatchTimer) clearInterval(usbWatchTimer);
  usbWatchTimer = null;
}

// ══ KAMERA & BIOMETRIK WAJAH (face-api.js) ═══════════════════════════════════
async function _startCamera(video) {
  if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
    throw new Error('Kamera tidak tersedia pada browser ini (pastikan menggunakan localhost).');
  }
  if (faceStream) faceStream.getTracks().forEach(t => t.stop());
  faceStream = await navigator.mediaDevices.getUserMedia({
    video: { width: 640, height: 480, facingMode: 'user' },
    audio: false,
  });
  video.srcObject = faceStream;
  await video.play();
}

async function loadFaceModels(onStatus) {
  if (faceModelsLoaded) return;
  if (typeof faceapi === 'undefined') {
    throw new Error('Modul face-api.js belum termuat (periksa koneksi jaringan).');
  }
  let lastErr;
  for (const url of FACE_MODEL_URLS) {
    try {
      if (onStatus) onStatus('Memuat model pengenalan wajah...');
      await Promise.all([
        faceapi.nets.tinyFaceDetector.loadFromUri(url),
        faceapi.nets.faceLandmark68Net.loadFromUri(url),
        faceapi.nets.faceRecognitionNet.loadFromUri(url),
      ]);
      faceModelsLoaded = true;
      return;
    } catch (e) {
      lastErr = e;
    }
  }
  throw new Error('Gagal memuat model pengenalan wajah: ' + (lastErr && lastErr.message || lastErr));
}

function euclideanDistance(a, b) {
  let sum = 0;
  for (let i = 0; i < a.length; i++) {
    const d = a[i] - b[i];
    sum += d * d;
  }
  return Math.sqrt(sum);
}

function _drawFaceOverlay(ctx, W, H, box, color, label) {
  ctx.clearRect(0, 0, W, H);
  if (!box) {
    ctx.fillStyle = '#f59e0b';
    ctx.font = '14px "JetBrains Mono", monospace';
    ctx.fillText(label || 'Posisikan wajah di tengah kamera', 16, 28);
    return;
  }
  const x = W - (box.x + box.width);
  ctx.strokeStyle = color;
  ctx.lineWidth = 2;
  ctx.strokeRect(x, box.y, box.width, box.height);
  ctx.fillStyle = color;
  ctx.font = '13px "JetBrains Mono", monospace';
  ctx.fillText(label, x, Math.max(18, box.y - 8));
}

async function scanFaceDescriptor(video, canvas, onStatus, { samples = 5, timeoutMs = 25000, reference = null, verb = 'Memindai' } = {}) {
  const runId = ++faceRunId;
  await loadFaceModels(onStatus);
  if (onStatus) onStatus('Mengaktifkan kamera...');
  await _startCamera(video);
  const W = (canvas.width = video.videoWidth || 640);
  const H = (canvas.height = video.videoHeight || 480);
  const ctx = canvas.getContext('2d');
  const opts = new faceapi.TinyFaceDetectorOptions({ inputSize: 320, scoreThreshold: 0.5 });
  const descs = [];
  const t0 = performance.now();

  while (descs.length < samples && performance.now() - t0 < timeoutMs) {
    if (runId !== faceRunId) throw new Error('Pemindaian dihentikan.');
    const det = await faceapi.detectSingleFace(video, opts).withFaceLandmarks().withFaceDescriptor();
    if (det) {
      descs.push(det.descriptor);
      let label = `${verb} ${descs.length}/${samples}`;
      if (reference) label += ` · d=${euclideanDistance(det.descriptor, reference).toFixed(3)}`;
      _drawFaceOverlay(ctx, W, H, det.detection.box, '#10b981', label);
      if (onStatus) onStatus(`${verb} sampel wajah (${descs.length}/${samples})...`);
    } else {
      _drawFaceOverlay(ctx, W, H, null, null, 'Wajah belum terlihat jelas — hadap ke kamera');
    }
  }
  if (descs.length < samples) {
    throw new Error('Wajah tidak terdeteksi secara stabil. Pastikan pencahayaan cukup.');
  }
  const mean = new Float32Array(128);
  for (const d of descs) for (let i = 0; i < 128; i++) mean[i] += d[i] / descs.length;
  return mean;
}

async function verifyUserFace(video, canvas, storedDescriptor, onStatus) {
  if (!storedDescriptor) {
    throw new Error('Akun ini tidak memiliki data vektor wajah. Gunakan opsi Simulasi Darurat.');
  }
  const desc = await scanFaceDescriptor(video, canvas, onStatus, {
    samples: 3,
    timeoutMs: 20000,
    reference: storedDescriptor,
    verb: 'Verifikasi',
  });
  const distance = euclideanDistance(desc, storedDescriptor);
  const ok = distance <= FACE_MATCH_THRESHOLD;
  const similarity = Math.max(0, Math.min(100, (1 - distance / (2 * FACE_MATCH_THRESHOLD)) * 100));
  const ctx = canvas.getContext('2d');
  ctx.fillStyle = ok ? '#10b981' : '#ef4444';
  ctx.font = '600 15px "JetBrains Mono", monospace';
  ctx.fillText(`${ok ? 'TERVERIFIKASI' : 'TIDAK COCOK'} · d=${distance.toFixed(3)}`, 16, 28);
  return { ok, distance, similarity };
}

/** Simulasi cadangan bila perangkat tidak memiliki kamera. */
async function initFaceScan(video, canvas, onStatus) {
  stopFaceScan();
  let camera = true;
  try {
    await _startCamera(video);
  } catch {
    camera = false;
    if (onStatus) onStatus('Kamera tidak ditemukan — menjalankan simulasi terkalibrasi...');
  }
  const ctx = canvas.getContext('2d');
  canvas.width = 640;
  canvas.height = 480;
  const DURATION = 2400;
  const start = performance.now();
  return new Promise(resolve => {
    function frame(now) {
      const t = Math.min((now - start) / DURATION, 1);
      ctx.clearRect(0, 0, 640, 480);
      if (!camera) {
        ctx.fillStyle = '#09090b';
        ctx.fillRect(0, 0, 640, 480);
      }
      const bw = 220, bh = 280, bx = 210, by = 100;
      const color = t < 1 ? '#f59e0b' : '#10b981';
      ctx.strokeStyle = color;
      ctx.lineWidth = 2;
      ctx.strokeRect(bx, by, bw, bh);
      if (t < 1) {
        ctx.fillStyle = 'rgba(245, 158, 11, 0.45)';
        ctx.fillRect(bx, by + ((now / 5) % bh), bw, 2);
      }
      ctx.fillStyle = color;
      ctx.font = '13px "JetBrains Mono", monospace';
      ctx.fillText(t < 1 ? `SIMULASI BIOMETRIK ${Math.round(t * 100)}%` : 'SIMULASI TERVERIFIKASI', bx, by - 10);
      if (t < 1) faceRaf = requestAnimationFrame(frame);
      else resolve({ ok: true, simulated: true });
    }
    faceRaf = requestAnimationFrame(frame);
  });
}

function stopFaceScan() {
  faceRunId++;
  if (faceRaf) cancelAnimationFrame(faceRaf);
  faceRaf = null;
  if (faceStream) faceStream.getTracks().forEach(t => t.stop());
  faceStream = null;
}
