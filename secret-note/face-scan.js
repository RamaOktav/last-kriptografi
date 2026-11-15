/**
 * face-scan.js — Secret Note
 * Gatekeeper Dongle-First Multi-User:
 *   (1) Dual-Mode USB Dongle — Dongle-First Identification (1 USB = 1 User)
 *   (2) Biometrik Wajah Riil Teroptimasi (face-api.js):
 *       • Model AI dimuat dari folder lokal ./models (instan tanpa unduh ulang dari internet)
 *       • Background Preloading + Warm Camera Stream Reuse (tanpa delay buka-tutup driver kamera)
 *       • InputSize 224 + 128-d descriptor + Euclidean Distance (<= 0.50)
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
let faceModelsLoadingPromise = null;
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
    throw new Error('Browser ini tidak mendukung Web File System Access API. Gunakan Chrome/Edge atau pilih mode File .key Manual.');
  }
  try {
    return await window.showDirectoryPicker({ id: 'secretnote-usb', mode });
  } catch (e) {
    if (e.name === 'AbortError') throw new Error('Pemilihan drive USB dibatalkan.');
    throw new Error('Drive tidak dapat diakses: ' + e.message + ' — jika root drive diblokir oleh OS, buat folder di dalam USB (misal E:\\VAULT) dan pilih folder tersebut.');
  }
}

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
    } catch { /* abaikan */ }
  }
  return candidates;
}

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

async function writeDongleToUsb(dongle) {
  const dirHandle = await pickUsbDrive('readwrite');
  const fh = await dirHandle.getFileHandle(dongle.fileName, { create: true });
  const w = await fh.createWritable();
  await w.write(dongle.json);
  await w.close();
  return dirHandle.name;
}

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

// ══ KAMERA & BIOMETRIK WAJAH TEROPTIMASI (face-api.js) ═══════════════════════
/**
 * Membuka atau menggunakan kembali stream kamera yang masih aktif agar tidak ada
 * delay inisialisasi ulang driver hardware webcam (1-2 detik di Windows).
 */
async function _startCamera(video) {
  if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
    throw new Error('Kamera tidak tersedia pada browser ini (pastikan menggunakan localhost).');
  }
  const hasLiveTrack = faceStream && faceStream.getVideoTracks().some(t => t.readyState === 'live');
  if (!hasLiveTrack) {
    faceStream = await navigator.mediaDevices.getUserMedia({
      video: {
        width: { ideal: 480 },
        height: { ideal: 360 },
        frameRate: { ideal: 30 },
        facingMode: 'user',
      },
      audio: false,
    });
  }
  if (video.srcObject !== faceStream) {
    video.srcObject = faceStream;
  }
  if (video.paused) {
    await video.play();
  }
}

/** Memuat model face-api.js sekali saja (singleton promise) dari ./models lokal. */
async function loadFaceModels(onStatus) {
  if (faceModelsLoaded) return;
  if (faceModelsLoadingPromise) return faceModelsLoadingPromise;
  if (typeof faceapi === 'undefined') {
    throw new Error('Modul face-api.js belum termuat.');
  }
  faceModelsLoadingPromise = (async () => {
    let lastErr;
    for (const url of FACE_MODEL_URLS) {
      try {
        if (onStatus) onStatus('Menyiapkan model biometrik lokal...');
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
  })();

  try {
    await faceModelsLoadingPromise;
  } finally {
    faceModelsLoadingPromise = null;
  }
}

/** Preload model di background saat aplikasi pertama kali dibuka agar siap instan. */
function preloadFaceModels() {
  if (typeof faceapi === 'undefined' || faceModelsLoaded) return;
  setTimeout(() => {
    loadFaceModels().catch(() => { /* abaikan saat preload background */ });
  }, 300);
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
    ctx.font = '13px "JetBrains Mono", monospace';
    ctx.fillText(label || 'Posisikan wajah di tengah kamera', 14, 24);
    return;
  }
  const x = W - (box.x + box.width);
  ctx.strokeStyle = color;
  ctx.lineWidth = 2;
  ctx.strokeRect(x, box.y, box.width, box.height);
  ctx.fillStyle = color;
  ctx.font = '12.5px "JetBrains Mono", monospace';
  ctx.fillText(label, x, Math.max(16, box.y - 6));
}

/**
 * Mengaktifkan kamera DAN memuat model secara paralel, lalu mengekstrak descriptor wajah.
 */
async function scanFaceDescriptor(video, canvas, onStatus, { samples = 3, timeoutMs = 20000, reference = null, verb = 'Memindai' } = {}) {
  const runId = ++faceRunId;
  if (onStatus) onStatus('Mengaktifkan kamera...');

  // Nyalakan kamera dan muat model secara paralel agar video langsung tampil tanpa menunggu
  await Promise.all([
    _startCamera(video),
    loadFaceModels(onStatus),
  ]);

  const W = (canvas.width = video.videoWidth || 480);
  const H = (canvas.height = video.videoHeight || 360);
  const ctx = canvas.getContext('2d');
  // inputSize 224 jauh lebih cepat dan responsif dibanding 320
  const opts = new faceapi.TinyFaceDetectorOptions({ inputSize: 224, scoreThreshold: 0.45 });
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
      _drawFaceOverlay(ctx, W, H, null, null, 'Posisikan wajah menghadap kamera');
    }
    // Beri jeda 1 frame agar UI browser tetap mulus 60fps
    await new Promise(r => requestAnimationFrame(r));
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
    throw new Error('Akun ini tidak memiliki data vektor wajah. Gunakan opsi Simulasi.');
  }
  const desc = await scanFaceDescriptor(video, canvas, onStatus, {
    samples: 2,
    timeoutMs: 18000,
    reference: storedDescriptor,
    verb: 'Verifikasi',
  });
  const distance = euclideanDistance(desc, storedDescriptor);
  const ok = distance <= FACE_MATCH_THRESHOLD;
  const similarity = Math.max(0, Math.min(100, (1 - distance / (2 * FACE_MATCH_THRESHOLD)) * 100));
  const ctx = canvas.getContext('2d');
  ctx.fillStyle = ok ? '#10b981' : '#ef4444';
  ctx.font = '600 14px "JetBrains Mono", monospace';
  ctx.fillText(`${ok ? 'TERVERIFIKASI' : 'TIDAK COCOK'} · d=${distance.toFixed(3)}`, 14, 24);
  return { ok, distance, similarity };
}

/** Simulasi cadangan bila perangkat tidak memiliki kamera. */
async function initFaceScan(video, canvas, onStatus) {
  cancelFaceScanLoop();
  let camera = true;
  try {
    await _startCamera(video);
  } catch {
    camera = false;
    if (onStatus) onStatus('Kamera tidak ditemukan — menjalankan simulasi terkalibrasi...');
  }
  const ctx = canvas.getContext('2d');
  const W = (canvas.width = video.videoWidth || 480);
  const H = (canvas.height = video.videoHeight || 360);
  const DURATION = 1600;
  const start = performance.now();
  return new Promise(resolve => {
    function frame(now) {
      const t = Math.min((now - start) / DURATION, 1);
      ctx.clearRect(0, 0, W, H);
      if (!camera) {
        ctx.fillStyle = '#09090b';
        ctx.fillRect(0, 0, W, H);
      }
      const bw = 180, bh = 220, bx = (W - bw) / 2, by = (H - bh) / 2;
      const color = t < 1 ? '#f59e0b' : '#10b981';
      ctx.strokeStyle = color;
      ctx.lineWidth = 2;
      ctx.strokeRect(bx, by, bw, bh);
      if (t < 1) {
        ctx.fillStyle = 'rgba(245, 158, 11, 0.45)';
        ctx.fillRect(bx, by + ((now / 4) % bh), bw, 2);
      }
      ctx.fillStyle = color;
      ctx.font = '12.5px "JetBrains Mono", monospace';
      ctx.fillText(t < 1 ? `SIMULASI BIOMETRIK ${Math.round(t * 100)}%` : 'SIMULASI TERVERIFIKASI', bx, by - 8);
      if (t < 1) faceRaf = requestAnimationFrame(frame);
      else resolve({ ok: true, simulated: true });
    }
    faceRaf = requestAnimationFrame(frame);
  });
}

/** Menghentikan loop deteksi tanpa mematikan stream kamera (agar percobaan berikutnya instan). */
function cancelFaceScanLoop() {
  faceRunId++;
  if (faceRaf) cancelAnimationFrame(faceRaf);
  faceRaf = null;
}

/** Menghentikan loop dan mematikan hardware kamera sepenuhnya (dipanggil saat keluar dari Gatekeeper/Modal). */
function stopFaceScan() {
  cancelFaceScanLoop();
  if (faceStream) faceStream.getTracks().forEach(t => t.stop());
  faceStream = null;
}
