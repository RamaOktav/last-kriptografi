/**
 * face-scan.js — Secret Note
 * Gatekeeper multi-user:
 *   (1) Dual-Mode USB Dongle — 1 USB = 1 User
 *       • Mode USB fisik : File System Access API (showDirectoryPicker) + watcher auto-lock saat dicabut
 *       • Mode upload    : <input type=file> manual (fallback)
 *   (2) Biometrik wajah SUNGGUHAN (face-api.js) — descriptor 128-d + jarak Euclidean
 *       Distance = sqrt( sum_i (A_i - B_i)^2 ),  cocok jika Distance <= 0.50
 *       Mode simulasi (initFaceScan) hanya fallback bila kamera/model tidak tersedia.
 */
'use strict';

const DONGLE_TYPE = 'SECRET-NOTE-DONGLE';
const USB_WATCH_INTERVAL = 2000;
const FACE_MATCH_THRESHOLD = 0.50;
// Urutan: folder lokal ./models (jika ada), lalu CDN
const FACE_MODEL_URLS = ['./models', 'https://cdn.jsdelivr.net/npm/@vladmandic/face-api/model/'];

let faceStream = null;
let faceRaf = null;
let faceRunId = 0;
let faceModelsLoaded = false;
let usbWatchTimer = null;

// ══ DONGLE TOKEN ═════════════════════════════════════════════════════════════
const dongleFileName = (username) => `dongle-${username}.key`;
const isUsbApiSupported = () => typeof window.showDirectoryPicker === 'function';

async function _dongleSignature(serial, username, secret) {
  return hashSHA256(`${DONGLE_TYPE}|${serial}|${username}|${secret}`);
}

/** Membuat token dongle untuk satu user. @returns {{blob, serial, fileName, json}} */
async function generateDongle(username) {
  const serial = 'SN-' + bytesToHex(crypto.getRandomValues(new Uint8Array(6))).toUpperCase();
  const secret = bytesToHex(crypto.getRandomValues(new Uint8Array(24)));
  const token = { type: DONGLE_TYPE, version: 2, serial, username, secret, signature: await _dongleSignature(serial, username, secret) };
  const json = JSON.stringify(token, null, 2);
  return { blob: new Blob([json], { type: 'application/octet-stream' }), serial, fileName: dongleFileName(username), json };
}

/**
 * Validasi isi token terhadap user yang dipilih.
 * @returns {Promise<{valid:boolean, reason:string, serial?:string}>}
 */
async function verifyDonglePayload(jsonStr, targetUsername) {
  let t;
  try { t = JSON.parse(jsonStr); } catch { return { valid: false, reason: 'Isi token bukan JSON yang valid.' }; }
  if (!t || t.type !== DONGLE_TYPE || !t.serial || !t.username || !t.secret || !t.signature) {
    return { valid: false, reason: 'Struktur token tidak dikenali.' };
  }
  if ((await _dongleSignature(t.serial, t.username, t.secret)) !== t.signature) {
    return { valid: false, reason: 'Signature SHA-256 tidak cocok — token telah dimodifikasi (tampered).' };
  }
  if (t.username !== targetUsername) {
    return { valid: false, reason: `Token ini milik user "${t.username}", bukan "${targetUsername}".` };
  }
  const user = await getUser(targetUsername);
  if (!user) return { valid: false, reason: 'User tidak ditemukan di database.' };
  if (user.dongleSerial !== t.serial) return { valid: false, reason: 'Serial token tidak terdaftar untuk user ini (token lama/dicabut).' };
  return { valid: true, reason: 'Token valid.', serial: t.serial };
}

/** Mode upload manual. */
async function checkDongleFile(file, targetUsername) {
  if (!file) return { valid: false, reason: 'Tidak ada file dipilih.' };
  if (!file.name.toLowerCase().endsWith('.key')) return { valid: false, reason: 'Ekstensi harus .key' };
  return verifyDonglePayload(await file.text(), targetUsername);
}

/** Mencari file token di folder (root dan subfolder SECRETNOTE). */
async function _findDongleHandle(dirHandle, username) {
  const name = dongleFileName(username);
  try { return await dirHandle.getFileHandle(name); } catch { /* lanjut */ }
  try {
    const sub = await dirHandle.getDirectoryHandle('SECRETNOTE');
    return await sub.getFileHandle(name);
  } catch { return null; }
}

/** Meminta akses folder/drive USB (butuh gesture user). */
async function pickUsbDrive(mode = 'read') {
  if (!isUsbApiSupported()) throw new Error('Browser tidak mendukung File System Access API (gunakan Chrome/Edge via localhost).');
  try {
    return await window.showDirectoryPicker({ id: 'secretnote-usb', mode });
  } catch (e) {
    if (e.name === 'AbortError') throw new Error('Pemilihan drive dibatalkan.');
    throw new Error('Drive tidak dapat dibuka: ' + e.message + ' — jika root drive diblokir, simpan token di folder E:\\SECRETNOTE lalu pilih folder itu.');
  }
}

/**
 * Mode USB fisik: pilih drive lalu baca dongle-<username>.key.
 * @returns {Promise<{valid, reason, serial?, dirHandle?, fileHandle?, content?}>}
 */
async function connectUsbDrive(targetUsername) {
  const dirHandle = await pickUsbDrive('read');
  const fileHandle = await _findDongleHandle(dirHandle, targetUsername);
  if (!fileHandle) {
    return { valid: false, reason: `File ${dongleFileName(targetUsername)} tidak ditemukan di drive "${dirHandle.name}".` };
  }
  const content = await (await fileHandle.getFile()).text();
  const r = await verifyDonglePayload(content, targetUsername);
  return { ...r, dirHandle, fileHandle, content, driveName: dirHandle.name };
}

/** Menulis token langsung ke flashdisk (registrasi). */
async function writeDongleToUsb(dongle) {
  const dirHandle = await pickUsbDrive('readwrite');
  const fh = await dirHandle.getFileHandle(dongle.fileName, { create: true });
  const w = await fh.createWritable();
  await w.write(dongle.json);
  await w.close();
  return dirHandle.name;
}

/**
 * Watcher: tiap 2 detik membaca ulang token dari drive.
 * Jika drive dicabut / file hilang / isi berubah → onEject(reason).
 */
function startUsbWatcher(fileHandle, expectedContent, onEject) {
  stopUsbWatcher();
  let busy = false;
  usbWatchTimer = setInterval(async () => {
    if (busy) return;
    busy = true;
    try {
      const text = await (await fileHandle.getFile()).text();
      if (text !== expectedContent) { stopUsbWatcher(); onEject('Isi token pada USB berubah.'); }
    } catch (e) {
      stopUsbWatcher();
      onEject('USB dongle dicabut / tidak dapat dibaca (' + (e.name || 'error') + ').');
    } finally { busy = false; }
  }, USB_WATCH_INTERVAL);
}

function stopUsbWatcher() {
  if (usbWatchTimer) clearInterval(usbWatchTimer);
  usbWatchTimer = null;
}

// ══ KAMERA & MODEL ═══════════════════════════════════════════════════════════
async function _startCamera(video) {
  if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
    throw new Error('Browser tidak mendukung kamera (gunakan localhost / HTTPS).');
  }
  if (faceStream) faceStream.getTracks().forEach(t => t.stop());
  faceStream = await navigator.mediaDevices.getUserMedia({ video: { width: 640, height: 480, facingMode: 'user' }, audio: false });
  video.srcObject = faceStream;
  await video.play();
}

/** Memuat model face-api.js (tiny detector, landmark 68, recognition 128-d). */
async function loadFaceModels(onStatus) {
  if (faceModelsLoaded) return;
  if (typeof faceapi === 'undefined') throw new Error('Library face-api.js gagal dimuat (cek koneksi internet).');
  let lastErr;
  for (const url of FACE_MODEL_URLS) {
    try {
      if (onStatus) onStatus(`Memuat model AI dari ${url} ...`);
      await Promise.all([
        faceapi.nets.tinyFaceDetector.loadFromUri(url),
        faceapi.nets.faceLandmark68Net.loadFromUri(url),
        faceapi.nets.faceRecognitionNet.loadFromUri(url),
      ]);
      faceModelsLoaded = true;
      return;
    } catch (e) { lastErr = e; }
  }
  throw new Error('Model AI gagal dimuat: ' + (lastErr && lastErr.message || lastErr));
}

/** Jarak Euclidean antara dua vektor descriptor. */
function euclideanDistance(a, b) {
  let sum = 0;
  for (let i = 0; i < a.length; i++) { const d = a[i] - b[i]; sum += d * d; }
  return Math.sqrt(sum);
}

function _drawFaceOverlay(ctx, W, H, box, color, label) {
  ctx.clearRect(0, 0, W, H);
  if (!box) {
    ctx.fillStyle = '#fbbf24'; ctx.font = '18px monospace';
    ctx.fillText(label || 'Wajah tidak terdeteksi', 16, 30);
    return;
  }
  const x = W - (box.x + box.width); // video dicerminkan lewat CSS, jadi koordinat dibalik
  ctx.strokeStyle = color; ctx.lineWidth = 3;
  ctx.strokeRect(x, box.y, box.width, box.height);
  ctx.fillStyle = color; ctx.font = '16px monospace';
  ctx.fillText(label, x, Math.max(18, box.y - 8));
}

/**
 * Mengumpulkan descriptor dari webcam dan merata-ratakannya.
 * @returns {Promise<Float32Array>}
 */
async function scanFaceDescriptor(video, canvas, onStatus, { samples = 5, timeoutMs = 25000, reference = null, verb = 'Memindai' } = {}) {
  const runId = ++faceRunId;
  await loadFaceModels(onStatus);
  if (onStatus) onStatus('Membuka kamera...');
  await _startCamera(video);
  const W = canvas.width = video.videoWidth || 640;
  const H = canvas.height = video.videoHeight || 480;
  const ctx = canvas.getContext('2d');
  const opts = new faceapi.TinyFaceDetectorOptions({ inputSize: 320, scoreThreshold: 0.5 });
  const descs = [];
  const t0 = performance.now();
  while (descs.length < samples && performance.now() - t0 < timeoutMs) {
    if (runId !== faceRunId) throw new Error('Pemindaian dibatalkan.');
    const det = await faceapi.detectSingleFace(video, opts).withFaceLandmarks().withFaceDescriptor();
    if (det) {
      descs.push(det.descriptor);
      let label = `${verb} ${descs.length}/${samples}`;
      if (reference) label += `  d=${euclideanDistance(det.descriptor, reference).toFixed(3)}`;
      _drawFaceOverlay(ctx, W, H, det.detection.box, '#22d3ee', label);
      if (onStatus) onStatus(`${verb}... sampel ${descs.length}/${samples}`);
    } else {
      _drawFaceOverlay(ctx, W, H, null, null, 'Wajah tidak terdeteksi — hadap kamera');
    }
  }
  if (descs.length < samples) throw new Error('Wajah tidak terdeteksi dengan jelas. Perbaiki pencahayaan lalu coba lagi.');
  const mean = new Float32Array(128);
  for (const d of descs) for (let i = 0; i < 128; i++) mean[i] += d[i] / descs.length;
  return mean;
}

/** Verifikasi wajah terhadap descriptor milik user. @returns {{ok, distance, similarity}} */
async function verifyUserFace(video, canvas, storedDescriptor, onStatus) {
  if (!storedDescriptor) throw new Error('User ini tidak memiliki data wajah (didaftarkan via simulasi). Aktifkan mode simulasi.');
  const desc = await scanFaceDescriptor(video, canvas, onStatus, { samples: 3, timeoutMs: 20000, reference: storedDescriptor, verb: 'Memverifikasi' });
  const distance = euclideanDistance(desc, storedDescriptor);
  const ok = distance <= FACE_MATCH_THRESHOLD;
  const similarity = Math.max(0, Math.min(100, (1 - distance / (2 * FACE_MATCH_THRESHOLD)) * 100));
  const ctx = canvas.getContext('2d');
  ctx.fillStyle = ok ? '#4ade80' : '#f87171';
  ctx.font = 'bold 20px monospace';
  ctx.fillText(`${ok ? 'MATCH' : 'DITOLAK'}  d=${distance.toFixed(3)} (batas ${FACE_MATCH_THRESHOLD})`, 16, 30);
  return { ok, distance, similarity };
}

// ══ FALLBACK SIMULASI ════════════════════════════════════════════════════════
/** Simulasi visual (tanpa AI). Hanya untuk cadangan demo saat kamera/model bermasalah. */
async function initFaceScan(video, canvas, onStatus) {
  stopFaceScan();
  let camera = true;
  try { await _startCamera(video); } catch (e) {
    camera = false;
    if (onStatus) onStatus(`Kamera tidak tersedia (${e.name || 'error'}) — simulasi tanpa video.`);
  }
  const ctx = canvas.getContext('2d');
  canvas.width = 640;
  canvas.height = 480;
  const DURATION = 3000;
  const start = performance.now();
  return new Promise(resolve => {
    function frame(now) {
      const t = Math.min((now - start) / DURATION, 1);
      ctx.clearRect(0, 0, 640, 480);
      if (!camera) { ctx.fillStyle = '#0b1220'; ctx.fillRect(0, 0, 640, 480); }
      const bw = 240, bh = 300, bx = 200, by = 90;
      const color = t < 1 ? '#fbbf24' : '#4ade80';
      ctx.strokeStyle = color; ctx.lineWidth = 3;
      ctx.strokeRect(bx, by, bw, bh);
      if (t < 1) { ctx.fillStyle = 'rgba(251,191,36,.6)'; ctx.fillRect(bx, by + ((now / 6) % bh), bw, 3); }
      ctx.fillStyle = color; ctx.font = '16px monospace';
      ctx.fillText(t < 1 ? 'SIMULASI (fallback)...' : 'SIMULASI SELESAI', bx, by - 10);
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
