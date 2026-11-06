/**
 * face-scan.js — Secret Note
 * Gatekeeper: token dongle (.key) + biometrik wajah SUNGGUHAN (face-api.js).
 *
 * Registrasi : webcam -> deteksi wajah -> descriptor 128-d (rata-rata beberapa frame) -> IndexedDB
 * Verifikasi : webcam -> descriptor 128-d -> jarak Euclidean ke descriptor tersimpan
 *              Distance = sqrt( sum_i (A_i - B_i)^2 ),  cocok jika Distance <= 0.50
 * Tidak ada foto yang disimpan, hanya vektor 128 angka.
 * Mode simulasi (initFaceScan) hanya fallback bila kamera/model tidak tersedia.
 */
'use strict';

const DONGLE_TYPE = 'SECRET-NOTE-DONGLE';
const FACE_MATCH_THRESHOLD = 0.50;
// Urutan: folder lokal ./models (jika ada), lalu CDN
const FACE_MODEL_URLS = ['./models', 'https://cdn.jsdelivr.net/npm/@vladmandic/face-api/model/'];

let faceStream = null;
let faceRaf = null;
let faceRunId = 0;
let faceModelsLoaded = false;

// ══ DONGLE ═══════════════════════════════════════════════════════════════════
async function _dongleSignature(serial, secret) {
  return hashSHA256(`${DONGLE_TYPE}|${serial}|${secret}`);
}

/** Membuat token dongle baru. @returns {{blob:Blob, serial:string}} */
async function generateDongle() {
  const serial = 'SN-' + bytesToHex(crypto.getRandomValues(new Uint8Array(6))).toUpperCase();
  const secret = bytesToHex(crypto.getRandomValues(new Uint8Array(24)));
  const token = { type: DONGLE_TYPE, version: 1, serial, secret, signature: await _dongleSignature(serial, secret) };
  return { blob: new Blob([JSON.stringify(token, null, 2)], { type: 'application/octet-stream' }), serial };
}

/**
 * Validasi file token .key dari flashdisk.
 * @returns {Promise<{valid:boolean, reason:string, serial?:string}>}
 */
async function checkDongle(file) {
  if (!file) return { valid: false, reason: 'Tidak ada file dipilih.' };
  if (!file.name.toLowerCase().endsWith('.key')) return { valid: false, reason: 'Ekstensi harus .key' };
  let t;
  try { t = JSON.parse(await file.text()); } catch { return { valid: false, reason: 'Isi token tidak valid.' }; }
  if (!t || t.type !== DONGLE_TYPE || !t.serial || !t.secret || !t.signature) return { valid: false, reason: 'Struktur token tidak dikenali.' };
  if ((await _dongleSignature(t.serial, t.secret)) !== t.signature) return { valid: false, reason: 'Signature token tidak cocok (dimodifikasi).' };
  const registered = await getAuth('dongle_serial');
  if (registered && registered !== t.serial) return { valid: false, reason: 'Token bukan milik akun ini.' };
  return { valid: true, reason: 'Token valid.', serial: t.serial };
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
async function _scanDescriptor(video, canvas, onStatus, { samples, timeoutMs, reference, verb }) {
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

/** Registrasi wajah: simpan descriptor 128-d ke IndexedDB (auth_store -> face_descriptor). */
async function registerFaceDescriptor(video, canvas, onStatus) {
  if (await getAuth('face_descriptor')) throw new Error('Wajah sudah terdaftar. Reset DB untuk mendaftar ulang.');
  const desc = await _scanDescriptor(video, canvas, onStatus, { samples: 5, timeoutMs: 25000, verb: 'Mendaftarkan' });
  await setAuth('face_descriptor', Array.from(desc));
  return desc;
}

/** Verifikasi wajah terhadap descriptor tersimpan. @returns {{ok, distance, similarity}} */
async function verifyFaceBiometric(video, canvas, onStatus) {
  const ref = await getAuth('face_descriptor');
  if (!ref) throw new Error('Belum ada wajah terdaftar. Klik "Daftarkan Wajah" dulu.');
  const desc = await _scanDescriptor(video, canvas, onStatus, { samples: 3, timeoutMs: 20000, reference: ref, verb: 'Memverifikasi' });
  const distance = euclideanDistance(desc, ref);
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
