/**
 * face-scan.js — Secret Note
 * Module biometrik wajah menggunakan face-api.js (TensorFlow.js).
 *
 * Alur pendaftaran wajah:
 *   Aktifkan kamera → Deteksi wajah → Hitung face descriptor →
 *   Simpan descriptor di localStorage (tidak ada foto tersimpan)
 *
 * Alur verifikasi wajah (login):
 *   Aktifkan kamera → Deteksi wajah → Hitung descriptor →
 *   Bandingkan jarak Euclidean dengan descriptor tersimpan →
 *   Jika jarak < threshold → unlock berhasil
 *
 * Face descriptor = array 128 angka float (representasi matematis wajah).
 * Tidak ada foto/gambar wajah yang disimpan, hanya vektor matematisnya.
 */

'use strict';

// ── Konstanta ─────────────────────────────────────────────────────────────────
/**
 * Model weights diambil langsung dari repo GitHub face-api.js.
 * npm package TIDAK menyertakan folder weights — harus dari raw.githubusercontent.
 */
const MODEL_URL = 'https://raw.githubusercontent.com/justadudewhohacks/face-api.js/master/weights';

/** Jarak Euclidean maksimal agar dianggap wajah yang sama (0 = identik, 1 = berbeda) */
const FACE_MATCH_THRESHOLD = 0.45;

/** Key localStorage untuk menyimpan descriptor wajah */
const FACE_DATA_KEY = 'sn_face_descriptor';

// ── State internal ────────────────────────────────────────────────────────────
let faceModelsLoaded  = false;    // apakah model sudah dimuat
let faceStreamLogin   = null;     // MediaStream untuk kamera login
let faceStreamBio     = null;     // MediaStream untuk kamera registrasi

// ── Pemuat Model ──────────────────────────────────────────────────────────────

/**
 * Memuat semua model face-api.js yang diperlukan dari CDN.
 * Dipanggil sekali; hasil di-cache di `faceModelsLoaded`.
 * @returns {Promise<void>}
 */
async function loadFaceModels() {
  if (faceModelsLoaded) return;

  // Deteksi wajah ringan (SSD Mobilenet)
  // + Ekspresi wajah + 68 titik landmark + pengenalan identitas
  await faceapi.nets.ssdMobilenetv1.loadFromUri(MODEL_URL);
  await faceapi.nets.faceLandmark68Net.loadFromUri(MODEL_URL);
  await faceapi.nets.faceRecognitionNet.loadFromUri(MODEL_URL);

  faceModelsLoaded = true;
}

// ── Kamera ────────────────────────────────────────────────────────────────────

/**
 * Memulai stream kamera dan menghubungkannya ke elemen <video>.
 * Memanggil play() secara eksplisit agar stream langsung berjalan.
 * @param {HTMLVideoElement} videoEl
 * @returns {Promise<MediaStream>}
 */
async function startCamera(videoEl) {
  const stream = await navigator.mediaDevices.getUserMedia({
    video: { facingMode: 'user', width: { ideal: 640 }, height: { ideal: 360 } },
    audio: false,
  });
  videoEl.srcObject = stream;

  // Tunggu hingga metadata video siap, lalu play() secara eksplisit
  await new Promise((resolve, reject) => {
    videoEl.onloadedmetadata = () => {
      videoEl.play().then(resolve).catch(reject);
    };
    // Fallback: jika event tidak muncul dalam 5 detik
    setTimeout(reject, 5000, new Error('Timeout menunggu kamera.'));
  });

  return stream;
}

/**
 * Menghentikan semua track pada MediaStream (matikan kamera).
 * @param {MediaStream|null} stream
 */
function stopCamera(stream) {
  if (!stream) return;
  stream.getTracks().forEach(t => t.stop());
}

// ── Deteksi & Descriptor ─────────────────────────────────────────────────────

/**
 * Mendeteksi satu wajah dari video dan mengembalikan descriptor 128-dimensi.
 * @param {HTMLVideoElement} videoEl
 * @returns {Promise<Float32Array|null>} - Descriptor atau null jika tidak ada wajah
 */
async function detectFaceDescriptor(videoEl) {
  const detection = await faceapi
    .detectSingleFace(videoEl, new faceapi.SsdMobilenetv1Options({ minConfidenceScore: 0.5 }))
    .withFaceLandmarks()
    .withFaceDescriptor();

  return detection ? detection.descriptor : null;
}

/**
 * Menggambar kotak deteksi wajah ke <canvas> yang overlay di atas <video>.
 * @param {HTMLVideoElement} videoEl
 * @param {HTMLCanvasElement} canvasEl
 * @param {faceapi.FaceDetection|null} detection
 */
function drawFaceBox(videoEl, canvasEl, detection) {
  // Sesuaikan dimensi canvas dengan video yang ditampilkan
  faceapi.matchDimensions(canvasEl, {
    width:  videoEl.clientWidth,
    height: videoEl.clientHeight,
  });

  const ctx = canvasEl.getContext('2d');
  ctx.clearRect(0, 0, canvasEl.width, canvasEl.height);

  if (!detection) return;

  // Skala bounding box deteksi ke ukuran tampilan
  const dims    = faceapi.matchDimensions(canvasEl, videoEl, true);
  const resized = faceapi.resizeResults(detection, dims);

  // Gambar kotak biru di sekitar wajah
  ctx.strokeStyle = '#2563eb';
  ctx.lineWidth   = 2;
  const { x, y, width, height } = resized.detection.box;
  ctx.strokeRect(x, y, width, height);
}

// ── Login: Scan Wajah ─────────────────────────────────────────────────────────

/**
 * Memulai proses scan wajah untuk login.
 * Memuat model → aktifkan kamera → deteksi → bandingkan descriptor.
 * Panggil onSuccess() jika wajah cocok, onFailure() jika tidak.
 *
 * @param {HTMLVideoElement}  videoEl
 * @param {HTMLCanvasElement} canvasEl
 * @param {HTMLElement}       statusEl  - Element teks status
 * @param {Function}          onSuccess - Dipanggil saat wajah cocok
 * @param {Function}          onFailure - Dipanggil saat wajah tidak cocok
 * @returns {Promise<void>}
 */
async function startFaceLogin(videoEl, canvasEl, statusEl, onSuccess, onFailure) {
  statusEl.textContent = 'Memuat model AI…';

  // Pastikan library face-api sudah ter-load
  if (typeof faceapi === 'undefined') {
    statusEl.textContent = 'Library AI belum siap. Muat ulang halaman.';
    onFailure(new Error('faceapi tidak tersedia.'));
    return;
  }

  try {
    await loadFaceModels();
  } catch (err) {
    statusEl.textContent = 'Gagal memuat model. Periksa koneksi internet.';
    onFailure(err);
    return;
  }

  statusEl.textContent = 'Mengaktifkan kamera…';
  try {
    faceStreamLogin = await startCamera(videoEl);
  } catch (err) {
    const msg = err.name === 'NotAllowedError'
      ? 'Izin kamera ditolak. Berikan akses kamera di browser.'
      : `Kamera tidak tersedia: ${err.message}`;
    statusEl.textContent = msg;
    onFailure(err);
    return;
  }

  // Sembunyikan panduan overlay setelah kamera aktif
  const guide = document.getElementById('faceScanGuide');
  if (guide) guide.style.opacity = '0';

  statusEl.textContent = 'Posisikan wajah dalam bingkai…';

  // Loop deteksi dengan interval tetap (bukan rAF) agar tidak berlomba dengan render
  const startTime  = Date.now();
  const TIMEOUT_MS = 12_000;
  let   scanning   = true;

  while (scanning) {
    if (Date.now() - startTime > TIMEOUT_MS) {
      stopCamera(faceStreamLogin);
      faceStreamLogin = null;
      if (guide) guide.style.opacity = '1';
      statusEl.textContent = 'Waktu habis. Tekan tombol untuk coba lagi.';
      onFailure(new Error('Timeout.'));
      return;
    }

    // Tunggu sebentar agar frame video stabil sebelum deteksi
    await sleep(200);

    let detectionWithBox;
    try {
      detectionWithBox = await faceapi
        .detectSingleFace(videoEl, new faceapi.SsdMobilenetv1Options({ minConfidenceScore: 0.5 }))
        .withFaceLandmarks();
    } catch {
      // Frame tidak valid (video belum stabil) — coba lagi
      continue;
    }

    drawFaceBox(videoEl, canvasEl, detectionWithBox || null);

    if (!detectionWithBox) {
      statusEl.textContent = 'Wajah tidak terdeteksi…';
      continue;
    }

    statusEl.textContent = 'Wajah terdeteksi. Memverifikasi…';

    // Ambil descriptor penuh
    let descriptor;
    try {
      descriptor = await detectFaceDescriptor(videoEl);
    } catch {
      continue;
    }

    if (!descriptor) continue;

    // Bandingkan dengan descriptor tersimpan
    const match = compareFaceDescriptor(descriptor);
    scanning = false;
    stopCamera(faceStreamLogin);
    faceStreamLogin = null;
    if (guide) guide.style.opacity = '1';

    if (match) {
      statusEl.textContent = 'Wajah dikenali!';
      onSuccess();
    } else {
      statusEl.textContent = 'Wajah tidak dikenali.';
      onFailure(new Error('Wajah tidak cocok.'));
    }
  }
}

/**
 * Menghentikan scanning login dan mematikan kamera.
 */
function stopFaceLogin() {
  stopCamera(faceStreamLogin);
  faceStreamLogin = null;
}

// ── Registrasi Wajah ─────────────────────────────────────────────────────────

/**
 * Memulai kamera untuk panel registrasi wajah di tab Biometrik.
 * @param {HTMLVideoElement}  videoEl
 * @param {HTMLElement}       statusEl
 * @returns {Promise<void>}
 */
async function startBioCameraStream(videoEl, statusEl) {
  // Pastikan library face-api sudah ter-load
  if (typeof faceapi === 'undefined') {
    statusEl.textContent = 'Library AI belum siap. Muat ulang halaman.';
    throw new Error('faceapi tidak tersedia.');
  }

  try {
    statusEl.textContent = 'Memuat model AI…';
    await loadFaceModels();
    statusEl.textContent = 'Mengaktifkan kamera…';
    faceStreamBio = await startCamera(videoEl);
    statusEl.textContent = 'Kamera aktif. Posisikan wajah Anda.';
  } catch (err) {
    const msg = err.name === 'NotAllowedError'
      ? 'Izin kamera ditolak. Berikan akses kamera di browser.'
      : `Kamera gagal: ${err.message}`;
    statusEl.textContent = msg;
    throw err;
  }
}

/**
 * Menghentikan kamera registrasi.
 */
function stopBioCameraStream() {
  stopCamera(faceStreamBio);
  faceStreamBio = null;
}

/**
 * Mengambil satu snapshot deskriptor wajah dari video dan menyimpannya.
 * @param {HTMLVideoElement}  videoEl
 * @param {HTMLCanvasElement} canvasEl
 * @param {HTMLElement}       statusEl
 * @returns {Promise<boolean>} - true jika berhasil terdaftar
 */
async function captureFaceDescriptor(videoEl, canvasEl, statusEl) {
  statusEl.textContent = 'Memindai wajah…';

  // Tunggu sejenak agar frame video stabil
  await sleep(300);

  let detectionWithBox;
  try {
    detectionWithBox = await faceapi
      .detectSingleFace(videoEl, new faceapi.SsdMobilenetv1Options({ minConfidenceScore: 0.5 }))
      .withFaceLandmarks();
  } catch (err) {
    statusEl.textContent = 'Gagal membaca kamera. Pastikan kamera aktif.';
    console.error('[captureFace]', err);
    return false;
  }

  drawFaceBox(videoEl, canvasEl, detectionWithBox || null);

  if (!detectionWithBox) {
    statusEl.textContent = 'Wajah tidak terdeteksi. Pastikan pencahayaan cukup.';
    return false;
  }

  const descriptor = await detectFaceDescriptor(videoEl);
  if (!descriptor) {
    statusEl.textContent = 'Gagal mengambil data wajah. Coba lagi.';
    return false;
  }

  // Simpan descriptor sebagai array biasa (JSON serializable)
  localStorage.setItem(FACE_DATA_KEY, JSON.stringify(Array.from(descriptor)));
  statusEl.textContent = 'Wajah berhasil didaftarkan!';
  return true;
}

// ── Utilitas ─────────────────────────────────────────────────
/** Menunggu sejumlah milidetik (digunakan untuk delay antar frame). */
function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

// ── Penyimpanan Descriptor ────────────────────────────────────────────────────

/**
 * Membandingkan descriptor wajah baru dengan yang tersimpan.
 * Menggunakan jarak Euclidean (standar face-api.js).
 *
 * @param {Float32Array} descriptor  - Descriptor wajah yang baru dideteksi
 * @returns {boolean}                - true jika wajah cocok
 */
function compareFaceDescriptor(descriptor) {
  const raw = localStorage.getItem(FACE_DATA_KEY);
  if (!raw) return false;

  try {
    const stored = new Float32Array(JSON.parse(raw));
    const dist   = faceapi.euclideanDistance(descriptor, stored);
    return dist < FACE_MATCH_THRESHOLD;
  } catch {
    return false;
  }
}

/**
 * Mengecek apakah data wajah sudah terdaftar.
 * @returns {boolean}
 */
function hasFaceData() {
  return !!localStorage.getItem(FACE_DATA_KEY);
}

/**
 * Menghapus data wajah dari localStorage.
 */
function removeFaceData() {
  localStorage.removeItem(FACE_DATA_KEY);
}
