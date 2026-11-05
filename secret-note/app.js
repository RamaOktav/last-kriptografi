/**
 * app.js — Secret Note
 * Orkestrasi utama aplikasi: state, UI, routing, dan event binding.
 *
 * Tanggung jawab:
 *   - Manajemen state aplikasi (terkunci / terbuka)
 *   - Routing antar tab & modal
 *   - Binding fitur enkripsi catatan (crypto.js)
 *   - Binding fitur enkripsi file (file-crypto.js)
 *   - Binding fitur biometrik (face-scan.js)
 *   - Toast & notifikasi
 */

'use strict';

// ══════════════════════════════════════════════════════════════
// SECTION 1 — STATE GLOBAL
// ══════════════════════════════════════════════════════════════

/** Kata sandi sesi aktif (di memori, tidak disimpan). */
let sessionPassword = null;

/** ID catatan yang sedang diedit (null = catatan baru). */
let currentEditNoteId = null;

// ── Keys localStorage ─────────────────────────────────────────
const LS_NOTES   = 'sn_notes';
const LS_PWHASH  = 'sn_password_hash';

// ══════════════════════════════════════════════════════════════
// SECTION 2 — INIT
// ══════════════════════════════════════════════════════════════

document.addEventListener('DOMContentLoaded', () => {
  // Cek apakah kata sandi sudah pernah diatur
  const hasPassword = !!localStorage.getItem(LS_PWHASH);

  if (!hasPassword) {
    // Pengguna baru — arahkan langsung ke setup
    openSetupModal();
  }

  // Update status biometrik di tab bio
  updateBioStatus();
});

// ══════════════════════════════════════════════════════════════
// SECTION 3 — LOCK / UNLOCK
// ══════════════════════════════════════════════════════════════

/**
 * Membuka kunci aplikasi setelah password diverifikasi.
 * Tampilkan main content dan sembunyikan layar lock.
 * @param {string} password - Kata sandi yang sudah diverifikasi
 */
function unlockApp(password) {
  sessionPassword = password;
  document.getElementById('lockScreen').style.display = 'none';
  showElement('navbar');
  showElement('mainContent');
  renderNoteList();
  renderFileList();
  updateBioStatus();
}

/**
 * Mengunci aplikasi kembali: hapus session, tampilkan lock screen.
 */
function lockApp() {
  sessionPassword = null;

  // Hentikan kamera jika aktif
  stopFaceLogin();
  stopBioCameraStream();

  hideElement('navbar');
  hideElement('mainContent');
  document.getElementById('lockScreen').style.display = 'flex';

  // Reset form login
  document.getElementById('masterPassword').value = '';
  hideElement('passwordWarning');

  showToast('Aplikasi dikunci.', 'info');
}

// ── Login: Kata Sandi ─────────────────────────────────────────

/**
 * Mencoba unlock dengan kata sandi yang dimasukkan pengguna.
 */
async function unlockWithPassword() {
  const pwInput = document.getElementById('masterPassword');
  const pw      = pwInput.value.trim();

  if (!pw) return;

  const storedHash = localStorage.getItem(LS_PWHASH);
  if (!storedHash) {
    openSetupModal();
    return;
  }

  const isValid = await verifyPassword(pw, storedHash);

  if (isValid) {
    hideElement('passwordWarning');
    unlockApp(pw);
  } else {
    showElement('passwordWarning');
    pwInput.value = '';
    pwInput.focus();
  }
}

// ── Login: Face Scan ──────────────────────────────────────────

/**
 * Memulai proses login dengan face scan.
 */
async function startFaceScan() {
  // Cek apakah data wajah tersedia
  if (!hasFaceData()) {
    document.getElementById('faceWarning').textContent =
      'Belum ada wajah terdaftar. Daftarkan wajah di tab Biometrik terlebih dahulu.';
    showElement('faceWarning');
    return;
  }

  hideElement('faceWarning');
  const btn = document.getElementById('faceStartBtn');
  btn.disabled    = true;
  btn.textContent = 'Sedang memindai…';

  const videoEl    = document.getElementById('faceVideo');
  const canvasEl   = document.getElementById('faceCanvas');
  const statusText = document.getElementById('faceStatusText');

  await startFaceLogin(
    videoEl,
    canvasEl,
    statusText,
    // onSuccess
    () => {
      // Ambil hash tersimpan; login face tidak memerlukan password asli,
      // tapi kita butuh sessionPassword untuk enkripsi/dekripsi.
      // Minta password sekali sebagai fallback setelah face sukses
      const pw = localStorage.getItem('sn_face_pw_hint');
      if (pw) {
        const decryptedHint = atob(pw);
        unlockApp(decryptedHint);
        btn.disabled    = false;
        btn.textContent = 'Mulai Pindai Wajah';
      } else {
        // Tidak ada hint → minta user masukkan password tetap
        switchLockTab('password');
        showElement('passwordWarning');
        document.getElementById('passwordWarning').textContent =
          'Wajah dikenali! Masukkan kata sandi untuk mendekripsi catatan.';
        btn.disabled    = false;
        btn.textContent = 'Mulai Pindai Wajah';
      }
    },
    // onFailure
    (err) => {
      console.warn('[FaceScan] Login gagal:', err.message);
      showElement('faceWarning');
      btn.disabled    = false;
      btn.textContent = 'Mulai Pindai Wajah';
    }
  );
}

// ══════════════════════════════════════════════════════════════
// SECTION 4 — SETUP & UBAH KATA SANDI
// ══════════════════════════════════════════════════════════════

/** Buka modal setup kata sandi awal. */
function openSetupModal() {
  showModal('setupModal');
  hideElement('setupWarning');
}

/** Tutup modal setup. */
function closeSetupModal() {
  hideModal('setupModal');
}

/**
 * Simpan kata sandi master dari modal setup.
 */
async function saveSetupPassword() {
  const pw      = document.getElementById('setupPassword').value;
  const confirm = document.getElementById('setupConfirm').value;

  if (pw.length < 8) {
    document.getElementById('setupWarning').textContent = 'Kata sandi minimal 8 karakter.';
    showElement('setupWarning');
    return;
  }

  if (pw !== confirm) {
    document.getElementById('setupWarning').textContent = 'Kata sandi tidak cocok.';
    showElement('setupWarning');
    return;
  }

  const hash = await hashPassword(pw);
  localStorage.setItem(LS_PWHASH, hash);

  // Simpan hint (base64) agar face scan bisa unlock — ini adalah trade-off
  // keamanan vs kenyamanan; di produksi gunakan secure enclave
  localStorage.setItem('sn_face_pw_hint', btoa(pw));

  closeSetupModal();
  showToast('Kata sandi berhasil diatur!', 'success');
  document.getElementById('masterPassword').focus();
}

/**
 * Ubah kata sandi master dari tab Biometrik.
 */
async function changePassword() {
  const newPw   = document.getElementById('newPasswordInput').value;
  const confirm = document.getElementById('confirmPasswordInput').value;
  const warning = document.getElementById('passwordMismatchWarning');

  if (newPw.length < 8) {
    warning.textContent = 'Kata sandi minimal 8 karakter.';
    showElement('passwordMismatchWarning');
    return;
  }

  if (newPw !== confirm) {
    warning.textContent = 'Kata sandi tidak cocok. Periksa kembali.';
    showElement('passwordMismatchWarning');
    return;
  }

  // Peringatan: mengubah kata sandi akan membuat catatan lama tidak bisa didekripsi
  if (getNotes().length > 0) {
    const ok = confirm(
      'PERINGATAN: Mengubah kata sandi akan membuat semua catatan yang sudah ada tidak dapat dibuka. ' +
      'Pastikan Anda sudah membaca semua catatan penting. Lanjutkan?'
    );
    if (!ok) return;
    // Hapus semua catatan karena tidak kompatibel dengan kunci baru
    localStorage.setItem(LS_NOTES, '[]');
    localStorage.setItem('sn_files', '[]');
  }

  const hash = await hashPassword(newPw);
  localStorage.setItem(LS_PWHASH, hash);
  localStorage.setItem('sn_face_pw_hint', btoa(newPw));
  sessionPassword = newPw;

  hideElement('passwordMismatchWarning');
  document.getElementById('newPasswordInput').value    = '';
  document.getElementById('confirmPasswordInput').value = '';

  showToast('Kata sandi berhasil diubah!', 'success');
  renderNoteList();
  renderFileList();
}

// ══════════════════════════════════════════════════════════════
// SECTION 5 — TAB NAVIGATION
// ══════════════════════════════════════════════════════════════

/**
 * Beralih antara tab password dan tab face scan di lock screen.
 * @param {'password'|'face'} tab
 */
function switchLockTab(tab) {
  const panels = { password: 'panelPassword', face: 'panelFace' };
  const tabs   = { password: 'tabPassword',   face: 'tabFace'   };

  Object.entries(panels).forEach(([key, id]) => {
    const el = document.getElementById(id);
    if (key === tab) el.classList.remove('hidden');
    else el.classList.add('hidden');
  });

  Object.entries(tabs).forEach(([key, id]) => {
    const btn = document.getElementById(id);
    if (key === tab) {
      btn.classList.add('bg-primary', 'text-white');
      btn.classList.remove('text-slate-400');
    } else {
      btn.classList.remove('bg-primary', 'text-white');
      btn.classList.add('text-slate-400');
    }
  });
}

/**
 * Beralih antar tab utama di aplikasi (note, file, bio).
 * @param {'note'|'file'|'bio'} tab
 * @param {HTMLElement}         clickedBtn
 */
function switchMainTab(tab, clickedBtn) {
  const sections = ['note', 'file', 'bio'];

  sections.forEach(s => {
    const el = document.getElementById(`tab-${s}`);
    if (s === tab) el.classList.remove('hidden');
    else el.classList.add('hidden');
  });

  // Update gaya tombol tab
  document.querySelectorAll('.nav-tab').forEach(btn => btn.classList.remove('active'));
  if (clickedBtn) clickedBtn.classList.add('active');
}

// ══════════════════════════════════════════════════════════════
// SECTION 6 — CATATAN
// ══════════════════════════════════════════════════════════════

// ── Storage ───────────────────────────────────────────────────

/**
 * Mengambil semua catatan dari localStorage.
 * @returns {Array<{id, title, payloadB64, createdAt, updatedAt}>}
 */
function getNotes() {
  try {
    return JSON.parse(localStorage.getItem(LS_NOTES) || '[]');
  } catch {
    return [];
  }
}

/**
 * Menyimpan array catatan ke localStorage.
 * @param {Array} notes
 */
function saveNotes(notes) {
  localStorage.setItem(LS_NOTES, JSON.stringify(notes));
}

// ── Render Daftar Catatan ─────────────────────────────────────

/**
 * Merender kartu catatan berdasarkan kata kunci pencarian.
 * Judul ditampilkan plaintext; konten tetap terenkripsi.
 */
function renderNoteList() {
  const query   = (document.getElementById('noteSearch')?.value || '').toLowerCase();
  const notes   = getNotes().filter(n =>
    n.title.toLowerCase().includes(query)
  );

  const list    = document.getElementById('noteList');
  const empty   = document.getElementById('noteEmpty');

  list.innerHTML = '';

  if (notes.length === 0) {
    showElement('noteEmpty');
    return;
  }
  hideElement('noteEmpty');

  // Urutkan: terbaru teratas
  notes
    .slice()
    .sort((a, b) => new Date(b.updatedAt) - new Date(a.updatedAt))
    .forEach(note => {
      const card = document.createElement('div');
      card.className  = 'note-card group';
      card.setAttribute('role', 'button');
      card.setAttribute('tabindex', '0');
      card.setAttribute('aria-label', `Buka catatan: ${note.title}`);

      card.innerHTML = `
        <div class="flex items-start justify-between gap-2 mb-2">
          <h3 class="text-sm font-semibold text-slate-800 leading-tight line-clamp-2 flex-1">
            ${escapeHtml(note.title) || '<span class="text-slate-400 font-normal">Tanpa judul</span>'}
          </h3>
          <!-- Ikon kunci terenkripsi -->
          <svg width="13" height="13" fill="none" stroke="currentColor" stroke-width="2"
            viewBox="0 0 24 24" class="text-primary shrink-0 mt-0.5" aria-label="Terenkripsi">
            <path stroke-linecap="round" stroke-linejoin="round"
              d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/>
          </svg>
        </div>
        <p class="text-xs text-slate-400">${formatRelativeDate(note.updatedAt)}</p>
        <!-- Aksi -->
        <div class="flex gap-1.5 mt-3">
          <button onclick="viewNote('${note.id}')"
            class="flex-1 py-1.5 rounded-lg text-xs font-medium bg-slate-50 hover:bg-primary hover:text-white
                   text-slate-600 border border-border transition-all duration-150">
            Buka
          </button>
          <button onclick="openNoteEditor('${note.id}')"
            class="py-1.5 px-3 rounded-lg text-xs font-medium bg-slate-50 hover:bg-slate-100
                   text-slate-600 border border-border transition-all duration-150">
            Edit
          </button>
          <button onclick="deleteNote('${note.id}')"
            class="py-1.5 px-3 rounded-lg text-xs font-medium border border-red-100 text-red-400
                   hover:bg-red-50 hover:text-red-600 transition-all duration-150">
            Hapus
          </button>
        </div>
      `;

      // Keyboard accessible
      card.addEventListener('keydown', e => {
        if (e.key === 'Enter' || e.key === ' ') viewNote(note.id);
      });

      list.appendChild(card);
    });
}

// ── Editor Catatan ────────────────────────────────────────────

/**
 * Membuka modal editor catatan.
 * @param {string|null} noteId - null untuk catatan baru
 */
function openNoteEditor(noteId) {
  currentEditNoteId = noteId;
  const title   = document.getElementById('noteModalTitle');
  const titleIn = document.getElementById('noteTitle');
  const bodyIn  = document.getElementById('noteContent');
  const idIn    = document.getElementById('noteEditId');

  titleIn.value = '';
  bodyIn.value  = '';
  idIn.value    = '';

  if (noteId) {
    title.textContent = 'Edit Catatan';
    idIn.value = noteId;
    // Judul bisa langsung ditampilkan (tidak dienkripsi)
    const note = getNotes().find(n => n.id === noteId);
    if (note) titleIn.value = note.title;
    // Konten perlu dekripsi
    decryptNoteForEdit(noteId);
  } else {
    title.textContent = 'Catatan Baru';
  }

  showModal('noteModal');
  titleIn.focus();
}

/**
 * Mendekripsi konten catatan dan mengisinya ke textarea editor.
 * @param {string} noteId
 */
async function decryptNoteForEdit(noteId) {
  const note    = getNotes().find(n => n.id === noteId);
  if (!note) return;

  try {
    const plain = await decryptText(note.payloadB64, sessionPassword);
    document.getElementById('noteContent').value = plain;
  } catch {
    showToast('Gagal mendekripsi catatan. Periksa kata sandi.', 'error');
  }
}

/** Tutup modal editor catatan. */
function closeNoteEditor() {
  hideModal('noteModal');
  currentEditNoteId = null;
}

/**
 * Menyimpan catatan (enkripsi konten lalu simpan ke localStorage).
 */
async function saveNote() {
  const title   = document.getElementById('noteTitle').value.trim();
  const content = document.getElementById('noteContent').value;
  const id      = document.getElementById('noteEditId').value;

  if (!title && !content) {
    showToast('Judul atau isi catatan tidak boleh kosong.', 'warning');
    return;
  }

  try {
    const payloadB64 = await encryptText(content, sessionPassword);
    const notes      = getNotes();
    const now        = new Date().toISOString();

    if (id) {
      // Update catatan yang ada
      const idx = notes.findIndex(n => n.id === id);
      if (idx !== -1) {
        notes[idx].title      = title || 'Tanpa judul';
        notes[idx].payloadB64 = payloadB64;
        notes[idx].updatedAt  = now;
      }
    } else {
      // Catatan baru
      notes.push({
        id:         crypto.randomUUID(),
        title:      title || 'Tanpa judul',
        payloadB64: payloadB64,
        createdAt:  now,
        updatedAt:  now,
      });
    }

    saveNotes(notes);
    closeNoteEditor();
    renderNoteList();
    showToast('Catatan berhasil dienkripsi & disimpan!', 'success');
  } catch (err) {
    console.error('[saveNote]', err);
    showToast('Gagal menyimpan catatan.', 'error');
  }
}

// ── Lihat Catatan ─────────────────────────────────────────────

/**
 * Membuka modal lihat catatan terdekripsi.
 * @param {string} noteId
 */
async function viewNote(noteId) {
  const note = getNotes().find(n => n.id === noteId);
  if (!note) return;

  document.getElementById('viewNoteTitle').textContent = note.title;
  document.getElementById('viewNoteDate').textContent  = formatDate(note.updatedAt);
  document.getElementById('viewNoteContent').textContent = 'Mendekripsi…';

  showModal('viewNoteModal');

  try {
    const plain = await decryptText(note.payloadB64, sessionPassword);
    document.getElementById('viewNoteContent').textContent = plain;
  } catch {
    document.getElementById('viewNoteContent').textContent = 'Gagal mendekripsi catatan.';
    showToast('Dekripsi gagal. Periksa kata sandi.', 'error');
  }

  // Bind tombol Edit
  document.getElementById('viewNoteEditBtn').onclick = () => {
    closeViewNote();
    openNoteEditor(noteId);
  };
}

/** Tutup modal lihat catatan. */
function closeViewNote() {
  hideModal('viewNoteModal');
}

// ── Hapus Catatan ─────────────────────────────────────────────

/**
 * Menghapus catatan setelah konfirmasi.
 * @param {string} noteId
 */
function deleteNote(noteId) {
  const note = getNotes().find(n => n.id === noteId);
  if (!note) return;

  const ok = confirm(`Hapus catatan "${note.title}"? Tindakan ini tidak bisa dibatalkan.`);
  if (!ok) return;

  const notes = getNotes().filter(n => n.id !== noteId);
  saveNotes(notes);
  renderNoteList();
  showToast('Catatan dihapus.', 'info');
}

// ══════════════════════════════════════════════════════════════
// SECTION 7 — FILE TERENKRIPSI
// ══════════════════════════════════════════════════════════════

/**
 * Merender daftar file terenkripsi yang tersimpan.
 */
function renderFileList() {
  const files = getStoredFiles();
  const list  = document.getElementById('fileList');
  const empty = document.getElementById('fileEmpty');

  list.innerHTML = '';

  if (files.length === 0) {
    showElement('fileEmpty');
    return;
  }
  hideElement('fileEmpty');

  files
    .slice()
    .sort((a, b) => new Date(b.encryptedAt) - new Date(a.encryptedAt))
    .forEach(file => {
      const item = document.createElement('div');
      item.className = 'file-item';
      item.innerHTML = `
        <!-- Ikon file -->
        <div class="w-9 h-9 rounded-lg bg-primary/10 flex items-center justify-center shrink-0">
          <svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2"
            viewBox="0 0 24 24" class="text-primary" aria-hidden="true">
            <path stroke-linecap="round" stroke-linejoin="round"
              d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414
                 a1 1 0 01.293.707V19a2 2 0 01-2 2z"/>
          </svg>
        </div>
        <!-- Info -->
        <div class="flex-1 min-w-0">
          <p class="text-sm font-medium text-slate-800 truncate">${escapeHtml(file.originalName)}</p>
          <p class="text-xs text-slate-400">${formatFileSize(file.size)} · ${formatDate(file.encryptedAt)}</p>
        </div>
        <!-- Aksi -->
        <div class="flex gap-1.5 shrink-0">
          <button onclick="downloadFile('${file.id}')"
            class="flex items-center gap-1 px-3 py-1.5 rounded-lg text-xs font-medium
                   bg-primary/10 hover:bg-primary text-primary hover:text-white
                   transition-all duration-150">
            <svg width="12" height="12" fill="none" stroke="currentColor" stroke-width="2.2"
              viewBox="0 0 24 24" aria-hidden="true">
              <path stroke-linecap="round" stroke-linejoin="round"
                d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"/>
            </svg>
            Unduh
          </button>
          <button onclick="removeFile('${file.id}')"
            class="px-2.5 py-1.5 rounded-lg text-xs font-medium border border-red-100 text-red-400
                   hover:bg-red-50 hover:text-red-600 transition-all duration-150"
            aria-label="Hapus file ${escapeHtml(file.originalName)}">
            <svg width="12" height="12" fill="none" stroke="currentColor" stroke-width="2.2"
              viewBox="0 0 24 24" aria-hidden="true">
              <path stroke-linecap="round" stroke-linejoin="round"
                d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5
                   4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"/>
            </svg>
          </button>
        </div>
      `;
      list.appendChild(item);
    });
}

// ── Upload & Enkripsi File ────────────────────────────────────

/** Handler saat file dipilih via input[type=file]. */
function handleFileSelect(event) {
  const files = Array.from(event.target.files);
  files.forEach(processFileUpload);
  event.target.value = '';
}

/** Handler drag-over: ubah visual drop zone. */
function handleFileDragOver(event) {
  event.preventDefault();
  document.getElementById('fileDropZone').classList.add('border-primary', 'bg-primary/10');
}

/** Handler drag-leave: kembalikan visual drop zone. */
function handleFileDragLeave(event) {
  document.getElementById('fileDropZone').classList.remove('border-primary', 'bg-primary/10');
}

/** Handler drop: ambil file dari drag event. */
function handleFileDrop(event) {
  event.preventDefault();
  handleFileDragLeave(event);
  const files = Array.from(event.dataTransfer.files);
  files.forEach(processFileUpload);
}

/**
 * Memproses satu file: validasi ukuran → enkripsi → render.
 * @param {File} file
 */
async function processFileUpload(file) {
  if (file.size > MAX_FILE_BYTES) {
    showElement('fileSizeWarning');
    setTimeout(() => hideElement('fileSizeWarning'), 4000);
    return;
  }

  // Buat item progress sementara di daftar
  const progressId  = `prog-${Date.now()}`;
  const progressEl  = document.createElement('div');
  progressEl.id     = progressId;
  progressEl.className = 'file-item';
  progressEl.innerHTML = `
    <div class="w-9 h-9 rounded-lg bg-slate-100 flex items-center justify-center shrink-0">
      <svg width="14" height="14" fill="none" stroke="currentColor" stroke-width="2"
        viewBox="0 0 24 24" class="spin text-primary" aria-hidden="true">
        <path stroke-linecap="round" stroke-linejoin="round"
          d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/>
      </svg>
    </div>
    <div class="flex-1 min-w-0">
      <p class="text-sm font-medium text-slate-700 truncate">${escapeHtml(file.name)}</p>
      <div class="file-progress-bar mt-1">
        <div class="file-progress-fill" id="${progressId}-fill" style="width:0%"></div>
      </div>
    </div>
  `;

  // Pastikan daftar file terlihat
  hideElement('fileEmpty');
  document.getElementById('fileList').prepend(progressEl);

  try {
    await encryptFile(file, sessionPassword, (pct) => {
      const fill = document.getElementById(`${progressId}-fill`);
      if (fill) fill.style.width = `${pct}%`;
    });

    // Hapus item progress, render ulang dari storage
    progressEl.remove();
    renderFileList();
    showToast(`"${file.name}" berhasil dienkripsi!`, 'success');
  } catch (err) {
    progressEl.remove();
    renderFileList();
    showToast(`Gagal mengenkripsi "${file.name}": ${err.message}`, 'error');
  }
}

/**
 * Mendekripsi dan mengunduh file.
 * @param {string} fileId
 */
async function downloadFile(fileId) {
  const meta = getStoredFiles().find(f => f.id === fileId);
  if (!meta) return;

  showToast(`Mendekripsi "${meta.originalName}"…`, 'info');

  try {
    await decryptAndDownloadFile(fileId, sessionPassword);
    showToast(`"${meta.originalName}" berhasil diunduh!`, 'success');
  } catch (err) {
    showToast(`Gagal mengunduh: ${err.message}`, 'error');
  }
}

/**
 * Menghapus file terenkripsi dari localStorage.
 * @param {string} fileId
 */
function removeFile(fileId) {
  const meta = getStoredFiles().find(f => f.id === fileId);
  if (!meta) return;

  const ok = confirm(`Hapus file "${meta.originalName}"? Tindakan ini tidak bisa dibatalkan.`);
  if (!ok) return;

  deleteEncryptedFile(fileId);
  renderFileList();
  showToast('File dihapus.', 'info');
}

// ══════════════════════════════════════════════════════════════
// SECTION 8 — BIOMETRIK (Tab Bio)
// ══════════════════════════════════════════════════════════════

/**
 * Mengaktifkan kamera di tab registrasi wajah.
 */
async function startBioCamera() {
  const videoEl  = document.getElementById('bioVideo');
  const statusEl = document.getElementById('bioStatusText');

  try {
    await startBioCameraStream(videoEl, statusEl);
  } catch (err) {
    // Pesan error sudah diset ke statusEl oleh startBioCameraStream
    // Tampilkan juga sebagai toast agar terlihat jelas
    showToast(err.message || 'Kamera gagal diaktifkan.', 'error');
  }
}

/**
 * Menangkap & mendaftarkan wajah dari kamera.
 */
async function registerFace() {
  const videoEl    = document.getElementById('bioVideo');
  const canvasEl   = document.getElementById('bioCanvas');
  const statusEl   = document.getElementById('bioStatusText');
  const warningEl  = document.getElementById('bioRegisterWarning');

  if (!videoEl.srcObject) {
    showToast('Aktifkan kamera terlebih dahulu.', 'warning');
    return;
  }

  hideElement('bioRegisterWarning');

  const success = await captureFaceDescriptor(videoEl, canvasEl, statusEl);

  if (success) {
    updateBioStatus();
    showToast('Wajah berhasil didaftarkan!', 'success');
  } else {
    showElement('bioRegisterWarning');
  }
}

/**
 * Menghapus data wajah yang tersimpan.
 */
function deleteFaceData() {
  if (!hasFaceData()) return;

  const ok = confirm('Hapus data wajah? Anda tidak bisa login dengan face scan setelahnya.');
  if (!ok) return;

  removeFaceData();
  updateBioStatus();
  showElement('bioDeleteWarning');
  setTimeout(() => hideElement('bioDeleteWarning'), 4000);
  showToast('Data wajah dihapus.', 'info');
}

/**
 * Memperbarui kartu status biometrik di tab Bio.
 */
function updateBioStatus() {
  const dot = document.getElementById('bioStatusDot');
  const msg = document.getElementById('bioStatusMsg');
  if (!dot || !msg) return;

  if (hasFaceData()) {
    dot.className    = 'w-2.5 h-2.5 rounded-full bg-green-500 shrink-0';
    msg.textContent  = 'Data wajah terdaftar. Login face scan aktif.';
    msg.className    = 'text-sm text-green-700 font-medium';
  } else {
    dot.className    = 'w-2.5 h-2.5 rounded-full bg-slate-300 shrink-0';
    msg.textContent  = 'Belum ada data wajah terdaftar.';
    msg.className    = 'text-sm text-slate-600';
  }
}

// ══════════════════════════════════════════════════════════════
// SECTION 9 — TOAST NOTIFIKASI
// ══════════════════════════════════════════════════════════════

/**
 * Menampilkan notifikasi toast.
 * @param {string} message          - Pesan
 * @param {'success'|'error'|'info'|'warning'} type
 * @param {number} duration         - Durasi tampil (ms), default 3500
 */
function showToast(message, type = 'info', duration = 3500) {
  const container = document.getElementById('toastContainer');
  const toast     = document.createElement('div');
  toast.className = `toast ${type}`;

  // Ikon per tipe
  const icons = {
    success: '<svg width="15" height="15" fill="none" stroke="currentColor" stroke-width="2.5" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M5 13l4 4L19 7"/></svg>',
    error:   '<svg width="15" height="15" fill="none" stroke="currentColor" stroke-width="2.5" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12"/></svg>',
    warning: '<svg width="15" height="15" fill="none" stroke="currentColor" stroke-width="2.5" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M12 9v4m0 4h.01M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/></svg>',
    info:    '<svg width="15" height="15" fill="none" stroke="currentColor" stroke-width="2.5" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M13 16h-1v-4h-1m1-4h.01"/><circle cx="12" cy="12" r="10"/></svg>',
  };

  toast.innerHTML = `${icons[type] || icons.info}<span>${escapeHtml(message)}</span>`;
  container.appendChild(toast);

  setTimeout(() => {
    toast.classList.add('fade-out');
    toast.addEventListener('animationend', () => toast.remove());
  }, duration);
}

// ══════════════════════════════════════════════════════════════
// SECTION 10 — MODAL HELPERS
// ══════════════════════════════════════════════════════════════

/** Tampilkan modal. */
function showModal(id) {
  document.getElementById(id).classList.remove('hidden');
}

/** Sembunyikan modal. */
function hideModal(id) {
  document.getElementById(id).classList.add('hidden');
}

// Tutup modal saat klik backdrop
document.querySelectorAll('[id$="Modal"]').forEach(modal => {
  modal.addEventListener('click', e => {
    if (e.target === modal) {
      modal.classList.add('hidden');
    }
  });
});

// ══════════════════════════════════════════════════════════════
// SECTION 11 — DOM HELPERS
// ══════════════════════════════════════════════════════════════

/** Tampilkan elemen (hapus hidden). */
function showElement(id) {
  document.getElementById(id)?.classList.remove('hidden');
}

/** Sembunyikan elemen (tambah hidden). */
function hideElement(id) {
  document.getElementById(id)?.classList.add('hidden');
}

/**
 * Escape karakter HTML khusus untuk mencegah XSS.
 * @param {string} str
 * @returns {string}
 */
function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/**
 * Format tanggal ISO menjadi string lokal yang mudah dibaca.
 * @param {string} iso
 * @returns {string}
 */
function formatDate(iso) {
  return new Date(iso).toLocaleString('id-ID', {
    day: '2-digit', month: 'short', year: 'numeric',
    hour: '2-digit', minute: '2-digit',
  });
}

/**
 * Format tanggal relatif (baru saja, X menit lalu, dll).
 * @param {string} iso
 * @returns {string}
 */
function formatRelativeDate(iso) {
  const diff = Date.now() - new Date(iso).getTime();
  const min  = Math.floor(diff / 60_000);
  const hr   = Math.floor(min / 60);
  const day  = Math.floor(hr / 24);

  if (min < 1)   return 'Baru saja';
  if (min < 60)  return `${min} menit lalu`;
  if (hr  < 24)  return `${hr} jam lalu`;
  if (day < 7)   return `${day} hari lalu`;
  return formatDate(iso);
}
