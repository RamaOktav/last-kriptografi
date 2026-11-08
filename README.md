# 🔐 Secret Note — Multi-User Client-Side Cryptography Suite

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](#license)
[![Platform: Client-Side Web](https://img.shields.io/badge/Platform-HTML5%20%7C%20CSS3%20%7C%20ES6%20JS-brightgreen.svg)](#features--fitur-utama)
[![Cryptography: Hybrid Suite](https://img.shields.io/badge/Cryptography-Vigen%C3%A8re%20%7C%20AES--GCM%20%7C%20RC4%20%7C%20LSB%20%7C%20Blockchain-cyan.svg)](#features--fitur-utama)

> **Tugas Akhir Mata Kuliah Kriptografi — UPN "Veteran" Yogyakarta**  
> A zero-knowledge, pure client-side cryptographic web application featuring multi-tenant data vaults, true 3-factor authentication (Dual-mode USB Hardware Dongle with Auto-Lock on Eject, Real AI Face Biometrics via `face-api.js`, and SHA-256 Master PIN), Classic-to-Modern Super-Encryption, Byte-level Stream Cipher (RC4), Canvas-based Image Steganography (LSB), and a verifiable Blockchain Audit Ledger with an in-app Database Inspector.

---

## 🌐 Language Navigation / Navigasi Bahasa
- [English Version (#english-version)](#-english-version)
- [Versi Bahasa Indonesia (#versi-bahasa-indonesia)](#-versi-bahasa-indonesia)

---

# 🇬🇧 English Version

## 📌 Overview
**Secret Note** is an enterprise-grade client-side cryptographic workstation designed for academic presentation and real-world zero-knowledge vault protection. All sensitive operations—key derivation, stream cipher generation, spatial steganographic bit embedding, and biometric vector distance calculation—occur directly in the client browser memory. No secret keys, plaintext passwords, or raw images are transmitted to external servers.

---

## ✨ Key Features

### 1. 🛡️ Tab 1: Gatekeeper & Multi-User 3-Factor Authentication (3FA)
- **Multi-Tenant Architecture**: Supports isolated user accounts stored locally in client-side **IndexedDB**.
- **Factor 1 (Possession) — Dual-Mode USB Dongle (1 USB = 1 User)**:
  - **Hardware Mode (Physical USB Drive)**: Interacts with external USB flash drives via the **Web File System Access API** (`window.showDirectoryPicker`). Automatically validates `dongle-<username>.key` with SHA-256 cryptographic signatures.
  - **Hardware Removal Policy (Auto-Lock on Eject)**: A background heartbeat watcher monitors the physical USB handle every 2 seconds. Ejecting or disconnecting the flashdrive triggers an immediate security alert and automatically locks the session.
  - **File Upload Mode**: Fallback file picker for non-Chromium or legacy environments.
- **Factor 2 (Inherence) — Real Biometric Face Recognition**:
  - Powered by **TensorFlow.js / `face-api.js`**.
  - Extracts a 128-dimensional floating-point facial descriptor vector during enrollment and stores it in IndexedDB (no facial photographs are ever saved).
  - During verification, evaluates real-time camera frames against the stored vector using **Euclidean Distance**:
    $$\text{Distance} = \sqrt{\sum_{i=0}^{127} (A_i - B_i)^2}$$
    Matches when $\text{Distance} \le 0.50$.
  - Includes a fallback visual simulation mode for hardware without webcams.
- **Factor 3 (Knowledge) — Master PIN**:
  - Verified against a SHA-256 digest via Web Crypto API.

### 2. 📜 Tab 2: Super-Encryption (Classic + Modern) & Educational Tracer
- **Two-Layer Pipeline**:
  $$\text{Plaintext} \xrightarrow[\text{A--Z Modulo 26}]{\text{Vigen\grave{e}re}} \text{Intermediate Ciphertext} \xrightarrow[\text{PBKDF2 Derived Key}]{\text{AES-256-GCM}} \text{Base64 Package}$$
- **Vigenère Cipher (Classic Academic Standard)**:
  - Maps alphabetic characters $A \mapsto 0, \dots, Z \mapsto 25$ using $C = (P + K) \pmod{26}$.
  - Non-alphabetic characters (numbers, punctuation, whitespace) are passed through unshifted according to classical syllabus standards, then fully secured by AES-256-GCM.
- **AES-256-GCM (Modern)**:
  - Key derived using **PBKDF2** (100,000 iterations, SHA-256, 16-byte random salt).
  - 12-byte random Initialization Vector (IV) and 16-byte authentication tag for Galois/Counter Mode integrity.
- **Educational Step-by-Step Breakdown**:
  - Live inspection table showing character-by-character shifts, PBKDF2 parameters, raw hex ciphertexts, and Base64 packing/unpacking.
- **User-Isolated Vault**: Notes are strictly partitioned by username.

### 3. 📁 Tab 3: File Cryptography (RC4 Stream Cipher)
- Encrypts any binary file (PDF, DOCX, ZIP, MP4, PNG, etc.) using byte-level **Rivest Cipher 4 (RC4)**.
- **Algorithms**:
  - Key-Scheduling Algorithm (KSA) permutations on state array $S[0..255]$.
  - Pseudo-Random Generation Algorithm (PRGA) for dynamic keystream emission.
  - Bitwise XOR operation: $\text{Byte}_{\text{out}} = \text{Byte}_{\text{in}} \oplus \text{Keystream}$.
- **Step-by-Step Tracer**:
  - Visualizes $S$-box state before and after KSA, first 16 bytes of PRGA keystream, and bitwise XOR truth tables.
- **Binary Envelope**: Generates and downloads `.enc` files with magic header bytes (`RC4F`) and recovers original file extensions upon decryption.

### 4. 🖼️ Tab 4: Image Steganography (LSB)
- Embeds arbitrary secret messages into the **Least Significant Bit (LSB)** of color channels (Red, Green, Blue) across an HTML5 Canvas.
- Preserves visual fidelity by capping bit-shift variances to $\pm 1$.
- Terminated with an unambiguous 16-bit binary delimiter (`1111111111111110`).
- **Pixel Bit Inspector**: Compares binary representations of the first sample pixels before and after bit substitution.
- Lossless PNG (`image/png`) export to prevent compression distortion.

### 5. ⛓️ Tab 5: Blockchain Ledger & Database Inspector
- **Cryptographic Blockchain Ledger**:
  - Each block records `index`, `timestamp`, `username`, `data`, `previousHash`, and `hash` (SHA-256).
  - Automatically records all critical actions (`USER_REGISTER`, `LOGIN`, `SUPER_ENCRYPT`, `FILE_ENCRYPT_RC4`, `STEGO_EMBED`, `AUTO_LOCK_USB_EJECT`).
  - Chain integrity validator with a live "Simulate Tamper" button to demonstrate immutability.
- **In-App Database Inspector**:
  - Client-side browser database explorer (analogous to phpMyAdmin for IndexedDB).
  - Inspect raw records across `users`, `vault_text`, `vault_files`, and `blockchain_ledger`.
  - Export database state as JSON and reset storage safely.

---

## 📂 Project Architecture

```
secret-note/
├── index.html        # Modern Cybersecurity Dark Theme UI & Tab Controller
├── style.css         # Responsive styling, step breakdown panels, modal layout
├── db.js             # IndexedDB engine (SecretNoteCryptoDB v2, Multi-Tenant)
├── crypto.js         # SHA-256, Classic Vigenère (A-Z mod 26), AES-256-GCM, Tracer
├── file-crypto.js    # RC4 Stream Cipher (KSA, PRGA, XOR), .enc packaging
├── face-scan.js      # Dual-mode Dongle (Web File System Access) & face-api.js
├── stego.js          # Canvas LSB Image Steganography & Pixel Bit Inspector
└── app.js            # Blockchain ledger class, state management, UI orchestrator
```

---

## 🚀 Getting Started

### Prerequisites
- A modern Chromium-based web browser (**Google Chrome** or **Microsoft Edge**) to support the Web File System Access API and Web Camera streams.
- A local HTTP server (browsers restrict camera and file-system APIs under `file://`).

### Running Locally
You can serve the directory using any lightweight server:

**Using Node.js (`npx serve`):**
```bash
npx serve secret-note
```

**Using Python:**
```bash
cd secret-note
python -m http.server 8000
```

**Using VS Code:**
- Install the **Live Server** extension.
- Right-click `secret-note/index.html` and select **"Open with Live Server"**.

Visit `http://localhost:8000` (or the port indicated) in your browser.

---

# 🇮🇩 Versi Bahasa Indonesia

## 📌 Ringkasan Proyek
**Secret Note** adalah aplikasi web kriptografi *client-side* tingkat lanjut yang dirancang khusus untuk memenuhi standar penilaian Tugas Akhir Mata Kuliah Kriptografi UPN "Veteran" Yogyakarta. Seluruh kalkulasi matematika kriptografi—penurunan kunci, stream cipher, penyisipan bit steganografi piksel, serta pencocokan vektor biometrik—dijalankan secara lokal di memori browser. Tidak ada kunci rahasia, kata sandi, maupun berkas mentah yang dikirim ke server luar (*zero-knowledge architecture*).

---

## ✨ Fitur-Fitur Utama

### 1. 🛡️ Tab 1: Gatekeeper & Autentikasi 3-Faktor Multi-User (3FA)
- **Arsitektur Multi-User**: Mendukung banyak akun pengguna dengan isolasi data vault pribadi yang tersimpan secara lokal pada **IndexedDB**.
- **Faktor 1 (Kepemilikan / Possession) — USB Dongle Dual-Mode (1 USB = 1 User)**:
  - **Mode Fisik (Deteksi Flashdisk USB)**: Terhubung langsung dengan drive flashdisk eksternal menggunakan **Web File System Access API** (`window.showDirectoryPicker`). Memvalidasi token `dongle-<username>.key` ber-tanda tangan digital SHA-256.
  - **Hardware Removal Policy (Auto-Lock saat USB Dicabut)**: Background watcher memeriksa handle USB setiap 2 detik. Begitu flashdisk dicabut dari laptop, sistem langsung memicu alarm keamanan dan **mengunci sesi secara otomatis**.
  - **Mode Unggah Berkas Manual**: Pilihan fallback untuk pengujian fleksibel tanpa perangkat flashdisk fisik.
- **Faktor 2 (Karakteristik Fisik / Inherence) — Biometrik Wajah Riil**:
  - Ditenagai oleh **TensorFlow.js / `face-api.js`**.
  - Mengekstrak vektor deskriptor wajah 128-dimensi saat pendaftaran akun dan menyimpannya di IndexedDB (tidak ada foto wajah mentah yang disimpan).
  - Saat login, menghitung kesamaan wajah langsung dari webcam menggunakan **Jarak Euclidean**:
    $$\text{Distance} = \sqrt{\sum_{i=0}^{127} (A_i - B_i)^2}$$
    Dinyatakan cocok (*MATCH*) jika $\text{Distance} \le 0.50$.
  - Dilengkapi tombol fallback simulasi visual jika perangkat tidak memiliki webcam.
- **Faktor 3 (Pengetahuan / Knowledge) — Master PIN**:
  - Verifikasi PIN menggunakan fungsi hash SHA-256 Web Crypto API.

### 2. 📜 Tab 2: Super-Enkripsi Teks (Klasik + Modern) & Visualisasi Langkah
- **Alur Dua Lapis**:
  $$\text{Plaintext} \xrightarrow[\text{A--Z Modulo 26}]{\text{Vigen\grave{e}re Klasik}} \text{Teks Perantara} \xrightarrow[\text{Kunci PBKDF2}]{\text{AES-256-GCM}} \text{Paket Base64}$$
- **Vigenère Cipher (Standar Teori Kuliah)**:
  - Karakter alfabet dipetakan $A \mapsto 0, \dots, Z \mapsto 25$ dengan rumus pergeseran $C = (P + K) \pmod{26}$.
  - Karakter non-alfabet (angka, spasi, simbol) di-bypass (*pass-through*) sesuai silabus klasik, kemudian dienkripsi secara total oleh AES-256-GCM.
- **AES-256-GCM (Kriptografi Modern)**:
  - Penurunan kunci via **PBKDF2** (100.000 iterasi, SHA-256, salt acak 16-byte).
  - Initialization Vector (IV) acak 12-byte dan Authentication Tag 16-byte untuk menjamin integritas data (anti-tamper).
- **Panel Edukasi Langkah demi Langkah (*Step-by-Step Breakdown*)**:
  - Memperlihatkan tabel pergeseran per karakter, parameter PBKDF2, ciphertext biner/hex, hingga pengemasan Base64.
- **Vault Catatan Pribadi**: Catatan terenkripsi tersimpan rapi dan hanya dapat dilihat oleh pemilik akun.

### 3. 📁 Tab 3: Enkripsi Berkas (RC4 Stream Cipher)
- Mengenkripsi semua jenis berkas biner (PDF, DOCX, ZIP, MP4, PNG, dll.) menggunakan algoritma **RC4 (Rivest Cipher 4)** pada level byte data.
- **Komponen Algoritma**:
  - Key-Scheduling Algorithm (KSA): Permutasi array status $S[0..255]$.
  - Pseudo-Random Generation Algorithm (PRGA): Pembangkitan keystream acak semu dinamis.
  - Operasi Bitwise XOR: $\text{Byte}_{\text{out}} = \text{Byte}_{\text{in}} \oplus \text{Keystream}$.
- **Pelacak Langkah Edukasi**:
  - Menampilkan cuplikan State Array sebelum dan sesudah KSA, 16-byte pertama keystream, dan tabel kebenaran XOR biner.
- **Pengemasan Biner**: Menghasilkan berkas `.enc` dengan header magic `RC4F` dan memulihkan nama serta format asli saat didekripsi.

### 4. 🖼️ Tab 4: Steganografi Gambar (LSB Canvas)
- Menyisipkan bit pesan rahasia ke dalam bit paling akhir (**Least Significant Bit**) kanal warna (Red, Green, Blue) piksel canvas gambar.
- Perubahan nilai warna maksimal hanya $\pm 1$ sehingga kasat mata dan tidak mengubah tampilan gambar cover.
- Penanda akhir pesan menggunakan delimiter biner 16-bit (`1111111111111110`).
- **Pixel Bit Inspector**: Menampilkan visualisasi dekomposisi biner piksel sebelum vs sesudah disisipkan pesan.
- Ekspor berkas dalam format lossless PNG (`image/png`) untuk menjaga keutuhan bit LSB.

### 5. ⛓️ Tab 5: Blockchain Ledger & Database Inspector
- **Ledger Audit Blockchain**:
  - Setiap blok menyimpan struktur `index`, `timestamp`, `username`, `data`, `previousHash`, dan `hash` SHA-256.
  - Mencatat seluruh transaksi pengguna (`USER_REGISTER`, `LOGIN`, `SUPER_ENCRYPT`, `FILE_ENCRYPT_RC4`, `STEGO_EMBED`, `AUTO_LOCK_USB_EJECT`).
  - Fitur verifikasi integritas rantai dengan tombol simulasi manipulasi data (*Tamper Block*).
- **Database Inspector (Simulator phpMyAdmin Client-Side)**:
  - Penjelajah isi IndexedDB langsung di antarmuka web.
  - Memeriksa record tabel `users`, `vault_text`, `vault_files`, dan `blockchain_ledger`.
  - Dilengkapi fitur Export snapshot JSON dan Reset Database.

---

## 🛠️ Panduan Menjalankan Aplikasi

### Persyaratan Sistem
- Web browser modern berbasis Chromium (**Google Chrome** atau **Microsoft Edge**) untuk mendukung Web File System Access API dan akses streaming webcam.
- Web server lokal (API kamera dan File System dibatasi browser jika dibuka langsung via protokol `file://`).

### Menjalankan Server Lokal
Pilih salah satu metode berikut di folder repositori:

**Menggunakan Node.js:**
```bash
npx serve secret-note
```

**Menggunakan Python:**
```bash
cd secret-note
python -m http.server 8000
```

**Menggunakan Visual Studio Code:**
- Pasang ekstensi **Live Server**.
- Klik kanan pada `secret-note/index.html` dan pilih **"Open with Live Server"**.

Buka alamat `http://localhost:8000` (atau port yang ditampilkan) pada browser Anda.

---

## 👥 Authors & Academic Context
- **Mata Kuliah**: Kriptografi
- **Program Studi**: Informatika / Sistem Informasi
- **Institusi**: UPN "Veteran" Yogyakarta

---

## 📄 License
This project is licensed under the [MIT License](LICENSE).
