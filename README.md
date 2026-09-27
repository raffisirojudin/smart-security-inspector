# 🛡️ Smart Security Inspector

**Smart Security Inspector** adalah aplikasi CLI (Command Line Interface) ringan berbasis Python yang dirancang untuk membantu memeriksa keamanan file dan link website. Tool ini mengombinasikan **Local Heuristic Analysis** (analisis statistik isi file di mesin lokal) dan **VirusTotal API v3** (pencocokan hash terhadap 70+ mesin antivirus global).

---

## 🚀 Fitur Utama

- 🔍 **File Inspection**: Menghitung SHA-256 hash dari file lokal dan mencocokkannya langsung dengan database threat intelligence VirusTotal.
- 🛠️ **Local Heuristic Check**: Menganalisis script (`.sh`, `.py`, dll.) untuk mendeteksi perintah atau fungsi yang berpotensi membahayakan sistem secara lokal tanpa bergantung pada koneksi internet.
- 🌐 **URL & Phishing Scanner**: Menguji tingkat reputasi alamat domain/URL terhadap ancaman *phishing* atau *malware*.
- 🛡️ **Privacy Guard**: Memberikan konfirmasi peringatan privasi sebelum mengunggah file baru yang belum terdaftar di database.
- 📊 **Log Automaticing**: Otomatis menyimpan semua riwayat pemeriksaan ke dalam file `scan_log.txt`.
- 🎨 **Colored Terminal Output**: UI terminal berbasis warna ANSI untuk mempermudah identifikasi ancaman secara visual.

---

## 💻 Cara Menggunakan

### 1. Prasyarat
- Python 3.x
- VirusTotal API Key (Bisa didapatkan gratis di [virustotal.com](https://www.virustotal.com))

### 2. Jalankan Program
1. Unduh file `checker.py`.
2. Buka Terminal dan install dependensi:
   ```bash
   pip install requests
