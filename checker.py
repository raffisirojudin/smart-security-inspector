import base64
from datetime import datetime
import hashlib
import os
import time
import requests

RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"

# Mengambil API Key dari Environment Variable (jika ada)
API_KEY = os.getenv("VT_API_KEY", "")

# Daftar kata kunci sensitif untuk Analisis Lokal
DANGEROUS_KEYWORDS = [
    "rm -rf",
    "mkfs",
    "> /dev/sd",
    "curl",
    "wget",
    "eval(",
    "exec(",
    "base64",
    "/dev/null",
    "chmod 777",
]


def log_result(text):
  """Menyimpan riwayat pemeriksaan ke file log"""
  with open("scan_log.txt", "a") as f:
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    f.write(f"[{timestamp}] {text}\n")


def get_file_hash(file_path):
  """Menghitung hash SHA-256 dari file"""
  sha256_hash = hashlib.sha256()
  with open(file_path, "rb") as f:
    for byte_block in iter(lambda: f.read(4096), b""):
      sha256_hash.update(byte_block)
  return sha256_hash.hexdigest()


def local_heuristic_check(file_path):
  """Menganalisis isi file secara lokal untuk menemukan pola kode berbahaya"""
  print(f"\n{CYAN}[+] Menjalankan Analisis Lokal (Local Heuristics)...{RESET}")
  found_suspicious = []

  try:
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
      content = f.read()
      for kw in DANGEROUS_KEYWORDS:
        if kw in content:
          found_suspicious.append(kw)

    if found_suspicious:
      print(
          f"{YELLOW}[!] PERINGATAN LOKAL: Ditemukan perintah berpotensi"
          f" sensitif/berbahaya:{RESET}"
      )
      for item in found_suspicious:
        print(f"    - Terdeteksi perintah/fungsi: {BOLD}{item}{RESET}")
    else:
      print(
          f"{GREEN}[✓] Analisis Lokal: Tidak ditemukan pola perintah"
          f" berbahaya.{RESET}"
      )
  except Exception:
    print(
        f"{YELLOW}[i] Analisis lokal dilewati (File biner/non-teks).{RESET}"
    )


def print_results(stats, name):
  """Menampilkan tabel hasil analisis"""
  print("\n" + "=" * 40)
  print(f"{BOLD}         HASIL PEMERIKSAAN VIRUSTOTAL         {RESET}")
  print("=" * 40)
  print(f"Target              : {name}")
  print(f"Deteksi Berbahaya   : {RED}{stats['malicious']} Antivirus{RESET}")
  print(
      "Deteksi Mencurigakan:"
      f" {YELLOW}{stats['suspicious']} Antivirus{RESET}"
  )
  print(
      "Terdeteksi Aman     :"
      f" {GREEN}{stats['harmless'] + stats['undetected']} Antivirus{RESET}"
  )
  print("=" * 40)

  status_msg = ""
  if stats["malicious"] > 0:
    status_msg = f"BAHAYA! Terdeteksi oleh {stats['malicious']} antivirus."
    print(f"\n{RED}{BOLD}[!] {status_msg}{RESET}")
  else:
    status_msg = "AMAN! Tidak terindikasi berbahaya."
    print(f"\n{GREEN}{BOLD}[✓] {status_msg}{RESET}")

  log_result(f"Target: {name} | Status: {status_msg}")


def upload_file(file_path, api_key):
  """Mengunggah file ke VirusTotal jika belum ada di database"""
  url = "https://www.virustotal.com/api/v3/files"
  headers = {"x-apikey": api_key}

  print(f"\n{CYAN}[+] Mengunggah file ke server VirusTotal...{RESET}")
  try:
    with open(file_path, "rb") as f:
      files = {"file": (os.path.basename(file_path), f)}
      response = requests.post(url, headers=headers, files=files)

    if response.status_code == 200:
      analysis_id = response.json()["data"]["id"]
      print(f"{GREEN}[+] Berhasil diunggah! Menunggu pemindaian...{RESET}")

      analysis_url = (
          f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
      )
      for _ in range(10):
        time.sleep(3)
        res = requests.get(analysis_url, headers=headers)
        if res.status_code == 200:
          status = res.json()["data"]["attributes"]["status"]
          if status == "completed":
            stats = res.json()["data"]["attributes"]["stats"]
            print_results(stats, os.path.basename(file_path))
            return
          else:
            print(
                f"{CYAN}[...] Pemindaian masih berjalan di cloud...{RESET}"
            )
    else:
      print(
          f"{RED}[!] Gagal mengunggah file. Status:"
          f" {response.status_code}{RESET}"
      )
  except Exception as e:
    print(f"{RED}[!] Error unggah: {e}{RESET}")


def scan_file(file_path, api_key):
  """Fitur Pemindaian File"""
  file_path = file_path.strip().replace("'", "").replace('"', "")

  if not os.path.exists(file_path):
    print(
        f"\n{RED}[!] Error: File tidak ditemukan di lokasi tersebut.{RESET}"
    )
    return

  local_heuristic_check(file_path)

  print(f"\n{CYAN}[+] Menghitung hash SHA-256...{RESET}")
  file_hash = get_file_hash(file_path)
  print(f"    Hash: {BOLD}{file_hash}{RESET}")

  print(f"{CYAN}[+] Memeriksa ke database VirusTotal...{RESET}")
  url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
  headers = {"x-apikey": api_key}

  try:
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
      data = response.json()["data"]["attributes"]
      stats = data["last_analysis_stats"]
      print_results(stats, os.path.basename(file_path))

    elif response.status_code == 404:
      print(f"\n{YELLOW}[i] File belum ada di database VirusTotal.{RESET}")
      print("--------------------------------------------------")
      print(
          f"{RED}[!] PERINGATAN PRIVASI: Jangan unggah dokumen"
          f" rahasia/pribadi!{RESET}"
      )
      print("--------------------------------------------------")

      pilihan = (
          input("Apakah kamu yakin ingin mengunggah file ini? (y/n): ")
          .strip()
          .lower()
      )
      if pilihan == "y":
        upload_file(file_path, api_key)
      else:
        print(f"\n{GREEN}[✓] Pengunggahan dibatalkan.{RESET}")
        log_result(
            f"Target: {os.path.basename(file_path)} | Status: Dibatalkan (File"
            " Baru)"
        )

    elif response.status_code == 401:
      print(f"\n{RED}[!] Error: API Key VirusTotal tidak valid.{RESET}")

  except Exception as e:
    print(f"\n{RED}[!] Gagal terhubung ke internet: {e}{RESET}")


def scan_url(url_input, api_key):
  """Fitur Pemindaian URL / Link Website"""
  url_input = url_input.strip().replace("'", "").replace('"', "")

  if not url_input.startswith(("http://", "https://")):
    url_input = "https://" + url_input

  print(f"\n{CYAN}[+] Memeriksa URL: {url_input}...{RESET}")

  url_id = base64.urlsafe_b64encode(url_input.encode()).decode().strip("=")
  api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
  headers = {"x-apikey": api_key}

  try:
    response = requests.get(api_url, headers=headers)

    if response.status_code == 200:
      stats = response.json()["data"]["attributes"]["last_analysis_stats"]
      print_results(stats, url_input)

    elif response.status_code == 404:
      print(
          f"\n{YELLOW}[i] Website ini belum pernah dipindai sebelumnya di"
          f" VirusTotal.{RESET}"
      )
      pilihan = (
          input(
              "Apakah kamu ingin mendaftarkan website ini untuk dipindai?"
              " (y/n): "
          )
          .strip()
          .lower()
      )

      if pilihan == "y":
        print(f"\n{CYAN}[+] Mengirimkan URL ke VirusTotal...{RESET}")
        post_url = "https://www.virustotal.com/api/v3/urls"
        payload = {"url": url_input}
        post_res = requests.post(post_url, headers=headers, data=payload)

        if post_res.status_code == 200:
          print(f"{GREEN}[✓] Permintaan pindaian sukses dikirim!{RESET}")
          print(
              f"{CYAN}[i] Tunggu 30–60 detik agar server memindai webmu, lalu"
              f" coba cek menu URL lagi.{RESET}"
          )
        else:
          print(
              f"{RED}[!] Gagal mendaftarkan URL. Status:"
              f" {post_res.status_code}{RESET}"
          )
      else:
        print(f"\n{GREEN}[✓] Pemindaian URL dibatalkan.{RESET}")
    else:
      print(
          f"\n{RED}[!] Error dari Server: Kode status"
          f" {response.status_code}{RESET}"
      )

  except Exception as e:
    print(f"\n{RED}[!] Error saat memeriksa URL: {e}{RESET}")


if __name__ == "__main__":
  if not API_KEY:
    print(f"{BOLD}{CYAN}=== VIRUSTOTAL API KEY SETUP ==={RESET}")
    API_KEY = input("Masukkan VirusTotal API Key kamu: ").strip()

  while True:
    print(f"\n{BOLD}{CYAN}=== SMART SECURITY INSPECTOR ==={RESET}")
    print("1. Scan File (Lokal + VirusTotal)")
    print("2. Scan URL / Link Website")
    print("3. Keluar")

    pilihan = input("\nPilih menu (1/2/3): ").strip()

    if pilihan == "1":
      target = input("\nMasukkan / Seret file ke sini: ")
      scan_file(target, API_KEY)
    elif pilihan == "2":
      target_url = input(
          "\nMasukkan URL/Link Website (contoh: google.com atau"
          " domainkamu.com): "
      )
      scan_url(target_url, API_KEY)
    elif pilihan == "3":
      print(f"\n{GREEN}Terima kasih telah menggunakan tool ini! Bye.{RESET}\n")
      break
    else:
      print(f"\n{RED}Pilihan tidak valid, coba lagi.{RESET}")
