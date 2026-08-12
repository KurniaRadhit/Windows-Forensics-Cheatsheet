## 📌 Daftar Isi — Bab 9

- [Bab 9 — Timeline Correlation & Anti-Forensics](#bab-9--timeline-correlation--anti-forensics)
  - [9.1 Konsep Dasar Timeline Correlation](#91-konsep-dasar-timeline-correlation)
    - [9.1.1 Kenapa Single-Artifact Analysis Tidak Cukup](#911-kenapa-single-artifact-analysis-tidak-cukup)
    - [9.1.2 Empat Kategori Timestamp Cross-Artifact](#912-empat-kategori-timestamp-cross-artifact)
    - [9.1.3 MACB / MACE Notation & Timestamp Semantics](#913-macb--mace-notation--timestamp-semantics)
  - [9.2 Membangun Super Timeline — Manual](#92-membangun-super-timeline--manual)
    - [9.2.1 Normalisasi Timezone (UTC vs Local)](#921-normalisasi-timezone-utc-vs-local)
    - [9.2.2 Menggabungkan CSV Multi-Artefak di Timeline Explorer](#922-menggabungkan-csv-multi-artefak-di-timeline-explorer)
    - [9.2.3 Tagging & Filtering Strategy](#923-tagging--filtering-strategy)
  - [9.3 Membangun Super Timeline — plaso / log2timeline](#93-membangun-super-timeline--plaso--log2timeline)
    - [9.3.1 Instalasi & Arsitektur plaso](#931-instalasi--arsitektur-plaso)
    - [9.3.2 Menjalankan log2timeline.py terhadap Disk Image](#932-menjalankan-log2timelinepy-terhadap-disk-image)
    - [9.3.3 psort.py — Filtering, Output Format, Time Slicing](#933-psortpy--filtering-output-format-time-slicing)
    - [9.3.4 Parser Selection](#934-parser-selection)
    - [9.3.5 plaso vs Manual — Kapan Pakai Mana](#935-plaso-vs-manual--kapan-pakai-mana)
  - [9.4 Custom Timeline Correlation — Python/Pandas](#94-custom-timeline-correlation--pythonpandas)
    - [9.4.1 Kenapa Butuh Scripting](#941-kenapa-butuh-scripting)
    - [9.4.2 Load & Normalize Multi-CSV](#942-load--normalize-multi-csv)
    - [9.4.3 Join/Merge Strategy Antar Artefak](#943-joinmerge-strategy-antar-artefak)
    - [9.4.4 Deteksi Anomali Otomatis](#944-deteksi-anomali-otomatis)
  - [9.5 Metodologi Korelasi Lintas-Artefak](#95-metodologi-korelasi-lintas-artefak)
    - [9.5.1 Root Cause → Timeline Reconstruction Workflow](#951-root-cause--timeline-reconstruction-workflow)
    - [9.5.2 Evidence of Existence vs Evidence of Execution](#952-evidence-of-existence-vs-evidence-of-execution)
    - [9.5.3 Studi Kasus Pola Korelasi — USB Insert → LNK → Prefetch → EVTX](#953-studi-kasus-pola-korelasi--usb-insert--lnk--prefetch--evtx)
  - [9.6 Anti-Forensics — Timestamp & Metadata Manipulation](#96-anti-forensics--timestamp--metadata-manipulation)
    - [9.6.1 Timestomping Lanjutan — Tools & Bypass SI-FN Check](#961-timestomping-lanjutan--tools--bypass-si-fn-check)
    - [9.6.2 SI vs FN vs $LogFile vs $UsnJrnl — 4-Way Cross-Check](#962-si-vs-fn-vs-logfile-vs-usnjrnl--4-way-cross-check)
  - [9.7 Anti-Forensics — Filesystem & Journal Level](#97-anti-forensics--filesystem--journal-level)
    - [9.7.1 MFT Record Wiping/Manipulation](#971-mft-record-wipingmanipulation)
    - [9.7.2 $LogFile Manipulation & Journal Gaps](#972-logfile-manipulation--journal-gaps)
    - [9.7.3 $UsnJrnl Truncation/Disable](#973-usnjrnl-truncationdisable)
  - [9.8 Anti-Forensics — Data & Log Destruction Tools](#98-anti-forensics--data--log-destruction-tools)
    - [9.8.1 Secure Deletion Tools (SDelete, CCleaner, Eraser)](#981-secure-deletion-tools-sdelete-ccleaner-eraser)
    - [9.8.2 USB/Removable Media Wiping](#982-usbremovable-media-wiping)
    - [9.8.3 Anti-Forensic Tool Execution Evidence](#983-anti-forensic-tool-execution-evidence)
  - [9.9 Mendeteksi Timeline Gap (Missing Evidence)](#99-mendeteksi-timeline-gap-missing-evidence)
    - [9.9.1 Konsep "Absence of Evidence is Evidence"](#991-konsep-absence-of-evidence-is-evidence)
    - [9.9.2 Statistical Gap Detection](#992-statistical-gap-detection)
    - [9.9.3 Correlation Matrix — Artefak yang Seharusnya Ada](#993-correlation-matrix--artefak-yang-seharusnya-ada)
    - [9.9.4 VSS/Backup sebagai Cross-Validation Gap](#994-vssbackup-sebagai-cross-validation-gap)
  - [9.10 Timestamp Normalization — Referensi Master](#910-timestamp-normalization--referensi-master)
    - [9.10.1 Tabel Epoch & Formula Konversi Lengkap](#9101-tabel-epoch--formula-konversi-lengkap)
    - [9.10.2 Precision Mismatch Antar Artefak](#9102-precision-mismatch-antar-artefak)
    - [9.10.3 Script Python — Universal Timestamp Converter](#9103-script-python--universal-timestamp-converter)
  - [9.11 Master Correlation Matrix — Event Type vs Artefak Lintas-Bab](#911-master-correlation-matrix--event-type-vs-artefak-lintas-bab)
  - [9.12 Evidence Survivability Matrix](#912-evidence-survivability-matrix)
  - [9.13 Tabel Master — Anti-Forensic Technique vs Detection Method](#913-tabel-master--anti-forensic-technique-vs-detection-method)
  - [9.14 Investigation Playbooks](#914-investigation-playbooks)
    - [9.14.1 Playbook — Suspected Malware Execution](#9141-playbook--suspected-malware-execution)
    - [9.14.2 Playbook — Data Exfiltration via USB/Removable Media](#9142-playbook--data-exfiltration-via-usbremovable-media)
    - [9.14.3 Playbook — Ransomware Incident](#9143-playbook--ransomware-incident)
    - [9.14.4 Playbook — Suspected Anti-Forensics / Insider Threat](#9144-playbook--suspected-anti-forensics--insider-threat)
    - [9.14.5 Playbook — Lateral Movement Cross-Host](#9145-playbook--lateral-movement-cross-host)
  - [9.15 Ringkasan Command & Tools Cheat Sheet](#915-ringkasan-command--tools-cheat-sheet)
  - [9.16 Mini Case Study — Full Timeline Reconstruction dengan Gap Detection](#916-mini-case-study--full-timeline-reconstruction-dengan-gap-detection)

*(Bab 1: Struktur Drive & Direktori — `bab1.md`. Bab 2: File Sistem NTFS & $MFT — `bab2.md`. Bab 3: Windows Registry Forensics — `bab3.md`. Bab 4: EVTX & Event ID Forensics — `bab4.md`. Bab 5: User Activity Trail — `bab5.md`. Bab 6: Browser Forensics — `bab6.md`. Bab 7: Memory Forensics — `bab7.md`. Bab 8: Malware & Persistence Analysis — `bab8.md`.)*

---

## Bab 9 — Timeline Correlation & Anti-Forensics

> 💡 **Posisi Bab 9 di seri ini:** Bab 1-8 fokus per-artefak — di mana bukti tersimpan, apa strukturnya, dan bagaimana anti-forensic sederhana terhadap artefak itu dideteksi (sudah dibahas lokal di tiap bab). Bab 9 **tidak mengulang** semua itu. Bab 9 menjahit semuanya jadi satu timeline utuh lintas-artefak (§9.1-9.5), lalu naik satu level ke teknik anti-forensik yang menyerang **fondasi filesystem/journal itu sendiri** — bukan satu artefak spesifik (§9.6-9.9). Bagian penutup (§9.10-9.14) adalah lapisan referensi & operasional: konversi timestamp lintas-format (§9.10), matrix korelasi & survivability lengkap (§9.11-9.12), matrix deteksi anti-forensik (§9.13), dan playbook siap-pakai per jenis kasus (§9.14) — dipakai sebagai lookup table saat kerja, bukan dibaca linear sekali jalan. Kalau kamu belum familiar dengan istilah SI/FN, $LogFile, $UsnJrnl, VSS, atau Event ID auth dasar, kembali dulu ke Bab 2-5 sebelum lanjut ke sini.

### 9.1 Konsep Dasar Timeline Correlation

#### 9.1.1 Kenapa Single-Artifact Analysis Tidak Cukup

**Pengertian & Fungsi:**
Satu artefak forensik hampir selalu hanya menjawab **satu sisi pertanyaan** — misalnya Prefetch menjawab "kapan terakhir dijalankan & berapa kali", tapi tidak menjawab "siapa yang menjalankan" atau "apakah ini hasil user klik langsung atau dijalankan remote". Attacker yang paham forensik juga sering menghapus/manipulasi satu artefak spesifik (misal timestomp $MFT saja) sambil lupa artefak lain (EVTX, Prefetch, $LogFile) yang mencatat kejadian sama dari sudut berbeda.

| Pertanyaan Investigasi | Artefak Tunggal | Kenapa Tidak Cukup Sendirian |
|---|---|---|
| Kapan malware dieksekusi? | Prefetch | Prefetch bisa didisable/dihapus attacker, atau tidak tercatat kalau fileless |
| Siapa yang login? | EVTX 4624 | Tidak menunjukkan apa yang dilakukan setelah login |
| File ini dibuat kapan? | $MFT SI timestamp | Bisa ditimestomp — perlu cross-check FN, $LogFile |
| USB kapan dicolok? | Registry USBSTOR | Tidak menunjukkan file apa yang diakses dari USB itu |

> ⚠️ **Prinsip inti Bab 9:** Satu artefak bisa dibohongi. **Kombinasi banyak artefak independen yang saling mengonfirmasi** jauh lebih sulit dipalsukan sekaligus — inilah alasan timeline correlation jadi tahap wajib sebelum kesimpulan investigasi ditulis.

---

#### 9.1.2 Empat Kategori Timestamp Cross-Artifact

Sebelum digabung, kenali dulu dari kategori mana tiap timestamp berasal — supaya tahu artefak lain mana yang relevan buat cross-check.

| Kategori | Sumber Timestamp | Detail di |
|---|---|---|
| **Filesystem** | $MFT (SI 0x10, FN 0x30), $LogFile, $UsnJrnl | Bab 2 §2.1.2, §2.2 |
| **Registry** | LastWrite key, UserAssist ROT13+FILETIME, ShimCache (kadang), Amcache | Bab 3 §3.1.5, §3.6.1, §3.8 |
| **EVTX / Log** | TimeCreated per event record, selalu UTC di disk | Bab 4 §4.8 |
| **Application** | Browser history (WebKit/PRTime), LNK/Jump List timestamp, ActivitiesCache.db | Bab 5 §5.3, §5.5; Bab 6 §6.2.4 |

> 💡 **Kenapa perlu dipetakan dulu:** Tiap kategori punya "jam" sendiri dengan epoch & timezone berbeda (lihat §9.2.1). Menggabungkan langsung tanpa normalisasi adalah penyebab #1 timeline yang salah kesimpulan.

---

#### 9.1.3 MACB / MACE Notation & Timestamp Semantics

**Pengertian & Fungsi:**
Notasi ringkas untuk menandai jenis aktivitas apa yang terjadi pada suatu timestamp — dipakai luas di plaso/log2timeline sebagai kolom `timestamp_desc`.

| Notasi | Kepanjangan | Makna di NTFS ($MFT) |
|---|---|---|
| **M** | Modified | Isi/konten file berubah terakhir kali |
| **A** | Accessed | File terakhir dibaca (di NTFS modern sering **disabled by default** sejak Vista+ demi performa — cek `fsutil behavior query disablelastaccess`) |
| **C** | Changed / MFT Entry Modified | Metadata MFT record berubah (rename, permission, dll) — **beda dengan Created** |
| **B** | Birth / Created | Kapan file pertama kali dibuat |

> ⚠️ **Jebakan umum:** Banyak yang salah kira "C" = Created. Di konvensi MACB (dipopulerkan oleh SleuthKit/plaso), **C = Changed** (MFT entry modified), sedangkan Created diwakili **B (Birth)**. Kalau baca tabel/tool yang pakai istilah "MACE" (Modified, Accessed, Created, Entry-modified), urutan hurufnya beda lagi. Selalu cek dokumentasi tool yang dipakai sebelum menyimpulkan dari notasi ini saja.

---

### 9.2 Membangun Super Timeline — Manual

#### 9.2.1 Normalisasi Timezone (UTC vs Local)

**Pengertian & Fungsi:**
Sebelum artefak digabung, semua timestamp harus dikonversi ke **satu timezone yang sama** — konvensi paling umum di DFIR adalah UTC, karena EVTX dan $MFT sendiri sudah disimpan dalam UTC di disk.

| Sumber | Disimpan Sebagai | Perlu Konversi? |
|---|---|---|
| $MFT (SI/FN) | FILETIME (UTC) | Tidak — tapi tool GUI kadang auto-convert ke local, cek setting |
| EVTX | FILETIME (UTC) | Tidak, tapi **Event Viewer GUI Windows menampilkan dalam local time** — beda dengan CSV mentah dari EvtxECmd |
| Registry LastWrite | FILETIME (UTC) | Tidak |
| Browser History (Chrome) | WebKit timestamp (UTC epoch 1601) | Perlu formula konversi — lihat Bab 6 §6.2.4 |
| Browser History (Firefox) | PRTime (UTC epoch 1970, microsecond) | Perlu konversi — Bab 6 §6.2.4 |
| Prefetch | FILETIME (UTC) | Tidak |

```bash
# Cek timezone sistem korban dari registry (SYSTEM hive) — WAJIB sebelum menyimpulkan "local time" pelaku
# Key: SYSTEM\CurrentControlSet\Control\TimeZoneInformation
.\RECmd.exe -f SYSTEM --sk "TimeZoneInformation" --recover false
```

> ⚠️ **Kesalahan fatal yang sering terjadi di CTF:** Menyimpulkan "attacker beraksi jam 2 pagi (mencurigakan)" padahal itu cuma efek belum dikonversi ke timezone lokal korban. **Selalu cek `TimeZoneInformation` dari SYSTEM hive dulu** (Bab 3 §3.3.4) sebelum menuliskan kesimpulan waktu apapun di laporan.

---

#### 9.2.2 Menggabungkan CSV Multi-Artefak di Timeline Explorer

Langkah generiknya sama seperti workflow di **Lampiran Bab 1**, hanya di sini beberapa CSV digabung sekaligus jadi satu file untuk dianalisis lintas-artefak, bukan satu-satu per bab.

```bash
# 1. Export semua CSV hasil parsing per-artefak ke satu folder
#    (hasil MFTECmd, EvtxECmd, PECmd, RECmd, LECmd, dst — lihat Lampiran Bab 1)
evidence\
├── mft.csv
├── evtx_all.csv
├── prefetch.csv
├── registry_run.csv
└── lnk.csv

# 2. Buka Timeline Explorer > File > Open > pilih SEMUA csv sekaligus (multi-select)
#    Timeline Explorer otomatis mendeteksi kolom timestamp tiap tool Eric Zimmerman
#    dan menggabungkannya jadi satu grid ter-sort berdasarkan waktu

# 3. Gunakan kolom "Source" / "SourceFile" bawaan untuk tetap tahu artefak asal tiap baris
```

> 💡 **Tip:** Timeline Explorer punya fitur **Tag** (klik kanan baris → Tag) untuk menandai baris yang relevan dengan investigasi — sangat membantu saat harus bolak-balik antar ribuan baris, dan tag ini bisa di-export terpisah untuk lampiran laporan.

---

#### 9.2.3 Tagging & Filtering Strategy

| Strategi | Kapan Dipakai |
|---|---|
| **Filter by time window** | Kalau sudah tahu perkiraan waktu insiden (dari EVTX 4625 gagal login beruntun, misal), persempit dulu ke window ±1 jam sebelum baca detail |
| **Filter by keyword** | Cari nama proses/file mencurigakan yang sudah diketahui dari static analysis (Bab 8) di semua kolom sekaligus |
| **Group by Source** | Kalau ingin lihat pola per-jenis-artefak dulu (misal semua Prefetch dulu, baru EVTX) sebelum full timeline |
| **Sort ascending dari titik nol** | Setelah window ditemukan, sort ascending dari event pertama yang mencurigakan untuk lihat urutan sebab-akibat |

> 📌 **Prinsip:** Jangan langsung scroll dari baris pertama di super timeline yang berisi puluhan ribu baris — selalu **persempit window waktu dulu** dari satu artefak "anchor" yang paling jelas (biasanya EVTX auth atau Prefetch eksekusi malware), baru perluas ke kiri/kanan untuk lihat konteks sebelum-sesudahnya.

---

### 9.3 Membangun Super Timeline — plaso / log2timeline

#### 9.3.1 Instalasi & Arsitektur plaso

**Pengertian & Fungsi:**
`plaso` (Plaso Langar Að Safna Öllu — "plaso" berarti "banyak" dalam bahasa Islandia) adalah framework untuk membuat **super timeline** otomatis dari sebuah disk image, dengan ratusan parser bawaan untuk hampir semua artefak yang sudah dibahas Bab 1-6 sekaligus. Berbeda dengan workflow manual (§9.2) yang butuh export-parse-gabung satu-satu, plaso melakukan semuanya dalam satu proses.

```
Disk Image / Mounted Volume
        │
        ▼
  log2timeline.py          ← menjalankan ratusan parser paralel, hasil disimpan ke storage file (.plaso)
        │
        ▼
   storage file (.plaso)   ← format internal, belum manusiawi dibaca
        │
        ▼
      psort.py             ← filter, sortir, convert ke output CSV/JSON/lain
        │
        ▼
   super_timeline.csv
```

```bash
# Instalasi (Linux/WSL, paling stabil)
pip install plaso

# Atau via package manager (Ubuntu/Debian)
sudo add-apt-repository ppa:gift/stable
sudo apt update && sudo apt install plaso-tools
```

> 💡 **Kenapa plaso beda dengan Eric Zimmerman Tools:** ZimmerTools (MFTECmd, EvtxECmd, dst) dirancang **satu tool per satu jenis artefak**, dengan kontrol detail per kolom. plaso dirancang untuk **skala** — parsing seluruh image sekaligus tanpa perlu tahu artefak mana yang ada di dalamnya, cocok untuk triase awal kasus besar sebelum masuk ke analisa detail per-artefak dengan tool ZimmerTools.

---

#### 9.3.2 Menjalankan log2timeline.py terhadap Disk Image

```bash
# Jalankan terhadap image langsung (E01/dd/raw) tanpa perlu mount manual
log2timeline.py --storage-file case.plaso /path/to/image.E01

# Terhadap direktori yang sudah di-mount/extract
log2timeline.py --storage-file case.plaso /mnt/evidence/

# Dengan multiprocessing eksplisit untuk image besar (default sudah auto-detect core CPU)
log2timeline.py --storage-file case.plaso --workers 8 /path/to/image.E01
```

> ⚠️ **Estimasi waktu:** Untuk image ukuran puluhan-ratusan GB, proses ini bisa berjalan berjam-jam karena scan hampir seluruh filesystem. Untuk CTF dengan image kecil (beberapa GB), biasanya selesai dalam belasan menit. Jalankan di background/screen session kalau image besar.

---

#### 9.3.3 psort.py — Filtering, Output Format, Time Slicing

```bash
# Convert storage file ke CSV, format kolom standar (L2T CSV)
psort.py -o l2tcsv -w super_timeline.csv case.plaso

# Filter berdasarkan rentang waktu tertentu (date filter)
psort.py -o l2tcsv -w filtered.csv case.plaso \
  "date > '2024-01-15 00:00:00' AND date < '2024-01-16 00:00:00'"

# Output ke format lain (JSON, untuk diproses lanjut dengan Python/pandas — lihat §9.4)
psort.py -o json_line -w timeline.jsonl case.plaso

# Filter hanya source tertentu (misal cuma WinEVTX + Prefetch, skip browser)
psort.py -o l2tcsv -w focused.csv case.plaso "source_short in ('EVT', 'PREFETCH')"
```

> 💡 **Kolom penting output L2T CSV:** `date`, `time`, `timezone`, `source` (kategori singkat), `source_long` (nama parser lengkap), `timestamp_desc` (notasi MACB, lihat §9.1.3), `message` (deskripsi human-readable event).

---

#### 9.3.4 Parser Selection

Secara default `log2timeline.py` mencoba semua parser (`winreg`, `winevtx`, `mft`, `chrome_history`, `firefox_history`, `prefetch`, `lnk`, dll) — untuk kasus fokus, batasi supaya lebih cepat & output lebih bersih.

```bash
# List semua parser preset yang tersedia
log2timeline.py --parsers list

# Hanya parser terkait filesystem + registry (skip browser & aplikasi lain)
log2timeline.py --parsers "winreg,mft,prefetch,winevtx" --storage-file focused.plaso /path/to/image.E01

# Preset bawaan yang sudah dikurasi (contoh: khusus win7/win10 artifact set)
log2timeline.py --parsers win10 --storage-file case.plaso /path/to/image.E01
```

---

#### 9.3.5 plaso vs Manual — Kapan Pakai Mana

| Situasi | Rekomendasi |
|---|---|
| Image besar, belum tahu artefak mana yang relevan (triase awal) | **plaso** — dapat gambaran menyeluruh cepat |
| Sudah tahu persis artefak target (misal cuma butuh Prefetch + EVTX 4688) | **Manual (ZimmerTools + Timeline Explorer)** — lebih cepat & kontrol kolom lebih detail |
| Butuh detail spesifik per-kolom (SI vs FN terpisah, raw hex offset) | **Manual** — plaso merangkum jadi satu `message` string, detail kolom mentah kadang hilang |
| Butuh korelasi custom / logic kompleks (join multi-kondisi) | **Python/Pandas** (§9.4), bisa pakai output CSV dari plaso ATAU manual sebagai input |
| CTF dengan time constraint ketat & image kecil | **Manual** biasanya lebih cepat untuk kasus scoped, plaso lebih worth it untuk kasus luas |

---

### 9.4 Custom Timeline Correlation — Python/Pandas

#### 9.4.1 Kenapa Butuh Scripting

Timeline Explorer dan plaso sudah cukup untuk sebagian besar kasus, tapi ada situasi di mana logic korelasi terlalu spesifik untuk dilakukan lewat filter/sort GUI biasa:

- Join dua artefak berdasarkan **kesamaan nama proses DAN window waktu** (bukan exact match timestamp) — misal cocokkan Prefetch run time dengan EVTX 4688 dalam toleransi ±2 detik.
- Deteksi anomali berbasis **statistik** (lihat §9.4.4, §9.9.2) yang butuh perhitungan, bukan filter manual.
- Multi-host correlation (lateral movement antar beberapa mesin, gabung timeline dari image berbeda).

#### 9.4.2 Load & Normalize Multi-CSV

```python
import pandas as pd

# Load beberapa CSV hasil tool berbeda
mft = pd.read_csv("mft.csv")
evtx = pd.read_csv("evtx_all.csv")
prefetch = pd.read_csv("prefetch.csv")

# Normalisasi nama kolom timestamp (tiap tool ZimmerTools beda nama kolom)
mft = mft.rename(columns={"Created0x10": "timestamp"})
evtx = evtx.rename(columns={"TimeCreated": "timestamp"})
prefetch = prefetch.rename(columns={"LastRun": "timestamp"})

# Parse jadi datetime UTC-aware, penting supaya bisa dibandingkan lintas-source
for df in (mft, evtx, prefetch):
    df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True, errors="coerce")

# Tandai sumber sebelum digabung, supaya tetap bisa dilacak balik
mft["source"] = "MFT"
evtx["source"] = "EVTX"
prefetch["source"] = "Prefetch"
```

#### 9.4.3 Join/Merge Strategy Antar Artefak

```python
# Contoh: cocokkan eksekusi Prefetch dengan Process Creation EVTX (4688)
# berdasarkan nama proses yang sama DAN dalam toleransi waktu 5 detik

evtx_4688 = evtx[evtx["EventId"] == 4688].copy()

# merge_asof cocok untuk "nearest timestamp match" — lebih tepat daripada exact merge
prefetch_sorted = prefetch.sort_values("timestamp")
evtx_sorted = evtx_4688.sort_values("timestamp")

correlated = pd.merge_asof(
    prefetch_sorted, evtx_sorted,
    on="timestamp", by="ProcessName",           # asumsikan kolom nama proses sudah dinormalisasi sama
    tolerance=pd.Timedelta("5s"),
    direction="nearest",
    suffixes=("_prefetch", "_evtx")
)

# Baris yang match di kedua sumber = evidence of execution paling kuat (dua artefak independen setuju)
strong_evidence = correlated.dropna(subset=["EventId"])
```

> 💡 **Kenapa `merge_asof`, bukan `merge` biasa:** Timestamp antar-artefak nyaris tidak pernah sama persis ke milidetik — proses tercatat di EVTX beberapa milidetik/detik berbeda dengan waktu Prefetch update. `merge_asof` dengan `tolerance` menghindari false negative karena mismatch presisi timestamp yang sebenarnya wajar.

#### 9.4.4 Deteksi Anomali Otomatis

```python
# Contoh 1: cari event di luar jam kerja (misal di luar 08:00-18:00 waktu lokal korban)
correlated["hour"] = correlated["timestamp"].dt.tz_convert("Asia/Jakarta").dt.hour
after_hours = correlated[(correlated["hour"] < 8) | (correlated["hour"] > 18)]

# Contoh 2: hitung gap waktu antar event berurutan — dipakai lebih lanjut di §9.9.2
combined_sorted = pd.concat([mft, evtx, prefetch]).sort_values("timestamp")
combined_sorted["gap_seconds"] = combined_sorted["timestamp"].diff().dt.total_seconds()

# Flag gap yang jauh di atas rata-rata (indikasi periode "sepi" mencurigakan)
threshold = combined_sorted["gap_seconds"].mean() + 3 * combined_sorted["gap_seconds"].std()
suspicious_gaps = combined_sorted[combined_sorted["gap_seconds"] > threshold]
```

> ⚠️ **Tip CTF:** Script seperti ini paling berguna kalau soal menyediakan **banyak sekali** CSV/log dan minta "temukan aktivitas mencurigakan" tanpa petunjuk waktu spesifik — daripada scroll manual ribuan baris, deteksi statistik seperti di atas bisa langsung mempersempit ke kandidat paling mungkin dalam hitungan detik.

---

### 9.5 Metodologi Korelasi Lintas-Artefak

#### 9.5.1 Root Cause → Timeline Reconstruction Workflow

```
1. Identifikasi Anchor Point
   (Event paling jelas: alert AV, EVTX 4625 beruntun, laporan user, dsb)
        │
        ▼
2. Persempit Time Window
   (±beberapa jam dari anchor point, lihat §9.2.3)
        │
        ▼
3. Kumpulkan Artefak Relevan di Window Itu
   (Prefetch, EVTX, Registry Run keys, LNK, browser history — sesuai konteks)
        │
        ▼
4. Bangun Timeline Gabungan (manual/plaso/pandas — §9.2-9.4)
        │
        ▼
5. Validasi Silang Tiap Klaim dengan ≥2 Artefak Independen
   (lihat §9.5.2 — jangan simpulkan dari 1 artefak saja)
        │
        ▼
6. Perluas Window ke Belakang (cari Root Cause / initial access)
   dan ke Depan (cari dampak/lateral movement/exfiltration)
        │
        ▼
7. Dokumentasikan sebagai Narrative Timeline
   (bukan cuma tabel — susun jadi cerita sebab-akibat yang bisa dipresentasikan)
```

#### 9.5.2 Evidence of Existence vs Evidence of Execution

Konsep ini sudah dibahas dari sisi registry di **Bab 3 §3.11** — di sini diperluas jadi prinsip lintas-artefak untuk timeline correlation.

| Kategori | Artinya | Artefak Pendukung |
|---|---|---|
| **Evidence of Existence** | File PERNAH ADA di sistem, tapi belum tentu dijalankan | $MFT, LNK (kalau cuma dibuat via Explorer autopreview), Recycle Bin, browser download record |
| **Evidence of Execution** | File TERBUKTI DIJALANKAN sebagai proses | Prefetch, Amcache, ShimCache (dengan catatan, Bab 3 §3.4.3), EVTX 4688/Sysmon 1, UserAssist |

> ⚠️ **Kesalahan umum dalam kesimpulan:** Menemukan file di `$MFT` atau Recycle Bin **tidak otomatis berarti file itu dijalankan**. Untuk klaim "malware ini dieksekusi", timeline harus menunjukkan minimal satu artefak dari kolom Evidence of Execution di window waktu yang sama — bukan cuma Evidence of Existence.

#### 9.5.3 Studi Kasus Pola Korelasi — USB Insert → LNK → Prefetch → EVTX

Contoh rantai korelasi klasik yang menggabungkan 4 artefak dari 3 bab berbeda, semua harus konsisten satu sama lain:

```
[1] USB Dicolok
    Registry: SYSTEM\CurrentControlSet\Enum\USBSTOR (Bab 3 §3.3.3)
    → catat FirstInsert / LastConnected time

[2] File Dibuka dari USB
    LNK file di Recent\ (Bab 5 §5.3) → TrackerDataBlock (§5.3.4) berisi
    Volume Serial Number yang HARUS cocok dengan volume serial USB tsb (Bab 1 §1.1.7)

[3] File Dieksekusi
    Prefetch (Bab 4 §4.13) → cek path argumen kalau ada, dan LastRun time
    HARUS sesudah [2] dan konsisten dengan waktu USB masih tercolok dari [1]

[4] Konfirmasi Independen
    EVTX 4688 / Sysmon Event ID 1 (Bab 4 §4.3.4, §4.6.1) → CommandLine & ParentImage
    HARUS match nama proses yang sama dari [3]
```

> 💡 **Kenapa pola ini kuat secara forensik:** Empat artefak ini berasal dari empat subsistem Windows yang sepenuhnya independen (registry USB enumeration, Explorer shell, prefetcher, event logging). Attacker yang mau memalsukan cerita ini harus memanipulasi keempatnya secara konsisten — jauh lebih sulit daripada memalsukan satu artefak saja.

---

### 9.6 Anti-Forensics — Timestamp & Metadata Manipulation

> 📖 **Dasar deteksi SI vs FN mismatch sudah dibahas lengkap di Bab 2 §2.1.3** — tidak diulang di sini. Bagian ini fokus ke tool-level yang dipakai attacker yang **sudah tahu** soal SI-FN mismatch, dan cara mendeteksi upaya mereka membohongi cross-check itu juga.

#### 9.6.1 Timestomping Lanjutan — Tools & Bypass SI-FN Check

| Tool | Cara Kerja | Kelemahan yang Bisa Dideteksi |
|---|---|---|
| **Timestomp.exe** (Metasploit) | Modifikasi langsung SI timestamp via NTFS API | Hanya ubah SI, FN tetap asli → mismatch klasik (Bab 2 §2.1.3) |
| **PowerShell `Set-ItemProperty`** | `(Get-Item file).LastWriteTime = "tanggal"` — pakai .NET API standar | Sama seperti di atas, hanya ubah SI; command-nya sendiri bisa tercatat di PSReadLine history (Bab 1 §1.2.14) atau Script Block Logging (Bab 4 §4.5.3) |
| **SetMace** | Tool khusus yang **bisa** menulis ulang SI **dan** FN sekaligus dengan nilai custom | SI-FN match sempurna → §9.6.2 (4-way cross-check) jadi satu-satunya cara deteksi realistis |
| **Nirsoft AttributeChanger / BulkFileChanger** | GUI, mirip Set-ItemProperty, biasanya hanya SI | Sama seperti PowerShell method |

```bash
# Contoh command Timestomp.exe (Metasploit) — konteks edukasi/deteksi, bukan panduan penyerangan
timestomp.exe evil.exe -z "01/01/2020 00:00:00"

# Contoh PowerShell timestomping sederhana
(Get-Item "C:\Windows\Temp\evil.exe").CreationTime = "01/01/2020 00:00:00"
(Get-Item "C:\Windows\Temp\evil.exe").LastWriteTime = "01/01/2020 00:00:00"
```

> ⚠️ **Tip CTF:** Kalau SI dan FN **sama-sama** menunjukkan tanggal tua tapi mencurigakan (misal file "system" dengan Created date sebelum Windows itu sendiri di-install — cek `$Volume`/instalasi OS date), itu tanda kuat **SetMace atau tool setara** dipakai, bukan Timestomp.exe biasa. Jangan berhenti di SI-FN check, lanjut ke §9.6.2.

---

#### 9.6.2 SI vs FN vs $LogFile vs $UsnJrnl — 4-Way Cross-Check

Ketika SI dan FN sudah sama-sama dipalsukan (via SetMace atau setara), satu-satunya jejak yang tersisa adalah **journal transaksi** — karena journal mencatat kapan transaksi *benar-benar terjadi secara fisik*, bukan nilai timestamp yang attacker inginkan.

```
Empat sumber independen untuk satu file:
┌─────────────────────┬──────────────────────────────────────┐
│ $STANDARD_INFORMATION │ Bisa dipalsukan (Timestomp/PS/SetMace) │
│ $FILE_NAME             │ Bisa dipalsukan JUGA (SetMace saja)    │
│ $LogFile                │ Journal transaksi — mencatat WAKTU ASLI operasi (create/write/rename) terjadi │
│ $UsnJrnl                 │ Change journal — mencatat sequence USN & timestamp asli tiap perubahan │
└─────────────────────┴──────────────────────────────────────┘
```

```bash
# Ekstrak & parse $LogFile — cari entry terkait file target berdasarkan MFT record number
.\LogFileParser.exe -f "$LogFile" --csv .

# Parse $UsnJrnl, cari semua perubahan untuk file target (by name atau by MFT entry)
.\MFTECmd.exe -f "$Extend\$UsnJrnl:$J" --csv . --json .

# Cross-reference: cari baris di $LogFile / $UsnJrnl dengan timestamp
# yang TIDAK cocok dengan SI/FN file tsb → itu bukti kuat manipulasi
```

| Skenario | Kesimpulan |
|---|---|
| SI ≠ FN | Timestomp sederhana (SI-only tool) |
| SI = FN, tapi $LogFile/$UsnJrnl catat waktu berbeda | SetMace / tool setara (SI+FN bersamaan) |
| SI = FN = $LogFile = $UsnJrnl, semua konsisten | Kemungkinan besar timestamp memang asli — atau **journal itu sendiri sudah dimanipulasi** (lihat §9.7.2-9.7.3) |
| $LogFile/$UsnJrnl tidak ada entry sama sekali untuk file yang "seharusnya" baru dibuat | Journal di-disable/di-truncate sebelum file dibuat — red flag besar, lihat §9.7.3 |

> 💡 **Ini adalah level anti-forensik detection paling tinggi yang dibahas di cheatsheet ini.** Kalau keempat sumber konsisten, kemungkinan besar attacker tidak (atau belum mampu) memanipulasi journal — kasus seperti ini jarang di CTF karena butuh akses low-level ke NTFS internals, tapi konsepnya penting dipahami untuk kasus real-world advanced.

---

### 9.7 Anti-Forensics — Filesystem & Journal Level

#### 9.7.1 MFT Record Wiping/Manipulation

**Pengertian & Fungsi:**
Alih-alih memalsukan timestamp, teknik ini menghapus/mengosongkan MFT record milik file secara langsung — lebih ekstrem daripada timestomping karena berpotensi menghilangkan jejak keberadaan file sepenuhnya dari `$MFT` normal.

| Teknik | Efek | Deteksi |
|---|---|---|
| Overwrite MFT record dengan nol | Record kosong, `InUse` flag hilang | Cek $LogFile untuk transaksi terkait MFT record number tsb — masih tercatat walau record-nya sendiri sudah kosong |
| Marking record sebagai "not in use" tanpa hapus data | File "hilang" dari listing normal tapi data masih ada | Carving `FILE0` signature di raw MFT (Bab 2 §2.2.9) — masih bisa ditemukan walau flag InUse = False |
| Rename ke nama tidak mencurigakan + pindah lokasi | Bukan wiping, tapi menyamarkan | Cross-check $UsnJrnl untuk history rename (USN reason: `RENAME_OLD_NAME`/`RENAME_NEW_NAME`) |

```bash
# Cek record yang statusnya "not in use" tapi datanya masih utuh (kandidat wiping/deletion)
.\MFTECmd.exe -f "$MFT" --csv . --fl
# lalu filter InUse == False di Timeline Explorer, cross-check dengan $LogFile
# untuk history perubahan record number yang sama (lihat Bab 2 §2.2.9)
```

---

#### 9.7.2 $LogFile Manipulation & Journal Gaps

$LogFile adalah journal **transaksi undo/redo** NTFS dengan kapasitas terbatas (biasanya beberapa puluh MB) dan bersifat **circular** — entry lama otomatis tertimpa entry baru seiring waktu. Attacker level lanjut bisa memicu banyak aktivitas disk "sampah" sengaja untuk mempercepat overwrite bagian journal yang mengandung jejak mereka.

```bash
# Parse $LogFile penuh untuk lihat rentang waktu yang tercakup
.\LogFileParser.exe -f "$LogFile" --csv . --dumpTransactions

# Cek apakah ada GAP waktu di dalam $LogFile yang tidak wajar
# (window waktu tertentu tidak punya transaksi sama sekali, padahal sistem aktif)
```

> ⚠️ **Batasan penting:** Karena sifatnya circular dan kapasitas kecil, **$LogFile secara alami hanya mencakup rentang waktu terbatas** (bisa cuma beberapa jam-hari tergantung aktivitas disk) — jangan langsung simpulkan "journal dimanipulasi" hanya karena kejadian lama tidak tercatat di $LogFile. Bandingkan dulu rentang waktu $LogFile yang tersisa dengan rentang waktu insiden yang dicurigai.

---

#### 9.7.3 $UsnJrnl Truncation/Disable

Berbeda dengan $LogFile, `$UsnJrnl` bisa **dinonaktifkan atau dihapus secara eksplisit** oleh siapapun dengan privilege admin — dan ini pola anti-forensik yang jauh lebih jelas niatnya dibanding sekadar menunggu circular overwrite.

```bash
# Command yang attacker pakai untuk menghapus/reset UsnJrnl
fsutil usn deletejournal /D C:

# Cek status UsnJrnl di live system
fsutil usn queryjournal C:
```

| Indikator | Makna |
|---|---|
| `$UsnJrnl` tidak ada sama sekali di image | Journal pernah dihapus (`fsutil usn deletejournal`), atau memang tidak pernah diaktifkan (jarang di Windows modern, USN journal aktif by default) |
| USN sequence number ada gap besar tidak wajar | Journal sempat dihapus lalu otomatis dibuat ulang oleh sistem — cek command line `fsutil usn deletejournal` di EVTX 4688/Sysmon 1 di sekitar waktu gap |
| Journal ada, tapi cakupan waktu terlalu pendek dibanding umur sistem | Kemungkinan journal baru saja di-reset |

> 💡 **Cross-reference paling kuat:** Command `fsutil usn deletejournal` sendiri akan tercatat di EVTX 4688 (Bab 4 §4.3.4) atau Sysmon Event ID 1 (Bab 4 §4.6.1) — kalau ditemukan command ini di CommandLine sekitar waktu gap USN journal, itu konfirmasi definitif journal sengaja dihapus, bukan sekadar retensi normal.

---

### 9.8 Anti-Forensics — Data & Log Destruction Tools

#### 9.8.1 Secure Deletion Tools (SDelete, CCleaner, Eraser)

**Pengertian & Fungsi:**
Berbeda dengan delete biasa (yang hanya menandai cluster "kosong" di `$Bitmap`, data fisik masih ada — lihat Bab 1 §1.1.11), secure deletion tool menimpa (overwrite) data fisik berkali-kali supaya tidak bisa di-carve/recovery.

| Tool | Ciri Khas | Jejak Eksekusi yang Tersisa |
|---|---|---|
| **SDelete** (Sysinternals) | Overwrite pattern (biasanya 0x00, 0xFF, random pass berulang) sebelum delete | Prefetch/Amcache untuk `sdelete.exe`/`sdelete64.exe` (Bab 3 §3.8, Bab 4 §4.13); EULA acceptance key di registry `HKCU\Software\Sysinternals\SDelete` |
| **CCleaner** | Wiping free space + clear browser/log artifacts massal | Registry Run history, Prefetch untuk `CCleaner64.exe`; config file `winapp2.ini` menunjukkan target apa saja yang di-clean |
| **Eraser** | Scheduler-based wiping, bisa dijadwalkan jauh-jauh hari | Scheduled Task terkait (Bab 8 §8.9.1), Prefetch untuk `Eraser.exe` |

```bash
# Contoh command SDelete yang sering dipakai attacker
sdelete64.exe -p 3 -s -z C:\Users\victim\Downloads\evil.exe

# Cari jejak eksekusi tool wiping dari Amcache (evidence of execution walau file sudah hilang)
.\AmcacheParser.exe -f Amcache.hve --csv . -i
# lalu filter nama file mengandung "sdelete", "ccleaner", "eraser", "bcwipe", dll
```

> 💡 **Ironi klasik yang jadi tip CTF:** Tool anti-forensik **itu sendiri** meninggalkan jejak eksekusi (Prefetch, Amcache, ShimCache — Bab 3-4) selama tool tersebut dijalankan sebagai proses biasa. Bahkan kalau attacker berhasil hapus data target, keberadaan **tool wiping-nya sendiri** biasanya masih terdeteksi — cukup untuk membuktikan **niat** anti-forensik walau data aslinya sudah hilang permanen.

---

#### 9.8.2 USB/Removable Media Wiping

Serupa dengan §9.8.1 tapi target khusus removable media — sering dipakai insider threat untuk menghilangkan jejak exfiltrasi data ke USB sebelum dikembalikan/dibuang.

| Indikator | Cek Di |
|---|---|
| USB history ada di registry (pernah dicolok) tapi filesystem-nya "bersih total" | Bab 3 §3.3.3 (USBSTOR) vs isi aktual kalau USB masih ada untuk diperiksa |
| LNK/Jump List menunjuk ke file di drive letter yang cocok dengan USB tsb, tapi file sudah tidak ada di manapun | Bab 5 §5.3.4 (TrackerDataBlock — Volume Serial Number matching) |
| Recycle Bin kosong padahal LNK/Jump List menunjukkan aktivitas file baru-baru ini | Kombinasi Bab 5 §5.2 + §5.3 — kemungkinan Shift+Delete atau secure wipe, bukan delete biasa ke Recycle Bin |

---

#### 9.8.3 Anti-Forensic Tool Execution Evidence

Ringkasan terpadu: setiap teknik anti-forensik di §9.6-9.8 punya satu kelemahan sama — **eksekusi tool anti-forensik itu sendiri adalah sebuah proses**, dan proses selalu meninggalkan jejak evidence of execution (§9.5.2) di lapisan yang **berbeda** dari apa yang coba dihapus attacker.

```
Attacker hapus/timestomp FILE X
        │
        ▼
Tapi PROSES yang melakukannya (sdelete.exe/timestomp.exe/fsutil.exe) tercatat di:
├── Prefetch (Bab 4 §4.13)
├── Amcache / ShimCache (Bab 3 §3.4.3, §3.8)
├── EVTX 4688 / Sysmon Event ID 1, dengan CommandLine lengkap (Bab 4 §4.3.4, §4.6.1)
├── UserAssist kalau dijalankan via GUI double-click (Bab 3 §3.6.1)
└── PSReadLine history kalau dijalankan lewat PowerShell (Bab 1 §1.2.14)
```

> 📌 **Prinsip penutup anti-forensik:** Semakin canggih teknik anti-forensik yang dipakai (§9.6-9.8), semakin besar kemungkinan attacker meninggalkan jejak proses eksekusi tool itu sendiri di lapisan yang tidak mereka sadari perlu dibersihkan juga. Investigator yang baik selalu bertanya "tool apa yang dipakai untuk melakukan ini, dan di mana jejak eksekusi tool itu tersimpan?" — bukan cuma fokus ke artefak yang hilang.

---

### 9.9 Mendeteksi Timeline Gap (Missing Evidence)

#### 9.9.1 Konsep "Absence of Evidence is Evidence"

**Pengertian & Fungsi:**
Dalam DFIR, ketiadaan artefak yang **seharusnya ada** justru bisa jadi indikator kuat anti-forensik — berbeda dengan asumsi awam "tidak ada bukti = tidak terjadi apa-apa". Prinsip ini menyatukan semua teknik deteksi §9.6-9.8 jadi satu metodologi sistematis.

> ⚠️ **Bukan berarti semua kekosongan mencurigakan:** Retensi log yang wajar (Bab 4 §4.1.5), circular $LogFile (§9.7.2), atau Prefetch yang memang didisable dari awal instalasi (Bab 4 §4.13.7) adalah kekosongan **normal**. Yang dicari di sini adalah kekosongan yang **tidak konsisten dengan baseline sistem** atau **tidak konsisten dengan artefak lain di sekitarnya**.

---

#### 9.9.2 Statistical Gap Detection

Pendekatan terprogram untuk menemukan window waktu "sepi" yang tidak wajar dalam super timeline — dibangun di atas teknik yang sama seperti §9.4.4.

```python
import pandas as pd

# Asumsi: df super timeline sudah digabung & di-sort (lihat §9.4.2-9.4.4)
df = df.sort_values("timestamp")
df["gap"] = df["timestamp"].diff().dt.total_seconds()

# Baseline: rata-rata & std dev gap waktu antar event di seluruh timeline
mean_gap = df["gap"].mean()
std_gap = df["gap"].std()

# Threshold statistik (contoh: 3 standar deviasi di atas rata-rata)
threshold = mean_gap + 3 * std_gap
gaps = df[df["gap"] > threshold][["timestamp", "gap", "source"]]

print(gaps)
# Cross-check manual: apakah window "sepi" ini bertepatan dengan
# waktu eksekusi tool anti-forensik (§9.8) atau reboot/shutdown wajar (Bab 4 §4.4.2)?
```

> 💡 **False positive yang wajar:** Gap besar sering juga terjadi karena sistem **memang mati/sleep** (bandingkan dengan EVTX 6006/6008 shutdown, Bab 4 §4.4.2) — selalu cross-check dulu ke log startup/shutdown sebelum menyimpulkan gap adalah hasil anti-forensik.

---

#### 9.9.3 Correlation Matrix — Artefak yang Seharusnya Ada

Teknik manual paling praktis untuk kasus CTF/HTB: buat tabel silang "kejadian apa yang seharusnya menghasilkan artefak apa", lalu tandai mana yang hilang.

| Kejadian yang Dicurigai | Artefak yang SEHARUSNYA Ada | Ditemukan? | Kesimpulan |
|---|---|---|---|
| Malware `evil.exe` dieksekusi | Prefetch, Amcache, EVTX 4688 | Amcache ✅, Prefetch ❌, EVTX ❌ | Prefetch mungkin didisable/dihapus manual — cek §9.9.1; Amcache jauh lebih sulit dihapus (butuh restart untuk update, Bab 3 §3.8) makanya sering jadi satu-satunya sisa |
| USB dicolok & file di-copy keluar | Registry USBSTOR, LNK/Jump List, $MFT entry baru | USBSTOR ✅, LNK ❌, $MFT ❌ | File mungkin di-secure-delete (§9.8.1) setelah copy, tapi USB history di registry sulit dihapus tanpa root-level access |
| Ransomware enkripsi masal file | $LogFile/$UsnJrnl banyak entry MODIFIED, VSS terhapus | $UsnJrnl ✅ (banyak modify), VSS ❌ | Konsisten dengan pola ransomware klasik — VSS deletion (Bab 5 §5.1.8) untuk cegah recovery |

> 📌 **Kegunaan tabel ini di laporan:** Selain jadi alat analisa, tabel korelasi seperti ini juga bagus dipakai **langsung sebagai bagian laporan forensik** — auditor/klien bisa langsung lihat bukti apa yang ada, apa yang hilang, dan kenapa itu penting, tanpa harus paham detail teknis tiap artefak.

---

#### 9.9.4 VSS/Backup sebagai Cross-Validation Gap

Kalau artefak "live" (disk saat ini) menunjukkan kekosongan mencurigakan, **VSS/shadow copy** (Bab 5 §5.1) adalah sumber cross-validation independen paling kuat — karena snapshot lama tidak terpengaruh anti-forensik yang dilakukan attacker setelah snapshot dibuat.

```bash
# Enumerasi shadow copy yang tersedia (lihat detail penuh di Bab 5 §5.1.4)
vssadmin list shadows

# Kalau artefak X hilang/dimanipulasi di disk sekarang,
# cek versi X di snapshot VSS sebelum tanggal insiden
# → bandingkan isi/timestamp versi lama vs sekarang (diffing, Bab 5 §5.1.6)
```

> 💡 **Kenapa ini penutup yang tepat untuk Bab 9:** Kalau attacker berhasil memanipulasi SEMUA lapisan (timestamp, MFT, journal, bahkan menghapus tool eksekusinya sendiri), **VSS yang dibuat SEBELUM insiden** tetap menyimpan kondisi asli — asalkan attacker belum sempat/tidak tahu untuk menghapus VSS juga (§5.1.8). Ini alasan kenapa `vssadmin delete shadows` adalah salah satu command anti-forensik paling "bernilai tinggi" bagi attacker yang paham forensik, dan kenapa investigator harus selalu cek VSS di awal, bukan di akhir, investigasi.

---

### 9.10 Timestamp Normalization — Referensi Master

> 💡 **Kenapa ini butuh section sendiri:** §9.2.1 sudah menyinggung normalisasi timezone secara konseptual per-artefak. Bagian ini adalah **referensi lengkap** yang dikumpulkan jadi satu tempat — semua epoch, semua formula konversi, dan jebakan presisi yang sering bikin korelasi meleset walau timezone-nya sudah benar. Dipakai sebagai lookup table saat kerja, bukan dibaca linear.

#### 9.10.1 Tabel Epoch & Formula Konversi Lengkap

| Format Timestamp | Epoch (Titik Nol) | Satuan | Ditemukan di | Formula ke Unix Epoch (detik) |
|---|---|---|---|---|
| **FILETIME** (Windows native) | 1 Januari 1601 00:00:00 UTC | 100-nanosecond intervals (ticks) | $MFT (SI/FN), EVTX, Registry LastWrite, Prefetch, LNK | `unix_seconds = (filetime / 10_000_000) - 11_644_473_600` |
| **Unix Epoch** | 1 Januari 1970 00:00:00 UTC | detik (kadang milidetik) | Linux artifact, sebagian log aplikasi, Volatility 3 | Sudah Unix — tidak perlu konversi |
| **WebKit / Chrome Time** | 1 Januari 1601 00:00:00 UTC | mikrodetik | Chrome/Edge/Opera History (Bab 6 §6.2.4) | `unix_seconds = (webkit_us / 1_000_000) - 11_644_473_600` |
| **PRTime (Mozilla)** | 1 Januari 1970 00:00:00 UTC | mikrodetik | Firefox `places.sqlite` (Bab 6 §6.2.4) | `unix_seconds = prtime_us / 1_000_000` |
| **DOS Date/Time (16-bit)** | Bergantung field, resolusi 2 detik | struct 2×16-bit | FAT32 legacy, sebagian ZIP metadata | Butuh bit-unpacking manual (year<<9 \| month<<5 \| day, dst) — jarang dipakai untuk NTFS modern |
| **OLE Automation Date** | 30 Desember 1899 | hari (fraksi = waktu) | Beberapa field Office/VBA macro metadata | `unix_seconds = (ole_date - 25569) * 86400` |
| **ICQ/Unix ms** | 1 Januari 1970 UTC | milidetik | Beberapa chat log, ActivitiesCache.db (Bab 5 §5.6) | `unix_seconds = unix_ms / 1000` |
| **Mac Absolute Time** | 1 Januari 2001 00:00:00 UTC | detik | Jarang di Windows DFIR, muncul kalau ada cross-platform artifact (mis. iCloud sync) | `unix_seconds = mac_abs + 978_307_200` |

> ⚠️ **Jebakan paling sering di CTF:** FILETIME dan WebKit Time **sama-sama** pakai epoch 1601, tapi **beda satuan** (100ns ticks vs mikrodetik) — dua kolom yang terlihat mirip besarannya sering ketuker formula konversinya kalau tidak hati-hati cek satuan dulu sebelum hitung.

---

#### 9.10.2 Precision Mismatch Antar Artefak

Setelah epoch & timezone sama-sama benar, jebakan berikutnya adalah **resolusi presisi** yang beda-beda antar sumber — ini penyebab utama `merge_asof` (§9.4.3) butuh `tolerance`, bukan exact match.

| Sumber | Resolusi Asli | Implikasi Korelasi |
|---|---|---|
| $MFT SI/FN | 100ns (FILETIME native) | Presisi tertinggi, tapi timestomp mengubah nilai ini duluan (§9.6) |
| EVTX TimeCreated | Milidetik | Cukup presisi untuk urutan sebab-akibat dalam 1 sistem |
| $UsnJrnl | 100ns tapi sering dibulatkan tool parsing ke detik | Cek dokumentasi tool parser — pembulatan bisa bikin urutan event kelihatan simultan padahal beda |
| Prefetch LastRun | Detik (kadang tanpa sub-second di beberapa versi Windows) | Jangan gunakan sebagai anchor presisi tinggi untuk urutan multi-event dalam window <1 detik |
| FAT32 Created/Modified | Resolusi 2 detik (legacy), Accessed hanya tanggal (tanpa jam) | Kalau ketemu removable media FAT32 lama, jangan harap presisi sub-detik |
| NTP/system clock drift | Bervariasi, bisa >beberapa detik kalau NTP sync gagal/dimatikan attacker | Cek EVTX Time-Service (Bab 4) kalau ada window korelasi yang "hampir cocok" tapi konsisten off by N detik |

> 📌 **Aturan praktis:** Kalau dua event dari sumber berbeda selisih hanya 1-3 detik, itu **kemungkinan besar event yang sama** dilihat dari dua subsistem berbeda (masing-masing subsistem punya latency mencatat sendiri) — bukan dua kejadian terpisah. Jangan simpulkan urutan sebab-akibat yang salah hanya karena selisih sub-detik.

---

#### 9.10.3 Script Python — Universal Timestamp Converter

Helper function untuk dipakai bareng workflow §9.4.2, mengonversi kolom mentah dari berbagai sumber ke satu kolom `timestamp` UTC yang konsisten sebelum digabung.

```python
from datetime import datetime, timedelta, timezone

def filetime_to_unix(filetime: int) -> datetime:
    """Windows FILETIME (100ns ticks sejak 1601-01-01) -> datetime UTC."""
    return datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=filetime / 10)

def webkit_to_unix(webkit_us: int) -> datetime:
    """Chrome/WebKit time (mikrodetik sejak 1601-01-01) -> datetime UTC."""
    return datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=webkit_us)

def prtime_to_unix(prtime_us: int) -> datetime:
    """Firefox PRTime (mikrodetik sejak 1970-01-01) -> datetime UTC."""
    return datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=prtime_us)

def ole_to_unix(ole_date: float) -> datetime:
    """OLE Automation Date (hari sejak 1899-12-30) -> datetime UTC."""
    return datetime(1899, 12, 30, tzinfo=timezone.utc) + timedelta(days=ole_date)

def mac_abs_to_unix(mac_abs: int) -> datetime:
    """Mac Absolute Time (detik sejak 2001-01-01) -> datetime UTC."""
    return datetime(2001, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=mac_abs)

# Dipakai di pipeline §9.4.2 sebelum pd.concat, misal:
# mft["timestamp"] = mft["FiletimeRaw"].apply(filetime_to_unix)
# chrome_hist["timestamp"] = chrome_hist["visit_time"].apply(webkit_to_unix)
```

> 💡 **Kenapa ditulis manual, bukan pakai library konversi generik:** Banyak tool ZimmerTools/plaso sudah otomatis konversi FILETIME→human-readable di kolom output CSV mereka — helper ini paling berguna justru untuk kasus **raw hex/decimal timestamp** yang belum diparse tool apapun (misal ditemukan manual lewat hex editor saat CTF, atau field custom di malware config yang tidak dikenali parser standar).

---

### 9.11 Master Correlation Matrix — Event Type vs Artefak Lintas-Bab

> 📖 **Beda dengan §9.9.3:** §9.9.3 adalah contoh penerapan (3 baris, kasus spesifik). Tabel di bawah ini adalah **referensi lengkap** yang mencakup hampir semua jenis event investigasi umum di DFIR Windows — dipakai sebagai checklist saat menyusun timeline dari nol, supaya tidak ada kategori artefak relevan yang terlewat.

| Jenis Event/Kejadian | Artefak Primer (Evidence of Execution) | Artefak Sekunder (Evidence of Existence/Context) | Bab Rujukan |
|---|---|---|---|
| Eksekusi executable/malware | Prefetch, Amcache, EVTX 4688/Sysmon 1, UserAssist | ShimCache, $MFT (file existence), LNK kalau dijalankan via shortcut | Bab 3, 4, 5 |
| Eksekusi script (PowerShell/VBS/JS) | Script Block Logging (EVTX 4104), PSReadLine history, Sysmon 1 | Prefetch untuk `powershell.exe`/`wscript.exe`, Amcache | Bab 4 §4.5.3, Bab 1 §1.2.14 |
| Login interaktif/RDP | EVTX 4624 (Logon Type 2/10), EVTX 4778/4779 (RDP session) | UserAssist update, ActivitiesCache.db | Bab 3, 4, 5 |
| Login gagal/brute force | EVTX 4625 (beruntun, source IP sama) | — | Bab 4 |
| Persistence dibuat | Registry Run/RunOnce LastWrite, Scheduled Task creation (EVTX 4698), Service install (EVTX 7045) | Amcache untuk binary target persistence | Bab 8 (semua sub-bab) |
| USB dicolok & file diakses | Registry USBSTOR, LNK TrackerDataBlock, $MFT entry file baru | Jump List, Recent folder | Bab 3 §3.3.3, Bab 5 §5.3 |
| Download file dari browser | Browser download history, $MFT Created time file target, Mark-of-the-Web (Zone.Identifier ADS) | Prefetch untuk browser process | Bab 6 §6.3 |
| Eksfiltrasi data keluar | Network artifact (di luar cakupan seri ini — cek firewall/proxy log eksternal), file access timestamp mendekati waktu network activity | $UsnJrnl READ/compression events, arsip (zip/rar) creation | Bab 2, luar-cakupan |
| Ransomware / mass encryption | $UsnJrnl burst MODIFIED events dalam window pendek, VSS deletion command | Ekstensi file berubah massal ($MFT FN rename pattern) | §9.9.3, Bab 5 §5.1.8 |
| Log/jejak dihapus manual | EVTX 1102 (Audit Log Cleared), EVTX 104 (System log cleared) | Gap statistik di super timeline (§9.9.2) | Bab 4 §4.9 |
| Timestomping | SI≠FN atau SI=FN tapi ≠ $LogFile/$UsnJrnl | — | §9.6 |
| Lateral movement | EVTX 4624 Logon Type 3 (network), Sysmon 3 (network connection), PsExec/WMI artifact (EVTX 4688 CommandLine) | Prefetch `psexec.exe`/`wmic.exe` di kedua host | Bab 4, Bab 8 |
| Privilege escalation | EVTX 4672 (special privileges assigned), 4720/4732 (account/group changes) | Registry UAC bypass artifact (Bab 3) | Bab 3, 4 |
| Anti-forensic tool dijalankan | Prefetch/Amcache untuk tool wiping/timestomp, EVTX 4688 CommandLine | Registry key khusus tool (mis. SDelete EULA key) | §9.8.3 |

> ⚠️ **Cara pakai tabel ini:** Saat mulai investigasi jenis event tertentu, cek dulu baris yang cocok — kolom **Artefak Primer** adalah target pencarian utama, kolom **Sekunder** adalah cross-validation kalau primer hilang/dimanipulasi. Kalau primer DAN sekunder sama-sama kosong padahal event seharusnya terjadi, itu sinyal anti-forensik kuat (§9.9.1) — lanjut ke §9.12 untuk menilai seberapa "aneh" kekosongan itu.

---

### 9.12 Evidence Survivability Matrix

**Pengertian & Fungsi:**
Tidak semua artefak sama tahannya terhadap anti-forensik. Matrix ini meranking artefak berdasarkan **seberapa sulit dihapus/dimanipulasi** attacker rata-rata — berguna untuk memprioritaskan artefak mana yang dicek duluan saat waktu investigasi terbatas (khas kondisi CTF timed), dan untuk menjelaskan ke klien/auditor kenapa satu artefak "lebih dipercaya" daripada yang lain dalam laporan.

| Artefak | Survivability | Kenapa | Cara Attacker Menghilangkannya | Rujukan |
|---|---|---|---|---|
| **Amcache.hve** | ⭐⭐⭐⭐⭐ Sangat Tinggi | Update ke hive butuh proses background (`Microsoft Compatibility Appraiser` task) + reboot, sulit di-manipulasi real-time saat eksekusi | Hapus manual file hive (mencurigakan sendiri karena hive sistem hilang), atau matikan scheduled task terkait sebelum eksekusi | Bab 3 §3.8 |
| **$UsnJrnl** | ⭐⭐⭐⭐ Tinggi | Butuh privilege admin eksplisit untuk dihapus, dan aksi hapusnya sendiri (`fsutil usn deletejournal`) biasanya tercatat di EVTX 4688 | `fsutil usn deletejournal /D` — tapi command-nya sendiri jadi jejak (§9.7.3) | §9.7.3 |
| **Registry USBSTOR/Run keys** | ⭐⭐⭐⭐ Tinggi | Tersebar di banyak sub-key, hapus satu key tidak menghapus semua histori (ControlSet backup, RegBack) | Hapus manual key spesifik, tapi shadow/backup registry (Bab 3 §3.1.7) sering masih menyimpan versi lama | Bab 3 |
| **VSS (Volume Shadow Copy)** | ⭐⭐⭐ Sedang | Snapshot otomatis periodik, tapi **satu command** (`vssadmin delete shadows /all`) menghapus semuanya sekaligus | `vssadmin delete shadows /all /quiet` — command tercatat di EVTX 4688 kalau logging aktif | Bab 5 §5.1.8 |
| **EVTX Security/System log** | ⭐⭐⭐ Sedang | Butuh privilege admin, tapi tindakan clear-nya **self-logging** (Event ID 1102 dicatat sebelum log kosong) | `wevtutil cl Security` atau clear via Event Viewer — selalu tinggalkan 1102 sebagai bukti tunggal | Bab 4 §4.9 |
| **$LogFile** | ⭐⭐ Rendah-Sedang | Circular buffer kapasitas kecil, otomatis overwrite alami tanpa perlu aksi attacker eksplisit | Cukup tunggu (biarkan aktivitas disk normal menimpa), tidak perlu tool khusus — sulit dibedakan dari retensi normal | §9.7.2 |
| **Prefetch** | ⭐⭐ Rendah | File individual per-executable, mudah dihapus manual atau lewat disable feature (`fsutil behavior set` /registry) | Hapus file `.pf` langsung dari `C:\Windows\Prefetch\`, atau disable Prefetch sebelum eksekusi | Bab 4 §4.13 |
| **$MFT SI Timestamp** | ⭐ Sangat Rendah | Bisa diubah langsung lewat API standar (`SetFileTime`), tidak butuh tool khusus/privilege tinggi | PowerShell `Set-ItemProperty`, Timestomp.exe, banyak tool GUI gratis | Bab 2 §2.1.3, §9.6.1 |
| **Recycle Bin ($I/$R files)** | ⭐ Sangat Rendah | Delete biasa masuk Recycle Bin, tapi Shift+Delete atau `Remove-Item -Force` skip sepenuhnya | Shift+Delete, atau empty Recycle Bin manual | Bab 5 §5.2 |

> 💡 **Cara pakai untuk strategi investigasi:** Kalau waktu terbatas (CTF timed, atau butuh jawaban cepat untuk klien), **cek artefak survivability tinggi duluan** (Amcache, $UsnJrnl, registry) sebagai anchor yang paling mungkin masih utuh, baru turun ke artefak survivability rendah (Prefetch, SI timestamp) untuk detail tambahan — bukan sebaliknya. Kalau artefak survivability tinggi justru yang hilang/tidak konsisten, itu red flag lebih besar daripada kalau cuma Prefetch yang hilang (karena butuh usaha jauh lebih besar dari attacker untuk menghilangkannya).

> ⚠️ **Survivability bukan jaminan mutlak:** Rating ini asumsi attacker "rata-rata" — attacker dengan akses kernel-level/rootkit (di luar cakupan seri ini yang fokus filesystem/registry/log forensics) berpotensi memanipulasi bahkan artefak ⭐⭐⭐⭐⭐ sekalipun. Gunakan matrix ini sebagai heuristik prioritas, bukan aturan absolut.

---

### 9.13 Tabel Master — Anti-Forensic Technique vs Detection Method

> 📖 **Anti-Forensic Detection Matrix** — versi lengkap, menggabungkan level teknik, deteksi utama, tingkat kesulitan bagi attacker (cross-ref §9.12), dan confidence level hasil deteksinya. Dipakai sebagai rujukan cepat saat laporan butuh justifikasi "kenapa kesimpulan ini kuat/lemah".

| Teknik Anti-Forensik | Level | Dibahas Detail di | Deteksi Utama | Effort Attacker | Confidence Deteksi |
|---|---|---|---|---|---|
| Timestomp SI-only | Metadata | Bab 2 §2.1.3 | SI vs FN mismatch | Rendah (tool gratis, GUI) | Tinggi — mismatch jelas & binary |
| Timestomp SI+FN (SetMace) | Metadata | §9.6.1-9.6.2 | 4-way cross-check ke $LogFile/$UsnJrnl | Sedang (butuh tool khusus) | Sedang — perlu journal masih ada |
| MFT record wiping | Filesystem | §9.7.1 | Carving FILE0 signature, $LogFile history | Sedang-Tinggi (butuh akses raw disk) | Sedang — bergantung journal survivability |
| $LogFile manipulation | Journal | §9.7.2 | Cek rentang waktu tercakup vs window insiden | Rendah (cukup tunggu, circular alami) | Rendah — sulit dibedakan dari retensi normal |
| $UsnJrnl deletion | Journal | §9.7.3 | Journal hilang/reset, cross-check `fsutil usn deletejournal` di EVTX | Sedang (privilege admin) | Tinggi — command self-logging di EVTX 4688 |
| VSS deletion | Backup | Bab 5 §5.1.8 | `vssadmin delete shadows` command di EVTX 4688/Sysmon 1 | Rendah (satu command) | Tinggi — command tercatat, sangat spesifik |
| Log cleared (1102) | Log | Bab 4 §4.9 | Event ID 1102 itu sendiri (self-logging saat log dihapus) | Rendah (built-in Windows) | Tinggi — self-logging by design |
| Secure deletion (SDelete, dll) | Data | §9.8.1 | Evidence of execution tool wiping-nya sendiri | Sedang (butuh download tool) | Tinggi — Prefetch/Amcache jarang ikut terhapus |
| USB wiping | Removable media | §9.8.2 | Cross-check registry USBSTOR vs LNK/Jump List | Sedang | Sedang — bergantung media masih tersedia diperiksa |
| Fileless malware | Execution | Bab 8 §8.12.3 | Memory forensics (Bab 7), Script Block Logging (Bab 4 §4.5.3) | Tinggi (skill teknis lebih besar) | Rendah-Sedang — hilang total kalau memory tidak sempat diakuisisi |
| VM/sandbox detection | Evasion | Bab 8 §8.12.1 | — (mencegah analisa, bukan menghapus jejak) | Sedang | Tidak berlaku — bukan penghapus jejak, tapi pencegah observasi |
| Registry key deletion manual | Metadata/Registry | Bab 3 §3.1.7 | RegBack/ControlSet backup, transaction log registry | Rendah (satu key) | Sedang — bergantung backup registry masih ada |
| System clock manipulation | Anti-korelasi | — (baru, lihat catatan di bawah) | Cross-check NTP/Time-Service EVTX vs $LogFile physical write order | Sedang | Sedang — journal urutan fisik tetap benar walau clock salah |
| Browser history clearing | Application | Bab 6 §6.5 | WAL/journal file SQLite belum ter-vacuum, cache/thumbnail masih ada | Rendah (built-in browser feature) | Sedang — bergantung seberapa cepat pemeriksaan dilakukan |

> ⚠️ **Tentang System Clock Manipulation:** Teknik ini tidak mengubah satu artefak spesifik, tapi mengubah **jam sistem itu sendiri** sebelum beraksi, supaya semua timestamp baru tercatat salah secara konsisten (SI, FN, EVTX, journal — semua "kompak" karena memang direkam saat jam sudah diubah). Ini **tidak terdeteksi** oleh 4-way cross-check §9.6.2 (karena semua sumber tetap konsisten satu sama lain). Deteksi realistis: cross-check EVTX Time-Service/Kernel-General Event ID terkait perubahan waktu sistem, dan **urutan relatif** kejadian di $LogFile (yang mencatat urutan fisik operasi disk, bukan cuma nilai timestamp) — kalau urutan logis kejadian tidak masuk akal dibanding timestamp yang tercatat, itu indikasi clock manipulation, bukan timestomping artefak individual.

> 💡 **Cara baca kolom Effort vs Confidence bersama-sama:** Teknik dengan **Effort Rendah + Confidence Deteksi Tinggi** (Timestomp SI-only, VSS deletion, Log cleared) adalah yang paling sering ditemukan di kasus CTF/real-world karena murah dilakukan attacker tapi mudah dideteksi investigator. Teknik dengan **Effort Tinggi + Confidence Rendah** (fileless malware tanpa memory capture) adalah kasus paling sulit — kombinasi ini yang butuh playbook khusus (§9.14) dan idealnya pencegahan (logging proaktif) daripada deteksi post-mortem semata.

---

### 9.14 Investigation Playbooks

> 📖 **Beda dengan §9.12 (mini case study nanti):** Playbook di sini adalah **template checklist yang dipakai DI AWAL** investigasi untuk jenis kasus yang sudah dikenal polanya — bukan narasi hasil investigasi. Tiap playbook mengikuti alur umum §9.5.1 tapi dikonkretkan jadi urutan langkah spesifik per skenario, lengkap dengan rujukan §/Bab supaya tinggal loncat ke detail teknisnya.

#### 9.14.1 Playbook — Suspected Malware Execution

```
[ ] 1. Cek Evidence of Execution dulu (§9.5.2) — Amcache, Prefetch, EVTX 4688/Sysmon 1
[ ] 2. Kalau ditemukan nama proses mencurigakan, catat: nama file, path, waktu eksekusi
[ ] 3. Cross-check UserAssist (Bab 3 §3.6.1) — apakah dijalankan via GUI double-click?
[ ] 4. Cek Evidence of Existence (§9.5.2) — $MFT Created time file tsb, konsisten dgn [2]?
[ ] 5. SI vs FN check (Bab 2 §2.1.3) — ada indikasi timestomp pada file malware?
[ ] 6. Cek asal file — Download history (Bab 6 §6.3), LNK/USB (§9.5.3), atau email attachment?
[ ] 7. Cek persistence (Bab 8, semua sub-bab) — apakah malware pasang mekanisme survive reboot?
[ ] 8. Cek jaringan/lateral movement kalau relevan (Sysmon 3, EVTX 4624 Type 3)
[ ] 9. Cek Evidence Survivability (§9.12) — artefak mana yang hilang, apakah polanya wajar?
[ ] 10. Susun timeline naratif (§9.5.1 langkah 7) dari titik masuk sampai dampak
```

---

#### 9.14.2 Playbook — Data Exfiltration via USB/Removable Media

```
[ ] 1. Registry USBSTOR (Bab 3 §3.3.3) — daftar semua device pernah dicolok, catat waktu FirstInsert/LastConnected
[ ] 2. Cocokkan window waktu USB tercolok dengan LNK/Jump List baru (Bab 5 §5.3) di window sama
[ ] 3. Cek TrackerDataBlock Volume Serial Number (§9.5.3) — konfirmasi LNK memang menunjuk device USB tsb
[ ] 4. Cek $MFT/$UsnJrnl untuk aktivitas COPY/WRITE ke device tsb (kalau drive letter USB diketahui)
[ ] 5. Cek ShellBag (Bab 3 §3.7) — apakah user pernah browse ke folder tertentu sebelum copy?
[ ] 6. Kalau dicurigai wiping setelah copy — cek §9.8.2 (USB wiping indicators)
[ ] 7. Cek Recycle Bin (Bab 5 §5.2) — apakah file "dihapus" biasa (masih recoverable) atau Shift+Delete?
[ ] 8. Evidence Survivability check (§9.12) — USBSTOR registry biasanya bertahan, jadikan anchor utama
[ ] 9. Dokumentasikan: device USB apa, kapan dicolok, file apa yang diakses/disalin, kapan dicabut
```

---

#### 9.14.3 Playbook — Ransomware Incident

```
[ ] 1. Cari anchor point — biasanya EVTX 1102 (log cleared) atau alert AV/EDR eksternal
[ ] 2. Cek $UsnJrnl untuk burst MODIFIED events dalam window pendek (§9.9.3, pola mass-encryption)
[ ] 3. Perluas window ke belakang — cari evidence of execution proses ransomware (Amcache/Prefetch/EVTX 4688)
[ ] 4. Cek VSS — vssadmin list shadows kosong? Cross-check EVTX 4688 untuk command "vssadmin delete shadows"
[ ] 5. Root cause — telusuri ke belakang lagi: initial access via USB (§9.14.2)? Email attachment (Bab 6)?
    Phishing link? RDP brute force (EVTX 4625 beruntun)?
[ ] 6. Cek persistence tambahan yang mungkin dipasang SEBELUM enkripsi mulai (Bab 8)
[ ] 7. Cek lateral movement — apakah ransomware menyebar ke host lain sebelum sampai ke mesin ini?
    (Sysmon 3, EVTX 4624 Type 3, artefak PsExec/WMI)
[ ] 8. Susun timeline final: initial access → persistence → lateral movement (kalau ada) →
    VSS deletion → mass encryption → log cleanup
[ ] 9. Identifikasi ransomware note/extension pattern untuk kemungkinan atribusi keluarga ransomware
    (di luar cakupan seri ini — cross-reference threat intel eksternal)
```

---

#### 9.14.4 Playbook — Suspected Anti-Forensics / Insider Threat

```
[ ] 1. Mulai dari Correlation Matrix (§9.11) — event apa yang dicurigai, artefak apa yang SEHARUSNYA ada
[ ] 2. Cek satu-satu apakah artefak primer & sekunder ada — kalau kosong semua, lanjut ke [3]
[ ] 3. Rank artefak yang hilang berdasarkan Evidence Survivability (§9.12) —
    kalau yang hilang justru artefak survivability TINGGI (Amcache, USBSTOR), itu sinyal kuat
[ ] 4. Terapkan Anti-Forensic Detection Matrix (§9.13) — teknik mana yang paling cocok
    dengan pola kekosongan yang ditemukan?
[ ] 5. Cari evidence of execution TOOL anti-forensik itu sendiri (§9.8.3) —
    Prefetch/Amcache/EVTX 4688 untuk nama tool wiping/timestomp
[ ] 6. Cek statistical gap detection (§9.9.2) di super timeline — window "sepi" yang tidak wajar?
[ ] 7. Cross-validate ke VSS (§9.9.4) — kondisi sebelum insiden, sebelum sempat dimanipulasi
[ ] 8. Kalau semua artefak "live" konsisten & tidak mencurigakan tapi kasus tetap dicurigai —
    pertimbangkan system clock manipulation (§9.13, catatan khusus) sebagai penjelasan alternatif
[ ] 9. Dokumentasikan bukan cuma APA yang ditemukan, tapi APA yang TIDAK ditemukan padahal
    seharusnya ada (§9.9.1) — kekosongan yang terdokumentasi rapi tetap punya nilai pembuktian
```

---

#### 9.14.5 Playbook — Lateral Movement Cross-Host

```
[ ] 1. Identifikasi host awal (patient zero) dari playbook §9.14.1 atau §9.14.3
[ ] 2. Cek EVTX 4624 Logon Type 3 (network) di host target — source IP/hostname dari host awal?
[ ] 3. Cek metode: PsExec (Service install EVTX 7045 + named pipe artifact),
    WMI (EVTX 4688 CommandLine `wmic.exe`/`wmiprvse.exe`), atau RDP (4624 Type 10)?
[ ] 4. Cross-check Prefetch/Amcache di HOST TARGET untuk tool lateral movement yang sama
[ ] 5. Bandingkan timestamp login di host target dengan timestamp aktivitas terakhir di host awal —
    harus ada urutan logis (host awal duluan, target sesudahnya, minus network latency)
[ ] 6. Ulangi §9.14.1 (malware execution playbook) di HOST TARGET sebagai host baru
[ ] 7. Lacak terus sampai ditemukan host yang tidak menunjukkan bukti lanjutan (titik akhir pergerakan
    lateral yang diketahui) atau sampai ke exfiltration point
[ ] 8. Susun diagram/tabel multi-host: host, waktu compromise, metode masuk, aksi dilakukan
    (Timeline Explorer §9.2.2 bisa load multi-host CSV sekaligus dengan kolom "Hostname" tambahan)
```

> 💡 **Catatan umum untuk semua playbook:** Checklist ini adalah **urutan default**, bukan urutan kaku — kalau di tengah jalan ditemukan bukti yang mengarah ke playbook lain (misal playbook malware execution menemukan indikasi USB jadi initial access), lompat ke playbook yang relevan (§9.14.2) lalu kembali. Prinsip §9.5.1 (persempit window, validasi silang ≥2 artefak, perluas ke belakang/depan) tetap berlaku di semua playbook ini.

---

### 9.15 Ringkasan Command & Tools Cheat Sheet

```bash
# ===== TIMELINE EXPLORER (manual) =====
# Buka multi-CSV sekaligus (File > Open > multi-select)

# ===== PLASO =====
log2timeline.py --storage-file case.plaso /path/to/image.E01
psort.py -o l2tcsv -w super_timeline.csv case.plaso
psort.py -o l2tcsv -w filtered.csv case.plaso "date > 'YYYY-MM-DD HH:MM:SS'"

# ===== JOURNAL FORENSICS =====
.\LogFileParser.exe -f "$LogFile" --csv .
.\MFTECmd.exe -f "$Extend\$UsnJrnl:$J" --csv .
fsutil usn queryjournal C:

# ===== SI vs FN CROSS-CHECK =====
.\MFTECmd.exe -f ".\$MFT" --csv . --fl

# ===== ANTI-FORENSIC TOOL DETECTION =====
.\AmcacheParser.exe -f Amcache.hve --csv . -i
.\PECmd.exe -d Prefetch\ --csv .

# ===== GAP DETECTION (Python) =====
python3 -c "
import pandas as pd
df = pd.read_csv('super_timeline.csv', parse_dates=['timestamp'])
df = df.sort_values('timestamp')
df['gap'] = df['timestamp'].diff().dt.total_seconds()
print(df.nlargest(10, 'gap')[['timestamp','gap']])
"
```

---

### 9.16 Mini Case Study — Full Timeline Reconstruction dengan Gap Detection

**Skenario:** Ditemukan indikasi ransomware pada sebuah image disk Windows 10. Prefetch untuk proses malware tidak ditemukan, VSS kosong, dan Event Log tampak "bersih" — tapi investigasi lanjutan menunjukkan cerita berbeda.

```
[1] Anchor Point — EVTX 1102 (Audit Log Cleared)
    ditemukan di Security.evtx, waktu: 14:32:07
    → mencurigakan, log dibersihkan MANUAL (Bab 4 §4.9)

[2] Perluas window ke belakang — cek Amcache.hve (lebih tahan hapus, Bab 3 §3.8)
    ditemukan entry eksekusi "svchost32.exe" (nama menyamar) jam 14:15:22
    Prefetch untuk file ini TIDAK ADA → kandidat kuat sengaja dihapus/didisable

[3] Cross-check $UsnJrnl
    ditemukan burst MODIFIED events (~4.000 file) antara 14:16:00-14:28:00
    → pola klasik ransomware mass-encryption (§9.9.3)

[4] Cek VSS
    vssadmin list shadows → KOSONG
    Cross-check EVTX 4688 sebelum log di-clear: ditemukan CommandLine
    "vssadmin.exe delete shadows /all /quiet" jam 14:29:45 (Bab 5 §5.1.8)

[5] Cek $LogFile untuk file svchost32.exe
    Ditemukan entry CREATE record jam 14:14:58 — SESUAI dengan Amcache (14:15:22),
    tidak ada indikasi timestomping (SI = FN = journal, konsisten — §9.6.2)

[6] Root Cause — perluas lebih jauh ke belakang
    LNK file di Recent\ menunjuk ke "invoice_Q4.pdf.exe" dari drive E:\ (USB)
    Volume Serial Number LNK cocok dengan entry USBSTOR jam 14:10:03 (§9.5.3)

REKONSTRUKSI TIMELINE FINAL:
14:10:03 → USB dicolok (USBSTOR)
14:14:58 → File "svchost32.exe" (asal invoice_Q4.pdf.exe) dibuat di disk ($LogFile)
14:15:22 → File dieksekusi (Amcache, evidence of execution)
14:16:00–14:28:00 → Mass file encryption (~4.000 file, $UsnJrnl)
14:29:45 → VSS dihapus (EVTX 4688, sebelum log dihapus)
14:32:07 → Security log dibersihkan (EVTX 1102, event terakhir sebelum log kosong)

KESIMPULAN: Prefetch yang hilang BUKAN berarti tidak ada eksekusi — evidence of
execution tetap terbukti kuat lewat Amcache + korelasi $LogFile/$UsnJrnl (§9.5.2).
Absennya VSS & Prefetch justru jadi bagian dari cerita anti-forensik itu sendiri
(§9.9.1), bukan penghalang investigasi.
```

> 📌 **Pelajaran utama studi kasus ini:** Tidak ada satupun artefak tunggal yang cukup untuk merekonstruksi kejadian ini secara meyakinkan — kombinasi Amcache (Bab 3) + $LogFile/$UsnJrnl (Bab 2) + LNK/USBSTOR (Bab 3, 5) + EVTX (Bab 4) + absennya Prefetch/VSS yang justru informatif (§9.9), semuanya menyatu jadi satu narasi timeline yang solid. Inilah inti dari **Timeline Correlation & Anti-Forensics** — bukan menguasai satu teknik sakti, tapi kemampuan menjahit banyak sumber lemah jadi satu kesimpulan kuat.
