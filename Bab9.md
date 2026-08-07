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
  - [9.10 Tabel Master — Anti-Forensic Technique vs Detection Method](#910-tabel-master--anti-forensic-technique-vs-detection-method)
  - [9.11 Ringkasan Command & Tools Cheat Sheet](#911-ringkasan-command--tools-cheat-sheet)
  - [9.12 Mini Case Study — Full Timeline Reconstruction dengan Gap Detection](#912-mini-case-study--full-timeline-reconstruction-dengan-gap-detection)

*(Bab 1: Struktur Drive & Direktori — `bab1.md`. Bab 2: File Sistem NTFS & $MFT — `bab2.md`. Bab 3: Windows Registry Forensics — `bab3.md`. Bab 4: EVTX & Event ID Forensics — `bab4.md`. Bab 5: User Activity Trail — `bab5.md`. Bab 6: Browser Forensics — `bab6.md`. Bab 7: Memory Forensics — `bab7.md`. Bab 8: Malware & Persistence Analysis — `bab8.md`.)*

---

## Bab 9 — Timeline Correlation & Anti-Forensics

> 💡 **Posisi Bab 9 di seri ini:** Bab 1-8 fokus per-artefak — di mana bukti tersimpan, apa strukturnya, dan bagaimana anti-forensic sederhana terhadap artefak itu dideteksi (sudah dibahas lokal di tiap bab). Bab 9 **tidak mengulang** semua itu. Bab 9 menjahit semuanya jadi satu timeline utuh lintas-artefak (§9.1-9.5), lalu naik satu level ke teknik anti-forensik yang menyerang **fondasi filesystem/journal itu sendiri** — bukan satu artefak spesifik (§9.6-9.9). Kalau kamu belum familiar dengan istilah SI/FN, $LogFile, $UsnJrnl, VSS, atau Event ID auth dasar, kembali dulu ke Bab 2-5 sebelum lanjut ke sini.

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

### 9.10 Tabel Master — Anti-Forensic Technique vs Detection Method

| Teknik Anti-Forensik | Level | Dibahas Detail di | Deteksi Utama |
|---|---|---|---|
| Timestomp SI-only | Metadata | Bab 2 §2.1.3 | SI vs FN mismatch |
| Timestomp SI+FN (SetMace) | Metadata | §9.6.1-9.6.2 | 4-way cross-check ke $LogFile/$UsnJrnl |
| MFT record wiping | Filesystem | §9.7.1 | Carving FILE0 signature, $LogFile history |
| $LogFile manipulation | Journal | §9.7.2 | Cek rentang waktu tercakup vs window insiden |
| $UsnJrnl deletion | Journal | §9.7.3 | Journal hilang/reset, cross-check `fsutil usn deletejournal` di EVTX |
| VSS deletion | Backup | Bab 5 §5.1.8 | `vssadmin delete shadows` command di EVTX 4688/Sysmon 1 |
| Log cleared (1102) | Log | Bab 4 §4.9 | Event ID 1102 itu sendiri (self-logging saat log dihapus) |
| Secure deletion (SDelete, dll) | Data | §9.8.1 | Evidence of execution tool wiping-nya sendiri |
| USB wiping | Removable media | §9.8.2 | Cross-check registry USBSTOR vs LNK/Jump List |
| Fileless malware | Execution | Bab 8 §8.12.3 | Memory forensics (Bab 7), Script Block Logging (Bab 4 §4.5.3) |
| VM/sandbox detection | Evasion | Bab 8 §8.12.1 | — (mencegah analisa, bukan menghapus jejak) |

---

### 9.11 Ringkasan Command & Tools Cheat Sheet

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

### 9.12 Mini Case Study — Full Timeline Reconstruction dengan Gap Detection

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
