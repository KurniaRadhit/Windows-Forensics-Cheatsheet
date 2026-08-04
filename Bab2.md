## 📌 Daftar Isi — Bab 2

- [Bab 2 — File Sistem NTFS & Master File Table](#bab-2--file-sistem-ntfs--master-file-table)
  - [2.1 File Sistem NTFS](#21-file-sistem-ntfs)
    - [2.1.1 File Sistem Khusus NTFS (hidden, diawali $)](#211-file-sistem-khusus-ntfs-hidden-diawali-)
    - [2.1.2 Timestamps NTFS (4 Timestamp per File)](#212-timestamps-ntfs-4-timestamp-per-file)
    - [2.1.3 Timestomping & Cara Deteksinya](#213-timestomping--cara-deteksinya)
    - [2.1.4 Alternate Data Streams (ADS)](#214-alternate-data-streams-ads)
  - [2.2 $MFT — Master File Table](#22-mft--master-file-table)
    - [2.2.1 Cara Kerja $MFT](#221-cara-kerja-mft)
    - [2.2.2 Isi Tiap MFT Record](#222-isi-tiap-mft-record)
    - [2.2.3 Tools untuk Analisa $MFT](#223-tools-untuk-analisa-mft)
    - [2.2.4 Output MFTECmd — Kolom Penting](#224-output-mftecmd--kolom-penting)
    - [2.2.5 MFT Carving & Recovery Record Terhapus](#225-mft-carving--recovery-record-terhapus)
  - [2.3 Ringkasan Command & Tools Cheat Sheet](#23-ringkasan-command--tools-cheat-sheet)
  - [2.4 Mini Case Study — Workflow Analisa End-to-End](#24-mini-case-study--workflow-analisa-end-to-end)

*(Bab 1 membahas Struktur Drive & Partisi serta Struktur Direktori Windows — lihat file terpisah `bab1.md`. Bab 3 dan seterusnya menyusul — akan fokus ke Registry hive detail, lalu EVTX & Event ID penting, dst.)*

---

## Bab 2 — File Sistem NTFS & Master File Table

### 2.1 File Sistem NTFS

Windows secara default menggunakan **NTFS** (New Technology File System). Ini bukan sekadar "tempat simpan file" — NTFS punya banyak metadata forensik yang menjadi dasar hampir semua tool Eric Zimmerman (MFTECmd, dst).

#### 2.1.1 File Sistem Khusus NTFS (hidden, diawali $)

Ini adalah metadata file NTFS itu sendiri — file-file "hidden" yang duduk di root tiap volume NTFS dan menyimpan seluruh cara kerja filesystem-nya.

| File | Lokasi | Fungsi Forensik |
|---|---|---|
| `$MFT` | Root volume | Database metadata semua file di disk — dibahas detail di **2.2** |
| `$MFTMirr` | Root volume | Backup 4 record pertama `$MFT` — dipakai recovery kalau `$MFT` corrupt |
| `$LogFile` | Root volume | Journal transaksi NTFS (undo/redo log) — bisa rekonstruksi aktivitas file yang sudah di-overwrite di `$MFT` |
| `$UsnJrnl` | `\$Extend\$UsnJrnl` | Change journal — rekaman create/modify/delete/rename dengan reason code |
| `$Bitmap` | Root volume | Peta cluster yang dipakai / kosong (lihat juga unallocated space di Bab 1, 1.1.6) |
| `$Boot` | Root volume | VBR + bootstrap code |
| `$Volume` | Root volume | Info volume (label, version, GUID, dirty flag) |
| `$Secure` | Root volume | ACL & security descriptor |
| `$BadClus` | Root volume | Daftar bad sector/cluster |
| `$AttrDef` | Root volume | Definisi tipe atribut NTFS yang valid |
| `$ObjId` | `\$Extend\$ObjId` | Object ID tracking — link antar file/shortcut lintas volume |
| `$Quota` | `\$Extend\$Quota` | Data disk quota per user |
| `$Reparse` | `\$Extend\$Reparse` | Index reparse point (symlink, junction, OneDrive placeholder) |

> 💡 **Forensic note:** `$UsnJrnl` sangat berguna — dia mencatat perubahan file bahkan **setelah file dihapus**, selama journal belum di-overwrite (journal berukuran terbatas, jadi entry lama akan tertimpa seiring waktu — makin cepat diakuisisi, makin lengkap datanya).

**Cara Analisa `$LogFile` & `$UsnJrnl`:**
```bash
# Parsing $LogFile (Eric Zimmerman Tools)
.\LogFileParser.exe -f "C:\`$LogFile" --csv .

# Parsing $UsnJrnl (bisa lewat MFTECmd juga)
.\MFTECmd.exe -f "C:\`$Extend\`$UsnJrnl:`$J" --csv . --de

# Live system: dump UsnJrnl langsung tanpa tool tambahan
fsutil usn readjournal C:
```

**Tools untuk `$LogFile` & `$UsnJrnl`:**

| Tool | Fungsi | Catatan |
|---|---|---|
| **MFTECmd.exe** | Parsing `$UsnJrnl:$J` → CSV, kolom `UpdateReasons` berisi flag perubahan | Paling praktis, satu tool buat `$MFT` + `$J` + `$Boot` |
| **LogFileParser.exe** (Eric Zimmerman) | Parsing `$LogFile` → CSV, merekonstruksi transaksi redo/undo | `$LogFile` ukurannya tetap (biasanya 64MB), jadi window waktunya lebih pendek dari `$UsnJrnl` |
| **NTFS Log Tracker** (GUI, Korean NFS/forensic tool) | Visualisasi `$LogFile` & `$UsnJrnl` sekaligus, bisa filter per file/folder | Enak buat presentasi/screenshot bukti di laporan CTF |
| **fsutil usn readjournal** | Baca `$UsnJrnl` langsung di live system tanpa tool tambahan | Hanya bisa dipakai di sistem hidup, bukan di image mati |

**Kolom penting output `$UsnJrnl` (MFTECmd):**

| Kolom | Keterangan |
|---|---|
| `UpdateTimestamp` | Waktu perubahan tercatat |
| `FileName` | Nama file yang berubah |
| `UpdateReasons` | Alasan perubahan — bisa lebih dari satu flag sekaligus, contoh: `FileCreate`, `DataExtend`, `RenameOldName`/`RenameNewName`, `FileDelete`, `SecurityChange`, `BasicInfoChange` |
| `FileAttributes` | Atribut file saat itu (Archive, Hidden, System, dll) |
| `ParentFileReferenceNumber` | Folder induk saat perubahan terjadi — berguna untuk lacak file yang di-*move* antar folder |

> 💡 **Tip CTF:** Kombinasi `FileCreate` → `RenameOldName`/`RenameNewName` → `FileDelete` di `UpdateReasons` untuk file yang sama adalah pola klasik **"drop payload → rename supaya menyamar → hapus"** yang sering dipakai malware/attacker untuk anti-forensik.

---

#### 2.1.4 Alternate Data Streams (ADS)

**Pengertian & Fungsi:**
NTFS mengizinkan satu file punya **lebih dari satu stream data** — stream utama (`$DATA` default, tidak bernama) dan stream tambahan bernama (`filename:streamname`). Fitur ini legit dipakai Windows sendiri (misal Zone.Identifier untuk menandai file yang didownload dari internet), tapi juga sering disalahgunakan attacker untuk **menyembunyikan payload** di dalam file yang terlihat biasa saja di Explorer.

```
document.txt                    ← Stream utama, terlihat normal di Explorer (ukuran kecil)
document.txt:Zone.Identifier    ← ADS legit dari browser (menandai file "dari internet")
document.txt:hidden.exe         ← ADS tersembunyi berisi payload (TIDAK terlihat di Explorer/dir biasa!)
```

**Cara Analisa & Tools:**

```powershell
# PowerShell — deteksi semua ADS di sebuah file/folder
Get-Item -Path "document.txt" -Stream *
Get-ChildItem -Recurse | ForEach-Object { Get-Item $_.FullName -Stream * } | Where-Object Stream -ne ':$DATA'

# CMD — dir dengan flag /r menampilkan ADS
dir /r

# Sysinternals streams.exe — scan ADS secara rekursif
streams.exe -s C:\Users\<user>\Downloads

# Jalankan/ekstrak isi ADS
more < document.txt:hidden.exe > extracted.exe
```

| Tool | Fungsi |
|---|---|
| **PowerShell `Get-Item -Stream *`** | Cara paling cepat cek ADS di live system, built-in tanpa install apapun |
| **Sysinternals `streams.exe`** | Scan ADS secara rekursif di banyak folder sekaligus |
| **MFTECmd.exe** | Saat parsing `$MFT`, ADS ikut muncul sebagai attribute `$DATA` bernama terpisah di record yang sama — cek kolom yang menyebut nama stream |
| **FTK Imager** | Menampilkan ADS sebagai "file" terpisah di bawah file induknya saat browsing image |

> 💡 **Tip CTF:** Kalau ukuran file di Explorer kecil tapi soal bilang *"payload disembunyikan di file ini"*, itu sinyal kuat cek ADS. Zone.Identifier yang berisi `ZoneId=3` menandakan file didownload dari internet — berguna untuk membuktikan file datang dari luar (misal browser download), bukan dibuat lokal.

---

#### 2.1.2 Timestamps NTFS (4 Timestamp per File)

Setiap file di NTFS punya **2 set timestamp** yang tersimpan di **2 attribute berbeda** di dalam MFT record yang sama:

| Attribute | Timestamp yang disimpan | Karakteristik |
|---|---|---|
| `$STANDARD_INFORMATION` (SI) | Modified, Accessed, Created (Born), MFT Changed — sering disingkat **MACB** | Yang ditampilkan Windows Explorer (`Properties`); **bisa dimanipulasi attacker via timestomping** |
| `$FILE_NAME` (FN) | 4 timestamp yang sama (Modified, Accessed, Created, MFT Changed) | Update lebih jarang (hanya saat rename/move/create), **lebih susah dimanipulasi** karena butuh akses low-level ke MFT langsung |

**Kenapa ada 2 set?** SI dirancang untuk kebutuhan aplikasi/user (gampang diubah program), sedangkan FN adalah bagian dari struktur index direktori NTFS (`$I30`) — perubahannya lebih terbatas dan biasanya cuma ter-update saat operasi filesystem-level (create, rename, move).

```
Contoh MFT Record untuk satu file:
├── $STANDARD_INFORMATION (0x10)
│     ├── Created:    2026-08-01 10:00:00
│     ├── Modified:   2026-08-01 10:05:00
│     ├── MFT Changed: 2026-08-01 10:05:00
│     └── Accessed:   2026-08-01 10:05:00
│
└── $FILE_NAME (0x30)
      ├── Created:    2026-08-01 10:00:00
      ├── Modified:   2026-08-01 10:00:00
      ├── MFT Changed: 2026-08-01 10:00:00
      └── Accessed:   2026-08-01 10:00:00
```

---

#### 2.1.3 Timestomping & Cara Deteksinya

**Pengertian:** Timestomping adalah teknik anti-forensik di mana attacker mengubah nilai timestamp `$STANDARD_INFORMATION` (biasanya disamakan dengan file legit di sekitarnya) supaya malware/tool mereka **terlihat seperti sudah lama ada** dan tidak mencolok di timeline.

| Indikator | Penjelasan |
|---|---|
| **SI vs FN mismatch** | Kalau timestamp `$STANDARD_INFORMATION` jauh lebih tua dari `$FILE_NAME` (atau sebaliknya, aneh urutannya) → **kuat indikasi timestomping**, karena tool timestomp umum hanya mengubah SI, jarang yang bisa ubah FN |
| **Created > Modified** | SI Created lebih baru dari Modified itu wajar hilang (harusnya Created ≤ Modified); kalau terbalik ekstrem → mencurigakan |
| **Timestamp presisi bulat/aneh** | Timestamp asli NTFS biasanya presisi hingga 100 nanosecond; timestamp hasil tool timestomp kadang terlihat "terlalu rapi" (misal 00:00:00 pas) |
| **Cross-check ke $LogFile/$UsnJrnl** | `$LogFile` & `$UsnJrnl` mencatat **kapan transaksi benar-benar terjadi** — kalau tidak cocok dengan timestamp SI, itu bukti kuat manipulasi |
| **Cross-check ke Prefetch/EventLog** | Timestamp eksekusi di Prefetch atau Event Log (proses creation) yang tidak sinkron dengan timestamp file di `$MFT` juga jadi red flag |

**Cara Analisa:**
```bash
# MFTECmd otomatis menampilkan kolom SI (0x10) dan FN (0x30) berdampingan
.\MFTECmd.exe -f ".\$MFT" --csv . --fl

# Bandingkan manual: cari baris di mana Created0x10 != Created0x30
# (paling gampang lewat Excel/Timeline Explorer, filter/sort dua kolom itu)
```

> ⚠️ **Tip CTF:** Kalau soal minta *"buktikan file ini di-timestomp"*, jawaban paling kuat adalah **screenshot perbandingan SI vs FN** dari output MFTECmd, bukan cuma bilang "timestamp mencurigakan". SI vs FN mismatch adalah bukti paling defensible secara forensik.

---

### 2.2 $MFT — Master File Table

**Pengertian & Fungsi:**
`$MFT` adalah **ground truth filesystem-level** — database pusat NTFS yang mencatat metadata **setiap file dan folder** yang pernah ada di volume, termasuk yang **sudah dihapus** (selama record-nya belum ditimpa record baru).

#### 2.2.1 Cara Kerja $MFT

```
[Disk]
  └── NTFS Volume
        └── $MFT (database, tiap record = 1024 byte)
              ├── Record 0  → $MFT itu sendiri (self-referencing)
              ├── Record 1  → $MFTMirr (backup)
              ├── Record 2  → $LogFile
              ├── Record 3  → $Volume
              ├── Record 4  → $AttrDef
              ├── Record 5  → Root Directory (.)
              ├── Record 6  → $Bitmap
              ├── Record 7  → $Boot
              ├── Record 8  → $BadClus
              ├── Record 9  → $Secure
              ├── Record 10 → $UpCase
              ├── Record 11 → $Extend (folder virtual berisi $UsnJrnl, $ObjId, $Quota, $Reparse)
              ├── ...
              └── Record N  → file/folder biasa (dokumen user, executable, dll)
```

#### 2.2.2 Isi Tiap MFT Record

Setiap MFT Record berisi (dalam bentuk attribute, bukan field flat):

| Bagian | Isi |
|---|---|
| Nama file | Dari attribute `$FILE_NAME` (0x30) |
| Path lengkap | Direkonstruksi dari `ParentEntryNumber` (parent-child chain) |
| Ukuran file | Dari attribute `$DATA` (real size vs allocated size) |
| Timestamps (SI & FN) | Dari `$STANDARD_INFORMATION` (0x10) dan `$FILE_NAME` (0x30) — lihat **2.1.2** |
| Status dihapus | `InUse` flag di record header — `False` = sudah dihapus (record masih ada sampai ditimpa) |
| Lokasi data di disk | **Data runs** — kalau file resident (kecil, <~700 byte) datanya ikut nempel di record; kalau non-resident, cuma pointer ke cluster di disk |

> 💡 File kecil (misal beberapa baris teks) bisa **resident** — artinya isinya langsung ada di dalam MFT record itu sendiri, tanpa perlu baca cluster lain sama sekali. Ini penting kalau kamu carving `$MFT` mentah dan nemu file kecil utuh langsung di situ.

#### 2.2.3 Tools untuk Analisa $MFT

```bash
# Extract $MFT ke CSV (Eric Zimmerman Tools)
.\MFTECmd.exe -f ".\$MFT" --csv . --fl

# Cari file spesifik dari output CSV
Select-String -Path *.csv -Pattern "ntds.dit"

# Kalau butuh timeline gabungan (MFT + registry + evtx dst), load CSV ini ke Timeline Explorer
```

**Flag MFTECmd yang sering dipakai:**

| Flag | Fungsi |
|---|---|
| `-f <path>` | Path ke file `$MFT` yang mau di-parse |
| `--csv <dir>` | Folder output CSV |
| `--csvf <name>` | Nama file CSV custom (default auto-generate dengan timestamp) |
| `--fl` | Sertakan attribute `$FILE_NAME` (FN) di output, penting untuk cek SI vs FN (**2.1.3**) |
| `--de` | Deduplikasi entry (berguna khusus parsing `$UsnJrnl:$J` yang entry-nya bisa sangat banyak) |
| `--json <dir>` | Output dalam format JSON, kalau mau diproses lebih lanjut dengan script sendiri |

**Tools lengkap untuk `$MFT`:**

| Tool | Fungsi | Catatan |
|---|---|---|
| **MFTECmd.exe** | Parser utama `$MFT` → CSV, mendukung juga `$J` (UsnJrnl) dan `$Boot` | Bagian dari Eric Zimmerman Tools (EZ Tools), paling sering dipakai |
| **MFTExplorer** | GUI untuk browse `$MFT` record secara visual, termasuk lihat data run dan raw attribute | Bagus untuk verifikasi manual satu-per-satu record |
| **Timeline Explorer** | Untuk buka hasil CSV MFTECmd dan filter/sort/search dengan cepat | Sering dipakai gabung timeline dari beberapa sumber (MFT + EVTX + Registry) |
| **analyzeMFT** (Python, open-source) | Alternatif CLI cross-platform kalau tidak bisa pakai tool .NET (mis. di Linux/Mac) | `python3 analyzeMFT.py -f \$MFT -o output.csv` |
| **FTK Imager** | Bisa export `$MFT` mentah langsung dari image tanpa perlu mount volume dulu | Langkah pertama sebelum jalankan MFTECmd |
| **INDXRipper** (Python) | Parsing `$I30` index attribute (index direktori NTFS) untuk temukan **nama file yang sudah dihapus** dari sebuah folder, walau record `$MFT`-nya sendiri sudah ditimpa | `python indx_ripper.py image.dd 5 -o output.csv` (5 = MFT entry number dari folder yang mau dicek) |
| **bulk_extractor** | Scan seluruh image untuk pola signature (termasuk `FILE0` header MFT record) — berguna untuk carving record yang terisolasi di unallocated space | `bulk_extractor -o output_dir disk.dd` |

#### 2.2.4 Output MFTECmd — Kolom Penting

| Kolom | Keterangan |
|---|---|
| `EntryNumber` | ID unik record di MFT |
| `ParentEntryNumber` | ID record folder induknya (dipakai rekonstruksi `FullPath`) |
| `FullPath` | Path lengkap file |
| `FileName` | Nama file saja |
| `FileSize` | Ukuran file dalam bytes |
| `Created0x10` | Timestamp Created dari `$STANDARD_INFORMATION` |
| `LastModified0x10` | Timestamp Modified dari `$STANDARD_INFORMATION` |
| `LastRecordChange0x10` | Timestamp MFT Changed dari `$STANDARD_INFORMATION` |
| `LastAccess0x10` | Timestamp Accessed dari `$STANDARD_INFORMATION` |
| `Created0x30` | Timestamp Created dari `$FILE_NAME` |
| `InUse` | `True` = file masih ada, `False` = sudah dihapus |
| `IsDirectory` | Menandai apakah record ini folder atau file |

> 💡 **Tip CTF:** Attacker sering dump `NTDS.dit` ke path non-default (mis. `C:\Users\Admin\Documents\...` alih-alih lokasi default-nya di `Windows\NTDS\`). Cari dengan pattern `ntds.dit` di output MFTECmd dan perhatikan `FullPath` yang anomali — itu indikator kuat **credential dumping**.

---

#### 2.2.5 MFT Carving & Recovery Record Terhapus

**Pengertian:** Kalau sebuah file dihapus, record-nya di `$MFT` **tidak langsung hilang** — flag `InUse` cuma diubah jadi `False`, dan slot record itu ditandai "boleh ditimpa". Selama belum ada file baru yang kebagian slot itu, record lama (termasuk nama file & timestamp aslinya) **masih bisa dibaca**.

```
Skenario recovery bertingkat:
1. Parsing $MFT normal (MFTECmd)          → record InUse=False = file terhapus, tapi record masih utuh
2. Parsing $I30 index folder (INDXRipper)  → nama file terhapus, walau record $MFT-nya sudah ditimpa
3. Carving signature "FILE0" di unallocated space (bulk_extractor / scalpel)
                                            → record MFT yang sudah "orphan" (lepas dari struktur $MFT normal)
4. Carving isi file itu sendiri di unallocated (PhotoRec/Foremost) → kalau cluster datanya juga belum ditimpa
```

**Cara Analisa:**
```bash
# 1. Cek record terhapus langsung dari $MFT (kolom InUse = False)
.\MFTECmd.exe -f ".\$MFT" --csv . --fl
# lalu filter InUse == False di Timeline Explorer / Excel

# 2. Cek nama file terhapus dari index folder tertentu (walau record MFT-nya sudah hilang)
python indx_ripper.py disk.dd <entry_number_folder> -o deleted_names.csv

# 3. Carving orphan MFT record ("FILE0" signature) di unallocated space
bulk_extractor -o out_dir disk.dd
# atau cari manual pakai hex editor / grep signature 46 49 4C 45 30 00 03 00 (FILE0...)

# 4. Kalau data cluster-nya masih ada, carving isi file dari unallocated
photorec disk.dd
```

> ⚠️ **Batasan:** Recovery cuma berhasil selama cluster/slot record belum ditimpa data baru. Semakin lama waktu antara penghapusan dan akuisisi image, semakin kecil peluang recovery berhasil — makanya kecepatan akuisisi forensik itu krusial.

---

### 2.3 Ringkasan Command & Tools Cheat Sheet

Satu tabel rangkuman semua tool yang dibahas di Bab 2 ini — dipakai sebagai contekan cepat pas lagi kerja soal.

| Artefak | Tool Utama | Command Contoh | Kegunaan |
|---|---|---|---|
| `$MFT` | `MFTECmd.exe` | `.\MFTECmd.exe -f ".\$MFT" --csv . --fl` | Timeline lengkap semua file (termasuk terhapus) |
| `$MFT` (GUI) | `MFTExplorer` | — | Inspeksi manual satu record, lihat raw attribute |
| `$MFT` (cross-platform) | `analyzeMFT` | `python3 analyzeMFT.py -f $MFT -o out.csv` | Alternatif kalau tidak bisa jalankan tool .NET |
| `$LogFile` | `LogFileParser.exe` | `.\LogFileParser.exe -f "C:\$LogFile" --csv .` | Rekonstruksi transaksi redo/undo NTFS |
| `$UsnJrnl:$J` | `MFTECmd.exe` | `.\MFTECmd.exe -f "C:\$Extend\$UsnJrnl:$J" --csv . --de` | Change journal — create/modify/delete/rename |
| `$UsnJrnl` (live) | `fsutil` | `fsutil usn readjournal C:` | Baca journal langsung di sistem hidup |
| `$LogFile` + `$UsnJrnl` (GUI) | `NTFS Log Tracker` | — | Visualisasi gabungan, enak buat laporan |
| ADS | PowerShell | `Get-Item -Path file -Stream *` | Deteksi stream tersembunyi di live system |
| ADS (scan massal) | `streams.exe` (Sysinternals) | `streams.exe -s C:\path` | Scan ADS rekursif di banyak folder |
| Nama file terhapus (index) | `INDXRipper` | `python indx_ripper.py disk.dd <entry> -o out.csv` | Recovery nama file dari `$I30` index, walau record MFT hilang |
| Orphan MFT record | `bulk_extractor` | `bulk_extractor -o out_dir disk.dd` | Carving signature `FILE0` di unallocated space |
| Isi file terhapus | `PhotoRec` / `Foremost` | `photorec disk.dd` | Carving isi file dari cluster unallocated |
| Timeline gabungan | `Timeline Explorer` | — | Buka & filter CSV dari MFTECmd/EvtxECmd/RECmd sekaligus |

---

### 2.4 Mini Case Study — Workflow Analisa End-to-End

Contoh alur berpikir kalau soal CTF/HTB Sherlock bilang: *"attacker menjalankan sebuah executable, lalu mengganti namanya, menghapusnya, dan mencoba menutupi jejak waktu eksekusi — buktikan!"*

```
Langkah 1 — Cari eksekusi program
   └── Windows\Prefetch\ (.pf files) → PECmd.exe
       → dapat nama file & waktu eksekusi kasar (dari nama Prefetch)

Langkah 2 — Cari record file tersebut di $MFT
   └── MFTECmd.exe -f ".\$MFT" --csv . --fl
       → cek FullPath, Created0x10, Created0x30, InUse

Langkah 3 — Bandingkan SI vs FN (2.1.3)
   └── Kalau Created0x10 != Created0x30 secara signifikan → indikasi timestomping

Langkah 4 — Rekonstruksi rename & delete dari $UsnJrnl
   └── MFTECmd.exe -f "$Extend\$UsnJrnl:$J" --csv . --de
       → cari UpdateReasons: FileCreate → RenameOldName/RenameNewName → FileDelete
       → dapat nama ASLI sebelum di-rename + waktu pasti tiap event (lebih presisi dari SI yang bisa dipalsu)

Langkah 5 — Cross-check ke $LogFile
   └── LogFileParser.exe -f "$LogFile" --csv .
       → verifikasi transaksi filesystem-level benar-benar terjadi di waktu yang diklaim $UsnJrnl

Langkah 6 — Cek apakah file masih bisa direcover
   └── Kalau InUse=False dan belum lama dihapus → coba carving (2.2.5)
       → PhotoRec / bulk_extractor untuk lihat isi asli file (mungkin ada indikator malware/flag)

Kesimpulan yang bisa ditulis di laporan:
"File X dieksekusi pada waktu Y (Prefetch), sempat di-rename dari nama_asli.exe menjadi nama_samaran.exe
pada waktu Z (UsnJrnl), lalu dihapus. Timestamp $STANDARD_INFORMATION dimanipulasi untuk terlihat
lebih tua dari $FILE_NAME (SI vs FN mismatch), mengindikasikan penggunaan teknik timestomping."
```

> 💡 **Prinsip umum:** Jangan cuma andalkan satu sumber data. `$MFT` kasih "kondisi sekarang", `$UsnJrnl` kasih "riwayat perubahan", `$LogFile` kasih "bukti transaksi paling granular". Kombinasi ketiganya jauh lebih kuat daripada cuma baca satu-satu.

---

> 📝 **Next (Bab 3 — direncanakan):** Registry hive detail (SYSTEM, SOFTWARE, SAM, SECURITY, NTUSER.DAT — key-key forensik penting seperti RunMRU, UserAssist, ShimCache/AmCache), lalu Bab 4: EVTX & Event ID penting untuk DFIR. Beri tahu aku kalau mau lanjut ke bab berikutnya atau ada bagian di Bab 2 ini yang mau diperdalam/dikoreksi dulu.
