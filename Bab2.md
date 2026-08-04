## 📌 Daftar Isi — Bab 2

- [Bab 2 — File Sistem NTFS & Master File Table](#bab-2--file-sistem-ntfs--master-file-table)
  - [2.1 File Sistem NTFS](#21-file-sistem-ntfs)
    - [2.1.0 Layout NTFS Volume](#210-layout-ntfs-volume)
    - [2.1.1 File Sistem Khusus NTFS (hidden, diawali $)](#211-file-sistem-khusus-ntfs-hidden-diawali-)
    - [2.1.2 Timestamps NTFS (4 Timestamp per File)](#212-timestamps-ntfs-4-timestamp-per-file)
    - [2.1.3 Timestomping & Cara Deteksinya](#213-timestomping--cara-deteksinya)
    - [2.1.4 Alternate Data Streams (ADS)](#214-alternate-data-streams-ads)
    - [2.1.5 NTFS Attributes (Semua Tipe)](#215-ntfs-attributes-semua-tipe)
    - [2.1.6 Resident vs Non-Resident Attribute](#216-resident-vs-non-resident-attribute)
    - [2.1.7 Compression & Encryption NTFS](#217-compression--encryption-ntfs)
    - [2.1.8 Reparse Point, Junction & Symlink](#218-reparse-point-junction--symlink)
    - [2.1.9 Hard Link](#219-hard-link)
  - [2.2 $MFT — Master File Table](#22-mft--master-file-table)
    - [2.2.1 Cara Kerja $MFT](#221-cara-kerja-mft)
    - [2.2.2 MFT Record Header (FILE0 Signature)](#222-mft-record-header-file0-signature)
    - [2.2.3 Isi Tiap MFT Record](#223-isi-tiap-mft-record)
    - [2.2.4 Data Runs](#224-data-runs)
    - [2.2.5 File Reference Number (FRN) & Sequence Number](#225-file-reference-number-frn--sequence-number)
    - [2.2.6 Directory Index ($I30)](#226-directory-index-i30)
    - [2.2.7 Tools untuk Analisa $MFT](#227-tools-untuk-analisa-mft)
    - [2.2.8 Output MFTECmd — Kolom Penting](#228-output-mftecmd--kolom-penting)
    - [2.2.9 MFT Carving & Recovery Record Terhapus](#229-mft-carving--recovery-record-terhapus)
  - [2.3 Korelasi NTFS Artifact (Tabel Cepat)](#23-korelasi-ntfs-artifact-tabel-cepat)
  - [2.4 Ringkasan Command & Tools Cheat Sheet](#24-ringkasan-command--tools-cheat-sheet)
  - [2.5 Mini Case Study — Workflow Analisa End-to-End](#25-mini-case-study--workflow-analisa-end-to-end)

---

## Bab 2 — File Sistem NTFS & Master File Table

### 2.1 File Sistem NTFS

Windows secara default menggunakan **NTFS** (New Technology File System). Ini bukan sekadar "tempat simpan file" — NTFS punya banyak metadata forensik yang menjadi dasar hampir semua tool Eric Zimmerman (MFTECmd, dst).

---

#### 2.1.0 Layout NTFS Volume

Sebelum masuk ke file-file khusus NTFS satu per satu, penting untuk lihat dulu **peta besarnya** — inilah yang muncul kalau kamu mount image di FTK Imager lalu aktifkan "Show hidden/system files" di root volume:

```
NTFS Volume
│
├── VBR ($Boot)
├── $MFT
├── $MFTMirr
├── $LogFile
├── $Volume
├── $AttrDef
├── . (Root Directory)
├── $Bitmap
├── $Boot
├── $BadClus
├── $Secure
├── $UpCase
└── $Extend
      ├── $UsnJrnl
      ├── $ObjId
      ├── $Quota
      └── $Reparse
```

> 💡 Semua file ini **hidden by default** dan tidak muncul di Explorer biasa — tapi terlihat jelas kalau kamu browse image lewat FTK Imager, Autopsy, atau mount read-only lewat `Arsenal Image Mounter`. Kalau baru pertama kali lihat daftar ini di FTK Imager, jangan panik — fungsi tiap file dibahas detail di **2.1.1**.

Secara konsep, urutan "dari disk sampai ke isi file" yang dipakai di seluruh Bab 2 ini adalah:

```
Disk
 └── Partition (NTFS Volume)
      └── $MFT (database record per file/folder)
           └── Attribute (SI, FN, DATA, INDEX, dst — lihat 2.1.5)
                └── Resident (nempel di record) ATAU Non-Resident (data runs → cluster, lihat 2.1.6 & 2.2.4)
```

---

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
| `$UpCase` | Root volume | Tabel konversi uppercase Unicode — dipakai NTFS untuk perbandingan nama file case-insensitive |
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
| `ParentFileReferenceNumber` | Folder induk saat perubahan terjadi — berguna untuk lacak file yang di-*move* antar folder (lihat **2.2.5** soal format FRN) |

> 💡 **Tip CTF:** Kombinasi `FileCreate` → `RenameOldName`/`RenameNewName` → `FileDelete` di `UpdateReasons` untuk file yang sama adalah pola klasik **"drop payload → rename supaya menyamar → hapus"** yang sering dipakai malware/attacker untuk anti-forensik.

---

#### 2.1.2 Timestamps NTFS (4 Timestamp per File)

Setiap file di NTFS punya **2 set timestamp** yang tersimpan di **2 attribute berbeda** di dalam MFT record yang sama:

| Attribute | Timestamp yang disimpan | Karakteristik |
|---|---|---|
| `$STANDARD_INFORMATION` (SI) | Modified, Accessed, Created (Born), MFT Changed — sering disingkat **MACB** | Yang ditampilkan Windows Explorer (`Properties`); **bisa dimanipulasi attacker via timestomping** |
| `$FILE_NAME` (FN) | 4 timestamp yang sama (Modified, Accessed, Created, MFT Changed) | Update lebih jarang (hanya saat rename/move/create), **lebih susah dimanipulasi** karena butuh akses low-level ke MFT langsung |

**Kenapa ada 2 set?** SI dirancang untuk kebutuhan aplikasi/user (gampang diubah program), sedangkan FN adalah bagian dari struktur index direktori NTFS (`$I30`, lihat **2.2.6**) — perubahannya lebih terbatas dan biasanya cuma ter-update saat operasi filesystem-level (create, rename, move).

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

> 💡 **Tip CTF:** Kalau ukuran file di Explorer kecil tapi soal bilang *"payload disembunyikan di file ini"*, itu sinyal kuat cek ADS. Zone.Identifier yang berisi `ZoneId=3` menandakan file didownload dari internet — berguna untuk membuktikan file datang dari luar (misal browser download), bukan dibuat lokal. ADS berukuran kecil juga bisa **resident** langsung di MFT record — lihat **2.1.6**.

---

#### 2.1.5 NTFS Attributes (Semua Tipe)

Inti sebenarnya dari NTFS bukan "file dan folder", tapi **attribute**. Setiap MFT record cuma berisi kumpulan attribute berurutan berdasarkan kode hex-nya, dan semua yang kamu lihat di Explorer (nama, timestamp, isi file, ACL, dst) sebenarnya adalah hasil parsing attribute-attribute ini.

| Attribute | Hex | Fungsi | Nilai Forensik |
|---|---|---|---|
| `$STANDARD_INFORMATION` | `0x10` | Timestamp SI (MACB), flag file (hidden/system/archive), owner ID | Target utama timestomping — lihat **2.1.2 & 2.1.3** |
| `$ATTRIBUTE_LIST` | `0x20` | Daftar lokasi attribute lain kalau record terlalu besar dan "meluber" ke MFT record tambahan (extension record) | Muncul di file dengan banyak fragment/ADS/hard link — tanda record sudah "penuh" |
| `$FILE_NAME` | `0x30` | Nama file, timestamp FN, parent directory reference | Satu record bisa punya **lebih dari satu** `$FILE_NAME` — indikasi hard link (**2.1.9**) atau short filename (8.3) |
| `$OBJECT_ID` | `0x40` | GUID unik file, dipakai untuk tracking shortcut/link lintas volume | Berguna untuk korelasi LNK file yang menunjuk ke file yang sudah dipindah/rename |
| `$SECURITY_DESCRIPTOR` | `0x50` | ACL & owner (legacy — NTFS modern biasanya simpan pointer ke `$Secure`) | Bisa ungkap siapa "pemilik" file saat dibuat |
| `$VOLUME_NAME` | `0x60` | Label volume (hanya ada di record `$Volume`) | Identifikasi volume dari raw image |
| `$VOLUME_INFORMATION` | `0x70` | Versi NTFS & dirty flag (hanya ada di record `$Volume`) | Dirty flag bisa jadi indikasi shutdown tidak normal / disk di-clone saat mounted |
| `$DATA` | `0x80` | Isi file sebenarnya (resident) atau data runs penunjuk cluster (non-resident) | Attribute paling sering diperiksa — lihat **2.1.6** & **2.2.4** |
| `$INDEX_ROOT` | `0x90` | Bagian awal index direktori (`$I30`), resident, muat entry index kecil | Lihat **2.2.6** |
| `$INDEX_ALLOCATION` | `0xA0` | Kelanjutan index direktori kalau isi folder besar, non-resident | Lihat **2.2.6** — sering jadi sumber recovery nama file terhapus |
| `$BITMAP` | `0xB0` | Peta bit slot index mana yang terpakai (dipakai baik oleh `$MFT` maupun `$I30`) | Menentukan slot index/record mana yang "aktif" vs "kosong tapi belum ditimpa" |
| `$REPARSE_POINT` | `0xC0` | Data reparse tag (symlink, junction, cloud placeholder) | Lihat **2.1.8** |
| `$EA` / `$EA_INFORMATION` | `0xD0` / `0xE0` | Extended attribute (legacy OS/2 compatibility) | Jarang dipakai, tapi kadang dipakai malware lawas untuk stashing data kecil |
| `$LOGGED_UTILITY_STREAM` | `0x100` | Data pendukung fitur seperti EFS (`$EFS`) atau transaksi TxF | Lihat **2.1.7** — indikator file terenkripsi EFS |

> 💡 Ini sangat berguna saat melihat **raw MFT record** di hex editor atau di tool seperti MFTExplorer: setiap attribute selalu diawali 4 byte tipe (hex di atas, little-endian) diikuti panjang attribute — jadi kalau kamu tahu urutan ini, kamu bisa "membaca" record MFT mentah tanpa parser sama sekali.

---

#### 2.1.6 Resident vs Non-Resident Attribute

Setiap attribute (terutama `$DATA`) di NTFS punya dua kemungkinan cara penyimpanan:

```
Resident
├─ Data attribute ikut nempel langsung di dalam MFT record (1024 byte)
└─ Biasanya untuk file kecil (kira-kira < 700-900 byte, tergantung attribute lain di record itu)

Non-Resident
├─ MFT record hanya menyimpan header attribute + data runs (pointer)
└─ Isi data sebenarnya berada di cluster lain di disk — lihat Data Runs (2.2.4)
```

| Aspek | Resident | Non-Resident |
|---|---|---|
| Lokasi data | Di dalam MFT record itu sendiri | Di cluster lain, MFT cuma simpan pointer (data run) |
| Ukuran tipikal | File sangat kecil | File berukuran normal ke besar |
| Kecepatan baca | Lebih cepat (satu kali baca record) | Perlu baca record + ikuti data run ke cluster |
| Bisa langsung dibaca dari `$MFT` mentah? | **Ya** — bahkan kalau file induknya sudah dihapus dari disk | Tidak — kalau cluster datanya sudah ditimpa, isi file hilang meski record MFT-nya masih ada |

**Nilai forensik:**
- File kecil (dokumen teks pendek, config, script kecil) bisa ditemukan **utuh langsung dari `$MFT`**, tanpa perlu carving cluster lain sama sekali.
- ADS kecil (**2.1.4**) sering resident — payload kecil attacker (misal script PowerShell singkat) bisa langsung terbaca dari record MFT.
- Malware config kecil (IP C2, key, path) sering disimpan resident supaya tidak meninggalkan jejak terpisah di cluster data.
- Sebaliknya, kalau attribute non-resident dan cluster-nya sudah ditimpa, MFT record hanya kasih tahu "file ini pernah ada segini besar" tanpa isinya — perlu carving (**2.2.9**).

> 💡 **Cara cek cepat:** di MFTExplorer atau output MFTECmd biasanya ada flag `Resident`/`Non-Resident` per attribute. Kalau lihat hex mentah, byte non-resident flag ada di offset tertentu pada header attribute (0 = resident, 1 = non-resident).

---

#### 2.1.7 Compression & Encryption NTFS

NTFS punya dua fitur bawaan yang sering muncul di soal DFIR karena berdampak langsung ke bagaimana data disimpan:

**NTFS Compression**
- Kompresi transparan per-file atau per-folder (`compact /c`), memecah data jadi *compression unit* (biasanya 16 cluster) sebelum ditulis.
- File yang di-compress ditandai flag `FILE_ATTRIBUTE_COMPRESSED` di `$STANDARD_INFORMATION`.
- Forensik: parser yang tidak sadar kompresi bisa salah baca ukuran/isi data run — pastikan tool carving/parsing MFT yang dipakai mendukung ini (mis. MFTECmd sudah handle).

**EFS (Encrypting File System)**
- Fitur enkripsi bawaan NTFS per-file, berbeda dari BitLocker (yang enkripsi seluruh volume).
- File terenkripsi EFS punya attribute tambahan `$LOGGED_UTILITY_STREAM` bernama `$EFS` (**0x100**, lihat **2.1.5**) yang menyimpan certificate/key info.
- Flag `FILE_ATTRIBUTE_ENCRYPTED` juga muncul di `$STANDARD_INFORMATION`.

| Artefak EFS | Fungsi Forensik |
|---|---|
| Attribute `$EFS` di MFT record | Konfirmasi file memang dienkripsi EFS (bukan cuma "tidak bisa dibuka") |
| Recovery Agent (DRA) certificate | Kalau ada di sistem/domain, bisa dipakai decrypt tanpa key user asli |
| `%APPDATA%\Microsoft\Crypto\RSA\` | Lokasi private key user yang dipakai EFS — kalau ter-acquire, file EFS bisa didekripsi offline |
| Export `.pfx` user | Kalau attacker/investigator punya ini + password, file EFS bisa dibuka di sistem lain |

> ⚠️ **Catatan:** Kompresi & enkripsi NTFS ini level filesystem, beda dengan enkripsi aplikasi (mis. ransomware yang enkripsi ulang isi file dengan algoritma sendiri). Jangan disalahartikan — cek dulu apakah flag `FILE_ATTRIBUTE_ENCRYPTED` NTFS menyala atau ini murni ulah malware.

---

#### 2.1.8 Reparse Point, Junction & Symlink

**Pengertian:** Reparse point adalah mekanisme NTFS untuk "mengalihkan" akses ke suatu path ke lokasi lain, disimpan di attribute `$REPARSE_POINT` (`0xC0`, lihat **2.1.5**). Dipakai untuk symbolic link, directory junction, dan (di Windows modern) placeholder cloud storage seperti OneDrive.

```
Documents and Settings   (path lama, Windows XP era)
        │
        ▼  (Junction / reparse point)
      Users                     (path aktual Windows modern)
```

```
OneDrive\Documents\file.docx
        │
        ▼  (reparse tag: cloud placeholder)
   File belum benar-benar ada di disk — hanya metadata "on-demand"
   sampai user membukanya (isi sebenarnya di cloud)
```

| Tipe | Dibuat dengan | Reparse Tag Umum |
|---|---|---|
| Directory Junction | `mklink /J` | `IO_REPARSE_TAG_MOUNT_POINT` |
| Symbolic Link (file/folder) | `mklink` / `mklink /D` | `IO_REPARSE_TAG_SYMLINK` |
| OneDrive Files On-Demand | Otomatis oleh OneDrive client | `IO_REPARSE_TAG_CLOUD` |
| Deduplication (Server) | NTFS Data Deduplication | `IO_REPARSE_TAG_DEDUP` |

**Cara Analisa:**
```powershell
# Cek reparse point di live system
fsutil reparsepoint query C:\path\to\target

# Tampilkan junction/symlink di listing folder
dir /a:l
```

**Nilai forensik:**
- Attacker bisa pakai symlink/junction untuk **redirect analyst** ke path yang salah, atau untuk **privilege escalation** (symlink attack ke file sistem yang di-load proses privileged).
- File OneDrive yang "terlihat ada" di Explorer belum tentu isinya sudah didownload ke disk lokal — penting dibedakan saat menilai apakah data benar-benar pernah tersimpan lokal.
- `$Reparse` index di `\$Extend\$Reparse` (**2.1.1**) menyimpan daftar semua reparse point di volume — cepat untuk cari junction/symlink mencurigakan tanpa scan seluruh `$MFT`.

---

#### 2.1.9 Hard Link

**Pengertian:** NTFS mengizinkan **lebih dari satu nama file** menunjuk ke **MFT record (dan data) yang sama** — beda dengan shortcut/symlink yang cuma "pointer", hard link adalah nama alternatif murni di level filesystem.

```
report.docx      ─┐
                   ├──►  MFT Record #1234  ──►  Data yang SAMA persis
secret.docx       ─┘
```

- Kedua nama (`report.docx` dan `secret.docx`) muncul sebagai **dua attribute `$FILE_NAME` (0x30) terpisah** di dalam **satu MFT record** yang sama (**2.1.5**).
- Karena data-nya benar-benar sama (bukan copy), hash file (MD5/SHA256) akan **identik**, dan `EntryNumber`/FRN (**2.2.5**) juga **identik**.

**Nilai forensik:**
- File yang "terlihat berbeda" (nama, lokasi folder beda) tapi punya hash sama dan `EntryNumber` sama di output MFTECmd → itu hard link, bukan file duplikat biasa.
- Sering dipakai attacker untuk membuat payload "terlihat legit" di path lain tanpa harus copy ulang data (menghemat jejak I/O tambahan).
- Saat investigasi, cek kolom hard link count di MFT record header (**2.2.2**) — kalau > 1, berarti file ini punya nama lain yang perlu dicari juga.

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

---

#### 2.2.2 MFT Record Header (FILE0 Signature)

Sebelum masuk ke isi (attribute) tiap record, tiap MFT record selalu diawali **header tetap** yang menjelaskan record itu sendiri:

```
MFT Record Header
│
├── FILE Signature        ("FILE" di awal record — atau "BAAD" kalau record corrupt)
├── Update Sequence Array (mekanisme deteksi write yang terputus di tengah)
├── Sequence Number        (naik tiap slot record dipakai ulang — lihat 2.2.5)
├── Hard Link Count         (berapa banyak $FILE_NAME menunjuk record ini — lihat 2.1.9)
├── Flags                   (in-use? directory? — lihat tabel di bawah)
├── Used Size               (ukuran data yang benar-benar terpakai di record)
├── Allocated Size          (ukuran slot record, biasanya 1024 byte)
└── First Attribute Offset  (dari sini parser mulai baca attribute pertama, lihat 2.1.5)
```

| Flag (offset header) | Arti |
|---|---|
| `0x00` | Record tidak terpakai (unused) |
| `0x01` | Record terpakai, file biasa (`InUse = True`) |
| `0x02` | Record terpakai, directory |
| `0x03` | Record terpakai, directory + in use |

**Kenapa header ini penting untuk carving:** Ketika mencari record MFT yang sudah terhapus/orphan di unallocated space, kita tidak bisa mengandalkan parser normal (karena struktur `$MFT` di sekitarnya sudah tidak utuh). Yang dicari justru **signature mentah** di awal tiap record:

```
Signature "FILE" dalam hex:  46 49 4C 45
Signature "BAAD" (corrupt):  42 41 41 44
```

```bash
# Cari signature FILE0 secara manual (grep pola hex di raw image)
grep -abo $'\x46\x49\x4c\x45' disk.dd

# Atau otomatis lewat bulk_extractor / scalpel dengan signature FILE header
bulk_extractor -o out_dir disk.dd
```

> 💡 Kalau kamu carving unallocated space dan menemukan blok 1024 byte yang diawali `46 49 4C 45` (`FILE`), itu **hampir pasti** satu MFT record utuh (atau sebagian, tergantung fragmentasi) — lanjut ke **2.2.9**.

---

#### 2.2.3 Isi Tiap MFT Record

Setiap MFT Record berisi (dalam bentuk attribute, bukan field flat):

| Bagian | Isi |
|---|---|
| Nama file | Dari attribute `$FILE_NAME` (0x30) |
| Path lengkap | Direkonstruksi dari `ParentEntryNumber` (parent-child chain) |
| Ukuran file | Dari attribute `$DATA` (real size vs allocated size) |
| Timestamps (SI & FN) | Dari `$STANDARD_INFORMATION` (0x10) dan `$FILE_NAME` (0x30) — lihat **2.1.2** |
| Status dihapus | `InUse` flag di record header — `False` = sudah dihapus (record masih ada sampai ditimpa) — lihat **2.2.2** |
| Lokasi data di disk | **Data runs** — kalau file resident (kecil), datanya ikut nempel di record; kalau non-resident, cuma pointer ke cluster di disk — lihat **2.1.6** & **2.2.4** |

> 💡 File kecil (misal beberapa baris teks) bisa **resident** — artinya isinya langsung ada di dalam MFT record itu sendiri, tanpa perlu baca cluster lain sama sekali. Ini penting kalau kamu carving `$MFT` mentah dan nemu file kecil utuh langsung di situ.

---

#### 2.2.4 Data Runs

Untuk attribute **non-resident** (**2.1.6**), MFT record tidak menyimpan isi data — hanya **pointer** ke lokasi cluster tempat data sebenarnya berada. Pointer inilah yang disebut **data run**.

```
File
 ↓
MFT Record
 ↓
Data Runs           (daftar pasangan "mulai di cluster berapa, sepanjang berapa cluster")
 ↓
Cluster (disk)
```

**Contoh data run untuk satu file (fragmented):**
```
Data Run 1:  Cluster 100–120   (21 cluster pertama)
Data Run 2:  Cluster 450–470   (lanjutan file, terpisah / fragmented)
```

Secara mentah, data run disimpan dalam format **run-length encoded**: setiap run diawali 1 byte header yang menyatakan berapa byte dipakai untuk *panjang* run dan berapa byte untuk *offset* (relatif ke run sebelumnya), lalu diikuti nilai-nilainya. Kamu tidak perlu decode manual sehari-hari — tool seperti **MFTExplorer** menampilkan data run per attribute secara visual — tapi paham konsepnya penting untuk kasus carving manual.

**Nilai forensik:**
- **Recovery file terhapus:** kalau record MFT masih ada tapi cluster belum ditimpa, data run masih menunjuk ke lokasi data asli yang bisa langsung diambil.
- **Carving:** saat carving manual, data run kasih tahu persis cluster mana yang harus diambil — jauh lebih presisi daripada carving signature murni (PhotoRec/Foremost) yang menebak batas file dari isi saja.
- **Fragmented file:** kalau data run terdiri dari banyak run terpisah (bukan 1 run kontinu), artinya file tersebut fragmented di disk — penting diketahui supaya proses recovery/carving mengambil **semua** run, bukan cuma run pertama (kalau cuma ambil run pertama, hasil recovery akan corrupt/terpotong).

> ⚠️ **Tip CTF:** Soal yang minta "recover isi file X yang sudah dihapus" kadang sengaja pakai file fragmented supaya solver yang cuma baca run pertama dapat file rusak. Selalu cek MFTExplorer/hex apakah ada lebih dari satu data run sebelum menyimpulkan recovery selesai.

---

#### 2.2.5 File Reference Number (FRN) & Sequence Number

**File Reference Number (FRN)** adalah "alamat" unik sebuah file di dalam `$MFT`, gabungan dari dua nilai:

```
EntryNumber     = 1234   (nomor slot record di $MFT)
SequenceNumber  = 5      (berapa kali slot ini sudah dipakai ulang)

FRN = 1234-5
```

Secara teknis, FRN adalah nilai 64-bit yang menggabungkan `EntryNumber` (48 bit) dan `SequenceNumber` (16 bit) — sering ditulis sebagai `EntryNumber-SequenceNumber` di output tool forensik.

**Kenapa perlu Sequence Number?** Karena slot MFT record **dipakai ulang**. Ketika sebuah file dihapus dan record-nya akhirnya ditimpa file baru, `EntryNumber` yang sama bisa dipakai lagi — tapi `SequenceNumber` akan **bertambah 1**, supaya referensi lama (misal dari `$UsnJrnl` atau LNK file) tidak salah menunjuk ke file yang baru menempati slot tersebut.

```
Entry 123, Sequence 1   → file_lama.txt (dibuat)
        ↓ file_lama.txt dihapus, slot jadi kosong
Entry 123, Sequence 2   → file_baru.exe (dibuat, menempati slot yang sama)
```

Kalau ada artefak lain yang masih menyimpan referensi `123-1`, itu **pasti** menunjuk ke `file_lama.txt`, bukan `file_baru.exe` — meskipun `EntryNumber`-nya sama.

**Di mana FRN muncul:**

| Artefak | Kegunaan FRN di sana |
|---|---|
| `$MFT` | `ParentEntryNumber` merekonstruksi `FullPath` (parent-child chain) |
| `$UsnJrnl` | `FileReferenceNumber` & `ParentFileReferenceNumber` — lacak file spesifik meski nama berubah |
| Prefetch | Menyimpan FRN dari file/DLL yang diakses program — bisa cross-check apakah file yang dijalankan memang file yang "seharusnya" (bukan yang sudah diganti diam-diam) |
| LNK file | Menyimpan FRN target asli — bisa membuktikan shortcut menunjuk ke file yang sekarang sudah tidak ada / sudah diganti |
| JumpList | Sama seperti LNK, menyimpan referensi FRN target file terakhir dibuka |

**Nilai forensik:**
- **Tracking rename:** `EntryNumber` tetap sama walau nama file berubah — file yang di-rename tetap bisa dilacak sebagai "file yang sama" via FRN, dikombinasikan dengan `$UsnJrnl` (**2.1.1**).
- **Tracking move:** `ParentFileReferenceNumber` yang berubah antar entry `$UsnJrnl` menunjukkan file dipindah folder.
- **Tracking deleted & reused slot:** kalau ada artefak menunjuk ke FRN dengan `SequenceNumber` lebih rendah dari yang sekarang ada di `$MFT`, itu bukti kuat file tersebut **sudah dihapus dan slot-nya dipakai file lain** — berguna untuk membuktikan keberadaan file yang sudah tidak ada sama sekali di `$MFT` terkini.

---

#### 2.2.6 Directory Index ($I30)

**Pengertian:** Folder di NTFS tidak menyimpan daftar isinya sebagai list flat — melainkan sebagai **struktur index (B-tree)** bernama `$I30`, yang tersusun dari beberapa attribute:

```
Directory Index ($I30)

Folder (MFT Record folder tersebut)
│
├── $INDEX_ROOT       (0x90) → bagian index kecil, resident, entry pertama
├── $INDEX_ALLOCATION (0xA0) → kelanjutan index kalau folder isinya banyak, non-resident
└── $BITMAP           (0xB0) → menandai slot index mana yang aktif/kosong
```

Tiap entry di dalam `$I30` menyimpan salinan `$FILE_NAME` (nama + timestamp FN) dari setiap file/subfolder yang ada di dalam folder tersebut — jadi `$I30` sebenarnya adalah **daftar isi folder + metadata ringan**, terpisah dari `$MFT` record file itu sendiri.

**Nilai forensik:**
- **Nama file terhapus:** ketika sebuah file dihapus, entry-nya di `$I30` folder induk **tidak langsung hilang** — slot index di `$INDEX_ALLOCATION` (mirip slot di `$MFT`) hanya ditandai kosong dan boleh ditimpa. Selama belum ditimpa, nama file + timestamp FN masih bisa dibaca — **bahkan kalau record `$MFT` file itu sendiri sudah ditimpa total**.
- **Bukti file pernah ada:** ini jadi salah satu sumber recovery paling kuat ketika `$MFT` record aslinya sudah hilang — `$I30` adalah "jejak kedua" yang independen dari `$MFT`.
- **Child file history:** membantu merekonstruksi isi folder di masa lalu (file apa saja yang pernah ada di folder tertentu), berguna untuk timeline aktivitas attacker di suatu direktori (mis. Downloads, Temp, staging folder).

**Cara Analisa:**
```bash
# INDXRipper — parsing $I30 index attribute untuk temukan nama file terhapus
python indx_ripper.py image.dd <entry_number_folder> -o output.csv
# <entry_number_folder> = EntryNumber (2.2.5) dari folder yang mau dicek, bisa didapat dari MFTECmd

# FTK Imager juga bisa export raw $INDEX_ALLOCATION dari sebuah folder record untuk dianalisa manual
```

> 💡 **Tip CTF:** Ini **sangat sering** jadi jawaban challenge yang menanyakan "file apa yang pernah ada di folder X sebelum dihapus, padahal MFT-nya sudah tidak ada". Kalau `MFTECmd` sudah tidak menemukan record file yang dicari, coba parsing `$I30` folder induknya dengan INDXRipper sebelum menyerah.

---

#### 2.2.7 Tools untuk Analisa $MFT

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
| **MFTExplorer** | GUI untuk browse `$MFT` record secara visual, termasuk lihat data run dan raw attribute | Bagus untuk verifikasi manual satu-per-satu record, termasuk cek data run (**2.2.4**) dan resident/non-resident (**2.1.6**) |
| **Timeline Explorer** | Untuk buka hasil CSV MFTECmd dan filter/sort/search dengan cepat | Sering dipakai gabung timeline dari beberapa sumber (MFT + EVTX + Registry) |
| **analyzeMFT** (Python, open-source) | Alternatif CLI cross-platform kalau tidak bisa pakai tool .NET (mis. di Linux/Mac) | `python3 analyzeMFT.py -f \$MFT -o output.csv` |
| **FTK Imager** | Bisa export `$MFT` mentah langsung dari image tanpa perlu mount volume dulu | Langkah pertama sebelum jalankan MFTECmd |
| **INDXRipper** (Python) | Parsing `$I30` index attribute (index direktori NTFS) untuk temukan **nama file yang sudah dihapus** dari sebuah folder, walau record `$MFT`-nya sendiri sudah ditimpa | `python indx_ripper.py image.dd 5 -o output.csv` (5 = MFT entry number dari folder yang mau dicek) — lihat **2.2.6** |
| **bulk_extractor** | Scan seluruh image untuk pola signature (termasuk `FILE0` header MFT record, **2.2.2**) — berguna untuk carving record yang terisolasi di unallocated space | `bulk_extractor -o output_dir disk.dd` |

---

#### 2.2.8 Output MFTECmd — Kolom Penting

| Kolom | Keterangan |
|---|---|
| `EntryNumber` | ID unik record di MFT — bagian dari FRN, lihat **2.2.5** |
| `SequenceNumber` | Berapa kali slot ini sudah dipakai ulang — bagian dari FRN, lihat **2.2.5** |
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

#### 2.2.9 MFT Carving & Recovery Record Terhapus

**Pengertian:** Kalau sebuah file dihapus, record-nya di `$MFT` **tidak langsung hilang** — flag `InUse` cuma diubah jadi `False`, dan slot record itu ditandai "boleh ditimpa". Selama belum ada file baru yang kebagian slot itu, record lama (termasuk nama file & timestamp aslinya) **masih bisa dibaca**.

```
Skenario recovery bertingkat:
1. Parsing $MFT normal (MFTECmd)          → record InUse=False = file terhapus, tapi record masih utuh
2. Parsing $I30 index folder (INDXRipper)  → nama file terhapus, walau record $MFT-nya sudah ditimpa (2.2.6)
3. Carving signature "FILE0" di unallocated space (bulk_extractor / scalpel)
                                            → record MFT yang sudah "orphan" (lepas dari struktur $MFT normal, 2.2.2)
4. Carving isi file itu sendiri di unallocated (PhotoRec/Foremost) → kalau cluster datanya juga belum ditimpa
                                            → posisi cluster asli sebenarnya sudah diketahui dari data run (2.2.4) selama record MFT-nya masih ada
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

### 2.3 Korelasi NTFS Artifact (Tabel Cepat)

Tabel ini adalah "contekan super cepat" yang paling sering dibuka pas lagi kerja soal CTF/HTB Sherlock — pertanyaan umum vs artefak NTFS mana yang paling relevan untuk menjawabnya.

| Pertanyaan | Artefak Utama | Bagian |
|---|---|---|
| File dibuat kapan | `$MFT` (SI/FN Created) | 2.1.2, 2.2.8 |
| File dihapus kapan | `$UsnJrnl` (`FileDelete`) | 2.1.1 |
| File pernah ada walau record `$MFT` sudah hilang | `$I30` (Directory Index) | 2.2.6 |
| Rename file | `$UsnJrnl` (`RenameOldName`/`RenameNewName`) + FRN yang sama | 2.1.1, 2.2.5 |
| File dipindah folder | `$UsnJrnl` — `ParentFileReferenceNumber` berubah | 2.1.1, 2.2.5 |
| Isi file terhapus | Data Runs (kalau cluster belum ditimpa) → Carving | 2.2.4, 2.2.9 |
| Timestomp / manipulasi waktu | SI vs FN mismatch | 2.1.2, 2.1.3 |
| File kecil/payload tersembunyi | Resident attribute / ADS | 2.1.4, 2.1.6 |
| File "duplikat" tapi hash sama | Hard link (multiple `$FILE_NAME` di 1 record) | 2.1.9 |
| Path/file terlihat aneh atau dialihkan | Reparse Point (junction/symlink/OneDrive) | 2.1.8 |
| File terenkripsi tanpa jelas alasannya | Attribute `$EFS` (`$LOGGED_UTILITY_STREAM`) | 2.1.7 |
| Transaksi filesystem paling presisi/granular | `$LogFile` | 2.1.1 |
| Record MFT sudah rusak/corrupt saat dibaca | Cek signature header (`FILE` vs `BAAD`) | 2.2.2 |

> 💡 **Prinsip pemakaian tabel ini:** mulai dari kolom kiri (pertanyaan di soal), lalu langsung lompat ke bagian yang tertera tanpa perlu baca ulang seluruh Bab 2 dari awal.

---

### 2.4 Ringkasan Command & Tools Cheat Sheet

Satu tabel rangkuman semua tool yang dibahas di Bab 2 ini — dipakai sebagai contekan cepat pas lagi kerja soal.

| Artefak | Tool Utama | Command Contoh | Kegunaan |
|---|---|---|---|
| `$MFT` | `MFTECmd.exe` | `.\MFTECmd.exe -f ".\$MFT" --csv . --fl` | Timeline lengkap semua file (termasuk terhapus) |
| `$MFT` (GUI) | `MFTExplorer` | — | Inspeksi manual satu record, lihat raw attribute & data run |
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
| Reparse point (live) | `fsutil` | `fsutil reparsepoint query <path>` | Cek symlink/junction/cloud placeholder |
| Timeline gabungan | `Timeline Explorer` | — | Buka & filter CSV dari MFTECmd/EvtxECmd/RECmd sekaligus |

---

### 2.5 Mini Case Study — Workflow Analisa End-to-End

Contoh alur berpikir kalau soal CTF/HTB Sherlock bilang: *"attacker menjalankan sebuah executable, lalu mengganti namanya, menghapusnya, dan mencoba menutupi jejak waktu eksekusi — buktikan!"*

```
Langkah 1 — Cari eksekusi program
   └── Windows\Prefetch\ (.pf files) → PECmd.exe
       → dapat nama file & waktu eksekusi kasar (dari nama Prefetch)

Langkah 2 — Cari record file tersebut di $MFT
   └── MFTECmd.exe -f ".\$MFT" --csv . --fl
       → cek FullPath, Created0x10, Created0x30, InUse, EntryNumber (2.2.5)

Langkah 3 — Bandingkan SI vs FN (2.1.3)
   └── Kalau Created0x10 != Created0x30 secara signifikan → indikasi timestomping

Langkah 4 — Rekonstruksi rename & delete dari $UsnJrnl
   └── MFTECmd.exe -f "$Extend\$UsnJrnl:$J" --csv . --de
       → cari UpdateReasons: FileCreate → RenameOldName/RenameNewName → FileDelete
       → cocokkan lewat FileReferenceNumber yang sama (2.2.5), bukan cuma nama
       → dapat nama ASLI sebelum di-rename + waktu pasti tiap event (lebih presisi dari SI yang bisa dipalsu)

Langkah 5 — Cross-check ke $LogFile
   └── LogFileParser.exe -f "$LogFile" --csv .
       → verifikasi transaksi filesystem-level benar-benar terjadi di waktu yang diklaim $UsnJrnl

Langkah 6 — Kalau nama file di $MFT sudah tidak ada sama sekali, cek $I30 folder induknya
   └── python indx_ripper.py disk.dd <entry_number_folder> -o out.csv (2.2.6)
       → kadang nama file masih terekam di index folder walau record $MFT-nya sudah ditimpa total

Langkah 7 — Cek apakah file masih bisa direcover
   └── Kalau InUse=False dan belum lama dihapus → cek data run (2.2.4), lalu carving (2.2.9)
       → PhotoRec / bulk_extractor untuk lihat isi asli file (mungkin ada indikator malware/flag)

Kesimpulan yang bisa ditulis di laporan:
"File X dieksekusi pada waktu Y (Prefetch), sempat di-rename dari nama_asli.exe menjadi nama_samaran.exe
pada waktu Z (UsnJrnl, dikonfirmasi via FileReferenceNumber yang sama), lalu dihapus. Timestamp
$STANDARD_INFORMATION dimanipulasi untuk terlihat lebih tua dari $FILE_NAME (SI vs FN mismatch),
mengindikasikan penggunaan teknik timestomping."
```

> 💡 **Prinsip umum:** Jangan cuma andalkan satu sumber data. `$MFT` kasih "kondisi sekarang", `$UsnJrnl` kasih "riwayat perubahan", `$LogFile` kasih "bukti transaksi paling granular", dan `$I30` kasih "jejak cadangan" kalau `$MFT`-nya sendiri sudah tidak bisa diandalkan. Kombinasi semuanya jauh lebih kuat daripada cuma baca satu-satu.

---
