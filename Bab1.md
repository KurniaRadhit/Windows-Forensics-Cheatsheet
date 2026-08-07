## 📌 Daftar Isi — Bab 1

- [Bab 1 — Struktur Windows & Filesystem](#bab-1-struktur-windows-filesystem)
  - [1.1 Struktur Drive & Partisi](#11-struktur-drive-partisi)
    - [1.1.1 Sector vs Cluster](#111-sector-vs-cluster)
    - [1.1.2 LBA (Logical Block Addressing)](#112-lba-logical-block-addressing)
    - [1.1.3 Filesystem Overview](#113-filesystem-overview)
    - [1.1.4 Physical Disk vs Partition vs Volume](#114-physical-disk-vs-partition-vs-volume)
    - [1.1.5 MBR vs GPT](#115-mbr-vs-gpt)
    - [1.1.6 Partisi Umum di Disk Windows](#116-partisi-umum-di-disk-windows)
    - [1.1.7 VBR (Volume Boot Record)](#117-vbr-volume-boot-record)
    - [1.1.8 Boot Process Overview](#118-boot-process-overview)
    - [1.1.9 Disk Signature / GUID](#119-disk-signature-guid)
    - [1.1.10 Cara Analisa di FTK Imager / KAPE](#1110-cara-analisa-di-ftk-imager-kape)
    - [1.1.11 Unallocated Space & Slack Space](#1111-unallocated-space-slack-space)
    - [1.1.12 Full Path Tree — Disk & Partition Level](#1112-full-path-tree-disk-partition-level)
    - [1.1.13 Disk Image Format](#1113-disk-image-format)
    - [1.1.14 Hidden Partition & Recovery Artefacts](#1114-hidden-partition-recovery-artefacts)
  - [1.2 Struktur Direktori Windows (C:\\)](#12-struktur-direktori-windows-c)
    - [1.2.1 Root C:\\ — Overview](#121-root-c-overview)
    - [1.2.2 Windows\\](#122-windows)
    - [1.2.3 Windows\\System32\\](#123-windowssystem32)
    - [1.2.4 Arsitektur Windows: System32 vs SysWOW64](#124-arsitektur-windows-system32-vs-syswow64)
    - [1.2.5 Users\\](#125-users)
    - [1.2.6 AppData Tree](#126-appdata-tree)
    - [1.2.7 Environment Variable](#127-environment-variable)
    - [1.2.8 Program Files\\ & Program Files (x86)\\](#128-program-files-program-files-x86)
    - [1.2.9 ProgramData\\](#129-programdata)
    - [1.2.10 PerfLogs\\](#1210-perflogs)
    - [1.2.11 $Recycle.Bin\\](#1211-recyclebin)
    - [1.2.12 Tabel Prioritas Investigasi](#1212-tabel-prioritas-investigasi)
    - [1.2.13 Root-Level Files & Folder yang Sering Terlewat](#1213-root-level-files-folder-yang-sering-terlewat)
    - [1.2.14 Full Path Tree — Seluruh C:\\ (Master Reference)](#1214-full-path-tree-seluruh-c-master-reference)
- [📍 Penutup Bab 1 — Windows Storage Architecture (Big Picture)](#📍-penutup-bab-1-windows-storage-architecture-big-picture)

---

## Bab 1 — Struktur Windows & Filesystem

### 1.1 Struktur Drive & Partisi

#### 1.1.1 Sector vs Cluster

**Pengertian & Fungsi:**
Sebelum bicara MBR/GPT/VBR, penting dulu paham hierarki penyimpanan data paling dasar — semua struktur di atasnya (termasuk NTFS internals di Bab 2) dibangun di atas konsep ini.

```
Disk
 │
 ├── Sector    ← unit terkecil level HARDWARE/disk
 │
 ├── Cluster   ← unit terkecil level FILESYSTEM (kumpulan beberapa sector)
 │
 └── File      ← selalu dialokasikan dalam kelipatan cluster, bukan byte
```

Contoh cluster size 4096 byte dengan sector 512 byte:

```
Disk
│
├── Sector 0
├── Sector 1
├── Sector 2
├── ...
│
Cluster 0  = Sector 0–7
Cluster 1  = Sector 8–15
Cluster 2  = Sector 16–23
```

| Istilah | Pengertian |
|---|---|
| **Physical Sector** | Ukuran sector sesungguhnya di media fisik disk/SSD |
| **Logical Sector** | Ukuran sector yang "dilaporkan" ke OS — bisa beda dari physical sector |
| **512B sector** | Standar lama, masih dipakai untuk kompatibilitas |
| **4K sector (Advanced Format / 4Kn)** | Standar disk modern; kalau di-emulasi ke 512B logis disebut **512e** |
| **Cluster (Allocation Unit)** | Unit terkecil yang dipakai filesystem untuk mengalokasikan file — gabungan beberapa sector berurutan |

> ⚠️ **Konsekuensi penting:** Karena file selalu dialokasikan dalam kelipatan cluster, file 1 byte tetap "memakan" 1 cluster penuh (misal 4096 byte). Sisa ruang yang tidak terpakai ini disebut **file slack** (lihat 1.1.11) — tempat klasik data lama bisa nyangkut, sering jadi tempat sembunyi flag di CTF.

**Kenapa wajib dipahami sebelum masuk NTFS internals (Bab 2):**

| Konsep NTFS | Bergantung pada cluster karena... |
|---|---|
| `$MFT` | Setiap record menunjuk lokasi data dalam satuan cluster |
| `$Bitmap` | Melacak cluster mana yang terpakai/kosong |
| Data Runs | Menyatakan rentang cluster tempat data file disimpan |
| Resident | Data kecil disimpan langsung di MFT record (tidak butuh cluster terpisah) |
| Nonresident | Data disimpan di luar MFT, dirujuk lewat data run (berbasis cluster) |

```bash
# Cek ukuran sector & cluster di live system
fsutil fsinfo ntfsinfo C:
```

---

#### 1.1.2 LBA (Logical Block Addressing)

**Pengertian & Fungsi:**
LBA adalah skema penomoran sector secara linear dan berurutan, menggantikan skema lama CHS (Cylinder-Head-Sector) yang bergantung pada geometri fisik disk. Semua tool forensik disk-level (FTK Imager, Autopsy, Hex Editor, SleuthKit) menampilkan offset dalam satuan LBA/sector, jadi ini istilah yang wajib dikenali sejak awal.

```
Sector Number →   0     1     2     3     4     5   ...
LBA           →  LBA0  LBA1  LBA2  LBA3  LBA4  LBA5  ...
```

- Setiap sector di disk punya satu nomor LBA unik, dimulai dari `LBA 0`.
- `LBA 0` pada skema GPT berisi **Protective MBR** (lihat 1.1.5), bukan partition table asli.
- `LBA 1` berisi **GPT Header**, `LBA 2` dan seterusnya berisi **Partition Entry Array**.

> 💡 Tanpa memahami LBA, akan bingung kenapa GPT "mulai" di `LBA 1`, bukan `LBA 0` — padahal `LBA 0` tetap terisi (oleh Protective MBR, demi kompatibilitas tool lama yang cuma paham MBR).

---

#### 1.1.3 Filesystem Overview

**Pengertian & Fungsi:**
Sebelum fokus total ke NTFS di bab-bab berikutnya, kenali dulu filesystem lain yang mungkin ditemui investigator, supaya jelas kenapa hampir seluruh DFIR Windows berpusat di NTFS.

| Filesystem | Umum Dipakai Untuk | Catatan Forensik |
|---|---|---|
| FAT16 | Media sangat lama, embedded system | Jarang ditemui di kasus modern |
| FAT32 | USB/flashdisk lama, kartu memori kamera lama | Tidak ada journaling, metadata timestamp terbatas |
| exFAT | Flashdisk modern, kartu SD kapasitas besar | Tidak ada journaling, dipakai lintas OS (Windows/Mac) |
| **NTFS** | **Partisi sistem Windows (default)** | Punya `$MFT`, journaling (`$LogFile`), ACL, sangat kaya metadata → **fokus utama cheatsheet ini** |
| ReFS | Windows Server, storage pool besar | Resilient filesystem, mulai muncul di kasus server/enterprise |

> 📌 **Kesimpulan singkat:** hampir seluruh DFIR Windows terpusat di NTFS karena di situlah OS berjalan dan menyimpan hampir semua artefak (registry, event log, prefetch, dsb) — makanya seluruh Bab 2 dikhususkan untuk NTFS internals.

---

#### 1.1.4 Physical Disk vs Partition vs Volume

Sebelum masuk ke isi file, kamu perlu paham **level-level fisik/logikal** dari sebuah disk image (`.E01`, `.dd`, `.raw`, `.vhd`, dll):

```
[Physical Disk / Disk Image]        ← seluruh media (misal: DESKTOP-01.E01)
   │
   ├── Partition Table (MBR/GPT)    ← "peta" pembagian disk
   │
   ├── Partition 1 (System Reserved / EFI)
   │     └── Volume (belum tentu ada drive letter)
   │
   └── Partition 2 (OS Volume)
         └── Volume C:\             ← ini yang biasa kamu buka di FTK Imager
```

| Istilah | Pengertian |
|---|---|
| **Physical Disk** | Media penyimpanan fisik/image mentah — kumpulan sector dari 0 sampai akhir |
| **Partition** | Pembagian logis disk yang didefinisikan di partition table (MBR/GPT) |
| **Volume** | Partisi yang sudah diformat dengan filesystem (NTFS/FAT32/exFAT) dan siap dibaca OS |
| **Drive Letter** | Huruf (C:, D:, E:) yang dipetakan Windows ke sebuah volume — bisa berbeda antar sistem |

> 💡 **Kenapa penting di CTF/forensik:** Attacker kadang menyembunyikan data di partisi yang **tidak di-mount** oleh Windows (unallocated space, hidden partition, atau partition gap). FTK Imager & Autopsy bisa menampilkan partisi yang tidak muncul di Windows Explorer korban.

---

#### 1.1.5 MBR vs GPT

Ini adalah dua skema **partition table** yang menentukan bagaimana disk dibagi.

| Aspek | MBR (Master Boot Record) | GPT (GUID Partition Table) |
|---|---|---|
| Era | Legacy BIOS | Modern UEFI |
| Lokasi | Sector 0 (LBA 0), 512 byte | Mulai dari LBA 1, punya backup di akhir disk |
| Maks partisi primer | 4 (atau 3 + 1 extended) | Sampai 128 (tergantung OS) |
| Maks ukuran disk | ~2 TB | Jauh lebih besar (exabyte-scale) |
| Redundansi | Tidak ada backup | Ada **Primary GPT** + **Backup GPT** di akhir disk |
| Identifikasi partisi | Partition type byte (1 byte, misal `0x07` = NTFS) | GUID unik per partition type |

**Struktur MBR (disederhanakan):**
```
Offset 0x000 – 0x1BD : Bootstrap code (446 byte)
Offset 0x1BE – 0x1FD : Partition Table (4 entry x 16 byte)
Offset 0x1FE – 0x1FF : Boot Signature (0x55AA)
```

**Struktur GPT (disederhanakan):**
```
LBA 0   : Protective MBR (kompatibilitas, semua disk "terlihat" 1 partisi besar oleh tool lama)
LBA 1   : GPT Header (jumlah entry, ukuran, checksum)
LBA 2-33: Partition Entry Array
...
Akhir disk: Backup GPT Header + Backup Partition Entry Array
```

> ⚠️ **Nilai forensik:** Karena GPT punya backup di akhir disk, kalau primary GPT dirusak (misal attacker overwrite awal disk), backup GPT di akhir disk kadang masih bisa dipakai untuk recovery partisi.

**Cara cek dengan cepat:**
- Buka disk image di FTK Imager → kalau ada label `EFI System Partition` → berarti GPT.
- Buka di hex editor pada offset `0x1FE` — kalau ada `55 AA` itu tanda boot sector valid (berlaku baik MBR maupun protective MBR di GPT).

---

#### 1.1.6 Partisi Umum di Disk Windows

Contoh layout disk Windows 10/11 modern (GPT + UEFI):

```
[Physical Disk]
├── Partition 1: EFI System Partition (ESP)     ~100-300 MB, FAT32
│     └── \EFI\Microsoft\Boot\bootmgfw.efi
│
├── Partition 2: Microsoft Reserved (MSR)        ~16 MB, tanpa filesystem (metadata only)
│
├── Partition 3: C:\ (OS Volume)                 NTFS — ini fokus utama investigasi
│     └── Windows\, Users\, Program Files\, dst.
│
└── Partition 4: Recovery Partition (WinRE)      NTFS, berisi Windows Recovery Environment
      └── \Recovery\WindowsRE\Winre.wim
```

| Partisi | Fungsi | Relevansi Forensik |
|---|---|---|
| **EFI System Partition** | Menyimpan bootloader UEFI | Bisa jadi tempat persistence bootkit (jarang tapi ada di CTF advance) |
| **MSR (Microsoft Reserved)** | Reserved space untuk kebutuhan sistem, tidak ada file biasa | Biasanya diabaikan di investigasi |
| **OS Volume (C:\)** | Volume utama sistem operasi | **Fokus utama 99% kasus DFIR** |
| **Recovery Partition** | WinRE, system reset image | Kadang berisi jejak konfigurasi image awal / snapshot OS |

> 💡 Di legacy BIOS/MBR system (lebih jarang sekarang), biasanya cuma ada 1 partisi aktif: `System Reserved` (kecil, berisi BCD) + `C:\` (OS Volume).

---

#### 1.1.7 VBR (Volume Boot Record)

VBR ada di **awal setiap partisi/volume** (beda dengan MBR/GPT yang levelnya disk).

```
[Partisi NTFS]
├── VBR (sector 0 partisi ini)   ← boot code + BIOS Parameter Block (BPB)
├── $MFT dan file system NTFS lain
└── ... isi volume
```

| Field di VBR (NTFS) | Isi |
|---|---|
| Jump instruction | Instruksi lompat ke boot code |
| OEM ID | Biasanya `"NTFS    "` |
| Bytes Per Sector | Ukuran sector (umumnya 512) |
| Sectors Per Cluster | Menentukan ukuran cluster |
| Total Sectors | Ukuran volume |
| `$MFT` Cluster Number | Lokasi awal Master File Table |
| Volume Serial Number | ID unik volume (dipakai di LNK file / jump list untuk identifikasi drive!) |

> 💡 **Forensic link:** *Volume Serial Number* dari VBR ini sering muncul lagi di **LNK files** dan **Jump Lists** (Bab selanjutnya) — berguna untuk membuktikan file dibuka dari drive/volume tertentu (misal USB attacker).

---

#### 1.1.8 Boot Process Overview

**Pengertian & Fungsi:**
Bagian ini menyambungkan seluruh istilah yang sudah dibahas (MBR, GPT, VBR, bootmgr, BCD) menjadi satu alur boot yang utuh — supaya tidak jadi istilah lepas-lepas.

```
Power On
   │
   ▼
BIOS / UEFI              ← firmware, menentukan mode boot (Legacy vs UEFI)
   │
   ▼
MBR  /  GPT                ← partition table (1.1.5), menunjuk partisi bootable/ESP
   │
   ▼
VBR (Volume Boot Record)   ← boot code + BPB spesifik per-partisi (1.1.7)
   │
   ▼
bootmgr / bootmgfw.efi     ← Windows Boot Manager, baca BCD (Boot Configuration Data)
   │
   ▼
winload.exe / winload.efi  ← memuat Windows Kernel & driver boot-critical
   │
   ▼
Windows Kernel (ntoskrnl.exe)
```

| Mode | Alur yang dipakai |
|---|---|
| **Legacy BIOS** | MBR → VBR → `bootmgr` → `winload.exe` |
| **UEFI (modern)** | GPT + EFI System Partition (ESP) → `bootmgfw.efi` → `winload.efi` |

> 💡 **Kenapa `BCD` penting:** file ini sebenarnya **registry hive tersendiri** (bisa dibuka `RegistryExplorer.exe` atau `bcdedit /store <path>`) yang menyimpan konfigurasi entry boot — relevan untuk deteksi dual-boot tidak sah atau modifikasi boot untuk persistence.

---

#### 1.1.9 Disk Signature / GUID

**Pengertian & Fungsi:**
Identitas unik disk dan partisi, tercatat dalam struktur partition table, dan sering dipakai ulang di berbagai artefak untuk korelasi antar-lokasi.

| Skema | Identitas Disk | Identitas Partisi |
|---|---|---|
| MBR | **Disk Signature** (4 byte, offset `0x1B8`) | Tidak ada GUID native — hanya index partisi |
| GPT | **Disk GUID** | **Partition GUID** (unik per partisi) |

**Kenapa penting di DFIR** — nilai ini sering muncul lagi dan dipakai untuk korelasi artefak di:

- **Registry** — `HKLM\SYSTEM\MountedDevices` menyimpan signature/GUID disk untuk memetakan drive letter ke disk fisik.
- **BCD** — entry boot merujuk ke partisi lewat identifier berbasis GUID/signature.
- **Mount Manager** — melacak device yang pernah di-mount, berbasis identitas disk ini.
- **Volume Shadow Copy (VSS)** — snapshot terikat ke volume tertentu lewat identitas ini juga.

> 💡 **Nilai forensik:** kalau ditemukan disk signature/GUID di satu artefak, bisa dicocokkan ke artefak lain untuk memastikan keduanya berasal dari disk fisik yang sama — sangat berguna saat disk sudah dipindah ke sistem lain atau cuma dianalisis lewat image. Konsepnya mirip **Volume Serial Number** di VBR (lihat 1.1.7) yang muncul lagi di LNK file/Jump List, hanya beda level (disk/partisi vs volume).

---

#### 1.1.10 Cara Analisa di FTK Imager / KAPE

**FTK Imager (GUI):**
1. `File > Add Evidence Item` → pilih Image File / Physical Drive.
2. Di panel kiri, kamu akan lihat hierarki: `Physical Drive` → `Partition 1, 2, 3...` → isi tiap volume.
3. Klik kanan pada Physical Drive → **Export Disk Image** kalau perlu ekstrak image lengkap.
4. Untuk lihat detail raw sector (MBR/GPT/VBR), gunakan tab **Hex Value Interpreter** sambil klik ke sector 0.

**KAPE (CLI/GUI targets & modules):**
- KAPE bekerja di **level volume** (butuh volume sudah ter-mount atau image sudah di-attach, misal via Arsenal Image Mounter).
- KAPE tidak "melihat" partition table secara langsung — dia mengasumsikan target sudah berupa drive letter/mount point.
- Workflow umum: `Mount image (Arsenal Image Mounter / FTK Imager) → assign drive letter → jalankan KAPE targets ke drive letter itu`.

```bash
# Contoh KAPE - copy artefak forensik penting dari volume yang sudah di-mount
kape.exe --tsource E: --tdest C:\triage --target !SANS_Triage
```

**Tools tambahan untuk analisa disk-level:**

| Tool | Fungsi |
|---|---|
| **FTK Imager** | Mount/view image, export file, lihat MBR/GPT/VBR mentah |
| **Arsenal Image Mounter** | Mount image (.E01/.dd/.vhd) jadi drive letter Windows |
| **Autopsy** | GUI open-source, otomatis parsing partition table & filesystem |
| **mmls** (The Sleuth Kit) | List partition table dari command line |
| **fsutil** (live system) | `fsutil fsinfo volumeinfo C:` — info volume dari sistem hidup |

```bash
# Contoh mmls (Sleuth Kit) — melihat partition table sebuah image
mmls disk.dd
```

---

#### 1.1.11 Unallocated Space & Slack Space

Ini sering muncul di CTF, khususnya soal *"cari flag yang disembunyikan di area yang tidak terpakai"*.

```
Disk
├── Allocated Space    ← Cluster yang sedang dipakai file aktif
├── Unallocated Space  ← Cluster bebas (belum/tidak dipakai file manapun)
└── Partition Gap      ← Ruang kosong ANTAR partisi (bukan di dalam partisi)
```

| Istilah | Pengertian | Kenapa penting di forensik/CTF |
|---|---|---|
| **Unallocated Space** | Cluster yang menurut `$Bitmap` berstatus "kosong", tapi bisa saja masih menyimpan data lama (file yang dihapus tapi belum ditimpa) | Tempat paling umum sembunyikan/recover file terhapus — carve pakai `PhotoRec`/`Scalpel`/`foremost` |
| **Volume Slack** | Ruang sisa di **akhir volume** kalau ukuran volume tidak habis dibagi cluster/sector penuh (jarang, biasanya kecil) | Kadang dipakai teknik anti-forensik sederhana untuk selipkan data kecil |
| **File Slack** | Ruang sisa antara **akhir data logis file** dan **akhir cluster** yang dialokasikan untuknya (karena cluster punya ukuran tetap, mis. 4 KB, sedangkan file jarang pas kelipatannya) | Bisa menyimpan sisa data file LAMA yang pernah menempati cluster itu — classic tempat sembunyi data di CTF |
| **RAM Slack** | Sub-bagian dari file slack — ruang antara akhir file dan akhir *sector* terakhir yang diisi dari RAM saat penulisan (khusus filesystem lama seperti FAT; NTFS modern biasanya diisi nol) | Historically penting di FAT, kurang relevan di NTFS modern tapi tetap bisa muncul di soal teori |
| **Partition Gap** | Ruang kosong **di antara dua partisi** (bukan slack dalam partisi) — bisa terjadi karena disk alignment atau sengaja dikosongkan attacker | FTK Imager & `mmls` menampilkan ini sebagai "Unallocated" antar entry partition table — cek manual kalau ada gap mencurigakan |

**Cara Analisa:**
```bash
# FTK Imager: klik kanan pada Unallocated Space (highlight merah di tree) → Export
# Lalu carve dengan tool khusus:

# PhotoRec (interaktif)
photorec disk.dd

# Foremost (signature-based carving)
foremost -t all -i disk.dd -o output_folder/

# Scalpel (mirip foremost, config-based)
scalpel disk.dd -o output_folder/
```

> 💡 **Tip CTF:** Kalau soal bilang *"flag tidak ada di file manapun"*, coba urutan: cek **Unallocated Space** dulu (carving), lalu **File Slack** di file besar/system file, baru **Partition Gap**. Banyak CTF DFIR menaruh flag sebagai string biasa di unallocated space tanpa enkripsi apapun.

---

#### 1.1.12 Full Path Tree — Disk & Partition Level

Versi lengkap, mencakup skema **GPT/UEFI modern** dan **MBR/BIOS legacy**, plus seluruh NTFS system file di root volume yang sering dilewatkan.

**A. Skema GPT + UEFI (Windows 10/11 modern):**

```
[Physical Disk / Disk Image]  (mis. DESKTOP-01.E01, disk.dd, disk.vhd)
│
├── LBA 0            : Protective MBR (kompatibilitas tool lama)
├── LBA 1            : GPT Header (Primary)
├── LBA 2–33         : GPT Partition Entry Array (Primary)
│
├── Partition 1 — EFI System Partition (ESP)     [FAT32, ~100–300 MB]
│   └── \EFI\
│       ├── Boot\bootx64.efi
│       └── Microsoft\Boot\
│           ├── bootmgfw.efi         ← Windows Boot Manager
│           ├── BCD                  ← Boot Configuration Data (binary registry hive!)
│           └── BCD.LOG
│
├── Partition 2 — Microsoft Reserved (MSR)       [~16 MB, tanpa filesystem/metadata only]
│
├── Partition 3 — C:\ (OS Volume)                [NTFS] ← FOKUS UTAMA INVESTIGASI
│   ├── VBR (sector 0 volume ini — boot code + BPB)
│   ├── $MFT                 ← Master File Table (ground truth semua file)
│   ├── $MFTMirr             ← Backup 4 record pertama $MFT
│   ├── $LogFile             ← Journal transaksi NTFS (undo/redo)
│   ├── $Volume               ← Info volume (label, versi NTFS, dirty flag)
│   ├── $AttrDef              ← Definisi tipe atribut NTFS
│   ├── $Bitmap               ← Peta cluster terpakai/kosong (lihat 1.1.11)
│   ├── $Boot                 ← Salinan VBR + bootstrap code
│   ├── $BadClus              ← Daftar bad sector/cluster
│   ├── $Secure               ← ACL & security descriptor
│   ├── $UpCase                ← Tabel konversi uppercase (untuk nama file case-insensitive)
│   ├── $Extend\
│   │   ├── $UsnJrnl          ← Change journal (create/modify/delete/rename)
│   │   ├── $ObjId             ← Object ID tracking (link antar file/shortcut)
│   │   ├── $Quota             ← Disk quota per user
│   │   └── $Reparse           ← Reparse point index (symlink, junction, OneDrive placeholder)
│   ├── $Recycle.Bin\          ← lihat 1.2.11
│   ├── System Volume Information\   ← Restore Point & Volume Shadow Copy metadata (butuh privilege SYSTEM)
│   ├── pagefile.sys           ← Memory swap file
│   ├── hiberfil.sys           ← Snapshot RAM saat hibernate
│   ├── swapfile.sys           ← Swap khusus UWP apps
│   ├── bootmgr                ← Windows Boot Manager (legacy path, tetap ada di beberapa setup)
│   ├── BOOTNXT                ← Penanda next-boot untuk WinRE/recovery
│   ├── Documents and Settings ← Junction/symlink kompatibilitas ke Users\ (legacy XP path)
│   ├── Recovery\              ← Metadata WinRE lokal (beda dengan partisi Recovery terpisah)
│   ├── Windows\               ← lihat 1.2.2 – 1.2.3
│   ├── Users\                 ← lihat 1.2.5
│   ├── Program Files\         ← lihat 1.2.8
│   ├── Program Files (x86)\  ← lihat 1.2.8
│   ├── ProgramData\           ← lihat 1.2.9
│   └── PerfLogs\              ← lihat 1.2.10
│
├── Partition 4 — Recovery Partition (WinRE)     [NTFS]
│   └── \Recovery\WindowsRE\
│       ├── Winre.wim          ← Image Windows Recovery Environment
│       └── ReAgent.xml        ← Konfigurasi recovery agent
│
└── LBA (akhir disk) : Backup GPT Partition Entry Array + Backup GPT Header
```

**B. Skema MBR + Legacy BIOS (masih ditemukan di VM tua / server lama):**

```
[Physical Disk / Disk Image]
│
├── Sector 0 : MBR
│   ├── Bootstrap code (446 byte)
│   ├── Partition Table (4 entry x 16 byte)
│   └── Boot Signature 0x55AA
│
├── Partition 1 — System Reserved      [NTFS, ~100–500 MB, flag: active/bootable]
│   └── \Boot\
│       ├── BCD
│       └── BCD.LOG
│   └── bootmgr                        ← Windows Boot Manager (legacy BIOS)
│
└── Partition 2 — C:\ (OS Volume)      [NTFS]
    └── (isi sama persis dengan Partition 3 skema GPT di atas)
```

> 💡 **File yang paling sering terlewat pemula:** `BCD` (dua-duanya — di ESP untuk UEFI atau di System Reserved untuk legacy) adalah registry hive tersendiri, sudah dibahas di **1.1.8**. `System Volume Information\` juga sering diabaikan padahal berisi Volume Shadow Copy yang bisa membuka file yang "sudah dihapus/terkunci" di titik waktu lama.

---

#### 1.1.13 Disk Image Format

Karena targetmu HTB dan CTF, kamu akan sering ketemu format image yang berbeda-beda tergantung tool akuisisi yang dipakai penyelenggara.

```
.E01     ← EnCase Evidence Format (paling umum, dari FTK Imager/EnCase; punya metadata + hash + kompresi)
.EX01    ← EnCase Evidence Format v2 (mendukung disk >2TB, hash SHA-1/256 ganda)
.AFF     ← Advanced Forensic Format (open-source, jarang di CTF modern, lebih umum di tool lama)
.DD      ← Raw/flat image (dd-style, bit-for-bit, tanpa metadata/kompresi)
.RAW     ← Sama seperti .dd, penamaan berbeda tergantung tool akuisisi
.VHD     ← Virtual Hard Disk (format Microsoft, bisa langsung di-mount native di Windows)
.VHDX    ← Versi VHD yang lebih baru, mendukung ukuran lebih besar & resiliency
.VMDK    ← Virtual Machine Disk (format VMware)
.QCOW2   ← QEMU Copy-On-Write v2 (format image untuk QEMU/KVM, sering di lab Linux)
```

| Format | Ciri Khas | Cara Buka/Mount |
|---|---|---|
| `.E01` / `.EX01` | Ada header, chunk terkompresi, embedded MD5/SHA1 untuk verifikasi integritas | FTK Imager, Autopsy, `ewfmount` (libewf) |
| `.AFF` | Open format, jarang dipakai lagi | `afflib`, Autopsy (dengan plugin) |
| `.DD` / `.RAW` | Bit-for-bit copy tanpa kompresi/metadata — paling "mentah" | `mmls`/`mount` langsung (Linux), FTK Imager, atau `Arsenal Image Mounter` |
| `.VHD` / `.VHDX` | Native Windows — bisa di-mount lewat Disk Management tanpa tool tambahan | Klik kanan → **Mount** (Windows), atau `Mount-VHD` (PowerShell) |
| `.VMDK` | Terkait erat dengan snapshot VMware, kadang datang bersama file `.vmsn`/`.vmem` (memory snapshot VM!) | Arsenal Image Mounter, `qemu-img convert`, VMware sendiri |
| `.QCOW2` | Copy-on-write, sering punya snapshot chain | `qemu-nbd`, `qemu-img convert qcow2 dd.raw` |

**Cara verifikasi & konversi cepat:**
```bash
# Cek info image E01 (metadata, hash, ukuran)
ewfinfo image.E01

# Convert VMDK/QCOW2 ke raw untuk kompatibilitas tool lain
qemu-img convert -O raw image.vmdk image.raw
qemu-img convert -O raw image.qcow2 image.raw

# Mount E01 di Linux (libewf + affuse/xmount)
ewfmount image.E01 /mnt/ewf
mount -o ro,loop /mnt/ewf/ewf1 /mnt/evidence
```

> 💡 **Tip CTF:** Kalau soal kasih file `.vmdk` + `.vmem`/`.vmsn`, itu artinya kamu dapat **disk snapshot DAN memory snapshot** sekaligus dari VM yang sama — sering perlu dianalisis berbarengan (disk forensic + memory forensic pakai Volatility).

---

#### 1.1.14 Hidden Partition & Recovery Artefacts

CTF suka menyembunyikan flag di partisi yang tidak langsung terlihat di Windows Explorer korban.

```
Recovery Partition   ← WinRE, kadang berisi snapshot OS asli / config awal
OEM Partition         ← Dari vendor laptop (Dell/HP/Lenovo dll), berisi tool recovery bawaan pabrik
Hidden Partition      ← Partisi tanpa drive letter, sengaja "disembunyikan" (via diskpart/attacker)
BitLocker Partition   ← Partisi terenkripsi (FVE) — butuh recovery key/password untuk dibuka
```

| Jenis Partisi | Nilai Forensik | Cara Deteksi/Analisa |
|---|---|---|
| **Hidden Volume** | Partisi yang ada di partition table tapi tidak di-assign drive letter — sering dipakai attacker untuk staging data/tools | FTK Imager & `mmls` tetap menampilkannya walau tidak muncul di Explorer korban; cek juga via `diskpart > list volume` di live system |
| **OEM Partition** | Berisi image factory reset / tool recovery vendor — kadang menyimpan versi OS/aplikasi awal sebelum modifikasi attacker | Mount & bandingkan hash file dengan versi "sekarang" di C:\ untuk deteksi perubahan |
| **Recovery Image (WinRE)** | `Winre.wim` bisa di-mount seperti image Windows biasa — kadang berisi script/tool custom yang di-inject attacker untuk persistence pre-boot | `dism /mount-wim /wimfile:Winre.wim /index:1 /mountdir:C:\mount` |
| **Old User Data** | Sisa partisi/volume dari instalasi OS sebelumnya (dual-boot lama, atau disk yang di-reuse) — file lama sering belum benar-benar terhapus | Cari signature filesystem lain di unallocated space (`mmls`, `testdisk`) |
| **BitLocker Partition** | Volume terenkripsi (FVE — Full Volume Encryption) — flag/bukti bisa ada di dalamnya | Butuh recovery key (48 digit) atau password; cek `Windows\System32\LogFiles\` / registry untuk kemungkinan key ter-cache, atau `manage-bde -status` di live system |

**Cara Analisa:**
```bash
# Lihat semua partisi termasuk yang hidden/tanpa drive letter
mmls disk.dd

# Mount WinRE image untuk inspeksi isi
dism /mount-wim /wimfile:C:\Recovery\WindowsRE\Winre.wim /index:1 /mountdir:C:\mount /readonly

# Cek status BitLocker di live system
manage-bde -status C:
```

> 💡 **Tip CTF:** Kalau soal bilang *"kami sudah cek seluruh C:\ tapi flag tidak ditemukan"* — itu sinyal kuat buat cek partition table penuh (`mmls`) dulu, karena kemungkinan besar flag ada di partisi lain yang tidak ter-mount sebagai C:\.

---

### 1.2 Struktur Direktori Windows (C:\\)

#### 1.2.1 Root C:\\ — Overview

```
C:\
│
├── Windows\                  ← Inti sistem operasi (lihat 1.2.2 – 1.2.3)
├── Users\                     ← Profil semua user (lihat 1.2.5)
├── Program Files\             ← Aplikasi 64-bit (lihat 1.2.8)
├── Program Files (x86)\      ← Aplikasi 32-bit (lihat 1.2.8)
├── ProgramData\  (Hidden)      ← Config aplikasi, per-mesin bukan per-user (lihat 1.2.9)
├── PerfLogs\                  ← Log performance counter (jarang dipakai, sering kosong) (lihat 1.2.10)
├── $Recycle.Bin\              ← Recycle bin, per-user (berdasarkan SID) (lihat 1.2.11)
│
│   ── Folder/file lain yang sering terlewat, dibahas detail di 1.2.13 ──
├── System Volume Information\  (Hidden, System)  ← VSS & Restore Point, CEK PERTAMA KALI
├── Recovery\                     (Hidden)
├── Documents and Settings\      (Junction)  ← symlink legacy ke Users\
├── Config.Msi\                   (Hidden)
├── Windows.old\                  (Hidden, kalau ada)
├── pagefile.sys
├── swapfile.sys
├── hiberfil.sys
├── DumpStack.log.tmp
├── bootmgr
└── BOOTNXT
```

> ⭐ **Jangan lewatkan `System Volume Information\`:** walau ditandai Hidden+System dan sekilas cuma "folder file lain yang terlewat", ini termasuk folder yang **paling awal dicek investigator berpengalaman** karena menyimpan Volume Shadow Copy — bisa membuka versi lama file yang sudah dimodifikasi/dihapus attacker (detail cara mount di 1.2.13).

> 📌 **Prinsip dasar forensik direktori:** Setiap folder di atas punya "peran" berbeda dalam merekonstruksi cerita insiden — Windows\ untuk config & log sistem, Users\ untuk aktivitas manusia, ProgramData\ untuk aplikasi yang jalan sebagai service/background. Folder tambahan seperti `Windows.old\` dan `System Volume Information\` sering jadi "harta karun" karena menyimpan salinan data lama yang sudah tidak ada di lokasi normalnya.

---

#### 1.2.2 Windows\\

**Pengertian & Fungsi:**
Folder ini adalah **root instalasi OS** — berisi seluruh binary sistem, driver, konfigurasi, dan log bawaan Windows. Hampir semua artefak forensik "level sistem" (bukan per-user) ada di sini.

```
Windows\
├── System32\          ← Binary inti OS, config, log, registry hive (lihat 1.2.3)
├── SysWOW64\           ← Versi 32-bit dari System32 (di OS 64-bit)
├── Prefetch\           ← Bukti eksekusi program (.pf files)
├── Temp\               ← Temp file sistem-wide (sering dipakai attacker untuk staging)
├── SoftwareDistribution\  ← Log & cache Windows Update
├── Logs\               ← Berbagai log komponen Windows (CBS, DISM, dll)
├── Panther\            ← Log instalasi/setup Windows (unattend.xml, setupact.log)
├── INF\                ← Driver install log (setupapi.dev.log — jejak USB device!)
├── Debug\              ← Debug log (misal PASSWD.LOG, NetSetup.log)
├── security\           ← Security policy & log tambahan
└── WinSxS\             ← Component store (Windows side-by-side assemblies)
```

**Cara Analisa & Tools:**

| Sub-area | Yang dicari | Tool |
|---|---|---|
| `Prefetch\` | Bukti program pernah dijalankan, run count, timestamp eksekusi | `PECmd.exe` |
| `Panther\setupact.log` | Waktu instalasi OS, log unattended setup | Text editor / `strings` |
| `INF\setupapi.dev.log` | Riwayat device (USB) yang pernah dipasang, dengan timestamp | Text editor, `Select-String` |
| `Temp\` | File staging malware, payload sementara | Hash check, VirusTotal, `strings` |
| `SoftwareDistribution\` | Riwayat Windows Update (kadang relevan untuk timeline patch) | Manual review |

```bash
# Contoh: cari jejak USB device dari setupapi log
Select-String -Path "C:\Windows\INF\setupapi.dev.log" -Pattern "USBSTOR"
```

> 💡 **Tip CTF:** Kalau soal minta "kapan USB pertama kali dicolok" atau "device apa yang terhubung", `setupapi.dev.log` sering jadi kunci selain registry `USBSTOR`.

---

#### 1.2.3 Windows\\System32\\

**Pengertian & Fungsi:**
`System32` adalah folder paling padat artefak forensik di seluruh disk. Ini bukan cuma "folder 32-bit" (nama historis) — di Windows 64-bit modern, ini justru berisi binary **64-bit**.

```
System32\
├── config\             ← Registry hive utama (SYSTEM, SOFTWARE, SAM, SECURITY, DEFAULT)
├── winevt\Logs\        ← Semua file .evtx (Event Log)
├── Tasks\              ← Scheduled Task XML (persistence umum!)
├── wbem\               ← WMI (Windows Management Instrumentation) binary & repository
├── LogFiles\           ← Log berbagai service (WMI, W3SVC/IIS, Firewall, dll)
├── drivers\            ← Driver kernel (.sys) — cek driver mencurigakan/unsigned
├── spool\PRINTERS\     ← Print spooler (relevan untuk exploit PrintNightmare dll)
├── Tasks\ / TaskCache\ ← Scheduled task definitions
├── LSA / dll terkait   ← Local Security Authority (credential-related)
└── drivers\etc\hosts   ← File hosts (DNS static mapping — cek modifikasi malware)
```

**Cara Analisa per Sub-folder:**

| Sub-folder | Fungsi Forensik | Tool Analisa |
|---|---|---|
| `config\` | Registry hive — persistence, user account, service, network config | `RegistryExplorer.exe`, `RECmd.exe` |
| `winevt\Logs\` | Rekaman aktivitas sistem (login, proses, service) | `EvtxECmd.exe`, `Event Viewer` |
| `Tasks\` | Scheduled task — teknik persistence populer di CTF & real attack | Baca XML langsung, atau `schtasks /query` (live) |
| `wbem\Repository\` | WMI persistence (WMI event subscription — teknik fileless) | `python-cim` / `PyWMIPersistenceFinder`, manual parsing |
| `drivers\etc\hosts` | Redirect domain (malware C2, phishing lokal) | Text editor biasa |
| `LogFiles\Firewall\` | Log firewall (kalau diaktifkan) — koneksi masuk/keluar | Text editor, filter manual |

```bash
# Contoh: cari scheduled task yang mencurigakan (baca XML langsung)
Get-ChildItem "C:\Windows\System32\Tasks" -Recurse | Select-String "powershell","cmd.exe","-enc"

# Contoh: extract semua registry hive dengan RECmd
.\RECmd.exe -f "C:\Windows\System32\config\SYSTEM" --csv .
```

> ⚠️ **Kenapa `config\` dan `winevt\Logs\` paling sering jadi target soal CTF forensik:** karena dua folder ini menyimpan **hampir seluruh bukti persistence, login activity, dan eksekusi proses** di level sistem. Kalau bingung mulai dari mana, mulai dari sini.

---

#### 1.2.4 Arsitektur Windows: System32 vs SysWOW64

**Pengertian & Fungsi:**
Penamaan ini sering membingungkan pemula karena terkesan terbalik — `System32` justru berisi binary **64-bit** di Windows 64-bit modern.

```
64-bit EXE   →  Windows\System32\
32-bit EXE   →  Windows\SysWOW64\
```

| Folder | Isi | Kenapa namanya begitu |
|---|---|---|
| `System32\` | Binary **native** sesuai arsitektur OS (64-bit di Windows 64-bit) | Nama historis dari era 32-bit, dipertahankan untuk kompatibilitas path |
| `SysWOW64\` | Binary **32-bit** | "WOW64" = **W**indows **o**n **W**indows **64**-bit, lapisan kompatibilitas |

> ⚠️ **Relevansi forensik:** saat analisis proses/malware, cek apakah binary berjalan dari `System32` atau `SysWOW64` untuk tahu arsitektur asli file tersebut — penting saat dikorelasikan dengan Prefetch (`.pf` filename kadang mencantumkan hash beda tergantung arsitektur) atau path lengkap di Event Log.

---

#### 1.2.5 Users\\

**Pengertian & Fungsi:**
Berisi **profil setiap user** yang pernah login ke mesin — ini adalah folder paling kaya untuk merekonstruksi **aktivitas manusia** (bukan sekadar sistem).

```
Users\
├── <username>\
│   ├── NTUSER.DAT                     ← Registry hive per-user (HKCU)
│   ├── AppData\
│   │   ├── Local\
│   │   │   ├── Temp\                  ← Malware sering drop payload di sini
│   │   │   └── Microsoft\Windows\PowerShell\PSReadLine\  ← History PowerShell
│   │   ├── LocalLow\                  ← Data app "low integrity" (sandboxed, misal browser)
│   │   └── Roaming\
│   │       └── Microsoft\Windows\Recent\  ← LNK files & Jump Lists
│   ├── Desktop\ / Documents\ / Downloads\  ← File user langsung
│   ├── Pictures\ / Videos\ / Music\
│   └── AppData\Local\Microsoft\Windows\UsrClass.dat  ← Registry hive tambahan (shell/file assoc)
│
└── Public\                            ← Folder shared antar semua user (tanpa login spesifik)
```

**Cara Analisa & Tools:**

| Sub-area | Yang dicari | Detail lanjutan |
|---|---|---|
| `NTUSER.DAT` | Aktivitas user: UserAssist, RecentDocs, typed paths, RunMRU | `RegistryExplorer.exe`, `RECmd.exe` — Bab 3 |
| `AppData\Local\Temp\` | File yang di-drop attacker/malware, seringkali payload stage 2 | Hash check, `strings`, VirusTotal |
| `AppData\Roaming\...\Recent\` | LNK files & Jump Lists — file apa yang dibuka, dari drive mana | **Bab 5** |
| `PSReadLine\ConsoleHost_history.txt` | Command PowerShell yang pernah diketik user | Text editor — korelasi ke Bab 4 §4.5 (4104) |
| `UsrClass.dat` | Shell bag (folder yang pernah dibuka via Explorer!) | `RegistryExplorer.exe`, ShellBag parser — Bab 3 §3.7 |
| `Downloads\` / `Desktop\` | File yang sengaja disimpan user, kadang bukti langsung | Manual review, hash |

```bash
# Contoh: parsing NTUSER.DAT untuk melihat semua key relevan
.\RECmd.exe -f "C:\Users\<user>\NTUSER.DAT" --csv .
```

> 📖 **Detail lengkap LNK & Jump List** (struktur binary, ShellItemID, volume serial, MAC address, cara parsing dengan `LECmd.exe`/`JLECmd.exe`) dibahas mendalam di **Bab 5 — User Activity Trail**. Bagian ini cuma peta lokasi & gambaran umum.

> 💡 **Tip CTF:** Kalau soal minta "file apa yang dibuka user sebelum insiden" atau "user pernah akses drive apa", cek urutan: **NTUSER.DAT (RecentDocs) → LNK files → Jump Lists → ShellBags (UsrClass.dat)**. Keempatnya saling melengkapi dan kadang salah satu "selamat" walau yang lain dihapus attacker — detail LNK/Jump List di Bab 5, ShellBags di Bab 3 §3.7.

---

#### 1.2.6 AppData Tree

**Pengertian & Fungsi:**
`Users\<username>\AppData` adalah salah satu folder terpadat artefak — hampir semua data aplikasi user (browser, chat app, cache) ada di sini. Perlu dipecah lebih detail dari sekadar disebut sekali di 1.2.5.

```
AppData
├── Local
├── LocalLow
└── Roaming
```

| Folder | Karakteristik |
|---|---|
| **Local** | Data spesifik mesin, **tidak** ikut roaming profile, sering berisi cache/data besar |
| **LocalLow** | Mirip Local, tapi integrity level rendah — dipakai app sandboxed (mis. browser Protected Mode) |
| **Roaming** | Data yang ikut berpindah kalau user profile roaming di domain environment |

**Contoh lokasi artefak yang sering dicari:**

| Aplikasi | Biasanya di |
|---|---|
| Chrome | `Local\Google\Chrome\User Data` |
| Edge | `Local\Microsoft\Edge\User Data` |
| Firefox | `Roaming\Mozilla\Firefox\Profiles` |
| Discord | `Roaming\discord` |
| Teams | `Local\Microsoft\Teams` / `Roaming\Microsoft\Teams` (tergantung versi) |
| OneDrive | `Local\Microsoft\OneDrive` |
| PowerShell history | `Roaming\Microsoft\Windows\PowerShell\PSReadLine` |
| Recent items | `Roaming\Microsoft\Windows\Recent` |
| Jump List | `Roaming\Microsoft\Windows\Recent\AutomaticDestinations` |

> 📖 **Detail analisa:** Tabel di atas cuma peta lokasi cepat. Analisa mendalam Browser (History/Cookies/Cache/Login Data via SQLite) ada di **Bab 6 — Browser Forensics**; analisa mendalam LNK & Jump List ada di **Bab 5 — User Activity Trail**.

> 💡 **Tip:** kalau bingung suatu artefak aplikasi ada di `Local` atau `Roaming`, aturan kasarnya — kalau datanya besar (cache, database lokal) biasanya `Local`; kalau datanya kecil dan "identitas user" (config, history) biasanya `Roaming`.

---

#### 1.2.7 Environment Variable

**Pengertian & Fungsi:**
Environment variable dipakai luas di registry, script, bahkan payload malware — jadi wajib dikenali sejak awal supaya path yang ditemukan di artefak bisa langsung "diterjemahkan".

| Variable | Mengarah ke |
|---|---|
| `%SystemRoot%` | `C:\Windows` |
| `%USERPROFILE%` | `C:\Users\<username>` |
| `%APPDATA%` | `C:\Users\<username>\AppData\Roaming` |
| `%LOCALAPPDATA%` | `C:\Users\<username>\AppData\Local` |
| `%ProgramData%` | `C:\ProgramData` |
| `%TEMP%` / `%TMP%` | `C:\Users\<username>\AppData\Local\Temp` |

> ⚠️ **Kenapa penting:** path di registry key persistence (misalnya `Run`/`RunOnce`) dan konfigurasi malware hampir selalu memakai environment variable, bukan path absolut — jadi kalau menemukan `%APPDATA%\update.exe` di registry, itu artinya harus dicek di `Roaming`, bukan dicari literal foldernya.

---

#### 1.2.8 Program Files\\ & Program Files (x86)\\

**Pengertian & Fungsi:**
Lokasi instalasi aplikasi pihak ketiga (bukan bawaan `Windows\`).

| Folder | Isi |
|---|---|
| `Program Files\` | Aplikasi **64-bit** |
| `Program Files (x86)\` | Aplikasi **32-bit** (berjalan via WOW64 di OS 64-bit) |

**Relevansi Forensik:**
- Software legit yang dipakai sebagai **LOLBins** (Living off the Land Binaries) — misal aplikasi remote access resmi yang disalahgunakan attacker (AnyDesk, TeamViewer, dll).
- Instalasi aplikasi yang **tidak biasa/tidak dikenal** — cocokkan nama folder dengan waktu instalasi (cek timestamp folder) untuk deteksi anomali.
- File installer (`.msi`, `.exe`) yang tertinggal bisa jadi indikator vektor awal infeksi (contoh kasus: fake installer software).

**Cara Analisa:**
```bash
# Cek daftar folder & waktu pembuatan (indikasi kapan software di-install)
Get-ChildItem "C:\Program Files" | Select Name, CreationTime, LastWriteTime

# Cross-check dengan Registry Uninstall key untuk info versi & install date resmi
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\
```

> 💡 Kasus seperti *"fake Mastercam X9 installer"* — biasanya software palsu tetap membuat folder di `Program Files\` (atau bahkan di `AppData\Local\Programs\` untuk installer per-user tanpa admin), jadi selalu cek juga folder instalasi non-standar di dalam profil user.

---

#### 1.2.9 ProgramData\\

**Pengertian & Fungsi:**
Folder **hidden** (secara default) yang menyimpan data konfigurasi aplikasi **per-mesin** (bukan per-user seperti `AppData`). Aplikasi yang jalan sebagai **service/background** biasanya nulis data di sini.

```
ProgramData\
├── Microsoft\Windows Defender\        ← Log & quarantine Windows Defender
│   └── Scans\History\...              ← Riwayat deteksi malware!
├── Microsoft\Windows\WER\             ← Windows Error Reporting (crash dump aplikasi)
├── Package Cache\                     ← Cache installer (kadang bisa cari asal installer)
└── <vendor>\<aplikasi>\               ← Config aplikasi pihak ketiga (AV, EDR, dll)
```

**Cara Analisa & Tools:**

| Sub-area | Yang dicari | Tool |
|---|---|---|
| `Windows Defender\Scans\History\` | Nama malware terdeteksi, path file, waktu deteksi | Text editor, atau parser khusus (mpam log) |
| `Windows\WER\` | Crash report aplikasi — kadang berisi bukti proses crash saat exploit | Manual review `.wer` file |
| `Package Cache\` | Installer yang pernah dijalankan (MSI/EXE cache) | File listing + hash |

```bash
# Contoh: cek riwayat deteksi Windows Defender
Get-ChildItem "C:\ProgramData\Microsoft\Windows Defender\Scans\History\Service" -Recurse
```

> ⚠️ **Sering terlewat:** Banyak yang lupa cek `ProgramData\Microsoft\Windows Defender\` padahal ini sering jadi "jawaban instan" kalau AV sempat mendeteksi malware sebelum akhirnya berhasil bypass/persist.

---

#### 1.2.10 PerfLogs\\

**Pengertian & Fungsi:**
Folder default untuk menyimpan log **Performance Monitor** (`perfmon`) — CPU, memory, disk counter dari waktu ke waktu.

**Relevansi Forensik:**
- Di kebanyakan mesin, folder ini **kosong** kecuali admin secara eksplisit mengatur data collector set.
- Kalau **berisi data**, artinya ada monitoring aktif yang bisa dikorelasikan dengan waktu terjadinya lonjakan resource (misal saat cryptominer/ransomware jalan).

**Cara Analisa:**
```bash
Get-ChildItem "C:\PerfLogs" -Recurse
```
File berformat `.blg` (Binary Log) bisa dibuka dengan `perfmon.exe /sys` atau di-convert ke CSV via `relog.exe`.

```bash
relog perf_log.blg -f CSV -o output.csv
```

> 💡 Folder ini **jarang jadi fokus utama** kecuali soal CTF secara eksplisit menyinggung anomali resource usage (contoh: deteksi cryptomining).

---

#### 1.2.11 $Recycle.Bin\\

**Pengertian & Fungsi:**
Recycle Bin NTFS modern — setiap user (berdasarkan SID) punya subfolder sendiri. Ini adalah **tempat pertama** untuk cek file yang "dihapus" user (soft-delete, belum di-shift-delete).

```
$Recycle.Bin\
└── S-1-5-21-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXX-1001\   ← SID user
    ├── $IXXXXXXX.ext     ← Metadata: nama asli file, path asli, waktu dihapus, ukuran
    └── $RXXXXXXX.ext     ← Isi/konten file yang dihapus (nama sama dg $I, prefix beda)
```

**Cara Analisa & Tools:**

```bash
# RBCmd — Eric Zimmerman Tools, parsing $I file jadi CSV
.\RBCmd.exe -d "C:\`$Recycle.Bin" --csv .
```

| Kolom output RBCmd | Keterangan |
|---|---|
| `FileName` | Nama file asli sebelum dihapus |
| `FileSize` | Ukuran file |
| `DeletedOn` | Timestamp file dihapus |
| `FileType` | Jenis metadata ($I record) |

> 💡 **Tip CTF:** SID di nama folder bisa langsung dicocokkan ke username lewat registry `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\<SID>` → key `ProfileImagePath`. Jadi walau nama folder cuma SID, kamu tetap bisa tahu itu recycle bin milik user siapa.

> 📖 **Edge case lanjutan** (format lama `INFO2` di Windows XP/7, recovery file yang di-*permanently delete* lewat Shift+Del) dibahas di **Bab 5 — User Activity Trail**, disandingkan dengan VSS/LNK/Jump List sebagai satu keluarga "artefak residu aktivitas".

---

#### 1.2.12 Tabel Prioritas Investigasi

Kalau baru mulai investigasi dan bingung folder mana yang dicek duluan, urutan prioritas umum (bisa disesuaikan konteks soal):

| Prioritas | Folder | Alasan |
|---|---|---|
| 1 | `Windows\System32\winevt\Logs\` | Timeline aktivitas sistem paling lengkap |
| 2 | `Windows\System32\config\` | Registry — persistence, akun, service |
| 3 | `Users\<user>\NTUSER.DAT` + `AppData\` | Aktivitas & jejak user spesifik |
| 4 | `Windows\Prefetch\` | Bukti eksekusi program |
| 5 | `ProgramData\Microsoft\Windows Defender\` | Cek apakah AV sempat mendeteksi sesuatu |
| 6 | `$Recycle.Bin\` | File yang dihapus pelaku/korban |
| 7 | `Windows\System32\Tasks\` | Persistence via scheduled task |
| 8 | `Program Files\` / `Program Files (x86)\` | Software terinstall, termasuk fake installer |
| 9 | `PerfLogs\` | Biasanya terakhir, kecuali soal spesifik minta resource anomaly |

---

#### 1.2.13 Root-Level Files & Folder yang Sering Terlewat

Selain 7 folder utama di 1.2.1, ada file/folder lain langsung di `C:\` yang sering luput dicek padahal bisa jadi kunci jawaban.

| File/Folder | Pengertian & Fungsi | Nilai Forensik |
|---|---|---|
| `System Volume Information\` | Menyimpan Volume Shadow Copy (VSS) & Restore Point | Bisa dipakai buka **versi lama file** yang sudah dimodifikasi/dihapus attacker — akses butuh privilege SYSTEM. Detail cara mount, enumerasi, & diffing antar snapshot ada di **Bab 5** |
| `Recovery\` | Metadata WinRE lokal (beda dari partisi Recovery terpisah) | Kadang berisi log recovery/reset yang menunjukkan sistem pernah di-reset (bisa jadi anti-forensik attacker) |
| `Documents and Settings\` | Junction/symlink kompatibilitas legacy ke `Users\` (peninggalan era Windows XP) | Kalau di-`dir`, terlihat seperti folder biasa tapi sebenarnya reparse point — jangan bingung saat listing filesystem |
| `Config.Msi\` | Folder sementara untuk proses install/uninstall MSI (rollback data) | Kadang menyimpan sisa file `.rbf`/`.rbs` dari instalasi software yang di-uninstall — bisa jadi bukti software pernah terpasang |
| `Windows.old\` | Backup OS lama setelah proses **upgrade Windows** (mis. Win10→Win11) | **Goldmine artefak**: berisi salinan penuh `Windows\`, `Users\`, registry hive lama — bisa dipakai lihat kondisi sistem SEBELUM upgrade/insiden |
| `pagefile.sys` | Virtual memory swap file | Bisa berisi fragmen data RAM (password, string command, dll) — carving string/strings search sangat berguna |
| `swapfile.sys` | Swap khusus untuk UWP/Modern apps | Serupa `pagefile.sys` tapi scope aplikasi UWP |
| `hiberfil.sys` | Snapshot **seluruh isi RAM** saat sistem hibernate | Setara memory dump — bisa dianalisis pakai `Volatility`/`Rekall` untuk lihat proses & koneksi jaringan yang aktif saat hibernate |
| `DumpStack.log.tmp` | Log sementara terkait proses crash dump/dump stack Windows | Biasanya tidak signifikan sendirian, tapi keberadaannya bisa mengindikasikan sistem pernah crash/BSOD |
| `bootmgr` | Windows Boot Manager (binary, bukan folder) | Cek integritas — modifikasi di sini bisa indikasi **bootkit** |
| `BOOTNXT` | Penanda konfigurasi next-boot (dipakai WinRE/recovery) | Jarang jadi fokus, tapi relevan untuk timeline reboot/recovery |

```bash
# Contoh: cari string mencurigakan (password, command) di pagefile
strings pagefile.sys | findstr /i "password powershell -enc"
```

> ⚠️ **Paling sering jadi "jawaban tersembunyi" di CTF:** `Windows.old\` (kalau ada) dan `System Volume Information\` — dua-duanya nyimpen **versi masa lalu** dari sistem, sedangkan kebanyakan peserta cuma cek kondisi sistem "sekarang".

---

#### 1.2.14 Full Path Tree — Seluruh C:\\ (Master Reference)

Rangkuman satu tabel besar seluruh path yang sudah dibahas di Bab 1, dari root sampai ke sub-folder terdalam — dipakai sebagai referensi cepat/contekan saat investigasi.

```
C:\
│
├── $MFT, $MFTMirr, $LogFile, $Volume, $Bitmap, $Boot, $Secure, $UpCase, $Extend\ (lihat 1.1.12)
├── System Volume Information\                         ← VSS & Restore Point (1.2.13)
├── Recovery\                                            ← Metadata WinRE lokal (1.2.13)
├── Documents and Settings\                              ← Junction legacy → Users\ (1.2.13)
├── Config.Msi\                                           ← Rollback data MSI installer (1.2.13)
├── Windows.old\                                          ← Backup OS sebelum upgrade (1.2.13)
├── pagefile.sys / swapfile.sys / hiberfil.sys           ← Memory-related files (1.2.13)
├── DumpStack.log.tmp                                     ← Log crash dump (1.2.13)
├── bootmgr / BOOTNXT                                     ← Boot manager & penanda next-boot (1.2.13)
│
├── Windows\                                              (1.2.2)
│   ├── System32\                                         (1.2.3)
│   │   ├── config\ (SYSTEM, SOFTWARE, SAM, SECURITY, DEFAULT)
│   │   │   └── RegBack\                                  ← Backup registry hive periodik
│   │   ├── winevt\Logs\ (*.evtx)
│   │   ├── Tasks\ / TaskCache\                            ← Scheduled task XML
│   │   ├── wbem\Repository\                               ← WMI database (fileless persistence)
│   │   ├── LogFiles\ (WMI\, Firewall\, W3SVC*\)
│   │   ├── drivers\ (*.sys)
│   │   ├── drivers\etc\hosts
│   │   ├── spool\PRINTERS\
│   │   └── LogFiles\ / LSA
│   ├── SysWOW64\
│   ├── Prefetch\ (*.pf)
│   ├── Temp\
│   ├── SoftwareDistribution\
│   ├── Logs\ (CBS\, DISM\)
│   ├── Panther\ (unattend.xml, setupact.log)
│   ├── INF\ (setupapi.dev.log)
│   ├── Debug\ (PASSWD.LOG, NetSetup.log)
│   ├── security\
│   ├── WinSxS\
│   └── Minidump\ + MEMORY.DMP                            ← Crash dump kernel (BSOD forensic)
│
├── Users\                                                (1.2.5)
│   ├── <username>\
│   │   ├── NTUSER.DAT
│   │   ├── AppData\Local\Microsoft\Windows\UsrClass.dat  ← ShellBags
│   │   ├── AppData\Local\Temp\
│   │   ├── AppData\Local\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
│   │   ├── AppData\Roaming\Microsoft\Windows\Recent\
│   │   │   ├── *.lnk
│   │   │   ├── AutomaticDestinations\*.automaticDestinations-ms
│   │   │   └── CustomDestinations\*.customDestinations-ms
│   │   ├── AppData\Local\Programs\                        ← Installer per-user (tanpa admin, sering dipakai fake installer)
│   │   ├── Desktop\ / Documents\ / Downloads\ / Pictures\ / Videos\ / Music\
│   │   └── AppData\LocalLow\                               ← Data app low-integrity (browser sandbox)
│   └── Public\
│
├── Program Files\ & Program Files (x86)\                 (1.2.8)
│
├── ProgramData\                                           (1.2.9)
│   ├── Microsoft\Windows Defender\Scans\History\
│   ├── Microsoft\Windows\WER\
│   └── Package Cache\
│
├── PerfLogs\                                               (1.2.10)
│
└── $Recycle.Bin\                                           (1.2.11)
    └── <SID user>\
        ├── $I*.ext   ← metadata
        └── $R*.ext   ← isi file
```

> 📝 Tabel/tree ini adalah rangkuman — untuk pengertian, fungsi, dan tools masing-masing path, kembali ke sub-bab yang tertera di setiap baris.

---

## 📎 Lampiran Bab 1 — Master Acquisition & Export Workflow

Ini adalah alur akuisisi/ekspor **generik** yang dipakai berulang kali di Bab 2, 3, dan 4 — daripada ditulis ulang tiap bab, semua bab lain cukup merujuk ke sini dan hanya menyebutkan **target file spesifik** mereka masing-masing.

```
1. Buka image (.E01/.dd/.raw/.vhd) di FTK Imager
   File > Add Evidence Item > pilih tipe image

2. Browse ke path target sesuai artefak yang mau diambil
   (lihat tabel di bawah untuk tiap jenis artefak)

3. Klik kanan file/folder target > Export Files...
   Simpan ke folder evidence lokal, idealnya per-jenis artefak (mis. evidence\registry\, evidence\evtx\)

4. Jalankan parser CLI/GUI sesuai jenis artefak (lihat kolom "Parser" di tabel)
   Output umumnya CSV/JSON

5. Buka hasil CSV di Timeline Explorer (Eric Zimmerman Tools)
   Filter, sort, dan (kalau perlu) gabungkan beberapa CSV jadi satu timeline lintas-artefak
```

**Target ekspor per jenis artefak (ringkasan lintas-bab):**

| Artefak | Path di Image | Parser | Detail di |
|---|---|---|---|
| `$MFT`, `$LogFile`, `$UsnJrnl` | Root volume / `$Extend\` | MFTECmd, LogFileParser | Bab 2, §2.2.7, §2.4 |
| Hive registry utama | `Windows\System32\config\` (SYSTEM, SOFTWARE, SAM, SECURITY, DEFAULT + `RegBack\`) | RECmd, RegistryExplorer | Bab 3, §3.9 |
| Hive per-user | `Users\<user>\NTUSER.DAT`, `Users\<user>\AppData\Local\Microsoft\Windows\UsrClass.dat` | RECmd, ShellBagsExplorer | Bab 3, §3.7, §3.9 |
| `Amcache.hve` | `Windows\AppCompat\Programs\Amcache.hve` | AmcacheParser | Bab 3, §3.8 |
| File EVTX | `Windows\System32\winevt\Logs\*.evtx` | EvtxECmd, Hayabusa/Chainsaw | Bab 4, §4.10 |
| Prefetch | `Windows\Prefetch\*.pf` | PECmd | Bab 4, §4.13.8 |
| VSS, Recycle Bin, LNK, Jump List | `System Volume Information\`, `$Recycle.Bin\`, `AppData\Roaming\...\Recent\` | RBCmd, LECmd, JLECmd | Bab 5 |
| Browser (History, Cookies, Cache, Login Data) | `AppData\Local\Google\Chrome\...`, `AppData\Roaming\Mozilla\Firefox\...`, dll | Hindsight, DB Browser for SQLite | Bab 6 |

> 💡 **Kenapa dipisah dari bab masing-masing:** Prosesnya (export → parse → load ke Timeline Explorer) selalu sama persis, yang beda cuma path & tool. Menulis ulang langkah generik ini di tiap bab cuma nambah panjang tanpa nambah pengetahuan baru — cukup satu rujukan di sini.

---

## 📍 Penutup Bab 1 — Windows Storage Architecture (Big Picture)

Satu diagram besar yang merangkum seluruh isi Bab 1, sekaligus jadi "peta mental" penghubung ke Bab 2 (NTFS internals), Bab 3 (Registry), Bab 4 (Event Log), dan seterusnya.

```
Physical Disk
│
├── Sector (1.1.1)
│
├── Partition Table — MBR / GPT (1.1.5)
│    └── Disk Signature / GUID (1.1.9)
│
├── Partition
│   │
│   ├── VBR (1.1.7)
│   │
│   ├── Filesystem — NTFS (1.1.3)
│   │    │
│   │    ├── $MFT
│   │    ├── $Bitmap
│   │    ├── $LogFile
│   │    └── ... (lihat 1.1.12)
│   │
│   └── C:\  (1.2.1)
│        │
│        ├── Windows\ (1.2.2)
│        │    ├── System32\ (1.2.3)
│        │    └── SysWOW64\ (1.2.4)
│        │
│        ├── Users\ (1.2.5)
│        │    └── <username>\AppData\ (1.2.6)
│        │         ├── Local
│        │         ├── LocalLow
│        │         └── Roaming
│        │
│        ├── ProgramData\ (Hidden) (1.2.9)
│        ├── System Volume Information\ (Hidden, System) (1.2.1 / 1.2.13)
│        └── ...
│
└── Unallocated Space (1.1.11)
```
