## 📌 Daftar Isi — Bab 1

- [Bab 1 — Struktur Windows & Filesystem](#bab-1--struktur-windows--filesystem)
  - [1.1 Struktur Drive & Partisi](#11-struktur-drive--partisi)
    - [1.1.1 Physical Disk vs Partition vs Volume](#111-physical-disk-vs-partition-vs-volume)
    - [1.1.2 MBR vs GPT](#112-mbr-vs-gpt)
    - [1.1.3 Partisi Umum di Disk Windows](#113-partisi-umum-di-disk-windows)
    - [1.1.4 VBR (Volume Boot Record)](#114-vbr-volume-boot-record)
    - [1.1.5 Cara Analisa di FTK Imager / KAPE](#115-cara-analisa-di-ftk-imager--kape)
    - [1.1.6 Full Path Tree — Disk & Partition Level](#116-full-path-tree--disk--partition-level)
  - [1.2 Struktur Direktori Windows (C:\\)](#12-struktur-direktori-windows-c)
    - [1.2.1 Root C:\\ — Overview](#121-root-c--overview)
    - [1.2.2 Windows\\](#122-windows)
    - [1.2.3 Windows\\System32\\](#123-windowssystem32)
    - [1.2.4 Users\\](#124-users)
    - [1.2.5 Program Files\\ & Program Files (x86)\\](#125-program-files--program-files-x86)
    - [1.2.6 ProgramData\\](#126-programdata)
    - [1.2.7 PerfLogs\\](#127-perflogs)
    - [1.2.8 $Recycle.Bin\\](#128-recyclebin)
    - [1.2.9 Tabel Prioritas Investigasi](#129-tabel-prioritas-investigasi)
    - [1.2.10 Root-Level Files & Folder yang Sering Terlewat](#1210-root-level-files--folder-yang-sering-terlewat)
    - [1.2.11 Full Path Tree — Seluruh C:\\ (Master Reference)](#1211-full-path-tree--seluruh-c-master-reference)

---

## Bab 1 — Struktur Windows & Filesystem

### 1.1 Struktur Drive & Partisi

#### 1.1.1 Physical Disk vs Partition vs Volume

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

#### 1.1.2 MBR vs GPT

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

#### 1.1.3 Partisi Umum di Disk Windows

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

#### 1.1.4 VBR (Volume Boot Record)

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

#### 1.1.5 Cara Analisa di FTK Imager / KAPE

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

#### 1.1.6 Full Path Tree — Disk & Partition Level

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
│   ├── $Bitmap               ← Peta cluster terpakai/kosong
│   ├── $Boot                 ← Salinan VBR + bootstrap code
│   ├── $BadClus              ← Daftar bad sector/cluster
│   ├── $Secure               ← ACL & security descriptor
│   ├── $UpCase                ← Tabel konversi uppercase (untuk nama file case-insensitive)
│   ├── $Extend\
│   │   ├── $UsnJrnl          ← Change journal (create/modify/delete/rename)
│   │   ├── $ObjId             ← Object ID tracking (link antar file/shortcut)
│   │   ├── $Quota             ← Disk quota per user
│   │   └── $Reparse           ← Reparse point index (symlink, junction, OneDrive placeholder)
│   ├── $Recycle.Bin\          ← lihat 1.2.8
│   ├── System Volume Information\   ← Restore Point & Volume Shadow Copy metadata (butuh privilege SYSTEM)
│   ├── pagefile.sys           ← Memory swap file
│   ├── hiberfil.sys           ← Snapshot RAM saat hibernate
│   ├── swapfile.sys           ← Swap khusus UWP apps
│   ├── bootmgr                ← Windows Boot Manager (legacy path, tetap ada di beberapa setup)
│   ├── BOOTNXT                ← Penanda next-boot untuk WinRE/recovery
│   ├── Documents and Settings ← Junction/symlink kompatibilitas ke Users\ (legacy XP path)
│   ├── Recovery\              ← Metadata WinRE lokal (beda dengan partisi Recovery terpisah)
│   ├── Windows\               ← lihat 1.2.2 – 1.2.3
│   ├── Users\                 ← lihat 1.2.4
│   ├── Program Files\         ← lihat 1.2.5
│   ├── Program Files (x86)\  ← lihat 1.2.5
│   ├── ProgramData\           ← lihat 1.2.6
│   └── PerfLogs\              ← lihat 1.2.7
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

> 💡 **File yang paling sering terlewat pemula:** `BCD` (dua-duanya — di ESP untuk UEFI atau di System Reserved untuk legacy) adalah **registry hive tersendiri**, bisa dibuka dengan `RegistryExplorer.exe` atau `bcdedit /store <path>` — berguna untuk lihat entry boot mencurigakan (misal boot ke OS lain / dual-boot yang tidak sah). `System Volume Information\` juga sering diabaikan padahal berisi Volume Shadow Copy yang bisa membuka file yang "sudah dihapus/terkunci" di title lama.

---

### 1.2 Struktur Direktori Windows (C:\\)

#### 1.2.1 Root C:\\ — Overview

```
C:\
│
├── Windows\                  ← Inti sistem operasi (lihat 1.2.2 – 1.2.3)
├── Users\                     ← Profil semua user (lihat 1.2.4)
├── Program Files\             ← Aplikasi 64-bit (lihat 1.2.5)
├── Program Files (x86)\      ← Aplikasi 32-bit (lihat 1.2.5)
├── ProgramData\               ← Config aplikasi (hidden, per-mesin bukan per-user) (lihat 1.2.6)
├── PerfLogs\                  ← Log performance counter (jarang dipakai, sering kosong) (lihat 1.2.7)
├── $Recycle.Bin\              ← Recycle bin, per-user (berdasarkan SID) (lihat 1.2.8)
│
│   ── Folder/file lain yang sering terlewat, lihat detail di 1.2.10 ──
├── System Volume Information\ ← Volume Shadow Copy & Restore Point
├── Recovery\                   ← Metadata WinRE lokal
├── Documents and Settings\    ← Junction legacy → Users\ (kompatibilitas XP)
├── PerfLogs\Admin\             ← Sub Data Collector Set (kalau ada)
├── inetpub\                    ← (kalau IIS terinstall) web root server
├── Windows.old\                ← Sisa OS lama setelah upgrade Windows (goldmine artefak lama!)
├── pagefile.sys                ← Memory swap
├── hiberfil.sys                ← Snapshot RAM hibernate
├── swapfile.sys                ← Swap UWP apps
├── bootmgr                     ← Windows Boot Manager
├── BOOTNXT                     ← Penanda next-boot
└── $MFT, $LogFile, $Boot, dst  ← NTFS system file (hidden, lihat 1.1.6)
```

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

#### 1.2.4 Users\\

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

| Sub-area | Yang dicari | Tool |
|---|---|---|
| `NTUSER.DAT` | Aktivitas user: UserAssist, RecentDocs, typed paths, RunMRU | `RegistryExplorer.exe`, `RECmd.exe` |
| `AppData\Local\Temp\` | File yang di-drop attacker/malware, seringkali payload stage 2 | Hash check, `strings`, VirusTotal |
| `AppData\Roaming\...\Recent\` | LNK files & Jump Lists — file apa yang dibuka, dari drive mana | `LECmd.exe` (LNK), `JLECmd.exe` (Jump List) |
| `PSReadLine\ConsoleHost_history.txt` | Command PowerShell yang pernah diketik user | Text editor |
| `UsrClass.dat` | Shell bag (folder yang pernah dibuka via Explorer!) | `RegistryExplorer.exe`, ShellBag parser |
| `Downloads\` / `Desktop\` | File yang sengaja disimpan user, kadang bukti langsung | Manual review, hash |

```bash
# Contoh: parsing NTUSER.DAT untuk melihat semua key relevan
.\RECmd.exe -f "C:\Users\<user>\NTUSER.DAT" --csv .

# Contoh: parsing semua LNK file di folder Recent
.\LECmd.exe -d "C:\Users\<user>\AppData\Roaming\Microsoft\Windows\Recent" --csv .
```

> 💡 **Tip CTF:** Kalau soal minta "file apa yang dibuka user sebelum insiden" atau "user pernah akses drive apa", cek urutan: **NTUSER.DAT (RecentDocs) → LNK files → Jump Lists → ShellBags (UsrClass.dat)**. Keempatnya saling melengkapi dan kadang salah satu "selamat" walau yang lain dihapus attacker.

---

#### 1.2.5 Program Files\\ & Program Files (x86)\\

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

#### 1.2.6 ProgramData\\

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

#### 1.2.7 PerfLogs\\

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

#### 1.2.8 $Recycle.Bin\\

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

---

#### 1.2.9 Tabel Prioritas Investigasi

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
