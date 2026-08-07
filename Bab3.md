## 📌 Daftar Isi — Bab 3

- [Bab 3 — Windows Registry Forensics](#bab-3--windows-registry-forensics)
  - [3.1 Struktur & Konsep Dasar Registry](#31-struktur--konsep-dasar-registry)
    - [3.1.1 Hive, Key, Subkey, Value](#311-hive-key-subkey-value)
    - [3.1.2 Root Keys (Live) vs Hive File (Disk)](#312-root-keys-live-vs-hive-file-disk)
    - [3.1.3 Struktur Biner Hive File (Regf, hbin, cell)](#313-struktur-biner-hive-file-regf-hbin-cell)
    - [3.1.4 Registry Transaction Log (.LOG1 / .LOG2)](#314-registry-transaction-log-log1--log2)
    - [3.1.5 Timestamp Registry — Hanya LastWrite](#315-timestamp-registry--hanya-lastwrite)
  - [3.2 Lokasi & Jenis Hive File](#32-lokasi--jenis-hive-file)
    - [3.2.1 Hive Utama (System32\\config\\)](#321-hive-utama-system32config)
    - [3.2.2 Hive Per-User](#322-hive-per-user)
    - [3.2.3 RegBack — Snapshot Periodik](#323-regback--snapshot-periodik)
    - [3.2.4 Amcache.hve](#324-amcachehve)
  - [3.3 SYSTEM Hive — Konfigurasi Sistem](#33-system-hive--konfigurasi-sistem)
    - [3.3.1 ControlSet & CurrentControlSet](#331-controlset--currentcontrolset)
    - [3.3.2 Services (Persistence)](#332-services-persistence)
    - [3.3.3 USB Device History](#333-usb-device-history)
    - [3.3.4 Network, ComputerName & TimeZone](#334-network-computername--timezone)
    - [3.3.5 BAM / DAM (Background Activity Moderator)](#335-bam--dam-background-activity-moderator)
  - [3.4 SOFTWARE Hive — Aplikasi & Konfigurasi](#34-software-hive--aplikasi--konfigurasi)
    - [3.4.1 Uninstall Key](#341-uninstall-key)
    - [3.4.2 Run / RunOnce](#342-run--runonce)
    - [3.4.3 ShimCache / AppCompatCache](#343-shimcache--appcompatcache)
    - [3.4.4 Image File Execution Options & Persistence Lanjutan](#344-image-file-execution-options--persistence-lanjutan)
    - [3.4.5 User Profile List (SID ↔ Username)](#345-user-profile-list-sid--username)
    - [3.4.6 AutoLogon & Winlogon Credentials](#346-autologon--winlogon-credentials)
  - [3.5 SAM & SECURITY Hive — Akun & Kredensial](#35-sam--security-hive--akun--kredensial)
    - [3.5.1 Struktur Akun User (SAM)](#351-struktur-akun-user-sam)
    - [3.5.2 Decrypt SAM dengan Boot Key dari SYSTEM](#352-decrypt-sam-dengan-boot-key-dari-system)
    - [3.5.3 SECURITY — LSA Secrets & Cached Credentials](#353-security--lsa-secrets--cached-credentials)
  - [3.6 NTUSER.DAT — Aktivitas Per-User](#36-ntuserdat--aktivitas-per-user)
    - [3.6.1 UserAssist](#361-userassist)
    - [3.6.2 RecentDocs](#362-recentdocs)
    - [3.6.3 RunMRU & TypedPaths](#363-runmru--typedpaths)
    - [3.6.4 WordWheelQuery](#364-wordwheelquery)
    - [3.6.5 Network Drive & Mapped Share History](#365-network-drive--mapped-share-history)
    - [3.6.6 MUICache](#366-muicache)
    - [3.6.7 OpenSaveMRU](#367-opensavemru)
    - [3.6.8 LastVisitedMRU](#368-lastvisitedmru)
    - [3.6.9 MountPoints2 (USB & Network Drive Mapping)](#369-mountpoints2-usb--network-drive-mapping)
    - [3.6.10 TypedURLs](#3610-typedurls)
    - [3.6.11 Terminal Server / RDP History](#3611-terminal-server--rdp-history)
  - [3.7 UsrClass.dat — ShellBags](#37-usrclassdat--shellbags)
  - [3.8 Amcache.hve — Bukti Eksekusi Tingkat Lanjut](#38-amcachehve--bukti-eksekusi-tingkat-lanjut)
  - [3.9 Tools & Cara Analisa Registry](#39-tools--cara-analisa-registry)
  - [3.10 Tabel Korelasi Cepat — "Cari Jawaban Ini, Cek Key Itu"](#310-tabel-korelasi-cepat--cari-jawaban-ini-cek-key-itu)
  - [3.11 Tabel Prioritas — Execution vs Existence](#311-tabel-prioritas--execution-vs-existence)
  - [3.12 Mini Case Study — Rekonstruksi Aktivitas User dari Registry](#312-mini-case-study--rekonstruksi-aktivitas-user-dari-registry)

*(Bab 1: Struktur Drive & Direktori — `bab1.md`. Bab 2: File Sistem NTFS & $MFT — `bab2.md`. Bab 4 dan seterusnya menyusul — akan fokus ke EVTX & Event ID penting untuk DFIR.)*

---

## Bab 3 — Windows Registry Forensics

Registry adalah salah satu sumber bukti paling "kaya" di DFIR Windows — hampir semua pertanyaan klasik CTF/HTB Sherlock (*kapan program dijalankan*, *USB apa yang dicolok*, *user login jam berapa*, *software apa yang terinstall*) jawabannya ada di sini.

### 3.1 Struktur & Konsep Dasar Registry

#### 3.1.1 Hive, Key, Subkey, Value

Registry adalah **database hierarkis** — mirip filesystem, tapi isinya konfigurasi, bukan file.

```
Hive                          ← File fisik di disk (mis. SOFTWARE, NTUSER.DAT)
 └── Key                      ← Setara "folder" (mis. HKLM\SOFTWARE\Microsoft)
      └── Subkey               ← Key di dalam key (nested, bisa berlapis-lapis)
           └── Value            ← Setara "file" — punya Name, Type, dan Data
                 ├── Name        (mis. "InstallDate")
                 ├── Type        (REG_SZ, REG_DWORD, REG_BINARY, REG_MULTI_SZ, dll)
                 └── Data        (nilai sebenarnya)
```

| Istilah | Pengertian |
|---|---|
| **Hive** | Satu file registry mandiri di disk yang berisi satu pohon key lengkap |
| **Key** | "Folder" registry, bisa punya subkey dan value |
| **Value** | Pasangan nama-data di dalam sebuah key, dengan tipe data tertentu |
| **REG_SZ** | String biasa |
| **REG_DWORD** | Angka 32-bit |
| **REG_BINARY** | Data biner mentah — sering dipakai buat struktur kompleks seperti ShellBags, UserAssist |
| **REG_MULTI_SZ** | Array string |

#### 3.1.2 Root Keys (Live) vs Hive File (Disk)

Saat Windows hidup, semua hive di-*mount* jadi 5 root key yang familiar di `regedit`. Tapi di **image mati** (offline forensic), yang kamu punya cuma **file hive mentah** — root key ini tidak ada, kamu langsung baca dari file-nya.

| Root Key (Live) | Sumber Hive File | Keterangan |
|---|---|---|
| `HKEY_LOCAL_MACHINE` (HKLM) | `SYSTEM`, `SOFTWARE`, `SAM`, `SECURITY`, `DEFAULT` | Konfigurasi sistem-wide |
| `HKEY_CURRENT_USER` (HKCU) | `NTUSER.DAT` milik user yang sedang login | Konfigurasi per-user yang sedang aktif |
| `HKEY_USERS` (HKU) | Semua `NTUSER.DAT` yang di-load (termasuk user lain yang tidak login) | Berisi HKCU semua user + `.DEFAULT` |
| `HKEY_CLASSES_ROOT` (HKCR) | Gabungan `SOFTWARE\Classes` (HKLM) + `NTUSER.DAT\Software\Classes` (HKCU) | File association, COM registration |
| `HKEY_CURRENT_CONFIG` (HKCC) | Subset dari `SYSTEM\CurrentControlSet\Hardware Profiles\Current` | Profil hardware aktif |

> 💡 **Kenapa penting dipahami:** Saat kamu forensik image mati, kamu tidak akan pernah lihat `HKLM\SOFTWARE\...` di tool parsing — yang ada cuma path relatif dari root hive file-nya sendiri, misal `\Microsoft\Windows\CurrentVersion\Run`. Root key hanya istilah untuk sistem hidup.

#### 3.1.3 Struktur Biner Hive File (Regf, hbin, cell)

Sekilas — berguna untuk paham kenapa hive rusak/corrupt kadang masih bisa di-*carve* sebagian datanya.

```
[Hive File]
├── Regf Header (4KB)      ← Signature "regf", checksum, sequence number
├── hbin (Hive Bin) #1      ← Blok alokasi 4KB, isinya banyak "cell"
│     ├── Cell: nk (Key Node)
│     ├── Cell: vk (Value Key)
│     ├── Cell: sk (Security Key — ACL)
│     └── Cell: lf/lh (List — index subkey)
├── hbin #2
└── ... dst
```

| Cell Type | Isi |
|---|---|
| `nk` (Key Node) | Metadata sebuah key: nama, timestamp `LastWrite`, pointer ke subkey & value |
| `vk` (Value Key) | Satu value: nama, tipe data, data (atau pointer ke data kalau besar) |
| `sk` (Security Key) | ACL/security descriptor key |
| `lf` / `lh` | Index list untuk mempercepat pencarian subkey |

> 💡 **Forensic value:** Setiap key `nk` punya timestamp **LastWrite** (kapan key itu terakhir dimodifikasi) — ini setara timestamp `Modified` tapi level registry key, bukan file. Sering dipakai buat cross-check timeline eksekusi/persistence.

#### 3.1.4 Registry Transaction Log (.LOG1 / .LOG2)

Mirip `$LogFile` di NTFS (Bab 2) — registry juga punya journal transaksi sendiri, letaknya **sejajar dengan hive file utama**.

```
System32\config\
├── SOFTWARE
├── SOFTWARE.LOG1     ← Transaction log
├── SOFTWARE.LOG2     ← Transaction log (kedua, untuk redundansi)
└── SOFTWARE.blf / .regtrans-ms   ← Metadata transaksi (format lama/baru)
```

> ⚠️ **Sering ke-skip padahal krusial:** Perubahan registry **paling baru** kadang belum di-*flush* ke hive utama saat image diambil (mis. mesin dimatikan paksa) — data terbaru itu **hanya ada di `.LOG1`/`.LOG2`**. Kalau parsing hive utama saja hasilnya "kurang lengkap" atau timestamp terasa ganjil, replay transaction log dulu.

**Cara replay log ke hive:**
```bash
# RECmd bisa otomatis merge transaction log saat parsing kalau file .LOG1/.LOG2 ada di folder yang sama
.\RECmd.exe -f "C:\Windows\System32\config\SOFTWARE" --csv .
# (RECmd otomatis mendeteksi & apply .LOG1/.LOG2 di folder yang sama secara default)
```

#### 3.1.5 Timestamp Registry — Hanya LastWrite

Ini kesalahan yang **sangat sering** dilakukan pemula saat baru pindah dari analisa filesystem (Bab 2) ke registry: menyamakan konsep timestamp `$MFT` (Created/Modified/Accessed/Entry Modified) dengan registry. **Registry tidak bekerja seperti itu.**

```
Registry Key
└── LastWrite    ← SATU-SATUNYA timestamp yang dipunyai sebuah key
```

| Filesystem ($MFT / $STANDARD_INFORMATION) | Registry Key |
|---|---|
| Created | ❌ Tidak ada |
| Modified | ✅ Setara **LastWrite** |
| MFT Entry Modified | ❌ Tidak ada |
| Accessed | ❌ Tidak ada |

**Yang perlu dipahami:**

* `LastWrite` melekat pada **key** (`nk` cell — lihat **3.1.3**), **bukan pada value**. Artinya kalau sebuah key punya 10 value dan cuma 1 value yang diubah, `LastWrite` seluruh key ikut ter-update — kamu **tidak bisa** tahu persis value mana yang berubah hanya dari timestamp ini.
* Tidak ada histori — `LastWrite` cuma menyimpan waktu **modifikasi terakhir**, bukan modifikasi pertama. Kalau butuh histori perubahan, satu-satunya cara adalah membandingkan hive utama dengan `RegBack\` (**3.2.3**) atau replay transaction log (**3.1.4**).
* Banyak artefak "timestamp" yang sebenarnya kamu lihat di tool seperti RECmd (mis. `Last Executed` di UserAssist, `Last Connected` di USBSTOR) itu **bukan** `LastWrite` — itu data biner yang di-*encode* di dalam value itu sendiri (`vk` cell), diparsing dan diformat ulang jadi timestamp yang manusiawi oleh tool-nya. `LastWrite` tetap ada terpisah di level key-nya.

> ⚠️ **Kesalahan umum di lapangan:** Menyebut `LastWrite` sebuah key sebagai "waktu file dieksekusi" atau "waktu file dibuat". `LastWrite` cuma bukti bahwa **key itu terakhir ditulis/dimodifikasi pada waktu tersebut** — interpretasinya tergantung konteks key yang bersangkutan (mis. `LastWrite` pada key Run key persistence = kira-kira kapan persistence itu dipasang, bukan kapan malware terakhir jalan).

---

### 3.2 Lokasi & Jenis Hive File

#### 3.2.1 Hive Utama (`System32\config\`)

| Hive | Fungsi |
|---|---|
| `SYSTEM` | Konfigurasi sistem: services, device, network, ControlSet — lihat **3.3** |
| `SOFTWARE` | Aplikasi terinstall, konfigurasi software, persistence — lihat **3.4** |
| `SAM` | Security Account Manager — akun user lokal — lihat **3.5** |
| `SECURITY` | Local Security Authority (LSA) policy & secrets — lihat **3.5** |
| `DEFAULT` | Profil default untuk user baru / sebelum ada user login |

#### 3.2.2 Hive Per-User

| Hive | Lokasi | Fungsi |
|---|---|---|
| `NTUSER.DAT` | `C:\Users\<user>\NTUSER.DAT` | Aktivitas & preferensi per-user — lihat **3.6** |
| `UsrClass.dat` | `C:\Users\<user>\AppData\Local\Microsoft\Windows\UsrClass.dat` | File association per-user, **ShellBags** — lihat **3.7** |

#### 3.2.3 RegBack — Snapshot Periodik

```
C:\Windows\System32\config\RegBack\
├── SYSTEM
├── SOFTWARE
├── SAM
├── SECURITY
└── DEFAULT
```

Windows secara berkala (tergantung versi & config Task Scheduler) menyalin hive utama ke `RegBack\`. Kalau attacker memodifikasi hive utama (mis. hapus key persistence setelah selesai dipakai), **`RegBack\` bisa jadi "time machine"** untuk lihat kondisi registry sebelum modifikasi.

> ⚠️ **Catatan:** Di Windows 10 versi baru, task otomatis backup ke `RegBack\` sempat dinonaktifkan default (mulai 1803) lalu balik lagi — cek dulu apakah isinya benar-benar ter-update atau cuma placeholder kosong dari instalasi awal.

#### 3.2.4 Amcache.hve

```
C:\Windows\AppCompat\Programs\Amcache.hve
```

Hive terpisah (bukan di `config\`) yang menyimpan metadata eksekusi program secara lebih detail dari ShimCache. Dibahas mendalam di **3.8**.

---

### 3.3 SYSTEM Hive — Konfigurasi Sistem

#### 3.3.1 ControlSet & CurrentControlSet

```
SYSTEM\
├── ControlSet001\
├── ControlSet002\           ← Bisa lebih dari satu (backup/alternate boot config)
├── Select\
│     ├── Current    → menunjuk ControlSet yang aktif (mis. value = 1 → ControlSet001)
│     ├── Default
│     ├── Failed
│     └── LastKnownGood
└── CurrentControlSet\        ← Symlink virtual ke ControlSet00X yang aktif (hanya ada saat live, tidak ada di hive mentah)
```

> 💡 **Penting saat offline analysis:** Karena `CurrentControlSet` tidak benar-benar ada di hive mentah, tool parsing (RECmd/RegistryExplorer) akan resolve otomatis ke `ControlSet001`/`002` berdasarkan value `Select\Current`. Kalau kamu baca manual pakai hex editor, jangan cari "CurrentControlSet" — cari `ControlSet001` dst.

#### 3.3.2 Services (Persistence)

```
SYSTEM\ControlSet001\Services\<NamaService>\
├── Start        ← 0=Boot, 1=System, 2=Automatic, 3=Manual, 4=Disabled
├── Type         ← 1=Kernel driver, 2=FS driver, 16=Own process, 32=Shared process
├── ImagePath    ← Path executable/driver yang dijalankan service ini
└── DisplayName
```

**Nilai forensik:** Service adalah teknik persistence yang sangat umum — attacker bikin service baru yang `ImagePath`-nya menunjuk ke malware, dengan `Start=2` (Automatic) supaya jalan tiap boot.

```bash
# Cek semua service & ImagePath-nya lewat RECmd/RegistryExplorer, filter ImagePath yang path-nya aneh
# (Program Files biasa vs C:\Users\...\AppData\Local\Temp\evil.exe misalnya)
```

#### 3.3.3 USB Device History

```
SYSTEM\ControlSet001\Enum\
├── USBSTOR\                          ← Mass storage USB (flashdisk, HDD eksternal)
│     └── Disk&Ven_...&Prod_...\
│           └── <SerialNumber>\
│                 ├── FriendlyName
│                 └── (Properties subkey → timestamp first/last connected)
└── USB\                               ← Semua device USB (bukan cuma storage)
      └── VID_xxxx&PID_xxxx\
```

| Key/Value | Info yang didapat |
|---|---|
| `USBSTOR\...\FriendlyName` | Nama device/vendor |
| `...\Properties\{83da6326-97a6-4088-9453-a1923f573b29}\0064` | Timestamp **first connected** |
| `...\Properties\{83da6326-...}\0066` | Timestamp **last connected** |
| `...\Properties\{83da6326-...}\0067` | Timestamp **last removed** |
| Serial Number (nama subkey) | ID unik device — dipakai cross-reference ke drive letter & volume serial number (kaitan ke **Bab 1, 1.1.4**) |

> 💡 **Cross-reference:** Serial number USB di sini bisa dicocokkan dengan `setupapi.dev.log` (**Bab 1, 1.2.2**) untuk waktu instalasi awal, dan dengan **ShellBags** (**3.7**) untuk lihat folder apa yang dibuka dari drive itu.

#### 3.3.4 Network, ComputerName & TimeZone

| Key | Info |
|---|---|
| `SYSTEM\ControlSet001\Services\Tcpip\Parameters\Interfaces\<GUID>` | IP config statis/DHCP per interface |
| `SYSTEM\ControlSet001\Control\ComputerName\ComputerName` | Nama komputer |
| `SYSTEM\ControlSet001\Control\TimeZoneInformation` | Timezone sistem — **wajib dicek di awal investigasi** supaya semua timestamp lain bisa dikonversi konsisten (UTC vs local time) |

#### 3.3.5 BAM / DAM (Background Activity Moderator)

Salah satu artefak **execution** paling penting di Windows 10/11 modern — dan paling sering luput dicek pemula karena kalah populer dibanding UserAssist/Prefetch.

```
SYSTEM\ControlSet001\Services\bam\State\UserSettings\<SID>\
```
dan (di sistem yang masih memilikinya — DAM adalah pendahulu/varian BAM di build lama)
```
SYSTEM\ControlSet001\Services\dam\State\UserSettings\<SID>\
```

```
<SID>\
└── \Device\HarddiskVolume3\Users\<user>\...\program.exe
      └── (REG_BINARY, 8 byte pertama = FILETIME terakhir dieksekusi)
```

**Nilai forensik:**

* Mencatat **program apa saja yang pernah dijalankan** oleh user tertentu (dipisah per-SID).
* Value data-nya menyimpan **timestamp eksekusi** dalam format FILETIME (8 byte pertama dari REG_BINARY).
* Sangat konsisten muncul di **Windows 10/11**, sedangkan artefak lama (mis. beberapa versi UserAssist) makin jarang reliable.
* Full path executable ikut tersimpan sebagai nama value — jadi selain waktu, kamu juga langsung dapat lokasi file-nya.

> 💡 **Tip CTF — "Program apa yang dijalankan user?":** Kalau soal minta bukti eksekusi dan **UserAssist kosong/tidak cocok** (misal karena program dijalankan bukan lewat double-click Explorer, atau history-nya sudah "ke-flush"), **cek BAM dulu**. BAM sering menangkap eksekusi yang tidak tercatat di UserAssist, termasuk yang dijalankan lewat command line/script — beda dengan UserAssist yang cuma mencatat eksekusi via GUI (**3.6.1**).

```bash
# RECmd punya batch khusus BAM, atau parsing manual dengan RegistryExplorer
.\RECmd.exe -f "SYSTEM" --bn BatchExamples\BAM_DAM.reb --csv .
```

> ⚠️ **Catatan presisi:** Timestamp BAM adalah waktu **terakhir** program itu dijalankan (last execution), bukan histori tiap kali dijalankan — mirip konsep `LastWrite` (**3.1.5**), BAM tidak menyimpan run count atau histori multi-eksekusi seperti UserAssist.

---

### 3.4 SOFTWARE Hive — Aplikasi & Konfigurasi

#### 3.4.1 Uninstall Key

```
SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\<AppKey>\
├── DisplayName
├── DisplayVersion
├── InstallDate     ← Format YYYYMMDD (string, bukan timestamp biner)
├── InstallLocation
└── Publisher
```

**Nilai forensik:** Bukti software pernah terinstall (walau sudah di-uninstall, key ini kadang masih tertinggal). Cocok untuk verifikasi software mencurigakan — cross-check dengan folder `Program Files\` (**Bab 1, 1.2.5**).

#### 3.4.2 Run / RunOnce

```
SOFTWARE\Microsoft\Windows\CurrentVersion\Run\           ← Jalan tiap login (HKLM = semua user)
SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\        ← Jalan sekali lalu key dihapus otomatis
```
*(Versi HKCU-nya ada juga di NTUSER.DAT, key path sama tapi scope per-user — lihat 3.6)*

**Nilai forensik:** Teknik persistence paling klasik dan paling gampang dicek — value name bebas, data-nya adalah command/path yang dieksekusi.

#### 3.4.3 ShimCache / AppCompatCache

```
SYSTEM\ControlSet001\Control\Session Manager\AppCompatCache\AppCompatCache
```
*(Catatan: walau namanya "AppCompatCache", key ini ada di hive **SYSTEM**, bukan SOFTWARE — disinggung di sini karena fungsinya berkaitan erat dengan bukti eksekusi/keberadaan aplikasi)*

**Pengertian:** Windows mencatat file executable yang pernah **diperiksa** OS untuk keperluan Application Compatibility — mencakup file yang dijalankan **maupun** yang cuma di-*enumerate* (mis. lewat Explorer) tanpa benar-benar dieksekusi.

| Kolom (hasil parsing) | Keterangan |
|---|---|
| `Path` | Path lengkap executable |
| `LastModifiedTimeUTC` | Timestamp modifikasi file dari `$STANDARD_INFORMATION` (**bukan** waktu eksekusi!) |
| `Executed` | Indikasi apakah file benar-benar dieksekusi (tergantung versi Windows, tidak selalu reliable) |

> ⚠️ **Miskonsepsi umum:** ShimCache **BUKAN** bukti pasti "file ini dijalankan pada waktu X". Timestamp yang tercatat adalah timestamp modifikasi file, bukan waktu eksekusi. ShimCache lebih tepat dibaca sebagai *"file ini pernah ada/terdeteksi di sistem"*. Untuk bukti eksekusi yang lebih kuat, kombinasikan dengan **Prefetch** (Bab 1) dan **Amcache** (**3.8**).

#### 3.4.4 Image File Execution Options & Persistence Lanjutan

```
SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<namaExe>\
└── Debugger    ← Kalau diisi, Windows akan jalankan "Debugger" ini SETIAP KALI <namaExe> dijalankan
```

**Nilai forensik:** Teknik persistence/hijack lanjutan — misal attacker set `Debugger` pada `sethc.exe` (Sticky Keys) untuk dapat command prompt SYSTEM dari login screen (teknik klasik "Sticky Keys backdoor").

Key persistence lain yang perlu dicek di SOFTWARE hive:
```
SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders\
SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell   ← Hijack shell login
SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit
SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects\  ← BHO (browser hijack lama)
```

#### 3.4.5 User Profile List (SID ↔ Username)

Wajib dicek di **awal** investigasi — ini "kamus" yang menghubungkan SID mentah (yang muncul di hampir semua artefak lain: BAM di **3.3.5**, ShellBags di **3.7**, SAM di **3.5**) dengan nama user dan lokasi profile-nya.

```
SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\<SID>\
├── ProfileImagePath   ← Path folder profile user, mis. C:\Users\John
├── State
└── (nama subkey = SID user, mis. S-1-5-21-...-1001)
```

**Nilai forensik:**

* Memetakan `S-1-5-21-...` ke `C:\Users\John` → dari path ini kamu langsung tahu **username**-nya.
* **Wajib** dilakukan pertama kali sebelum menganalisa artefak per-user lain (NTUSER.DAT, BAM, ShellBags) yang datanya dikelompokkan per-SID — tanpa mapping ini, temuan cuma jadi daftar SID tanpa identitas.
* Bisa juga membedakan **profile lokal** vs **profile domain** (SID domain punya pola berbeda dari SID lokal mesin).

```bash
# Contoh: cross-reference SID dari BAM ke username
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\S-1-5-21-...-1001" /v ProfileImagePath
```

> 💡 **Tip CTF:** Soal yang menyebut "user tertentu menjalankan X" padahal bukti mentahnya cuma berupa SID (mis. dari BAM/DAM) — jawaban pertama yang harus dicari **bukan** langsung ke BAM, tapi **ProfileList dulu** untuk konfirmasi identitas user di balik SID tersebut.

#### 3.4.6 AutoLogon & Winlogon Credentials

Sering jadi jawaban langsung untuk challenge bertema **credential hunting** — kredensial tersimpan **plaintext** di registry (bukan hash), karena fitur auto-logon memang didesain begitu.

```
SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\
├── DefaultUserName     ← Username yang auto-login
├── DefaultPassword     ← Password PLAINTEXT (kalau auto-logon diaktifkan!)
├── AutoAdminLogon       ← "1" = auto-logon aktif, "0" = nonaktif
└── DefaultDomainName
```

**Nilai forensik:**

* Kalau `AutoAdminLogon = 1` dan `DefaultPassword` terisi, itu artinya password user tersebut **tersimpan plaintext** di SOFTWARE hive — tidak perlu decrypt SAM sama sekali (bandingkan dengan **3.5.2** yang butuh boot key).
* Sering dipasang admin untuk kemudahan (kiosk mode, mesin lab, VM testing) — tapi jadi kelemahan besar kalau image/VM tersebut bocor atau diakses attacker.
* `Winlogon\Shell` dan `Winlogon\Userinit` (sudah disinggung di **3.4.4**) juga satu key ini — kalau attacker sempat hijack shell login, sekalian cek area ini untuk kredensial yang mungkin ditinggalkan.

> 💡 **Tip CTF:** Kalau soal minta "temukan password user X" dan SAM ternyata sudah di-reset/tidak bisa di-crack, **selalu cek `Winlogon\DefaultPassword` dulu** — banyak challenge sengaja menaruh jawaban di sini karena lebih realistis (mesin lab/VM sering dikonfigurasi auto-logon) dan tidak butuh tools cracking sama sekali.

---

### 3.5 SAM & SECURITY Hive — Akun & Kredensial

#### 3.5.1 Struktur Akun User (SAM)

```
SAM\SAM\Domains\Account\Users\
├── Names\<username>\        ← Mapping nama user → RID
└── <RID hex, mis. 000001F4>\
      ├── F      ← Fixed-length data: login count, last login, password last set, account flags
      └── V      ← Variable-length data: username, full name, comment (dalam bentuk binary terenkode)
```

| Info yang bisa diekstrak | Field |
|---|---|
| Username | `V` |
| RID (Relative ID) | Nama subkey (hex) — RID `500` = built-in Administrator, `501` = Guest |
| Login count | `F` |
| Last login timestamp | `F` |
| Password last set | `F` |
| Account disabled/locked flag | `F` (bit flag) |

#### 3.5.2 Decrypt SAM dengan Boot Key dari SYSTEM

**Penting:** Hash password di SAM **tidak bisa dibaca langsung** — dienkripsi dengan *boot key* yang justru disimpan (dalam bentuk obfuscated) di hive **SYSTEM**. Ini kenapa tool dump SAM (`secretsdump.py`, `Mimikatz`, dst) selalu butuh **kedua hive** SAM + SYSTEM sekaligus.

```bash
# Contoh: dump hash NTLM dari SAM + SYSTEM offline (Impacket)
secretsdump.py -sam SAM -system SYSTEM LOCAL
```

#### 3.5.3 SECURITY — LSA Secrets & Cached Credentials

```
SECURITY\Policy\Secrets\        ← LSA Secrets (kadang berisi password service account, auto-logon, dll — terenkripsi juga pakai boot key SYSTEM)
SECURITY\Cache\                  ← Cached domain credentials (kalau mesin pernah login domain, meski DC offline)
```

**Nilai forensik:** LSA Secrets kadang menyimpan kredensial dalam bentuk yang bisa didekripsi (auto-logon password, service account password) — sering jadi temuan besar di CTF privilege escalation.

```bash
# Dump LSA secrets (butuh SYSTEM + SECURITY hive)
secretsdump.py -security SECURITY -system SYSTEM LOCAL
```

---

### 3.6 NTUSER.DAT — Aktivitas Per-User

#### 3.6.1 UserAssist

```
NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\
└── {GUID}\Count\
      └── <nama program ter-ROT13>
            ├── Run Count
            ├── Last Executed timestamp
            └── Focus Time / Focus Count (versi baru)
```

**Pengertian:** Mencatat program yang dijalankan **lewat GUI** (double-click di Explorer/Start Menu) — command line/script yang dijalankan langsung dari terminal biasanya **tidak** tercatat di sini.

> ⚠️ **ROT13 encoding:** Nama program di key ini di-ROT13 (mis. `Cebtenz Svyrf` = `Program Files`). Semua tool parsing modern (RECmd) sudah otomatis decode ini.

#### 3.6.2 RecentDocs

```
NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\
├── (default, semua file)
└── .<ext>\    ← Sub-key per ekstensi file (.docx, .pdf, dst), MRU order tersendiri
```

**Nilai forensik:** File yang terakhir dibuka lewat Explorer/dialog Open-Save — termasuk file yang sudah dipindah/dihapus.

#### 3.6.3 RunMRU & TypedPaths

```
NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU\           ← History Run dialog (Win+R)
NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths\       ← History path yang diketik manual di address bar Explorer
```

**Nilai forensik:** `RunMRU` sering jadi bukti kuat command/tool yang dijalankan manual oleh user (atau attacker yang punya akses interactive desktop), misal `powershell -enc ...` atau path ke tool attacker.

#### 3.6.4 WordWheelQuery

```
NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery\
```

**Nilai forensik:** Riwayat pencarian di kotak search File Explorer — kadang menunjukkan user/attacker mencari file spesifik (mis. "password", "flag", nama file target).

#### 3.6.5 Network Drive & Mapped Share History

```
NTUSER.DAT\Network\<DriveLetter>\      ← Mapped network drive yang masih aktif
NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\Map Network Drive MRU\
```

**Nilai forensik:** Bukti akses ke share jaringan/file server — relevan untuk kasus lateral movement.

#### 3.6.6 MUICache

```
NTUSER.DAT\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache\
```
atau di sistem lebih baru:
```
UsrClass.dat\Local Settings\Software\Microsoft\Windows\Shell\MuiCache\
```

**Pengertian:** Windows menyimpan nama "friendly" aplikasi (diambil dari resource string di dalam PE file, mis. `FriendlyAppName`) setiap kali sebuah executable **muncul di GUI** — misalnya lewat file association dialog, "Open With", atau saat Explorer perlu menampilkan nama aplikasi.

**Nilai forensik:**

* Menyimpan nama aplikasi yang **pernah muncul secara visual** di Windows Shell.
* **Bertahan walau file EXE-nya sudah dihapus** — mirip prinsip ShimCache/Amcache, ini jadi bukti "keberadaan" bukan "eksekusi murni".
* Value name berisi **full path** executable, data-nya berisi nama aplikasi yang human-readable.

Sering dipakai untuk menjawab dua jenis pertanyaan yang mirip tapi beda nuansa:
```
"Program X pernah ada di sistem?"     → MUICache bisa konfirmasi (mirip ShimCache/Amcache)
"Program X pernah muncul ke user?"    → MUICache lebih spesifik ke sini (bukan cuma "ada di disk")
```

> ⚠️ **Bedakan dengan BAM/UserAssist:** MUICache **bukan** bukti eksekusi — munculnya nama aplikasi di sini bisa terjadi hanya karena user klik kanan file lalu Explorer menampilkan opsi "Open with [App]", tanpa aplikasi itu benar-benar dijalankan. Selalu korelasikan dengan BAM (**3.3.5**) atau UserAssist (**3.6.1**) kalau butuh bukti eksekusi yang lebih kuat.

#### 3.6.7 OpenSaveMRU

```
NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSaveMRU\
└── .<ext>\    ← Sub-key per ekstensi file, MRU order tersendiri (mirip pola RecentDocs)
```

**Nilai forensik:**

* Mencatat file yang dipilih lewat **dialog Open/Save** aplikasi apa pun (bukan cuma Explorer) — jadi cakupannya lebih luas dari RecentDocs yang lebih terikat ke shell Explorer.
* **Sangat berguna untuk dokumen Office**: kalau user buka/simpan file `.docx`/`.xlsx` lewat Word/Excel (bukan double-click di Explorer), jejaknya lebih mungkin muncul di sini.
* Di versi Windows lebih baru, fungsi ini sebagian besar sudah "digantikan" oleh `OpenSavePidlMRU` (struktur data serupa, tapi menyimpan **shell item ID list** biner, bukan string path biasa) — kalau `OpenSaveMRU` kosong di image Windows 10/11, cek `OpenSavePidlMRU` di key yang sama.

> 💡 **Tip CTF:** Kombinasikan dengan **RecentDocs** (**3.6.2**) — kalau satu artefak "kosong" atau tidak mencakup file yang dicari, cek artefak satunya. Keduanya sering saling melengkapi, terutama untuk file yang dibuka lewat aplikasi Office/PDF reader dibanding lewat Explorer langsung.

#### 3.6.8 LastVisitedMRU

```
NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedMRU\
```
(di versi lebih baru bernama `LastVisitedPidlMRU`)

**Nilai forensik:** Mencatat **executable** yang terakhir membuka dialog Open/Save — bukan nama file yang dipilih (itu tugas OpenSaveMRU di **3.6.7**), tapi **program apa** yang memicu dialog tersebut. Kedua key ini saling berpasangan dan sebaiknya dibaca bersamaan.

```
Contoh isi:
winword.exe
notepad.exe
putty.exe
```

> 💡 **Nilai tambah:** Kalau soal CTF menyebut *"program apa yang dipakai attacker untuk membuka/menyimpan file X"* — `LastVisitedMRU` memberi nama **program**-nya, sementara `OpenSaveMRU` (**3.6.7**) memberi nama **file**-nya. Cocokkan urutan MRU keduanya (indeks paling atas = paling baru) untuk merekonstruksi "program apa membuka file apa".

#### 3.6.9 MountPoints2 (USB & Network Drive Mapping)

Salah satu artefak yang paling sering muncul di challenge bertema USB.

```
NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2\
├── {GUID}\                          ← Satu per volume yang pernah di-mount
└── ##<server>#<share>\              ← Network share yang pernah diakses (format UNC ter-encode)
```

**Nilai forensik:**

* Histori **drive letter** yang pernah dipakai untuk sebuah volume (USB atau network share) — dari perspektif **user tertentu** (key ini per-user, beda dengan USBSTOR di **3.3.3** yang system-wide).
* Nama subkey `{GUID}` bisa dicocokkan ke **Volume GUID** yang sama yang muncul di `MountedDevices` (hive SYSTEM) untuk mengaitkan drive letter historis dengan device fisiknya.
* Untuk network share, formatnya menunjukkan nama server & nama share yang pernah dipetakan (mapped drive).

> 💡 **Sangat bagus dikorelasikan dengan USBSTOR (3.3.3):** Alurnya biasanya begini — `USBSTOR` kasih tahu **device USB apa** dan **kapan** dicolok (system-wide), sedangkan `MountPoints2` konfirmasi **user mana** yang benar-benar berinteraksi dengan drive tersebut (karena key ini ada di `NTUSER.DAT` per-user). Kombinasi ini memperkuat argumen "user spesifik X yang menggunakan USB Y", bukan cuma "USB Y pernah tercolok di mesin ini".

#### 3.6.10 TypedURLs

```
NTUSER.DAT\Software\Microsoft\Internet Explorer\TypedURLs\
```

**Nilai forensik:** Menyimpan URL yang **diketik manual** oleh user di address bar Internet Explorer (bukan hasil klik link atau autocomplete dari history biasa).

> ⚠️ **Konteks browser lama:** Ini artefak khas Internet Explorer/Edge Legacy. Untuk browser modern (Edge Chromium, Chrome, Firefox), history/typed-URL tersimpan di **database SQLite** milik masing-masing browser, dibahas lengkap di **Bab 6 — Browser Forensics**, bukan di registry. Tapi key ini **masih sering muncul** di image Windows lama atau VM lab yang belum pernah pakai browser modern — jangan diskip kalau image target ternyata masih pakai IE/Edge Legacy.

#### 3.6.11 Terminal Server / RDP History

```
NTUSER.DAT\Software\Microsoft\Terminal Server Client\Servers\<hostname atau IP>\
└── UsernameHint    ← Username terakhir yang dipakai login ke server tersebut
```
dan
```
NTUSER.DAT\Software\Microsoft\Terminal Server Client\Default\
└── MRU0, MRU1, ...    ← Daftar host RDP dalam urutan Most Recently Used
```

**Nilai forensik:**

* Mencatat **host RDP** (hostname/IP) yang pernah dihubungi lewat `mstsc.exe` dari mesin ini, beserta **username** yang dipakai (`UsernameHint`).
* Key ini ada di `NTUSER.DAT` milik **user yang melakukan koneksi** — jadi kalau ada beberapa profile di satu mesin, cek NTUSER.DAT tiap user untuk gambaran lengkap siapa connect ke mana.
* Tidak menyimpan password, tapi kombinasi hostname + username sudah sangat berguna untuk merekonstruksi **lateral movement** dalam sebuah intrusion.

> 💡 **Tip CTF:** Sangat sering muncul di challenge bertema **intrusion/lateral movement multi-host**. Kalau soal minta "ke server mana saja attacker melakukan RDP dari mesin ini", jawabannya ada di sini — bandingkan `UsernameHint` antar host untuk melihat apakah attacker memakai kredensial yang sama (indikasi credential reuse) di beberapa target.

---

### 3.7 UsrClass.dat — ShellBags

**Pengertian & Fungsi:**
**ShellBags** adalah kumpulan key di `UsrClass.dat` yang menyimpan **preferensi tampilan folder** (ukuran window, posisi icon, view mode) — tapi efek sampingnya, Windows jadi **mencatat folder apa saja yang pernah dibuka lewat Explorer**, termasuk:
- Folder yang **sudah dihapus**
- Folder di **drive USB yang sudah dicabut**
- Folder di **network share** yang sudah tidak terhubung

```
UsrClass.dat\Local Settings\Software\Microsoft\Windows\Shell\BagMRU\
└── 0\ (folder pertama level 1)
     └── 1\ (subfolder di dalamnya)
          └── 2\ ...dst, nested sesuai kedalaman folder yang dibuka
```

**Nilai forensik:** Karena datanya bisa bertahan **walau folder/drive sumbernya sudah tidak ada**, ShellBags jadi salah satu artefak paling kuat untuk membuktikan *"user/attacker pernah membuka folder X di drive Y"* meski drive-nya sekarang sudah tidak terpasang.

**Cara Analisa:**
```bash
# ShellBags Explorer (Eric Zimmerman Tools) — GUI khusus
.\ShellBagsExplorer.exe

# Atau via RECmd dengan batch file khusus shellbags
.\RECmd.exe -f "UsrClass.dat" --bn BatchExamples\Kroll_Batch.reb --csv .
```

> 💡 **Tip CTF:** Kalau soal minta *"buktikan attacker pernah akses folder di USB drive yang sekarang sudah dicabut"* — ShellBags + USB history (**3.3.3**) adalah kombinasi jawaban paling kuat.

> 📖 **Pelengkap:** ShellBags mencatat folder yang dibuka, tapi kalau butuh **file spesifik** apa yang dibuka (bukan cuma folder), cross-check ke LNK files & Jump List — dibahas di **Bab 5 — User Activity Trail**.

---

### 3.8 Amcache.hve — Bukti Eksekusi Tingkat Lanjut

**Pengertian & Fungsi:**
`Amcache.hve` adalah hive terpisah (bukan bagian dari `config\`) yang menyimpan metadata **jauh lebih detail** dibanding ShimCache — termasuk **SHA1 hash file**, compile timestamp (PE header), full path, dan publisher/digital signature info.

```
Amcache.hve\Root\
├── File\<VolumeGUID>\<EntryID>\    ← Metadata per file executable
│     ├── SHA1
│     ├── FullPath
│     ├── FileId
│     ├── ProductName / Publisher
│     └── LinkDate (compile timestamp dari PE header)
├── Programs\                        ← Aplikasi ter-install (mirip Uninstall key tapi versi Amcache)
└── InventoryApplicationFile\        (versi Windows lebih baru, struktur key sedikit beda)
```

| Info | ShimCache | Amcache |
|---|---|---|
| Path file | ✅ | ✅ |
| Hash SHA1 | ❌ | ✅ |
| Compile timestamp (LinkDate) | ❌ | ✅ |
| Publisher/signature | ❌ | ✅ |
| Bukti eksekusi pasti | ⚠️ Ambigu | ⚠️ Lebih kuat, tapi tetap bukan 100% "waktu eksekusi" |

**Cara Analisa:**
```bash
# AmcacheParser (Eric Zimmerman Tools)
.\AmcacheParser.exe -f "C:\Windows\AppCompat\Programs\Amcache.hve" --csv .
```

> 💡 **Tip CTF:** Kalau ShimCache/Amcache menunjukkan sebuah executable pernah ada tapi **filenya sudah tidak ada di disk** (sudah dihapus attacker), **SHA1 hash dari Amcache** bisa langsung dicocokkan ke VirusTotal untuk identifikasi malware — walau file fisiknya sudah tidak bisa di-carve.

---

### 3.9 Tools & Cara Analisa Registry

| Tool | Fungsi | Contoh Command |
|---|---|---|
| **RegistryExplorer.exe** (Eric Zimmerman) | GUI utama untuk browse hive apapun secara manual, mendukung bookmark key penting, auto-apply transaction log | Buka langsung, load file hive |
| **RECmd.exe** | CLI/batch parser — bisa jalankan **ratusan key sekaligus** pakai file batch (`.reb`) berisi daftar key forensik penting | `.\RECmd.exe -f "SYSTEM" --csv .` |
| **RECmd Batch Mode** | Menjalankan batch predefined (mis. `Kroll_Batch.reb`) yang sudah mencakup UserAssist, RunMRU, USBSTOR, Run key, dll sekaligus | `.\RECmd.exe -f "NTUSER.DAT" --bn BatchExamples\Kroll_Batch.reb --csv .` |
| **AmcacheParser.exe** | Parser khusus `Amcache.hve` | `.\AmcacheParser.exe -f Amcache.hve --csv .` |
| **AppCompatCacheParser.exe** | Parser khusus ShimCache dari hive SYSTEM | `.\AppCompatCacheParser.exe -f SYSTEM --csv .` |
| **ShellBagsExplorer.exe** | GUI khusus parsing ShellBags dari `UsrClass.dat` | Buka langsung, load `UsrClass.dat` |
| **secretsdump.py** (Impacket) | Dump hash SAM & LSA secrets offline (butuh SYSTEM + SAM/SECURITY) | `secretsdump.py -sam SAM -system SYSTEM LOCAL` |
| **regedit** (live system) | Browse registry langsung di sistem hidup | GUI bawaan Windows |
| **reg query** (live system, CLI) | Query key/value tertentu dari command line | `reg query "HKLM\SYSTEM\CurrentControlSet\Services"` |
| **Registry Viewer** (AccessData) | Alternatif GUI, sering dipaketkan bareng FTK | Buka file hive langsung |

**Workflow offline analysis (image mati):**

Ikuti alur akuisisi umum di **Bab 1, Lampiran — Master Acquisition & Export Workflow**. Target ekspor untuk registry: `SYSTEM`, `SOFTWARE`, `SAM`, `SECURITY`, `DEFAULT`, `RegBack\*`, `Amcache.hve`, dan tiap `NTUSER.DAT` + `UsrClass.dat` per user.

Setelah file hive ada di folder evidence lokal, langkah spesifik registry:
```bash
# Parsing cepat semua key penting sekaligus pakai RECmd batch mode
.\RECmd.exe -f "C:\evidence\SYSTEM" --bn BatchExamples\Kroll_Batch.reb --csv output\

# Cross-check temuan dengan hive spesifik pakai RegistryExplorer kalau butuh detail manual lebih
```

---

### 3.10 Tabel Korelasi Cepat — "Cari Jawaban Ini, Cek Key Itu"

| Pertanyaan Umum CTF | Hive | Key / Artefak |
|---|---|---|
| Kapan program dijalankan (via GUI)? | `NTUSER.DAT` | UserAssist (**3.6.1**) |
| Apakah file executable ini pernah ada di sistem? | `SYSTEM` / `Amcache.hve` | ShimCache (**3.4.3**) / Amcache (**3.8**) |
| USB apa saja yang pernah dicolok, kapan? | `SYSTEM` | USBSTOR/USB (**3.3.3**) + `setupapi.dev.log` (Bab 1) |
| Software apa yang terinstall? | `SOFTWARE` | Uninstall key (**3.4.1**) |
| Apa mekanisme persistence-nya? | `SOFTWARE` / `SYSTEM` | Run/RunOnce (**3.4.2**), Services (**3.3.2**), IFEO (**3.4.4**) |
| Command apa yang diketik manual di Run dialog? | `NTUSER.DAT` | RunMRU (**3.6.3**) |
| File apa yang terakhir dibuka user? | `NTUSER.DAT` | RecentDocs (**3.6.2**) |
| Folder apa yang dibuka dari drive yang sudah dicabut? | `UsrClass.dat` | ShellBags (**3.7**) |
| Apa password hash user lokal? | `SAM` + `SYSTEM` | SAM decrypt (**3.5.2**) |
| Apa timezone sistem (buat konversi timestamp)? | `SYSTEM` | TimeZoneInformation (**3.3.4**) |
| User mencari file apa lewat search Explorer? | `NTUSER.DAT` | WordWheelQuery (**3.6.4**) |
| Apakah ada kredensial tersimpan (auto-logon, service account)? | `SECURITY` + `SYSTEM` | LSA Secrets (**3.5.3**) / AutoLogon (**3.4.6**) |
| Program apa yang dijalankan user (tidak lewat GUI/Explorer)? | `SYSTEM` | BAM / DAM (**3.3.5**) |
| Program pernah ada/terlihat di sistem walau sudah dihapus? | `NTUSER.DAT` / `UsrClass.dat` | MUICache (**3.6.6**) |
| File apa yang dibuka/disimpan lewat dialog Office/aplikasi lain? | `NTUSER.DAT` | OpenSaveMRU (**3.6.7**) + LastVisitedMRU (**3.6.8**) |
| SID ini punya nama user apa? | `SOFTWARE` | User Profile List (**3.4.5**) |
| Drive letter USB ini dipakai user yang mana? | `NTUSER.DAT` | MountPoints2 (**3.6.9**) |
| URL apa yang diketik manual di browser (IE/Edge Legacy)? | `NTUSER.DAT` | TypedURLs (**3.6.10**) |
| Attacker RDP ke server mana saja? | `NTUSER.DAT` | Terminal Server Client (**3.6.11**) |

---

### 3.11 Tabel Prioritas — Execution vs Existence

Salah satu kebingungan paling umum di forensik registry: **"artefak ini bukti program dijalankan, atau cuma bukti program pernah ada?"** Kedua hal ini **beda tingkat kekuatan** sebagai bukti, dan sering jadi jebakan soal CTF. Tabel ini jadi rujukan cepat yang paling sering dibuka saat lomba.

| Artefak | Jenis Bukti | Hive | Referensi |
|---|---|---|---|
| **UserAssist** | Execution (via GUI) | `NTUSER.DAT` | **3.6.1** |
| **BAM / DAM** | Execution | `SYSTEM` | **3.3.5** |
| **Prefetch** | Execution (timestamp presisi) | *(bukan registry — file `.pf` terpisah)* | Bab 4, **4.13** |
| **ShimCache** | Existence | `SYSTEM` | **3.4.3** |
| **Amcache** | Existence + Metadata (hash, compile time) | `Amcache.hve` | **3.8** |
| **MUICache** | Existence (pernah muncul di GUI) | `NTUSER.DAT` / `UsrClass.dat` | **3.6.6** |
| **RunMRU** | Command (diketik manual) | `NTUSER.DAT` | **3.6.3** |
| **RecentDocs** | Opened file | `NTUSER.DAT` | **3.6.2** |
| **OpenSaveMRU / LastVisitedMRU** | Opened/saved file via dialog | `NTUSER.DAT` | **3.6.7 / 3.6.8** |
| **ShellBags** | Opened folder | `UsrClass.dat` | **3.7** |
| **USBSTOR** | USB history (system-wide) | `SYSTEM` | **3.3.3** |
| **MountPoints2** | USB/network drive mapping (per-user) | `NTUSER.DAT` | **3.6.9** |
| **Run Key** | Persistence | `SOFTWARE` / `NTUSER.DAT` | **3.4.2** |
| **Services** | Persistence | `SYSTEM` | **3.3.2** |
| **Terminal Server Client** | Lateral movement (RDP) | `NTUSER.DAT` | **3.6.11** |

> 💡 **Cara pakai tabel ini di lomba:** Kalau soal minta *"buktikan X dijalankan"*, cari dulu di baris **Execution** (UserAssist/BAM/Prefetch) — jangan puas hanya dengan ShimCache/Amcache/MUICache yang levelnya cuma **Existence**. Sebaliknya, kalau file sudah dihapus dan tinggal butuh bukti "pernah ada", baris **Existence** (ShimCache/Amcache/MUICache) itulah yang harus dicari, dan biasanya lebih tahan lama dibanding artefak eksekusi murni.

---

### 3.12 Mini Case Study — Rekonstruksi Aktivitas User dari Registry

Skenario: *"Buktikan attacker mendapat initial access lewat USB, menjalankan tool dari drive tersebut, lalu set persistence."*

```
Langkah 1 — Identifikasi USB yang terhubung
   └── SYSTEM\...\Enum\USBSTOR (3.3.3) → dapat serial number + timestamp first/last connected

Langkah 2 — Cross-check waktu instalasi device
   └── Windows\INF\setupapi.dev.log (Bab 1, 1.2.2) → konfirmasi waktu USB pertama dipasang

Langkah 3 — Cari folder yang dibuka dari drive USB tersebut
   └── UsrClass.dat → ShellBags (3.7) → cocokkan drive letter/volume label dengan USB di langkah 1

Langkah 4 — Cari bukti eksekusi tool dari drive USB
   └── NTUSER.DAT → UserAssist (3.6.1) untuk eksekusi via GUI
   └── SYSTEM → BAM/DAM (3.3.5) untuk eksekusi via command line/script (tidak tertangkap UserAssist)
   └── Amcache.hve (3.8) untuk hash SHA1 + full path (walau file sudah dihapus dari USB)
   └── Windows\Prefetch\ (Bab 1) untuk timestamp eksekusi presisi

Langkah 5 — Cek mekanisme persistence yang di-set attacker
   └── SOFTWARE\...\Run (3.4.2) atau SYSTEM\...\Services (3.3.2)
   └── Bandingkan ImagePath/command dengan path tool dari USB di langkah 4

Langkah 6 — Verifikasi lewat RunMRU (kalau dijalankan manual via Run dialog)
   └── NTUSER.DAT → RunMRU (3.6.3) → command line persis yang diketik

Kesimpulan yang bisa ditulis di laporan:
"USB dengan serial number X terhubung pada waktu Y (USBSTOR + setupapi.dev.log). ShellBags
menunjukkan folder Z di drive tersebut dibuka via Explorer. UserAssist & Amcache mengonfirmasi
eksekusi tool.exe (SHA1: ...) dari drive USB tersebut pada waktu W. Selanjutnya attacker membuat
Run key persistence yang menunjuk ke salinan tool tersebut di %APPDATA%, mengonfirmasi upaya
persistence pasca initial access."
```

> 💡 **Prinsip umum:** Registry jarang berdiri sendiri sebagai bukti kuat — nilainya justru muncul saat **dikorelasikan** dengan artefak filesystem (Prefetch, `$MFT`, `$UsnJrnl` dari Bab 2) dan log lain (EVTX di Bab 4). Selalu bangun timeline gabungan, bukan cuma baca satu hive terisolasi.

---
