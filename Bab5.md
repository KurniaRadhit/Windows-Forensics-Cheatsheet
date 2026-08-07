## 📌 Daftar Isi — Bab 5

- [Bab 5 — User Activity Trail: VSS, Recycle Bin, LNK & Jump Lists](#bab-5--user-activity-trail-vss-recycle-bin-lnk--jump-lists)
  - [5.1 Volume Shadow Copy (VSS)](#51-volume-shadow-copy-vss)
    - [5.1.1 Pengertian & Fungsi](#511-pengertian--fungsi)
    - [5.1.2 Cara Kerja (Copy-on-Write)](#512-cara-kerja-copy-on-write)
    - [5.1.3 Lokasi & Struktur Penyimpanan](#513-lokasi--struktur-penyimpanan)
    - [5.1.4 Enumerasi Shadow Copy](#514-enumerasi-shadow-copy)
    - [5.1.5 Mounting & Browsing Shadow Copy](#515-mounting--browsing-shadow-copy)
    - [5.1.6 Diffing Antar Shadow Copy](#516-diffing-antar-shadow-copy)
    - [5.1.7 Retensi & Limit Storage](#517-retensi--limit-storage)
    - [5.1.8 Anti-Forensic: VSS Dihapus](#518-anti-forensic-vss-dihapus)
    - [5.1.9 Tools VSS](#519-tools-vss)
  - [5.2 Recycle Bin](#52-recycle-bin)
    - [5.2.1 Struktur Modern ($I/$R)](#521-struktur-modern-ir)
    - [5.2.2 Format Binary $I File](#522-format-binary-i-file)
    - [5.2.3 Format Lama — INFO2 (Windows XP/2003)](#523-format-lama--info2-windows-xp2003)
    - [5.2.4 Recovery File yang Di-Permanently Delete](#524-recovery-file-yang-di-permanently-delete)
    - [5.2.5 Tools Recycle Bin](#525-tools-recycle-bin)
    - [5.2.6 Cross-Reference SID → Username](#526-cross-reference-sid--username)
  - [5.3 LNK Files (Shortcut)](#53-lnk-files-shortcut)
    - [5.3.1 Pengertian & Kapan LNK Dibuat](#531-pengertian--kapan-lnk-dibuat)
    - [5.3.2 Struktur Binary LNK](#532-struktur-binary-lnk)
    - [5.3.3 Metadata Forensik Kunci](#533-metadata-forensik-kunci)
    - [5.3.4 TrackerDataBlock — MAC Address & Droid ID](#534-trackerdatablock--mac-address--droid-id)
    - [5.3.5 LNK sebagai Bukti Sesudah File/Drive Hilang](#535-lnk-sebagai-bukti-sesudah-filedrive-hilang)
    - [5.3.6 Tools LNK](#536-tools-lnk)
    - [5.3.7 Tip CTF — LNK](#537-tip-ctf--lnk)
  - [5.4 Jump Lists](#54-jump-lists)
    - [5.4.1 Pengertian & Fungsi](#541-pengertian--fungsi-1)
    - [5.4.2 AutomaticDestinations vs CustomDestinations](#542-automaticdestinations-vs-customdestinations)
    - [5.4.3 Struktur OLE Compound File & DestList Stream](#543-struktur-ole-compound-file--destlist-stream)
    - [5.4.4 App ID — Mapping ke Nama Aplikasi](#544-app-id--mapping-ke-nama-aplikasi)
    - [5.4.5 Korelasi dengan LNK Tertanam](#545-korelasi-dengan-lnk-tertanam)
    - [5.4.6 Tools Jump List](#546-tools-jump-list)
    - [5.4.7 Tip CTF — Jump List](#547-tip-ctf--jump-list)
  - [5.5 Korelasi Artefak (Tabel Cepat)](#55-korelasi-artefak-tabel-cepat)
  - [5.6 Ringkasan Command & Tools Cheat Sheet](#56-ringkasan-command--tools-cheat-sheet)
  - [5.7 Mini Case Study — Rekonstruksi Aktivitas dari User Activity Trail](#57-mini-case-study--rekonstruksi-aktivitas-dari-user-activity-trail)

*(Bab 1: Struktur Drive & Direktori — `bab1.md`. Bab 2: File Sistem NTFS & $MFT — `bab2.md`. Bab 3: Windows Registry Forensics — `bab3.md`. Bab 4: EVTX & Event ID Forensics — `bab4.md`. Bab 6 — Browser Forensics menyusul.)*

---

## Bab 5 — User Activity Trail: VSS, Recycle Bin, LNK & Jump Lists

Kalau Bab 2–4 fokus ke artefak yang menceritakan "apa yang terjadi di sistem", Bab 5 ini fokus ke artefak yang menceritakan **jejak aktivitas manusia yang bertahan lebih lama dari sumber aslinya**. Benang merah keempat artefak di bab ini:

| Artefak | Yang "hilang" | Yang tetap tersisa |
|---|---|---|
| **VSS** | Kondisi file/sistem saat ini (sudah dimodifikasi/dihapus) | Snapshot versi lama dari seluruh volume |
| **Recycle Bin** | File yang dihapus user | Metadata ($I) + isi file ($R) — sampai di-*empty* atau ditimpa |
| **LNK** | File source, atau drive/USB tempat file itu berada | Shortcut yang menyimpan metadata lengkap target-nya |
| **Jump List** | Riwayat pemakaian aplikasi | Daftar file yang pernah dibuka per-aplikasi, dengan LNK tertanam |

Keempatnya juga saling melengkapi dengan artefak yang sudah dibahas di Bab 3 — **ShellBags** (folder yang dibuka, §3.7) dan **RecentDocs** (file yang dibuka via Explorer, §3.6.2). Kalau ShellBags/RecentDocs jawab "folder/file apa", bab ini jawab lebih detail: "dari drive/mesin mana", "kapan persis", dan "apakah masih bisa direcover isinya".

---

### 5.1 Volume Shadow Copy (VSS)

#### 5.1.1 Pengertian & Fungsi

**Volume Shadow Copy Service (VSS)** adalah layanan Windows yang membuat **snapshot point-in-time** dari sebuah volume NTFS — semacam "cadangan kondisi disk" pada waktu tertentu, tanpa perlu meng-copy seluruh volume secara penuh. VSS dipakai oleh beberapa fitur Windows sekaligus:

| Fitur yang memakai VSS | Fungsi |
|---|---|
| **System Restore** | Snapshot sebelum instalasi update/driver, buat rollback kalau bermasalah |
| **File History / Previous Versions** | User bisa klik kanan file → "Restore previous versions" |
| **Backup aplikasi (Windows Backup, banyak software backup pihak ketiga)** | Snapshot volume tetap konsisten walau ada file yang sedang terbuka/terkunci |
| **Instalasi update/patch** | Windows Update kadang bikin snapshot otomatis sebelum instalasi besar |

> 💡 **Kenapa penting di DFIR:** VSS adalah salah satu **"time machine"** paling kuat di forensik Windows — bisa membuka kondisi file/registry/sistem di masa lalu, termasuk file yang sudah dihapus/dimodifikasi attacker, **tanpa** butuh backup eksternal apa pun. Snapshot-nya sudah ada di dalam disk yang sama.

#### 5.1.2 Cara Kerja (Copy-on-Write)

VSS **tidak** meng-copy seluruh volume tiap kali snapshot dibuat — itu akan sangat boros storage. VSS memakai teknik **Copy-on-Write (CoW)**:

```
Saat snapshot dibuat:
   └── VSS TIDAK copy apa-apa dulu — cuma "menandai" titik waktu ini sebagai referensi

Saat ada block data yang mau di-OVERWRITE (file dimodifikasi/dihapus) SETELAH snapshot dibuat:
   └── VSS COPY block LAMA (sebelum di-overwrite) ke area shadow storage TERLEBIH DAHULU
   └── Baru setelah itu block baru ditulis ke lokasi aslinya

Hasilnya:
   └── Shadow copy = volume asli SEKARANG + "tumpukan" block lama yang di-diff-kan mundur ke titik snapshot
```

> 💡 **Konsekuensi forensik:** Karena berbasis diff block-level (bukan full copy), shadow copy **hanya** menyimpan block yang berubah **setelah** titik snapshot dibuat. File yang tidak pernah disentuh sejak snapshot dibuat tetap bisa diakses lewat shadow copy manapun — tapi file yang berubah berkali-kali antar beberapa snapshot bisa punya versi berbeda-beda di tiap shadow copy.

#### 5.1.3 Lokasi & Struktur Penyimpanan

```
C:\System Volume Information\
└── {GUID}                                    ← Berbagai file konfigurasi VSS & restore point
```

Shadow copy sendiri **tidak muncul sebagai file biasa** yang bisa di-browse langsung di Explorer — dia diakses lewat device path virtual:

```
\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\
\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\
...
```

Angka di belakang (`1`, `2`, dst) adalah nomor urut shadow copy pada volume tersebut — **bukan** ID unik permanen; setelah shadow copy lama dihapus, nomor bisa dipakai ulang oleh shadow copy baru.

> 💡 **Cross-reference:** Identitas volume yang dipakai VSS untuk mengikat snapshot ke volume tertentu berasal dari **Disk GUID/Volume GUID** yang sudah dibahas di Bab 1 §1.1.9 — kalau disk dipindah ke sistem lain, GUID inilah yang memastikan shadow copy tetap terikat ke volume yang benar.

#### 5.1.4 Enumerasi Shadow Copy

Di **live system**:

```bash
# List semua shadow copy yang ada di sistem, beserta ID & waktu dibuat
vssadmin list shadows

# List kapasitas storage yang dialokasikan untuk shadow copy per volume
vssadmin list shadowstorage

# List shadow copy per volume tertentu saja
vssadmin list shadows /for=C:
```

Contoh output penting dari `vssadmin list shadows`:

| Field Output | Keterangan |
|---|---|
| `Shadow Copy ID` | GUID unik shadow copy ini |
| `Original Volume` | Volume asal (mis. `C:`) |
| `Shadow Copy Volume` | Device path virtual (`\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyN\`) |
| `Originating Machine` / `Service Machine` | Nama komputer — berguna kalau disk dipindah dari mesin lain |
| `Creation Time` | **Timestamp paling penting** — kapan snapshot ini dibuat, jadi acuan "kondisi sistem per waktu X" |

Di **image mati** (offline forensic), `vssadmin` tidak bisa dipakai langsung karena butuh sistem hidup. Enumerasi shadow copy dari image dilakukan lewat tool khusus (lihat §5.1.9), yang membaca struktur VSS langsung dari raw disk image.

#### 5.1.5 Mounting & Browsing Shadow Copy

**Di live system** (atau mounted image via Arsenal Image Mounter dkk), shadow copy bisa dipetakan ke path yang bisa di-browse biasa:

```bash
# Buat symbolic link ke shadow copy tertentu supaya bisa dibrowse via Explorer/CMD
mklink /d C:\shadow_copy_1 \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\

# Setelah itu, browse seperti folder biasa
dir C:\shadow_copy_1\Users\
```

**Di image mati** (raw `.dd`/`.E01`), dipakai library `libvshadow` (bagian dari `libyal`):

```bash
# Info shadow copy yang ada di dalam image
vshadowinfo -o <offset_partisi> disk.dd

# Mount seluruh shadow copy dari image sebagai virtual filesystem read-only
vshadowmount -o <offset_partisi> disk.dd /mnt/vss/

# Setelah mount, tiap shadow copy muncul sebagai file vssN di /mnt/vss/
# bisa di-mount lagi satu-satu pakai `mount -o ro,loop /mnt/vss/vss1 /mnt/vss_1`
```

> ⚠️ **Perlu privilege tinggi:** Baik `mklink` (butuh admin/SYSTEM di live system) maupun `vshadowmount` (butuh akses raw disk) sama-sama butuh privilege elevated. Di kompetisi CTF/HTB Sherlock yang biasanya kasih image mati, jalur `libvshadow` (`vshadowinfo`/`vshadowmount`) ini yang paling sering dipakai.

#### 5.1.6 Diffing Antar Shadow Copy

Salah satu teknik paling powerful: membandingkan **file yang sama** di beberapa shadow copy berbeda untuk melihat evolusi perubahannya dari waktu ke waktu — misalnya melacak kapan persis sebuah file registry/dokumen dimodifikasi attacker.

```bash
# Contoh alur manual: bandingkan hash file yang sama di 3 shadow copy berbeda
sha256sum /mnt/vss_1/Windows/System32/config/SOFTWARE
sha256sum /mnt/vss_2/Windows/System32/config/SOFTWARE
sha256sum /mnt/vss_3/Windows/System32/config/SOFTWARE

# Kalau hash berbeda antar shadow copy, artinya file berubah di antara waktu snapshot tersebut
# Lanjutkan dengan diff isi (untuk file text) atau parsing masing-masing versi (untuk hive/MFT)
diff <(strings vss_1_file.txt) <(strings vss_2_file.txt)
```

> 💡 **Tip CTF:** Kalau soal minta *"file config ini sempat diubah kapan sebelum insiden"* — jangan cuma parsing kondisi file sekarang. Mount semua shadow copy yang tersedia, urutkan berdasarkan `Creation Time` (§5.1.4), lalu cek satu-satu sampai ketemu titik di mana hash file berubah. Ini juga berlaku untuk hive registry (bisa parsing `SOFTWARE`/`NTUSER.DAT` versi lama dari tiap shadow copy) dan bahkan `$MFT` versi lama untuk lihat kondisi filesystem historis.

#### 5.1.7 Retensi & Limit Storage

Shadow copy **tidak disimpan selamanya** — Windows mengalokasikan kuota storage tertentu (default biasanya sekitar 5–10% kapasitas volume, tergantung versi Windows & konfigurasi). Ketika kuota penuh, shadow copy **paling lama otomatis dihapus** untuk memberi ruang shadow copy baru.

> ⚠️ **Implikasi forensik:** Jangan asumsikan shadow copy lama pasti masih ada. Kalau volume sering berubah drastis (mis. banyak file besar ditulis/dihapus) setelah insiden terjadi, shadow copy dari sebelum insiden bisa saja sudah "termakan" kuota dan hilang duluan sebelum image diambil. Makin cepat akuisisi dilakukan setelah insiden, makin besar peluang shadow copy relevan masih ada.

#### 5.1.8 Anti-Forensic: VSS Dihapus

Attacker yang paham forensik sering menghapus shadow copy secara sengaja supaya jejak recovery hilang — teknik ini populer terutama di serangan **ransomware** (menghindar dari file recovery korban) dan **anti-forensic pasca intrusion**.

```bash
# Command yang sering dipakai attacker untuk menghapus SEMUA shadow copy
vssadmin delete shadows /all /quiet

# Variasi lain via WMIC
wmic shadowcopy delete

# Variasi via PowerShell
Get-WmiObject Win32_ShadowCopy | ForEach-Object { $_.Delete() }
```

> 💡 **Cross-reference ke Bab 4:** Command di atas biasanya tercatat di **Event ID 4688** (Process Creation, Bab 4 §4.3.4) atau **Sysmon Event ID 1** (Bab 4 §4.6.1) dengan `CommandLine` yang eksplisit menyebut `vssadmin delete shadows` atau `wmic shadowcopy delete` — kombinasi command line ini adalah salah satu **IOC (Indicator of Compromise)** paling jelas untuk ransomware/anti-forensic. Kalau ditemukan command ini di EVTX tapi shadow copy sekarang memang kosong, itu konfirmasi kuat bahwa VSS sengaja dihapus, bukan sekadar termakan kuota storage.

#### 5.1.9 Tools VSS

| Tool | Fungsi | Konteks |
|---|---|---|
| **vssadmin** (live/mounted) | Enumerasi & manajemen shadow copy | Butuh sistem hidup atau image yang di-mount penuh |
| **ShadowExplorer** (GUI, gratis) | Browse & extract file dari shadow copy tanpa command line | Cocok untuk live system atau mounted VM |
| **ShadowCopyView** (NirSoft) | List & export shadow copy, GUI ringan | Live system |
| **libvshadow** (`vshadowinfo`, `vshadowmount`) | Parsing & mounting VSS langsung dari raw image | Paling relevan untuk image mati (`.dd`/`.raw`), dukungan Linux |
| **Arsenal Image Mounter** | Mount image `.E01`/`.dd` lengkap dengan VSS-nya sekaligus (di Windows) | Kombinasi praktis: mount image → shadow copy otomatis ke-detect Windows |

---

### 5.2 Recycle Bin

#### 5.2.1 Struktur Modern ($I/$R)

Ini ringkasan dari Bab 1 §1.2.11 sebagai pengantar sebelum masuk ke detail yang belum dibahas di sana:

```
$Recycle.Bin\
└── <SID user>\
    ├── $IXXXXXXX.ext     ← Metadata: nama asli, path asli, waktu dihapus, ukuran
    └── $RXXXXXXX.ext     ← Isi/konten file yang dihapus (nama sama dengan $I, prefix beda)
```

Pasangan `$I`/`$R` selalu punya nama acak yang **sama** setelah prefix-nya — kalau ketemu `$RABC123.docx` tapi `$IABC123.docx`-nya hilang (atau sebaliknya), itu indikasi salah satunya sudah ditimpa data baru sementara satunya masih bertahan.

#### 5.2.2 Format Binary $I File

Struktur `$I` **berbeda** antara Windows versi lama dan baru (perubahan besar terjadi di Windows 10):

```
$I File (Windows 10/11):
Offset 0x00 (8 byte)   → Header/Version (nilai 2 untuk Windows 10+)
Offset 0x08 (8 byte)   → File size asli (sebelum dihapus), dalam byte
Offset 0x10 (8 byte)   → Deleted timestamp (FILETIME format, UTC)
Offset 0x18 (4 byte)   → Panjang path asli (jumlah karakter, bukan byte)
Offset 0x1C (variabel) → Path asli file (UTF-16LE, null-terminated)
```

> 💡 **Kenapa perlu tahu struktur manual:** Kalau soal CTF sengaja kasih file `$I` yang corrupt atau tool parser (`RBCmd`) gagal jalan, kamu tetap bisa baca manual pakai hex editor — cari offset `0x10` untuk FILETIME (convert ke waktu manusiawi) dan offset `0x1C` untuk path asli file dalam UTF-16LE.

```bash
# Contoh parsing manual pakai Python (kalau tool GUI/CLI tidak tersedia)
python3 -c "
import struct
with open('\$IABC123.docx', 'rb') as f:
    data = f.read()
    filesize = struct.unpack('<Q', data[8:16])[0]
    filetime = struct.unpack('<Q', data[16:24])[0]
    path_len = struct.unpack('<i', data[24:28])[0]
    path = data[28:28+path_len*2].decode('utf-16-le')
    print(f'Size: {filesize}, Path: {path}')
"
```

#### 5.2.3 Format Lama — INFO2 (Windows XP/2003)

Sebelum skema `$I`/`$R` per-file (dimulai sejak Vista), Windows XP/2003 memakai **satu file index tunggal** bernama `INFO2` per drive per user, isinya adalah **tabel record** semua file yang dihapus (bukan satu file metadata per item):

```
Recycler\
└── <SID>\
    ├── INFO2              ← Index tunggal, satu record per file terhapus
    ├── DC1.ext            ← Isi file terhapus #1 (nama "DCN" sequential, bukan hash acak)
    ├── DC2.ext
    └── ...
```

> ⚠️ **Masih relevan di CTF/lab lawas:** Walau jarang ditemui di kasus modern, `INFO2` masih sering muncul di image Windows XP lawas atau VM lab edukasi yang sengaja pakai OS lama. Kalau tool `RBCmd` (yang didesain untuk `$I` modern) tidak menemukan apa-apa, cek dulu apakah image-nya masih format XP sebelum menyimpulkan Recycle Bin kosong.

#### 5.2.4 Recovery File yang Di-*Permanently Delete*

Kalau file dihapus dengan **Shift+Del** (bypass Recycle Bin) atau Recycle Bin di-*empty*, file `$I`/`$R`-nya sendiri **hilang** — tapi bukan berarti buntu total. Ikuti alur recovery bertingkat yang sudah dibahas di Bab 2 §2.2.9:

```
1. Record $MFT untuk file $I/$R itu sendiri → cek InUse=False (MFTECmd)
2. $I30 index folder $Recycle.Bin\<SID>\ → cari nama $I/$R yang sudah tidak ada di $MFT (INDXRipper)
3. Kalau cluster data-nya belum tertimpa → carving isi file dari unallocated (PhotoRec/bulk_extractor)
```

> 💡 **Insight tambahan khusus Recycle Bin:** Karena file yang di-drag ke Recycle Bin sebenarnya **di-rename & dipindah** ke `$Recycle.Bin\<SID>\` (bukan langsung dihapus), jejaknya juga tercatat di `$UsnJrnl` (Bab 2 §2.1.1) dengan pola `RenameOldName`/`RenameNewName` yang parent folder-nya berubah ke `$Recycle.Bin` — bisa dipakai cross-check waktu "dibuang ke recycle bin" vs waktu "di-empty/permanently delete" secara terpisah.

#### 5.2.5 Tools Recycle Bin

| Tool | Fungsi | Catatan |
|---|---|---|
| **RBCmd.exe** (Eric Zimmerman) | Parser `$I` modern → CSV | Tidak mendukung `INFO2` lama |
| **rifiuti2** (open-source, cross-platform) | Parser `$I` **dan** `INFO2` lama, jalan di Linux/Mac | Pilihan lebih fleksibel kalau image campuran versi Windows |
| **FTK Imager** | Browse `$Recycle.Bin\` langsung dari image, export manual | Bagus untuk verifikasi visual sebelum parsing massal |

```bash
# RBCmd — parsing seluruh isi $Recycle.Bin jadi CSV
.\RBCmd.exe -d "C:\`$Recycle.Bin" --csv .

# rifiuti2 — mendukung format lama (INFO2) maupun baru ($I), auto-detect
rifiuti-vista -o output.csv "C:\`$Recycle.Bin\<SID>"
rifiuti INFO2 -o output.csv        # khusus format lama
```

#### 5.2.6 Cross-Reference SID → Username

Nama folder di `$Recycle.Bin\` cuma berupa SID, bukan username langsung. Cara resolve:

```
Registry: SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\<SID>\
Value:    ProfileImagePath   ← path profile, mis. C:\Users\jdoe → username "jdoe"
```

```bash
# Query cepat di live system
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\<SID>" /v ProfileImagePath

# Di image mati: parsing hive SOFTWARE pakai RECmd, cari key ProfileList (Bab 3, §3.4.5 — User Profile List)
```

> 📖 **Cross-reference:** Key `ProfileList` ini sama persis dengan yang dibahas di Bab 3 §3.4.5 untuk keperluan lain (resolve SID di banyak konteks: Recycle Bin, event log, ShellBags, dll) — satu key registry, dipakai berulang di banyak jenis investigasi.

---

### 5.3 LNK Files (Shortcut)

#### 5.3.1 Pengertian & Kapan LNK Dibuat

File `.lnk` adalah shortcut Windows — tapi nilai forensiknya bukan dari fungsinya sebagai "jalan pintas", melainkan dari **metadata kaya** yang tertanam di dalamnya. Ada dua skenario pembuatan LNK yang penting dibedakan:

| Jenis | Kapan dibuat | Lokasi |
|---|---|---|
| **Auto-created (Recent)** | Otomatis oleh Windows setiap kali user membuka file (double-click di Explorer, "Open" dari aplikasi, dsb) | `AppData\Roaming\Microsoft\Windows\Recent\` |
| **User-created (Manual)** | User sengaja klik kanan → "Create shortcut" | Bisa di mana saja (Desktop, folder custom) |

> 💡 **Kenapa bedanya penting:** LNK **auto-created** di folder `Recent\` adalah bukti kuat "file ini pernah dibuka", sedangkan LNK **manual** di Desktop cuma bukti "user pernah sengaja bikin shortcut" — belum tentu file-nya pernah benar-benar dibuka setelah shortcut dibuat. Kalau soal CTF minta bukti "file dibuka", prioritaskan cek LNK di folder `Recent\`.

#### 5.3.2 Struktur Binary LNK

```
[File LNK]
├── Shell Link Header (76 byte)     ← Signature, flag, target file attributes, 3 timestamp, target file size
├── LinkTargetIDList (opsional)     ← ShellItemID — representasi path target dalam bentuk shell namespace
├── LinkInfo (opsional)             ← Info lokasi target: local path, volume info, atau network share
├── StringData (opsional)           ← Nama deskripsi, relative path, working directory, command line arguments, icon path
└── ExtraData (opsional, banyak blok)
      ├── TrackerDataBlock          ← MAC address, Droid ID (lihat 5.3.4)
      ├── ConsoleDataBlock          ← Setting console (kalau target adalah cmd.exe/PowerShell)
      └── ... blok lain (icon, environment variable, dll)
```

> 💡 Setiap blok di atas bersifat **opsional** — tidak semua LNK punya semua blok. Semakin banyak blok yang terisi, semakin banyak metadata forensik yang bisa digali.

#### 5.3.3 Metadata Forensik Kunci

| Field | Sumber Blok | Nilai Forensik |
|---|---|---|
| **Target Path** | LinkInfo / StringData | File/folder apa yang dituju shortcut ini |
| **Volume Serial Number** | LinkInfo | ID volume tempat target berada — dicocokkan ke USBSTOR (Bab 3 §3.3.3) untuk identifikasi drive fisik |
| **File Size Target** | Shell Link Header | Ukuran file target **pada saat LNK dibuat** — bisa beda dari ukuran file sekarang kalau file sudah dimodifikasi setelahnya |
| **File Attributes Target** | Shell Link Header | Hidden/System/ReadOnly dari target saat LNK dibuat |
| **4 Timestamp Target** | Shell Link Header | Created/Modified/Accessed target file **pada saat LNK dibuat** — bisa dipakai bandingkan dengan timestamp `$MFT` sekarang untuk deteksi modifikasi setelahnya |
| **Working Directory** | StringData | Folder kerja saat shortcut dijalankan — berguna untuk executable yang butuh file pendukung di folder yang sama |
| **Command Line Arguments** | StringData | Kalau target adalah executable dengan argumen (mis. `powershell.exe -enc <base64>`) — **sering jadi bukti langsung payload/command attacker** |
| **Network Share Info** | LinkInfo | Kalau target di UNC path (`\\server\share\file`), tersimpan info server & share-nya |

> ⚠️ **Poin penting yang sering salah dipahami:** Timestamp di LNK (Shell Link Header) adalah kondisi file **target** *pada saat LNK dibuat/di-update*, **bukan** timestamp file LNK itu sendiri di filesystem. LNK-nya sendiri tetap punya timestamp `$MFT` normal (Bab 2 §2.1.2) yang mencatat kapan shortcut-nya dibuat/diakses.

#### 5.3.4 TrackerDataBlock — MAC Address & Droid ID

Ini bagian paling sering terlewat padahal sangat kuat sebagai bukti: `TrackerDataBlock` (bagian dari `ExtraData`) menyimpan **Droid ID (Distributed Link Tracking)** yang mengandung:

```
TrackerDataBlock
├── Machine ID (NetBIOS name komputer sumber)
├── Droid Volume ID (GUID)
├── Droid File ID
│     └── Berisi TIMESTAMP pembuatan Object ID + MAC ADDRESS network adapter mesin sumber
├── Birth Droid Volume ID
└── Birth Droid File ID (Object ID ASLI, sebelum file di-copy/pindah — kalau file pernah di-copy antar volume)
```

> 💡 **Kenapa ini "sakti":** MAC address yang tertanam di Droid File ID adalah identitas **hardware** mesin sumber — bukan sekadar volume serial number yang bisa berubah kalau drive di-format ulang. Kalau ditemukan LNK di komputer korban yang nunjuk ke file dari mesin **lain** (MAC address beda dari mesin korban), ini bukti kuat file tersebut datang dari komputer attacker atau perangkat eksternal tertentu — bahkan bisa dipakai identifikasi mesin spesifik di jaringan kalau MAC address-nya dikenali.

- **Birth Droid** (Object ID asli) vs **Droid** (Object ID saat ini) yang beda menandakan file pernah **di-copy** (bukan cuma di-*move*) antar volume — perbedaan ini bisa dipakai membuktikan file "aslinya" datang dari volume/mesin lain sebelum di-copy ke lokasi sekarang.

#### 5.3.5 LNK sebagai Bukti Sesudah File/Drive Hilang

Karena semua metadata di §5.3.3–5.3.4 tersimpan **di dalam file LNK itu sendiri** (bukan sekadar pointer/link), LNK tetap bisa dibaca lengkap meski:

- File target sudah **dihapus**
- Drive/USB tempat target berada sudah **dicabut**
- Network share sudah **tidak terhubung** lagi

Ini menjadikan LNK salah satu artefak paling "awet" untuk membuktikan keberadaan file/drive yang sekarang sudah tidak ada sama sekali di sistem.

#### 5.3.6 Tools LNK

```bash
# LECmd — parsing satu file LNK
.\LECmd.exe -f "C:\Users\<user>\AppData\Roaming\Microsoft\Windows\Recent\document.lnk" --csv .

# LECmd — parsing seluruh folder Recent sekaligus
.\LECmd.exe -d "C:\Users\<user>\AppData\Roaming\Microsoft\Windows\Recent" --csv .
```

**Kolom output LECmd yang penting:**

| Kolom | Keterangan |
|---|---|
| `TargetIDAbsolutePath` / `LocalPath` | Path lengkap target |
| `VolumeSerialNumber` | Cross-check ke USBSTOR (Bab 3 §3.3.3) |
| `MachineID` | NetBIOS name mesin sumber (dari TrackerDataBlock) |
| `MacAddress` | MAC address mesin sumber (dari TrackerDataBlock) |
| `TargetCreationDate` / `TargetModificationDate` / `TargetLastAccessedDate` | Timestamp target saat LNK dibuat |
| `Arguments` | Command line arguments kalau target executable |
| `SourceCreated` / `SourceModified` / `SourceAccessed` | Timestamp LNK **file itu sendiri** (dari `$MFT`, bukan target) |

#### 5.3.7 Tip CTF — LNK

> 💡 Kalau soal CTF menyebut **"USB apa yang dipakai attacker untuk membawa tool ke sistem ini"** atau **"buktikan file ini datang dari komputer lain"** — kombinasi `VolumeSerialNumber` + `MachineID` + `MacAddress` dari LNK adalah jawaban paling defensible, jauh lebih kuat daripada cuma menyebut "ada indikasi file eksternal". Bandingkan juga `TargetModificationDate` di LNK dengan timestamp `$MFT` file yang sama sekarang (kalau filenya masih ada) — kalau beda jauh, itu bukti file dimodifikasi **setelah** shortcut terakhir di-update.

---

### 5.4 Jump Lists

#### 5.4.1 Pengertian & Fungsi

Jump List adalah fitur taskbar Windows (mulai Windows 7) yang menampilkan **riwayat file/aksi per-aplikasi** saat klik kanan icon aplikasi di taskbar. Secara forensik, Jump List punya nilai lebih spesifik dari LNK folder `Recent\` biasa karena datanya **dikelompokkan per-aplikasi** — jadi bisa langsung tahu "aplikasi apa" yang membuka "file apa".

#### 5.4.2 AutomaticDestinations vs CustomDestinations

```
AppData\Roaming\Microsoft\Windows\Recent\
├── AutomaticDestinations\
│     └── <AppID>.automaticDestinations-ms
└── CustomDestinations\
      └── <AppID>.customDestinations-ms
```

| Jenis | Sumber | Karakteristik |
|---|---|---|
| **AutomaticDestinations** | Dibuat **otomatis** oleh Windows setiap kali user membuka file lewat aplikasi tertentu | Paling umum ditemui, isinya daftar MRU (Most Recently Used) file per-aplikasi |
| **CustomDestinations** | Dibuat oleh **aplikasi itu sendiri** kalau developer implementasikan custom Jump List (mis. "Pinned" items, task khusus seperti "New Document" di Word) | Lebih jarang, isinya tergantung desain aplikasi masing-masing |

#### 5.4.3 Struktur OLE Compound File & DestList Stream

File `.automaticDestinations-ms` sebenarnya adalah **OLE Compound File (CFB — Compound File Binary)**, format container yang sama dipakai dokumen Office lama (`.doc`, `.xls`). Di dalamnya ada banyak "stream" tertanam:

```
<AppID>.automaticDestinations-ms (OLE Compound File)
├── Stream "1"          ← LNK stream individual (struktur sama persis dengan LNK biasa, lihat 5.3.2)
├── Stream "2"
├── ... (satu stream per entry)
└── Stream "DestList"    ← Index/urutan MRU seluruh entry di atas
```

**DestList stream** menyimpan urutan **Most Recently Used** — entry paling atas adalah yang paling baru diakses. Setiap record di DestList berisi:

| Field DestList | Keterangan |
|---|---|
| Entry Number | Urutan MRU (posisi 0 = paling baru) |
| Droid ID | Sama seperti TrackerDataBlock di LNK (§5.3.4) — bisa cross-check mesin sumber |
| Last Accessed Timestamp | Kapan entry ini terakhir diakses |
| Path | Path file yang diakses |
| Pin Status | Apakah entry di-*pin* manual oleh user ke Jump List |

#### 5.4.4 App ID — Mapping ke Nama Aplikasi

Nama file Jump List (`<AppID>.automaticDestinations-ms`) memakai **hash 16-karakter hex** dari path executable aplikasi, bukan nama aplikasi langsung. Perlu tabel referensi untuk decode:

| App ID (contoh) | Aplikasi |
|---|---|
| `5f7b5f1e01b83767` | Windows Explorer |
| `1b4dd67f29cb1962` | Internet Explorer / Edge |
| `f01b4d95cf55d32a` | Windows PowerShell |
| `5d696d521de238c3` | Command Prompt (cmd.exe) |
| `9b9cdc69c1c24e2b` | Notepad |
| `6a5b9d19d3a17e21` | Microsoft Word |

> ⚠️ **Catatan:** App ID di atas cuma contoh — daftar lengkap App ID resmi cukup panjang dan sebagian besar tool parser (§5.4.6) sudah punya database mapping bawaan, jadi tidak perlu hafal manual. Kalau ketemu App ID yang tidak dikenali tool, itu bisa jadi indikasi **aplikasi custom/jarang** yang tetap layak dicurigai (mis. tool attacker yang jarang dipakai orang, sehingga App ID-nya tidak ada di database umum).

#### 5.4.5 Korelasi dengan LNK Tertanam

Karena tiap stream bernomor di dalam `.automaticDestinations-ms` **adalah** LNK dengan struktur sama persis seperti §5.3.2, semua field yang dibahas di §5.3.3 dan §5.3.4 (Volume Serial Number, MachineID, MAC Address, timestamp target) **berlaku juga** di sini — tinggal parsing streamnya sebagai LNK biasa.

> 💡 **Praktisnya:** Jump List = "LNK yang dikelompokkan per-aplikasi + ada urutan MRU tambahan". Kalau kamu sudah paham cara baca LNK (§5.3), Jump List tinggal ditambah satu layer: tahu aplikasi mana yang buka, dan urutan aksesnya.

#### 5.4.6 Tools Jump List

```bash
# JLECmd — parsing satu file Jump List
.\JLECmd.exe -f "C:\Users\<user>\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\5f7b5f1e01b83767.automaticDestinations-ms" --csv .

# JLECmd — parsing seluruh folder AutomaticDestinations + CustomDestinations sekaligus
.\JLECmd.exe -d "C:\Users\<user>\AppData\Roaming\Microsoft\Windows\Recent" --csv .
```

JLECmd otomatis: (1) resolve App ID ke nama aplikasi yang dikenali, (2) extract semua LNK stream jadi baris CSV terpisah, (3) sertakan urutan DestList sebagai kolom.

#### 5.4.7 Tip CTF — Jump List

> 💡 Kalau soal minta *"program apa yang dipakai attacker, dan file apa saja yang dibuka lewat program itu secara berurutan"* — Jump List jauh lebih efisien dibanding scan semua LNK satu-satu di folder `Recent\`, karena sudah otomatis terkelompok per-aplikasi dengan urutan MRU. Kombinasikan dengan **LastVisitedMRU** (Bab 3 §3.6.8) yang juga mencatat "program apa yang terakhir membuka dialog" untuk verifikasi silang.

---

### 5.5 Korelasi Artefak (Tabel Cepat)

| Pertanyaan Umum CTF | Artefak Utama | Bagian |
|---|---|---|
| Kondisi file/sistem sebelum dimodifikasi/dihapus attacker | VSS (mount & bandingkan) | 5.1.5, 5.1.6 |
| Attacker hapus jejak recovery (ransomware pattern) | VSS dihapus (`vssadmin delete shadows`) + cross-check EVTX | 5.1.8 |
| File yang dihapus user, isi & waktu hapusnya | Recycle Bin ($I/$R) | 5.2.1, 5.2.2 |
| File dihapus permanen (Shift+Del) tapi butuh recovery | MFT/$I30 carving (Bab 2) via lokasi `$Recycle.Bin\` | 5.2.4 |
| File dibuka dari drive/USB tertentu, drive-nya sudah dicabut | LNK — VolumeSerialNumber + MachineID/MAC | 5.3.3, 5.3.4 |
| Buktikan file datang dari komputer lain | LNK — TrackerDataBlock (MAC Address) | 5.3.4 |
| Command line argumen yang dijalankan lewat shortcut | LNK — StringData (Arguments) | 5.3.3 |
| Program apa yang dipakai buka file apa, berurutan | Jump List — DestList + LNK tertanam | 5.4.3, 5.4.5 |
| Folder yang dibuka (bukan file spesifik) dari drive yang sudah dicabut | ShellBags (Bab 3 §3.7) | Bab 3 |
| File yang dibuka via Explorer (bukan dialog Open/Save) | RecentDocs (Bab 3 §3.6.2) | Bab 3 |

---

### 5.6 Ringkasan Command & Tools Cheat Sheet

| Artefak | Tool Utama | Command Contoh | Kegunaan |
|---|---|---|---|
| VSS (live/mounted) | `vssadmin` | `vssadmin list shadows` | Enumerasi shadow copy |
| VSS (live/mounted, browse) | `mklink` | `mklink /d C:\vss1 \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\` | Mount shadow copy jadi bisa dibrowse |
| VSS (image mati) | `libvshadow` | `vshadowmount -o <offset> disk.dd /mnt/vss/` | Mount VSS langsung dari raw image |
| VSS (GUI) | `ShadowExplorer` | — | Browse & extract file dari shadow copy tanpa CLI |
| Recycle Bin ($I modern) | `RBCmd.exe` | `.\RBCmd.exe -d "C:\$Recycle.Bin" --csv .` | Parsing metadata file terhapus |
| Recycle Bin (INFO2 + $I) | `rifiuti2` | `rifiuti-vista -o output.csv "C:\$Recycle.Bin\<SID>"` | Cross-platform, dukung format lama & baru |
| LNK | `LECmd.exe` | `.\LECmd.exe -d "...\Recent" --csv .` | Parsing shortcut, termasuk TrackerDataBlock |
| Jump List | `JLECmd.exe` | `.\JLECmd.exe -d "...\Recent" --csv .` | Parsing Jump List + resolve App ID |

---

### 5.7 Mini Case Study — Rekonstruksi Aktivitas dari User Activity Trail

Skenario: *"Buktikan attacker membuka file sensitif dari network share, menyalinnya secara lokal, menghapus salinan lokal setelah selesai, lalu mencoba menutup jejak dengan menghapus shadow copy."*

```
Langkah 1 — Cari bukti file network share pernah dibuka
   └── AppData\Roaming\...\Recent\ → LECmd.exe (5.3.6)
       → cek LinkInfo untuk UNC path (\\server\share\file), catat waktu TargetAccessedDate

Langkah 2 — Konfirmasi program yang dipakai & urutan aksesnya
   └── AutomaticDestinations\ → JLECmd.exe (5.4.6)
       → cocokkan App ID dengan aplikasi yang relevan (mis. Explorer/Word)
       → cek posisi entry di DestList untuk urutan waktu relatif

Langkah 3 — Cari salinan lokal file tersebut
   └── $MFT (Bab 2, §2.2.7) → cari FullPath yang cocok dengan nama file dari LNK
       → catat EntryNumber & timestamp Created0x10/Created0x30

Langkah 4 — Cek apakah salinan lokal sudah dihapus
   └── $Recycle.Bin\<SID>\ → RBCmd.exe (5.2.5)
       → kalau ketemu $I dengan nama & path original yang cocok → konfirmasi dihapus via Recycle Bin
       → kalau tidak ketemu → cek kemungkinan Shift+Del, lanjut ke $UsnJrnl (Bab 2, §2.1.1) &
         carving MFT/unallocated (Bab 2, §2.2.9)

Langkah 5 — Cek upaya penghapusan jejak lewat VSS
   └── vssadmin list shadows (5.1.4) → bandingkan jumlah & Creation Time shadow copy yang ada
       sekarang dengan histori command line di EVTX (Bab 4, §4.3.4 — 4688) untuk
       "vssadmin delete shadows" atau "wmic shadowcopy delete"
   └── Kalau command tersebut ditemukan di EVTX tapi shadow copy relevan sudah tidak ada →
       konfirmasi kuat anti-forensic disengaja, bukan kebetulan kuota storage penuh (5.1.7)

Langkah 6 — Kalau shadow copy masih ada (attacker gagal menghapus semua), manfaatkan untuk recovery
   └── vshadowmount (5.1.5) → mount shadow copy sebelum insiden
       → bandingkan isi $Recycle.Bin atau file yang relevan di shadow copy vs kondisi sekarang (5.1.6)

Kesimpulan yang bisa ditulis di laporan:
"Attacker membuka file X dari network share \\server\share\ pada waktu Y (LNK — LinkInfo +
TargetAccessedDate), dikonfirmasi lewat Jump List aplikasi Z (JLECmd — DestList entry #1).
Salinan lokal file tersebut ditemukan di $MFT dengan EntryNumber N pada waktu Y+beberapa menit,
lalu dihapus lewat Recycle Bin pada waktu W ($I file, RBCmd). Attacker kemudian menjalankan
'vssadmin delete shadows /all /quiet' (Event 4688) untuk menghapus shadow copy — namun satu
shadow copy sebelumnya masih tersisa (kemungkinan gagal terhapus atau di luar rentang command),
yang berhasil dipakai untuk memverifikasi kondisi $Recycle.Bin sebelum penghapusan tersebut."
```

> 💡 **Prinsip umum:** Keempat artefak di bab ini paling kuat saat **saling melengkapi satu sama lain** — LNK/Jump List membuktikan "file dibuka", Recycle Bin membuktikan "file dihapus", VSS membuktikan "kondisi sebelum dihapus/dimodifikasi". Kombinasikan juga dengan ShellBags & RecentDocs (Bab 3) serta `$MFT`/`$UsnJrnl` (Bab 2) untuk timeline yang benar-benar utuh — satu artefak tunggal di bab ini jarang cukup untuk membuktikan keseluruhan alur kejadian.

---
