## 📌 Daftar Isi — Bab 7

- [Bab 7 — Memory Forensics](#bab-7--memory-forensics)
  - [7.1 Konsep Dasar Memory Forensics](#71-konsep-dasar-memory-forensics)
    - [7.1.1 Kenapa Memory Forensics Penting](#711-kenapa-memory-forensics-penting)
    - [7.1.2 Order of Volatility (RFC 3227)](#712-order-of-volatility-rfc-3227)
    - [7.1.3 Struktur Umum RAM Image](#713-struktur-umum-ram-image)
  - [7.2 Akuisisi Memory (RAM Acquisition)](#72-akuisisi-memory-ram-acquisition)
    - [7.2.1 Tools Akuisisi Live RAM](#721-tools-akuisisi-live-ram)
    - [7.2.2 Format Output](#722-format-output)
    - [7.2.3 Hibernation & Crash Dump sebagai Sumber Alternatif](#723-hibernation--crash-dump-sebagai-sumber-alternatif)
    - [7.2.4 Validasi Integritas RAM Dump](#724-validasi-integritas-ram-dump)
    - [7.2.5 Kendala Akuisisi & Alternatif](#725-kendala-akuisisi--alternatif)
  - [7.3 Volatility 3 — Setup & Profiling](#73-volatility-3--setup--profiling)
    - [7.3.1 Instalasi & Symbol Table](#731-instalasi--symbol-table)
    - [7.3.2 Plugin Dasar](#732-plugin-dasar)
    - [7.3.3 Volatility 2 vs 3](#733-volatility-2-vs-3)
    - [7.3.4 Plugin Tambahan (Non-Bawaan / Community Plugins)](#734-plugin-tambahan-non-bawaan--community-plugins)
  - [7.4 Process & Network Analysis](#74-process--network-analysis)
    - [7.4.1 pslist vs psscan vs pstree](#741-pslist-vs-psscan-vs-pstree)
    - [7.4.2 cmdline, dlllist, handles](#742-cmdline-dlllist-handles)
    - [7.4.3 netscan / netstat](#743-netscan--netstat)
    - [7.4.4 Driver & Kernel Module Analysis](#744-driver--kernel-module-analysis)
    - [7.4.5 Plugin Pelengkap: SID, Environment Variable, YARA Scan](#745-plugin-pelengkap-sid-environment-variable-yara-scan)
  - [7.5 Handle, DLL, Named Pipe & Mutex Analysis](#75-handle-dll-named-pipe--mutex-analysis)
    - [7.5.1 Handle Analysis Mendalam](#751-handle-analysis-mendalam)
    - [7.5.2 DLL Analysis (Loaded, Hidden, Unlinked)](#752-dll-analysis-loaded-hidden-unlinked)
    - [7.5.3 Named Pipes](#753-named-pipes)
    - [7.5.4 Mutex](#754-mutex)
  - [7.6 Registry & Filesystem Artifacts dari Memory](#76-registry--filesystem-artifacts-dari-memory)
    - [7.6.1 hivelist + printkey](#761-hivelist--printkey)
    - [7.6.2 filescan / dumpfiles](#762-filescan--dumpfiles)
    - [7.6.3 mftscan](#763-mftscan)
    - [7.6.4 Credential & Secret Extraction](#764-credential--secret-extraction)
    - [7.6.5 Full-Disk Encryption Key Recovery](#765-full-disk-encryption-key-recovery)
  - [7.7 Deteksi Anomali Proses di Memory](#77-deteksi-anomali-proses-di-memory)
    - [7.7.1 malfind](#771-malfind)
    - [7.7.2 ldrmodules](#772-ldrmodules)
    - [7.7.3 hollowfind & Perbandingan VAD vs Disk Image](#773-hollowfind--perbandingan-vad-vs-disk-image)
    - [7.7.4 procdump — Ekspor untuk Analisis Lanjutan](#774-procdump--ekspor-untuk-analisis-lanjutan)
    - [7.7.5 CTF-Specific Artifact Hunting](#775-ctf-specific-artifact-hunting)
  - [7.8 MemProcFS — Alternatif Analisis Interaktif](#78-memprocfs--alternatif-analisis-interaktif)
  - [7.9 Strings & Manual Carving](#79-strings--manual-carving)
  - [7.10 Analisis Memory Image Linux](#710-analisis-memory-image-linux)
    - [7.10.1 Symbol Table Linux](#7101-symbol-table-linux)
    - [7.10.2 Plugin Dasar Linux](#7102-plugin-dasar-linux)
    - [7.10.3 Artefak Khas Linux](#7103-artefak-khas-linux)
    - [7.10.4 Format Akuisisi Linux (LiME)](#7104-format-akuisisi-linux-lime)
  - [7.11 Korelasi Artefak (Tabel Cepat)](#711-korelasi-artefak-tabel-cepat)
  - [7.12 Peta Cepat: Pertanyaan Investigasi → Plugin](#712-peta-cepat-pertanyaan-investigasi--plugin)
  - [7.13 Ringkasan Command & Tools Cheat Sheet](#713-ringkasan-command--tools-cheat-sheet)
  - [7.14 Mini Case Study — End-to-End: Disk + Registry + Memory](#714-mini-case-study--end-to-end-disk--registry--memory)

*(Bab 1: Struktur Drive & Direktori — `bab1.md`. Bab 2: File Sistem NTFS & $MFT — `bab2.md`. Bab 3: Windows Registry Forensics — `bab3.md`. Bab 4: EVTX & Event ID — `bab4.md`. Bab 5: User Activity Trail — `bab5.md`. Bab 6: Browser Forensics — `bab6.md`.)*

---

## Bab 7 — Memory Forensics

Sampai Bab 6, hampir semua artefak yang dibahas bersifat **non-volatile** — tersimpan di disk, bertahan meski komputer dimatikan. Bab ini membahas sumber yang sifatnya berlawanan: **RAM**, yang isinya hilang begitu daya listrik terputus, tapi justru menyimpan hal-hal yang **tidak pernah ditulis ke disk sama sekali** — proses yang di-inject, koneksi jaringan aktif, command line lengkap, hingga kredensial plaintext yang sempat ada di memory sebelum di-hash/dienkripsi ulang ke disk.

> ⚠️ **Batasan cakupan bab ini:** Bab 7 murni menjawab pertanyaan **"bagaimana cara akuisisi & extract artefak dari RAM"** — bukan menginterpretasikan artefak tersebut. Klasifikasi malware, pemetaan teknik persistence, dan penyusunan timeline lintas-sumber sengaja **tidak** dibahas di sini:
> - **Bab 8** — interpretasi & analisis malware (apakah proses ini trojan, family apa, teknik persistence apa yang dipakai)
> - **Bab 9** — korelasi timeline penuh lintas semua sumber (disk + registry + EVTX + memory) & anti-forensics
>
> Kalau nemu istilah yang terasa "kurang tuntas" di bab ini (mis. `malfind` cuma dijelaskan cara baca output-nya, bukan apakah itu Cobalt Strike atau bukan) — itu memang disengaja, ditinggalkan untuk Bab 8/9.

---

### 7.1 Konsep Dasar Memory Forensics

#### 7.1.1 Kenapa Memory Forensics Penting

RAM menyimpan **state runtime** yang tidak pernah (atau belum) ditulis ke disk:

| Ada di RAM, sering TIDAK ada di disk | Kenapa |
|---|---|
| Command line lengkap proses yang sedang/sudah berjalan | Kalau proses sudah exit dan tidak ada logging (EVTX 4688/Sysmon), command line-nya hilang dari disk sama sekali |
| Payload malware yang **fileless** (di-inject langsung ke proses lain, tidak pernah ditulis sebagai file) | Teknik injection modern (reflective DLL injection, process hollowing) sengaja menghindari disk untuk lolos dari antivirus berbasis file-scan |
| Kredensial plaintext (sebelum di-hash) | Windows LSASS menyimpan kredensial dalam bentuk yang bisa didekripsi balik ke plaintext selama proses berjalan — di disk hanya ada bentuk hash |
| Koneksi jaringan yang **sedang aktif** persis saat snapshot diambil | PCAP/firewall log mencatat traffic historis, tapi memory menunjukkan state koneksi (`ESTABLISHED`, PID pemilik) di titik waktu itu juga |
| Kunci enkripsi volume yang ter-*mount* (BitLocker VMK, VeraCrypt master key) | Kunci ini sengaja tidak pernah ditulis ke disk dalam bentuk plaintext — hanya ada di RAM selama volume aktif digunakan |

> 💡 **Prinsip inti:** Disk forensics (Bab 1–6) menjawab *"apa yang PERNAH terjadi dan tercatat"*. Memory forensics menjawab *"apa yang SEDANG/BARU SAJA terjadi, termasuk yang sengaja didesain untuk tidak meninggalkan jejak di disk"*. Keduanya saling melengkapi, bukan saling menggantikan — makanya bab ini ditutup dengan mini case study yang menggabungkan sumber disk *dan* memory (§7.14).

#### 7.1.2 Order of Volatility (RFC 3227)

RFC 3227 menetapkan urutan prioritas akuisisi bukti digital berdasarkan **seberapa cepat data itu hilang** — ini prinsip yang sama yang mendasari kenapa RAM harus diakuisisi *sebelum* mematikan sistem untuk imaging disk (kalau memang kebijakan investigasi mengizinkan live acquisition):

```
Paling volatile (akuisisi duluan)
│
├── CPU register, cache CPU
├── Routing table, ARP cache, tabel proses kernel  ← RAM secara umum ada di sini
├── RAM (isi memory)
├── Temporary filesystem / swap space (pagefile.sys)
├── Data di disk (relatif stabil)
├── Log yang di-mirror/di-backup di lokasi remote
└── Konfigurasi fisik, topologi jaringan
│
Paling tidak volatile (akuisisi belakangan)
```

> ⚠️ **Implikasi praktis:** Kalau sistem masih menyala dan kamu harus memilih urutan akuisisi, RAM (dan artefak volatile lain seperti koneksi jaringan aktif) harus diambil **sebelum** mematikan mesin untuk disk imaging — begitu daya diputus, isi RAM hilang permanen dan tidak bisa diambil ulang, sementara disk imaging masih bisa dilakukan kapan saja setelahnya.

#### 7.1.3 Struktur Umum RAM Image

Sebatas konteks yang dibutuhkan untuk memahami cara kerja Volatility (bukan kuliah arsitektur OS):

| Istilah | Penjelasan Singkat |
|---|---|
| **Physical Address** | Alamat memory yang sebenarnya di chip RAM — ini yang tertulis apa adanya di file image hasil akuisisi |
| **Virtual Address** | Alamat yang dilihat oleh tiap proses (tiap proses punya "pandangan" address space sendiri, terisolasi dari proses lain) |
| **Page Table** | Struktur yang memetakan virtual address → physical address per-proses — inilah yang dibaca Volatility untuk "menerjemahkan" isi RAM mentah jadi struktur proses yang bisa dibaca |
| **PFN Database (Page Frame Number)** | Struktur kernel yang melacak status tiap page fisik (dipakai proses mana, free, atau termasuk cache) — dasar bagi plugin seperti `pslist` untuk menemukan proses secara struktural |

> 💡 Kamu tidak perlu hafal detail struktur ini untuk memakai Volatility — cukup paham bahwa **RAM image mentah cuma kumpulan byte fisik**, dan tugas tool seperti Volatility adalah "menerjemahkan" byte itu balik jadi struktur logis (daftar proses, koneksi jaringan, dst) memakai page table dan symbol yang sesuai versi OS (§7.3.1).

---

### 7.2 Akuisisi Memory (RAM Acquisition)

#### 7.2.1 Tools Akuisisi Live RAM

| Tool | Karakteristik |
|---|---|
| **DumpIt** (Comae/Magnet) | Single executable, paling simpel — jalankan, otomatis dump ke file di lokasi yang sama |
| **WinPmem** | Open-source, mendukung kompresi & format AFF4, umum dipakai di lingkungan yang butuh chain-of-custody terstandar |
| **Magnet RAM Capture** | GUI ramah pengguna, populer untuk first responder tanpa background teknis mendalam |
| **FTK Imager** (mode "Capture Memory") | Satu tool yang sama juga dipakai untuk disk imaging (Bab 1) — praktis kalau sudah standar di toolkit investigator |

```bash
# Contoh akuisisi dengan WinPmem
winpmem_mini_x64.exe C:\evidence\ram_dump.raw

# DumpIt — cukup dijalankan sebagai admin, otomatis dump ke folder yang sama
DumpIt.exe
```

> ⚠️ **Prinsip minimal footprint:** Sama seperti akuisisi disk (Bab 1), proses akuisisi RAM sendiri **mengubah isi RAM** (karena tool akuisisi juga butuh dijalankan sebagai proses baru). Ini tidak bisa dihindari sepenuhnya — dokumentasikan tool & versi yang dipakai di catatan chain-of-custody, dan pilih tool dengan footprint sekecil mungkin.

#### 7.2.2 Format Output

| Format | Ekstensi Umum | Catatan |
|---|---|---|
| Raw/flat memory dump | `.raw`, `.mem`, `.bin` | Format paling sederhana — byte mentah tanpa metadata tambahan, didukung hampir semua tool analisis |
| Microsoft Crash Dump | `.dmp` | Dihasilkan Windows sendiri saat crash (BSOD) atau lewat `procdump`/Task Manager, punya header metadata (bisa full/kernel/minidump) |
| AFF4 | `.aff4` | Format modern dengan kompresi & metadata built-in (mirip E01 di dunia disk imaging, Bab 1 §1.1.13) — dipakai WinPmem versi baru |

> 💡 Volatility 3 bisa membaca hampir semua format ini langsung tanpa konversi manual — tinggal arahkan path file-nya lewat `-f`.

#### 7.2.3 Hibernation & Crash Dump sebagai Sumber Alternatif

Sudah disinggung sebagai *path* di Bab 1 §1.2.13 — di sini dibahas tuntas cara analisisnya. Kedua file ini penting karena **live RAM capture sering tidak tersedia** (mis. sistem sudah dimatikan sebelum investigator tiba, atau kasus CTF/Sherlock cuma menyediakan disk image):

```
C:\hiberfil.sys       ← Snapshot RAM saat sistem masuk mode Hibernate
C:\Windows\MEMORY.DMP  ← Kernel/full crash dump saat BSOD
C:\Windows\Minidump\   ← Versi ringkas crash dump (per-crash, ukuran kecil)
```

**hiberfil.sys** menyimpan snapshot RAM (terkompresi, dengan header Windows sendiri) di titik sistem terakhir masuk mode hibernate — bukan RAM "saat ini", tapi RAM "pada waktu hibernate terjadi", yang tetap berharga sebagai snapshot historis.

```bash
# Konversi hiberfil.sys ke raw image yang bisa dibaca Volatility
# Volatility 3 sudah punya plugin bawaan untuk baca hiberfil.sys langsung:
vol -f hiberfil.sys windows.info

# Kalau perlu konversi eksplisit ke raw:
python3 hibr2bin.py hiberfil.sys hiberfil_converted.raw
```

**MEMORY.DMP / Minidump** dihasilkan sistem sendiri saat crash — formatnya sudah dikenali Volatility langsung tanpa konversi:

```bash
vol -f MEMORY.DMP windows.pslist
```

> ⚠️ **Batasan hiberfil.sys & crash dump:** Keduanya **bukan** snapshot RAM penuh yang identik dengan live capture — hiberfil.sys hanya mencatat state di waktu hibernate (bisa jadi jauh sebelum insiden), dan crash dump (apalagi Minidump) sering cuma menyimpan sebagian memory yang relevan dengan crash, bukan seluruh RAM. Kalau soal CTF/Sherlock menyediakan file ini alih-alih raw RAM dump, itu petunjuk kuat bahwa live capture memang tidak tersedia dan file ini adalah sumber terbaik yang ada — bukan berarti otomatis lebih lengkap dari live dump.

> 💡 **Relevansi HTB Sherlock:** Banyak challenge forensik memory di HTB Sherlock justru menyediakan `hiberfil.sys` atau `MEMORY.DMP` alih-alih raw RAM dump, karena skenarionya meniru kondisi dunia nyata di mana investigator baru datang setelah sistem sudah dimatikan atau habis crash — bukan selalu dapat live capture yang "sempurna".

#### 7.2.4 Validasi Integritas RAM Dump

Praktik standar yang sama dengan disk imaging (Bab 1 §1.1.13 — hash embedded di E01) berlaku juga untuk RAM dump, walau formatnya (raw/mem) biasanya tidak punya hash built-in seperti E01:

```bash
# Hash segera setelah akuisisi, sebelum image dipindah/disalin
sha256sum ram_dump.raw > ram_dump.raw.sha256

# Verifikasi ulang kapan pun sebelum analisis, untuk pastikan file tidak berubah
sha256sum -c ram_dump.raw.sha256
```

> ⚠️ Karena RAM dump sering berukuran besar (bisa puluhan GB) dan dipindah-pindah antar storage/investigator, hash harus dibuat **sesegera mungkin** setelah akuisisi selesai — sama seperti prinsip chain-of-custody untuk disk image, hash inilah yang membuktikan file yang dianalisis identik dengan file hasil akuisisi awal, bukan versi yang sudah (sengaja/tidak sengaja) berubah.

#### 7.2.5 Kendala Akuisisi & Alternatif

| Kendala | Alternatif |
|---|---|
| EDR/anti-cheat memblokir tool akuisisi RAM (dianggap perilaku mencurigakan) | Pakai driver akuisisi bersertifikat/ditandatangani, atau matikan sementara komponen EDR yang relevan sesuai prosedur (dengan dokumentasi lengkap) |
| Ukuran RAM sangat besar (128 GB+), waktu/storage akuisisi jadi kendala | Akuisisi terarah (targeted process dump — §7.7.4) alih-alih full RAM dump kalau skenario mengizinkan |
| Sistem sudah dimatikan sebelum investigator tiba | Gunakan hiberfil.sys / MEMORY.DMP (§7.2.3) sebagai gantinya |
| Sistem berupa Virtual Machine | Snapshot VM (`.vmem` untuk VMware, `.sav`/checkpoint untuk Hyper-V) berfungsi sebagai RAM dump — Volatility bisa membaca `.vmem` langsung |

---

### 7.3 Volatility 3 — Setup & Profiling

#### 7.3.1 Instalasi & Symbol Table

```bash
pip install volatility3
# atau clone dari source untuk versi paling baru
git clone https://github.com/volatilityfoundation/volatility3.git
```

Volatility 3 mendeteksi versi & build Windows **secara otomatis** dari image itu sendiri, lalu mengunduh/mencocokkan **symbol table** yang sesuai (berisi definisi struktur kernel untuk build tersebut) — beda dengan Volatility 2 yang mengharuskan user memilih *profile* secara manual (§7.3.3).

```bash
# Plugin pertama yang dijalankan di hampir semua kasus — verifikasi OS & build terdeteksi benar
vol -f ram_dump.raw windows.info
```

> 💡 Kalau `windows.info` gagal mendeteksi versi OS dengan benar (mis. hasil kosong/error symbol not found), curigai image korup atau format yang tidak didukung langsung — cek ulang hasil akuisisi (§7.2.4) sebelum lanjut ke plugin lain.

#### 7.3.2 Plugin Dasar

| Plugin | Fungsi |
|---|---|
| `windows.info` | Info dasar image: versi OS, build number, arsitektur, base address kernel |
| `windows.pslist` | Daftar proses (traversal linked list `EPROCESS` — bisa "ditipu" proses hidden, lihat §7.4.1) |
| `windows.pstree` | Sama seperti `pslist`, ditampilkan sebagai tree parent-child |
| `windows.psscan` | Scan proses lewat pattern-matching struktur `EPROCESS` di seluruh memory, tidak bergantung linked list (bisa temukan proses yang di-unlink) |

```bash
vol -f ram_dump.raw windows.pstree
```

#### 7.3.3 Volatility 2 vs 3

| Aspek | Volatility 2 | Volatility 3 |
|---|---|---|
| Deteksi OS/versi | Manual — user pilih `--profile=Win10x64_19041` dsb. | Otomatis dari symbol table yang cocok dengan image |
| Bahasa | Python 2 (sudah EOL) | Python 3 |
| Nama plugin | `pslist`, `netscan` (tanpa prefix) | `windows.pslist`, `windows.netscan` (prefix OS) |
| Status pengembangan | Maintenance mode, tidak ada fitur baru | Aktif dikembangkan, jadi standar saat ini |

> 💡 Kalau nemu writeup CTF lama yang masih pakai command `vol.py --profile=... pslist`, itu tanda mereka pakai Vol2 — konsepnya sama, tapi command & nama plugin perlu disesuaikan ke Vol3 (`vol -f image.raw windows.pslist`) kalau environment kamu sudah pakai versi baru.

#### 7.3.4 Plugin Tambahan (Non-Bawaan / Community Plugins)

Selain plugin bawaan (`windows.*` yang sudah ter-install otomatis), Volatility 3 mendukung **plugin komunitas** lewat flag `--plugin-dirs` — beberapa sudah disebut sekilas di bagian sebelumnya (`hollowfind`, `bitlocker`) tanpa dijelaskan cara instalasinya.

```bash
# Clone repository community plugin resmi Volatility Foundation
git clone https://github.com/volatilityfoundation/community3.git

# Arahkan Volatility ke folder plugin tambahan lewat --plugin-dirs
vol -f ram_dump.raw --plugin-dirs community3/volatility3/community windows.pslist
```

| Plugin Komunitas | Fungsi |
|---|---|
| `hollowfind.HollowFind` | Deteksi indikasi process hollowing (§7.7.3) |
| `bitlocker.Bitlocker` | Ekstraksi BitLocker VMK dari memory (§7.6.5) |
| `skeleton_key_check` | Deteksi indikasi malware **Skeleton Key** — patch pada proses autentikasi domain yang memungkinkan login dengan password master tunggal selain password asli user |
| `mimikatz` | Ekstraksi kredensial plaintext dari `lsass.exe` langsung lewat Volatility, mereplikasi sebagian teknik Mimikatz tanpa perlu menjalankan tool aslinya di sistem korban |
| `poolscanner.PoolScanner` | Pool tag scanning generik — dasar dari banyak plugin `*scan` (bisa dipakai custom untuk struktur kernel yang belum ada plugin resminya) |
| `truecrypt.Passphrase` | Varian ekstraksi passphrase/key TrueCrypt dari memory, melengkapi `bitlocker` untuk skema enkripsi non-BitLocker (§7.6.5) |
| `callbacks.Callbacks` | Daftar kernel callback (notify routine untuk proses/thread/image load) — berguna mendeteksi driver yang mendaftarkan hook untuk memata-matai pembuatan proses baru (pola umum EDR *dan* rootkit) |

> ⚠️ **Validasi ekstra dibutuhkan:** Plugin komunitas tidak selalu ter-maintain seaktif plugin core, dan cakupan kompatibilitas versi Windows-nya sering lebih sempit. Selalu **cross-check** hasil plugin komunitas dengan plugin core yang setara (mis. hasil `hollowfind` dengan `malfind` + `ldrmodules` manual) sebelum menjadikannya bukti utama di laporan — terutama untuk kasus yang butuh tingkat kepercayaan tinggi, bukan sekadar eksplorasi awal di CTF.

---

### 7.4 Process & Network Analysis

#### 7.4.1 pslist vs psscan vs pstree

| Plugin | Metode | Bisa Deteksi Proses "Hidden"? |
|---|---|---|
| `pslist` | Traversal **linked list** `EPROCESS` yang dikelola kernel (`ActiveProcessLinks`) | **Tidak** — kalau proses di-*unlink* dari list ini (teknik DKOM/klasik proses hiding), `pslist` tidak akan menampilkannya |
| `pstree` | Sama seperti `pslist`, ditampilkan hierarkis parent-child | Sama seperti `pslist` — sama-sama bergantung linked list |
| `psscan` | **Pattern-scan** seluruh memory mencari signature struktur `EPROCESS`, tidak bergantung linked list | **Bisa** — karena struktur proses tetap ada di memory walau sudah di-unlink dari list aktif |

```bash
vol -f ram_dump.raw windows.pslist
vol -f ram_dump.raw windows.psscan
```

> 💡 **Tip investigasi:** Selalu jalankan **keduanya** lalu bandingkan. Kalau ada PID yang muncul di `psscan` tapi **tidak** muncul di `pslist`, itu indikasi kuat proses tersebut sengaja di-unlink dari daftar proses aktif — pola klasik proses hiding yang layak diselidiki lebih lanjut (tapi ingat, interpretasi "ini teknik apa/malware apa" adalah domain Bab 8 — di sini cukup identifikasi anomalinya).

#### 7.4.2 cmdline, dlllist, handles

| Plugin | Isi |
|---|---|
| `windows.cmdline` | Command line lengkap tiap proses (termasuk argumen) — sering satu-satunya sumber command line kalau proses sudah tidak ada di EVTX/Sysmon logging |
| `windows.dlllist` | Daftar DLL yang di-load tiap proses, lengkap dengan path asalnya |
| `windows.handles` | Daftar handle yang dipegang tiap proses (file, registry key, mutex, dll) — berguna untuk lihat file/registry apa yang sedang "dipegang" proses tertentu saat snapshot diambil |

```bash
vol -f ram_dump.raw windows.cmdline
vol -f ram_dump.raw windows.dlllist --pid 4321
```

> 💡 Cross-reference: `cmdline` di sini adalah pelengkap penting untuk PowerShell logging (Bab 4 §4.5) dan Sysmon Event ID 1 (Bab 4) — kalau logging tersebut tidak aktif/sudah di-clear, `cmdline` dari memory bisa jadi satu-satunya cara melihat argumen lengkap yang dipakai proses mencurigakan.

#### 7.4.3 netscan / netstat

```bash
vol -f ram_dump.raw windows.netscan
```

Menampilkan koneksi TCP/UDP yang aktif atau baru saja ditutup pada saat snapshot diambil, lengkap dengan PID pemilik koneksi, local/remote address & port, dan state (`ESTABLISHED`, `LISTENING`, `CLOSED`, dll).

> 💡 Cross-reference: Bandingkan hasil `netscan` dengan Sysmon Event ID 3 — Network Connection (Bab 4 §4.6) untuk verifikasi silang. `netscan` menunjukkan **state koneksi persis di titik snapshot**, sementara Sysmon Event ID 3 mencatat **histori kapan koneksi itu pertama dibuat** — kombinasi keduanya memberi gambaran lebih lengkap daripada masing-masing sendirian.

#### 7.4.4 Driver & Kernel Module Analysis

Sebatas cara **listing** struktur kernel — bukan analisis/klasifikasi rootkit atau hooking behavior (itu ranah Bab 8/9 kalau nanti dibahas lebih dalam):

| Plugin | Fungsi |
|---|---|
| `windows.driverscan` | Scan seluruh memory mencari struktur driver yang ter-load (mirip `psscan` tapi untuk driver, bukan proses) |
| `windows.modules` | Daftar kernel module yang ter-load lewat linked list resmi (analog `pslist` tapi di level kernel module) |
| `windows.ssdt` | Menampilkan isi **System Service Descriptor Table** — tabel pemetaan syscall ke alamat fungsi kernel |

```bash
vol -f ram_dump.raw windows.driverscan
vol -f ram_dump.raw windows.modules
```

> 💡 Sama seperti pola `pslist` vs `psscan`, membandingkan `windows.modules` (linked list resmi) dengan `windows.driverscan` (pattern-scan) bisa mengungkap driver yang di-unlink dari daftar resmi. Di bab ini cukup paham **cara membaca structure-nya** — kalau soal minta interpretasi "apakah ini rootkit" atau "apa fungsi hook di SSDT ini", itu sudah masuk analisis mendalam yang jadi ranah bab lanjutan.

#### 7.4.5 Plugin Pelengkap: SID, Environment Variable, YARA Scan

Tiga plugin bawaan yang sering terlewat karena bukan bagian dari alur "proses → jaringan" yang standar, padahal sering jadi jawaban cepat di CTF/Sherlock:

| Plugin | Fungsi |
|---|---|
| `windows.getsids` | Menampilkan **SID** (Security Identifier) yang dipegang tiap proses — berguna untuk identifikasi proses yang berjalan dengan privilege tidak wajar (mis. proses user biasa yang punya SID `SYSTEM`, indikasi privilege escalation) |
| `windows.envars` | Menampilkan **environment variable** tiap proses — kadang menyimpan path, flag konfigurasi, atau bahkan kredensial yang sengaja/tidak sengaja diteruskan lewat variable alih-alih argumen command line |
| `windows.svcscan` | Daftar **Windows Service** yang terdaftar (nama, display name, path binary, start type) — versi memory dari service yang biasanya dibaca dari hive `SYSTEM\CurrentControlSet\Services` (Bab 3), berguna kalau butuh state service *saat snapshot* tanpa parsing hive manual |
| `windows.yarascan` | Scan seluruh (atau sebagian) memory dengan **YARA rule**, bisa diarahkan ke proses tertentu (`--pid`) atau seluruh image. Ini jembatan langsung ke Bab 8 — begitu kamu punya YARA rule untuk keluarga malware tertentu, plugin ini yang dipakai untuk mencari kecocokan langsung di RAM, bukan cuma di file di disk |

```bash
vol -f ram_dump.raw windows.getsids
vol -f ram_dump.raw windows.envars --pid 4321
vol -f ram_dump.raw windows.svcscan
vol -f ram_dump.raw windows.yarascan --yara-rules "rule test {strings: $a = \"mimikatz\" condition: $a}"
# atau merujuk file rule:
vol -f ram_dump.raw windows.yarascan --yara-file rules/cobaltstrike.yar
```

> 💡 **Kapan `getsids` berguna:** Kombinasikan dengan `pslist`/`pstree` (§7.4.1) — proses child yang SID-nya "naik" dibanding parent-nya (mis. parent jalan sebagai user biasa, child punya SID admin/SYSTEM) adalah sinyal awal privilege escalation yang layak ditelusuri lebih lanjut di Bab 8.

---

### 7.5 Handle, DLL, Named Pipe & Mutex Analysis

> ⚠️ **Kenapa bagian ini dipisah dari §7.4:** `windows.handles` sudah disebut sekilas di §7.4.2, tapi cakupannya jauh lebih luas dari sekadar "daftar file terbuka" — satu plugin ini adalah pintu masuk ke tiga jenis artefak berbeda (file/registry handle, named pipe, mutex) yang masing-masing punya nilai investigasi sendiri. Banyak investigator pemula berhenti di `pslist`/`pstree`/`cmdline` padahal jawaban justru sering ada di sini.

#### 7.5.1 Handle Analysis Mendalam

Tiap proses Windows memegang **handle** — referensi ke objek kernel yang sedang dipakainya: file, registry key, mutex, named pipe, event, section (memory-mapped file), thread, proses lain, dsb. `windows.handles` menampilkan seluruh handle ini per-proses, lengkap dengan **tipe objek**-nya.

```bash
# Semua handle milik satu proses
vol -f ram_dump.raw windows.handles --pid 4321

# Filter hanya tipe tertentu (jauh lebih cepat & terarah untuk RAM dump besar)
vol -f ram_dump.raw windows.handles --pid 4321 | grep -i "File\|Mutant\|Key"
```

| Tipe Objek Handle | Nilai Investigasi |
|---|---|
| `File` | File yang sedang/baru saja dibuka — termasuk file yang **sudah dihapus dari disk** tapi handle-nya masih ada di memory selama proses belum menutupnya |
| `Key` | Registry key yang sedang dibaca/ditulis proses tersebut — pelengkap `printkey` (§7.6.1) untuk tahu key mana yang **aktif dipakai**, bukan cuma isinya |
| `Mutant` (Mutex) | Lihat §7.5.4 |
| `File` dengan path `\Device\NamedPipe\...` | Lihat §7.5.3 |
| `Thread` / `Process` | Proses/thread lain yang di-*handle* — indikasi satu proses melakukan operasi ke proses lain (mis. `OpenProcess` yang jadi prasyarat teknik injection di §7.7.1) |
| `Section` | Memory-mapped file/section object — dasar mekanisme process hollowing & shared memory antar-proses |

**Contoh kasus klasik:** `malware.exe` sudah dihapus dari disk (tidak akan muncul lagi di `filescan`/$MFT aktif), tetapi selama proses itu masih berjalan di memory saat snapshot diambil, `windows.handles` tetap menunjukkan:

```
PID   Handle   Type   Name
4321  0x1a4    File   \Device\HarddiskVolume2\Users\Bob\AppData\Local\Temp\malware.exe
```

> 💡 **Kenapa ini murni memory forensics:** Begitu proses ditutup atau sistem dimatikan, handle ini hilang — tidak ada versi "disk" dari artefak ini. Ini salah satu contoh paling jelas kenapa RAM menyimpan hal yang **tidak pernah bisa direkonstruksi dari disk image saja** (lihat prinsip di §7.1.1). Kalau soal CTF/Sherlock menyebutkan "file sudah dihapus tapi..." — `windows.handles` pada proses yang masih berjalan adalah tempat pertama yang harus dicek.

#### 7.5.2 DLL Analysis (Loaded, Hidden, Unlinked)

`dlllist` (§7.4.2) sudah disinggung, tapi analisis DLL yang lengkap butuh dibandingkan lintas beberapa sumber sekaligus — karena DLL yang di-*load* secara tidak normal (injection) justru sering **tidak** muncul di `dlllist` biasa.

| Plugin | Sumber Data | Bisa Deteksi DLL "Hidden"? |
|---|---|---|
| `windows.dlllist` | **PEB** (Process Environment Block) — daftar resmi yang "diketahui" proses itu sendiri | **Tidak** — DLL yang di-unlink dari PEB tidak akan tampil di sini |
| `windows.ldrmodules` | Membandingkan **PEB vs VAD vs kernel list** sekaligus (§7.7.2) | **Bisa** — DLL yang ada di VAD (benar-benar ter-map di memory) tapi tidak ada di PEB langsung terlihat sebagai baris `False` |
| `windows.vadinfo` (manual) | Seluruh region **VAD** proses, tanpa bergantung PEB sama sekali | **Bisa**, tapi manual — dipakai untuk cross-check lanjutan kalau `ldrmodules` sudah menunjukkan anomali dan butuh detail region-nya (base address, protection, ukuran) |

> 📝 **Catatan istilah:** Volatility 2 dulu punya plugin bernama `moddump`/pattern-scan khusus untuk *kernel* module (bukan DLL user-mode). Di Volatility 3, tidak ada plugin bernama persis "`modscan`" untuk DLL — kombinasi `ldrmodules` (untuk deteksi) + `vadinfo`/`procdump` (untuk ekstraksi region-nya) adalah cara yang setara di level user-mode. Untuk *kernel* module/driver yang unlinked, itu ranah `windows.driverscan` vs `windows.modules` (§7.4.4).

```bash
vol -f ram_dump.raw windows.dlllist --pid 4321
vol -f ram_dump.raw windows.ldrmodules --pid 4321
vol -f ram_dump.raw windows.vadinfo --pid 4321
```

Tiga teknik yang membuat DLL "hilang" dari `dlllist` biasa tapi tetap kelihatan di `ldrmodules`/`vadinfo`:

| Teknik | Ciri di Memory |
|---|---|
| **DLL Injection klasik** (`CreateRemoteThread` + `LoadLibrary`) | DLL biasanya masih terdaftar di PEB (karena dimuat lewat loader resmi Windows) — kadang tetap muncul normal di `dlllist`, ciri utamanya justru ada di `handles` (proses lain membuka handle `Process`/`Thread` ke target, lihat §7.5.1) |
| **Reflective DLL Injection** | DLL di-map manual ke memory tanpa lewat `LoadLibrary`, sehingga **tidak terdaftar di PEB** — inilah yang muncul sebagai baris `False` di `ldrmodules`, punya PE header (`MZ`) tapi tanpa entry loader resmi |
| **Manual Mapping** | Mirip reflective injection tapi lebih "bersih" (menghindari artefak loader sama sekali, kadang bahkan tanpa PE header utuh) — paling sulit dideteksi lewat `ldrmodules` saja, sering butuh `malfind` (§7.7.1) untuk menangkap region RWX-nya |

> 💡 Cukup identifikasi **pola mana** yang terlihat (DLL hilang dari PEB tapi ada di VAD, atau region RWX tanpa DLL sama sekali) — menyimpulkan ini teknik injection spesifik apa dan dipakai malware keluarga apa tetap ranah Bab 8.

#### 7.5.3 Named Pipes

**Named pipe** adalah mekanisme komunikasi antar-proses (IPC) di Windows — dan jadi metode komunikasi favorit tooling C2/post-exploitation karena traffic-nya **tidak lewat jaringan** (tidak akan tertangkap `netscan`/PCAP) selama komunikasi terjadi antar-proses di mesin yang sama, atau dipakai untuk **SMB named pipe** yang menyamar sebagai traffic Windows normal saat lateral movement.

Named pipe muncul sebagai objek `File` dengan path di bawah `\Device\NamedPipe\` — jadi dicari lewat dua plugin yang sama seperti file handle biasa:

```bash
# Lewat handle proses tertentu
vol -f ram_dump.raw windows.handles --pid 4321 | grep -i "NamedPipe"

# Atau scan seluruh memory untuk semua FILE_OBJECT, termasuk pipe
vol -f ram_dump.raw windows.filescan | grep -i "pipe"
```

Contoh artefak yang sering muncul di Sherlock/CTF bertema C2:

```
\.\pipe\msagent_1234        ← pola umum Cobalt Strike named pipe (nama beacon acak/semi-acak)
\.\pipe\postex_ssh_1a2b3c   ← pola post-exploitation module Cobalt Strike
\.\pipe\mypipe-...          ← pola generik Meterpreter/Metasploit named pipe pivot
```

> 💡 **Batas cakupan di sini:** Menemukan **nama pipe** dan **proses mana yang memegang handle-nya** murni teknik ekstraksi memory — cukup dicatat sebagai temuan. Mengidentifikasi bahwa pola nama tertentu = Cobalt Strike vs Meterpreter vs tool lain adalah **klasifikasi keluarga tool/malware**, yang jadi pembahasan Bab 8. Di sini named pipe diperlakukan sama seperti artefak lain di bab ini: ditemukan dan dicatat prosesnya, bukan diklasifikasi.

#### 7.5.4 Mutex

**Mutex** (Windows: sering muncul sebagai objek `Mutant` di Volatility) dipakai untuk sinkronisasi — termasuk pola klasik malware yang membuat mutex **bernama unik** di awal eksekusi untuk memastikan **hanya satu instance** dirinya yang berjalan sekaligus (mencegah infeksi ganda pada mesin yang sama).

```bash
vol -f ram_dump.raw windows.handles --pid 4321 | grep -i "Mutant"

# Cari di semua proses sekaligus tanpa filter --pid
vol -f ram_dump.raw windows.handles | grep -i "Mutant"
```

Format artefak yang umum ditemukan:

```
Global\MutexName          ← mutex yang visible lintas-session (bukan cuma di dalam satu login session)
Local\MutexName           ← mutex terbatas di satu login session saja
```

| Nilai Mutex sebagai Artefak | Catatan |
|---|---|
| **Indikator keberadaan malware** | Kehadiran mutex dengan nama yang tidak biasa/acak di proses yang mencurigakan adalah sinyal tambahan yang menguatkan temuan `malfind`/`ldrmodules` |
| **Indikator keluarga malware** | Banyak keluarga malware punya **pola/nama mutex yang konsisten** antar-sample (nama hardcoded atau hasil algoritma tertentu) — nilai ini sering dipakai sebagai *indicator of compromise* (IOC) untuk deteksi lintas-mesin |

> ⚠️ **Batas cakupan yang sama seperti named pipe:** Bab ini berhenti di titik "mutex bernama X ditemukan, dipegang proses Y" — memetakan nama mutex spesifik ke keluarga malware tertentu (mis. "mutex ini khas ransomware Z") butuh database IOC/threat intel yang jadi pembahasan Bab 8, bukan teknik ekstraksi Volatility itu sendiri.

---

### 7.6 Registry & Filesystem Artifacts dari Memory

Bagian ini murni teknik **"cara baca artefak lama dari sumber baru (RAM)"** — bukan analisis persistence baru. Registry key dan konsep file yang dibahas di sini sudah dijelaskan lengkap di Bab 2 & Bab 3; di sini fokusnya cara ekstraksi kalau sumber aslinya (disk) tidak bisa diakses langsung.

#### 7.6.1 hivelist + printkey

```bash
# Daftar semua registry hive yang ter-load di memory beserta alamat virtualnya
vol -f ram_dump.raw windows.registry.hivelist

# Baca key tertentu langsung dari hive di memory
vol -f ram_dump.raw windows.registry.printkey --key "Software\Microsoft\Windows\CurrentVersion\Run"
```

> 💡 **Kapan ini berguna dibanding baca hive langsung dari disk (Bab 3):** Kalau hive di disk **terkunci** (sistem live, file `SYSTEM`/`SOFTWARE` sedang dipakai OS) atau **sengaja dienkripsi/dihapus** attacker pasca-serangan, hive yang sudah di-*load* ke memory oleh OS tetap bisa dibaca lewat plugin ini — RAM menyimpan salinan hive yang sedang aktif dipakai, terlepas dari kondisi file aslinya di disk.

#### 7.6.2 filescan / dumpfiles

```bash
# Scan seluruh memory mencari struktur FILE_OBJECT
vol -f ram_dump.raw windows.filescan

# Recover file tertentu berdasarkan physical offset dari hasil filescan
vol -f ram_dump.raw windows.dumpfiles --physaddr 0x1a2b3c4d
```

`filescan` menemukan file yang **cache/isinya masih ada di memory** — meski file itu sendiri sudah dihapus dari disk, atau proses yang membukanya sudah menutup handle-nya. `dumpfiles` mengekstrak isi file tersebut ke disk untuk analisis lanjutan.

> 💡 Berguna untuk recovery file yang **sengaja dihapus segera setelah dieksekusi** (teknik anti-forensic klasik) — kalau masih ada cache-nya di RAM saat snapshot diambil, `filescan`/`dumpfiles` bisa jadi jalan recovery terakhir setelah Recycle Bin (Bab 5 §5.2) dan $MFT (Bab 2) sudah tidak menyisakan apa-apa.

#### 7.6.3 mftscan

```bash
vol -f ram_dump.raw windows.mftscan.MFTScan
```

Sama seperti `filescan` tapi khusus mencari **MFT record** ($MFT — Bab 2) yang kebetulan ter-cache di memory (Windows meng-cache sebagian metadata filesystem yang sering diakses). Berguna kalau kamu cuma punya RAM dump tanpa disk image sama sekali, tapi tetap butuh metadata filesystem seperti timestamp `$STANDARD_INFORMATION`/`$FILE_NAME` (Bab 2 §2.2) untuk file tertentu.

> ⚠️ **Batasan:** Cakupan `mftscan` jauh lebih terbatas dibanding parsing $MFT langsung dari disk image (Bab 2) — cuma record yang kebetulan masih ter-cache di RAM saat snapshot yang bisa ditemukan, bukan seluruh isi $MFT.

#### 7.6.4 Credential & Secret Extraction

Paralel ke ekstraksi offline dari hive `SAM`/`SECURITY` di Bab 3 §3.5, tapi versi ini bekerja langsung dari memory proses `lsass.exe` — murni teknik ekstraksi, bukan cracking atau analisis lanjutan atas hasilnya:

| Plugin | Fungsi |
|---|---|
| `windows.hashdump` | Ekstrak NTLM hash akun lokal langsung dari struktur memory (setara membaca `SAM`+`SYSTEM` tapi dari RAM, bukan file hive) |
| `windows.lsadump` | Ekstrak LSA secret (termasuk cached domain credential & service account password kalau tersimpan) |
| `windows.cachedump` | Ekstrak cached domain credential (`MSCache`/`MSCache2`) — kredensial domain yang di-cache untuk login offline |

```bash
vol -f ram_dump.raw windows.hashdump
vol -f ram_dump.raw windows.lsadump
```

> ⚠️ **Perbandingan dengan Bab 3:** Bab 3 §3.5 membahas ekstraksi hash **offline** dari hive `SAM`/`SECURITY`/`SYSTEM` di disk. Plugin di sini melakukan hal yang sama secara **fungsional**, tapi sumbernya struktur memory `lsass.exe` yang sedang berjalan — berguna kalau hive di disk terkunci/tidak bisa diakses, atau kalau butuh kredensial yang **belum sempat ditulis ulang ke disk**. Hasil akhirnya (NTLM hash) sama, cara membacanya beda sumber.

> 💡 Cracking hash yang berhasil diekstrak (rainbow table, brute force, dsb.) dan analisis "kredensial ini dipakai untuk apa" adalah langkah lanjutan yang **di luar cakupan bab ini** — di sini berhenti di titik ekstraksi.

#### 7.6.5 Full-Disk Encryption Key Recovery

Kunci enkripsi volume yang sedang ter-*mount* tersimpan di RAM selama volume itu aktif digunakan — teknik klasik DFIR untuk kasus disk terenkripsi, dan sering muncul di HTB Sherlock kategori disk encryption:

| Skema Enkripsi | Kunci yang Dicari di Memory |
|---|---|
| **BitLocker** | VMK (Volume Master Key) — bisa dicari lewat plugin komunitas Volatility (mis. `bitlocker`) atau tool khusus seperti `Elcomsoft Forensic Disk Decryptor` yang membaca RAM dump |
| **VeraCrypt/TrueCrypt** | Master key AES tersimpan di memory selama volume ter-mount — dicari lewat pattern-matching struktur key schedule AES di RAM |

```bash
# Contoh alur konseptual — plugin/tool spesifik tergantung skema enkripsi & versi Volatility yang dipakai
vol -f ram_dump.raw bitlocker.Bitlocker
```

> ⚠️ **Ketergantungan pada RAM dump yang tepat waktu:** Kunci ini **hanya** ada di memory selama volume dalam kondisi ter-mount (unlocked). Kalau RAM dump diambil **setelah** volume di-unmount atau sistem di-shutdown, kunci sudah tidak akan ditemukan di RAM — ini salah satu alasan kenapa Order of Volatility (§7.1.2) menekankan akuisisi RAM secepat mungkin pada sistem yang masih menyala, terutama kalau diketahui ada volume terenkripsi yang sedang aktif.

---

### 7.7 Deteksi Anomali Proses di Memory

> ⚠️ Bagian ini dipersempit khusus ke **kemampuan teknis Volatility yang hanya bisa dilakukan di memory** — deteksi anomali di level struktur. Static analysis payload, klasifikasi keluarga malware, dan pemetaan teknik persistence (Run key/service/scheduled task) sengaja **tidak** dibahas di sini — itu domain Bab 8.

#### 7.7.1 malfind

```bash
vol -f ram_dump.raw windows.malfind
```

`malfind` mencari region memory dengan kombinasi karakteristik yang jarang muncul secara legit:

| Karakteristik yang Dicari | Kenapa Mencurigakan |
|---|---|
| Permission **RWX** (Read-Write-Execute) sekaligus | Memory legit biasanya cuma butuh salah satu kombinasi (kode = RX, data = RW) — RWX sekaligus adalah pola umum shellcode/payload yang di-inject lalu langsung dieksekusi |
| Ada **PE header** (`MZ`) di region **tanpa backing file** yang jelas | Kode/DLL normal punya file asal di disk yang bisa ditelusuri balik (lewat `vad`/`dlllist`) — region dengan PE header tapi tanpa file asal indikasi kode di-inject langsung ke memory, bukan di-load lewat mekanisme normal |

> 💡 **Cara baca output `malfind` (bukan interpretasi lanjutan):** Output menampilkan PID, alamat region, protection flag, dan hex dump/disassembly awal region tersebut. Tugas di level bab ini cukup **mengidentifikasi** region yang punya kombinasi RWX + PE header mencurigakan — menentukan apakah itu benar-benar malicious, apa jenisnya, dan bagaimana cara kerjanya, itu masuk analisis statis/dinamis lanjutan (Bab 8).

#### 7.7.2 ldrmodules

```bash
vol -f ram_dump.raw windows.ldrmodules
```

Membandingkan tiga sumber daftar DLL yang seharusnya konsisten satu sama lain:

1. **PEB** (Process Environment Block) — daftar DLL resmi yang "diketahui" oleh proses itu sendiri
2. **VAD** (Virtual Address Descriptor) — daftar region memory yang benar-benar di-*map* sebagai executable
3. Kernel object list

> 💡 **Deteksi DLL unlinked:** Kalau ada DLL yang muncul di VAD (benar-benar ada di memory, ter-map sebagai executable) tapi **tidak muncul** di PEB (proses "tidak tahu" DLL ini ada), itu indikasi DLL tersebut di-*unlink* dari PEB — teknik yang dipakai untuk menyembunyikan DLL dari tool yang cuma mengandalkan `dlllist` biasa (§7.4.2), yang membaca daftar dari PEB.

#### 7.7.3 hollowfind & Perbandingan VAD vs Disk Image

Deteksi **process hollowing** — teknik di mana proses legit dijalankan lalu isi memory-nya "dikosongkan" dan diganti dengan payload lain, sementara nama proses & metadata luar tetap terlihat normal (mis. `svchost.exe` yang isinya sudah bukan `svchost.exe` asli).

Dua pendekatan level struktur (bukan reversing payload-nya):

```bash
# Kalau tersedia sebagai plugin komunitas
vol -f ram_dump.raw hollowfind.HollowFind
```

**Perbandingan VAD vs disk image** — pendekatan manual yang tidak butuh plugin khusus: bandingkan isi region memory proses (lewat `vaddump`/`memdump`) dengan isi file executable aslinya di disk (kalau masih ada). Perbedaan signifikan antara apa yang ada di memory dengan apa yang ada di file disk untuk proses yang "seharusnya" sama adalah indikasi hollowing.

> 💡 **Tetap level struktur:** Di sini cukup identifikasi **bahwa** ada indikasi hollowing (base address proses tidak cocok dengan image file aslinya, atau section PE di memory berbeda dari section di file disk) — bukan menganalisis payload apa yang menggantikannya atau menyimpulkan family malware (Bab 8).

#### 7.7.4 procdump — Ekspor untuk Analisis Lanjutan

```bash
vol -f ram_dump.raw windows.procdump --pid 4321
```

`procdump` mengekstrak (dump) memory image satu proses spesifik ke file `.exe`/`.dmp` di disk, direkonstruksi ulang sebisa mungkin menjadi PE yang valid. Di bab ini, `procdump` disebut **hanya** sebagai cara ekspor artefak — proses ini menjadi jembatan ke Bab 8 (misalnya untuk dianalisis lebih lanjut dengan disassembler atau di-scan ulang dengan YARA/antivirus offline), tanpa masuk ke cara analisisnya di sini.

#### 7.7.5 CTF-Specific Artifact Hunting

Pelengkap §7.9 (Strings & Manual Carving) — lokasi spesifik di memory yang sering jadi tempat "flag" atau data tersembunyi disimpan panitia CTF, karena sifatnya yang natural (bukan pola malware, tapi tetap butuh teknik ekstraksi dari RAM):

| Sumber | Plugin/Cara |
|---|---|
| Isi clipboard saat snapshot diambil | `windows.clipboard` |
| History command yang diketik di `cmd.exe`/`conhost.exe` (termasuk yang sudah di-scroll keluar layar) | Cari region memory milik proses `conhost.exe` lewat `vadinfo`/`memdump`, lalu grep manual — clipboard history dan console buffer sering menyimpan command yang sudah "hilang" dari layar tapi belum ter-overwrite di memory |
| Isi text editor/Notepad yang **belum di-save** | Dump memory proses `notepad.exe` (atau editor lain) lewat `memdump`, lalu cari teks plaintext — karena belum di-save, teks ini **tidak ada di disk sama sekali**, cuma ada di RAM |

```bash
vol -f ram_dump.raw windows.clipboard
vol -f ram_dump.raw windows.memmap --pid <PID_notepad> --dump
```

> 💡 **Tip CTF:** Kalau soal minta *"temukan flag yang disembunyikan di memory"* dan flag-nya bukan bagian dari payload malware, cek dulu clipboard, console history, dan buffer text editor sebelum masuk ke teknik carving yang lebih berat (§7.9) — sering kali flag CTF sengaja diletakkan di lokasi-lokasi "manusiawi" ini karena gampang di-setup panitia, bukan di-inject sebagai bagian dari skenario malware.

---

### 7.8 MemProcFS — Alternatif Analisis Interaktif

MemProcFS me-*mount* RAM image sebagai **virtual filesystem** — proses, registry, dan koneksi jaringan bisa di-*browse* langsung layaknya folder biasa di Explorer/terminal, tanpa perlu mengetik command plugin satu-satu seperti Volatility.

```bash
# Mount RAM image sebagai drive virtual (Windows) atau mount point (Linux)
MemProcFS.exe -device ram_dump.raw -mount M:

# Setelah mount, struktur jadi bisa dijelajahi seperti folder biasa:
M:\pid\<PID>\        ← Info proses, handle, module per-PID
M:\registry\         ← Hive registry yang ter-load, browsable seperti folder biasa
M:\net\               ← Daftar koneksi jaringan aktif
```

| Kapan Pakai MemProcFS | Kapan Pakai Volatility |
|---|---|
| Eksplorasi cepat/awal — belum tahu persis mau cari apa, ingin "jalan-jalan" di struktur memory | Sudah tahu persis artefak yang dicari, butuh output terstruktur untuk parsing/scripting lanjutan |
| Investigator kurang familiar command-line, lebih nyaman navigasi seperti file explorer | Butuh integrasi ke pipeline otomasi (mis. dijalankan sebagai bagian dari script investigasi besar) |
| Butuh preview cepat isi file/registry tanpa command dump terpisah | Butuh plugin spesifik yang belum ada versi "folder browsing"-nya di MemProcFS (mis. `hashdump`, `bitlocker`) |

> 💡 Kedua tool **saling melengkapi**, bukan saling menggantikan — banyak investigator pakai MemProcFS untuk eksplorasi awal cepat, baru pindah ke Volatility untuk plugin spesifik yang dibutuhkan setelah tahu persis apa yang dicari.

---

### 7.9 Strings & Manual Carving

Dipakai saat parsing terstruktur (Volatility) gagal atau tidak cukup — image korup, versi OS tidak dikenal simbolnya, atau data yang dicari memang bukan struktur proses/registry melainkan sekadar teks polos yang tersebar di RAM.

```bash
# strings biasa — cari semua ASCII printable string minimal 6 karakter
strings -n 6 ram_dump.raw | grep -i "password"

# bstrings (Eric Zimmerman) — mendukung regex bawaan untuk pola umum
bstrings.exe -f ram_dump.raw --ls "https?://" -o urls_found.txt

# bulk_extractor — carving otomatis banyak pola sekaligus (email, IP, base64, credit card, dll)
bulk_extractor -o output_dir ram_dump.raw
```

| Tool | Kelebihan |
|---|---|
| `strings` | Bawaan hampir semua sistem, cepat untuk pencarian sederhana |
| `bstrings` (Eric Zimmerman) | Regex bawaan untuk pola umum forensik (URL, email, IP), lebih terarah dibanding `strings` polos |
| `bulk_extractor` | Scan paralel banyak pola sekaligus, hasilnya sudah terkategorikan per jenis data (histogram email, URL, dll) — cocok untuk triase cepat image besar |

> 💡 **Kapan teknik manual dipakai walau Volatility tersedia:** (1) image corrupt sebagian — Volatility butuh struktur konsisten untuk parsing, sementara `strings`/`bulk_extractor` tetap jalan di data yang rusak sekalipun; (2) versi OS tidak dikenal/symbol table tidak tersedia — Volatility gagal total tanpa symbol yang cocok, sementara pencarian string tidak bergantung struktur OS sama sekali; (3) yang dicari memang cuma teks polos (kredensial, domain C2 yang terlihat plaintext) — tidak perlu overhead parsing struktur proses kalau tujuannya cuma grep pola teks.

> ⚠️ **Batasan konteks yang tetap dalam cakupan bab ini:** Hasil carving cuma menunjukkan **data ditemukan** (mis. domain terlihat di memory), bukan konteks lengkap (proses mana yang memilikinya, kapan, untuk apa) — kalau butuh konteks itu, kombinasikan dengan plugin terstruktur (`cmdline`, `netscan`, `malfind`) di bagian sebelumnya. Interpretasi lebih dalam soal "domain ini dipakai untuk C2 protokol apa" tetap ranah Bab 8.

---

### 7.10 Analisis Memory Image Linux

Seluruh bagian sebelumnya (§7.1–§7.9) berfokus pada memory image **Windows**. Kalau target akuisisi adalah mesin Linux (server yang di-compromise, container host, dst), sebagian besar **konsep** tetap sama (page table, order of volatility, malfind-style anomaly detection) — tapi **tooling dan cara setup-nya berbeda cukup signifikan**, terutama soal symbol table.

#### 7.10.1 Symbol Table Linux

Perbedaan paling mendasar dengan Windows (§7.3.1): Volatility 3 **tidak bisa** otomatis mendeteksi & mengunduh symbol yang cocok untuk Linux, karena setiap distro + versi kernel + konfigurasi compile punya struktur `task_struct` dkk yang bisa sedikit berbeda. Symbol table harus **dibuat manual** dari kernel yang persis sama dengan mesin target.

```bash
# 1. Di mesin target (atau mesin dengan kernel identik), install debug symbol kernel
#    Contoh Ubuntu/Debian:
apt install linux-image-$(uname -r)-dbgsym
# atau kalau tidak tersedia di repo, cari paket dbgsym yang sesuai versi kernel persis

# 2. Generate symbol table pakai dwarf2json dari file vmlinux (kernel dengan debug info)
dwarf2json linux --elf /usr/lib/debug/boot/vmlinux-$(uname -r) > ubuntu_5.15.0-generic.json

# 3. Kompres & taruh di folder symbols Volatility 3
gzip ubuntu_5.15.0-generic.json
mv ubuntu_5.15.0-generic.json.gz volatility3/symbols/linux/
```

> ⚠️ **Kenapa versi kernel harus PERSIS sama:** Beda Windows yang punya versi build resmi terbatas & terdokumentasi baik, distro Linux + custom kernel bisa menghasilkan ribuan kombinasi struktur yang sedikit berbeda. Symbol table dari kernel versi `5.15.0-91-generic` **tidak otomatis kompatibel** dengan `5.15.0-92-generic` — kalau `linux.pslist` gagal total (bukan cuma hasil aneh, tapi error/kosong), curigai symbol table tidak cocok persis, bukan image korup.

> 💡 **Tip praktis:** Kalau kamu **tidak** punya akses ke mesin target untuk generate symbol (skenario paling umum di CTF/Sherlock — cuma dikasih file image), cek dulu apakah `linux.banner` bisa membaca banner kernel dari image (biasanya berhasil walau symbol lain belum ada) untuk tahu versi kernel & distro persis, lalu cari/generate symbol table yang sesuai versi tersebut.

```bash
vol -f linux_ram.lime banner.Banner
```

#### 7.10.2 Plugin Dasar Linux

Nama plugin pakai prefix `linux.` (analog `windows.` di bab sebelumnya), dan sebagian punya padanan konsep langsung dengan plugin Windows yang sudah dibahas:

| Plugin Linux | Padanan Windows | Fungsi |
|---|---|---|
| `linux.pslist` | `windows.pslist` | Daftar proses via traversal linked list kernel |
| `linux.pstree` | `windows.pstree` | Tree parent-child proses |
| `linux.psaux` | `windows.cmdline` | Command line lengkap tiap proses (setara `ps aux`) |
| `linux.lsof` | `windows.handles` | File descriptor terbuka tiap proses (§7.5.1) — di Linux **semua** hampir jadi "file", termasuk socket & pipe |
| `linux.sockstat` / `linux.netstat` | `windows.netscan` | Koneksi jaringan aktif per-proses |
| `linux.malfind` | `windows.malfind` | Region memory mencurigakan (permission RWX, tanpa backing file) — targetnya format **ELF**, bukan PE |
| `linux.elfs` | `windows.dlllist` | Shared library (`.so`) yang di-load tiap proses — padanan konsep DLL di Linux |
| `linux.lsmod` | `windows.modules` | Kernel module yang ter-load (linked list resmi) |
| `linux.check_modules` | `windows.driverscan` | Bandingkan `lsmod` vs struktur module di memory langsung — deteksi **hidden kernel module** (rootkit LKM klasik) |
| `linux.check_syscall` | `windows.ssdt` | Bandingkan syscall table dengan alamat fungsi resminya — deteksi syscall hooking |
| `linux.bash` | *(tidak ada padanan langsung di Windows)* | Lihat §7.10.3 |

```bash
vol -f linux_ram.lime linux.pslist
vol -f linux_ram.lime linux.pstree
vol -f linux_ram.lime linux.bash
```

#### 7.10.3 Artefak Khas Linux

Beberapa artefak yang **tidak punya padanan di Windows** (atau nilainya jauh lebih tinggi di Linux) dan layak jadi prioritas pencarian:

| Artefak | Plugin | Kenapa Berharga |
|---|---|---|
| **Bash history dari memory** | `linux.bash` | Membaca history langsung dari struktur memory proses `bash` yang masih berjalan — termasuk command yang **belum sempat ter-flush** ke `~/.bash_history` di disk (mis. sesi yang belum logout, atau attacker yang set `HISTFILE=/dev/null` untuk menghindari logging ke disk sama sekali). Ini salah satu artefak memory Linux paling bernilai karena sering jadi satu-satunya jejak command attacker |
| **Hidden kernel module (LKM rootkit)** | `linux.check_modules` / `linux.hidden_modules` | Rootkit klasik Linux berbasis Loadable Kernel Module (LKM) sering di-unlink dari `/proc/modules` — polanya identik dengan konsep unlinked process di Windows (§7.4.1), tapi levelnya di kernel module |
| **SSH key / kredensial di memory proses** | `linux.lsof` (cari file descriptor mengarah ke `id_rsa`/`known_hosts`) atau `linux.malfind` pada proses `sshd`/`ssh-agent` | File descriptor yang masih terbuka ke private key menunjukkan proses mana yang sedang memakainya, berguna kalau file aslinya sudah dihapus/di-shred dari disk |
| **Environment variable proses** | `linux.envars` | Setara `windows.envars` (§7.4.5) — kadang menyimpan path/kredensial yang diteruskan lewat variable, termasuk variable yang sengaja dipakai attacker untuk menghindari command line logging (`auditd`) |
| **Namespace & cgroup info** | `linux.pslist` (kolom PID namespace) | Relevan untuk investigasi **container escape** — proses yang PID namespace-nya beda dari proses induk host adalah indikasi proses tersebut berjalan di dalam container terisolasi |

> ⚠️ **Perbedaan mendasar dengan analisis Windows:** Linux tidak punya Registry (Bab 3) dan tidak punya konsep PE header untuk `malfind` (targetnya format ELF) — jadi sebagian besar teknik §7.6 (registry-based) **tidak berlaku** di Linux. Sebagai gantinya, config persistence di Linux dicari lewat cara lain: entry cron (`/etc/cron.d`, `/var/spool/cron`), systemd unit file, atau `/etc/rc.local` — yang kalau masih ter-cache di memory bisa ditemukan lewat `linux.lsof`/carving manual (§7.9) pada proses `cron`/`systemd`, tapi analisis persistence penuh tetap ranah Bab 8/9.

#### 7.10.4 Format Akuisisi Linux (LiME)

**LiME** (Linux Memory Extractor) adalah tool akuisisi RAM standar untuk Linux — beda dari tool Windows (§7.2.1) yang berupa executable siap pakai, LiME adalah **kernel module** yang harus **di-compile khusus** untuk kernel target persis (alasan yang sama dengan kebutuhan symbol table di §7.10.1).

```bash
# Di mesin target: compile LiME terhadap header kernel yang sedang berjalan
git clone https://github.com/504ensicsLabs/LiME.git
cd LiME/src
make    # menghasilkan lime-<versi_kernel>.ko, harus dikompile di/untuk kernel yang identik

# Load module untuk melakukan akuisisi
insmod lime.ko "path=/mnt/evidence/ram_dump.lime format=lime"

# Setelah akuisisi selesai, unload module
rmmod lime
```

| Format Output LiME | Karakteristik |
|---|---|
| `raw` | Dump mentah tanpa metadata, mirip `.raw` Windows — perlu tahu base address/layout memory secara eksternal |
| `padded` | Seperti raw, tapi gap memory diisi padding supaya offset tetap konsisten dengan physical address aslinya |
| `lime` | Format khusus LiME dengan **header metadata per-segment** (mencatat range address tiap chunk memory yang di-dump) — format inilah yang paling umum dipakai karena Volatility bisa langsung membaca strukturnya tanpa perlu tahu layout memory manual |

> ⚠️ **Kendala khas akuisisi Linux (beda dari Windows):** LiME **harus** dikompile terhadap kernel header yang **persis sama** dengan kernel yang sedang berjalan di mesin target (`uname -r` harus cocok exact) — tidak ada versi "universal binary" seperti WinPmem/DumpIt di Windows. Ini sering jadi kendala praktis: kalau mesin target tidak punya kernel header ter-install (umum di server production yang di-strip minimal), compile LiME harus dilakukan di mesin lain dengan kernel identik dulu, baru modul hasil compile-nya dipindahkan ke target.

> 💡 **Alternatif tanpa LiME:** `/proc/kcore` adalah representasi RAM yang di-expose kernel sebagai pseudo-file ELF — bisa langsung di-`cp`/`dd` tanpa compile module tambahan, tapi kurang reliable untuk RAM berukuran besar dan beberapa distro membatasi aksesnya lewat kernel hardening (`/proc/sys/kernel/kptr_restrict` dkk). LiME tetap jadi standar de-facto untuk akuisisi Linux yang butuh chain-of-custody terpercaya.

> 💡 **Cross-reference akuisisi:** Sama seperti Windows (§7.2.4), hash hasil dump LiME **segera setelah akuisisi** — prinsip validasi integritas dan Order of Volatility (§7.1.2) berlaku identik terlepas dari OS target.

---

### 7.11 Korelasi Artefak (Tabel Cepat)

Mengikuti pola bab-bab sebelumnya (Bab 2 §2.3, Bab 3 §3.10-style, dst) — tabel ringkas "temuan X di memory → field/tool apa di bab lain untuk verifikasi silang", bukan metodologi rekonstruksi timeline penuh (itu Bab 9).

| Temuan di Memory | Plugin/Bagian | Verifikasi/Lengkapi di | Bagian |
|---|---|---|---|
| Proses mencurigakan terdeteksi | `pslist`/`psscan` (§7.4.1) | Prefetch (bukti eksekusi) | Bab 4 §4.13 |
| Proses mencurigakan terdeteksi | `pslist`/`psscan` (§7.4.1) | Amcache (bukti eksekusi & hash file) | Bab 3 §3.8 |
| Command line lengkap proses | `cmdline` (§7.4.2) | PowerShell Script Block Logging | Bab 4 §4.5 |
| Command line lengkap proses | `cmdline` (§7.4.2) | EVTX 4688 / Sysmon Event ID 1 | Bab 4 |
| Koneksi jaringan aktif | `netscan` (§7.4.3) | Sysmon Event ID 3 — Network Connection | Bab 4 §4.6 |
| Region memory RWX + PE header (`malfind`) | §7.7.1 | Prefetch/Amcache untuk proses induk yang melakukan injection | Bab 3 §3.8, Bab 4 §4.13 |
| DLL unlinked dari PEB (`ldrmodules`) | §7.7.2 | Bandingkan path DLL dengan lokasi file di $MFT | Bab 2 |
| Registry key dibaca dari memory (`printkey`) | §7.6.1 | Bandingkan dengan hive `SYSTEM`/`SOFTWARE` di disk (kalau masih bisa diakses) | Bab 3 |
| File recovered dari cache memory (`dumpfiles`) | §7.6.2 | Cross-check apakah file sama masih/pernah ada di $MFT | Bab 2 |
| Hash NTLM/LSA secret dari `lsass.exe` | §7.6.4 | Bandingkan dengan hasil ekstraksi offline dari hive `SAM`/`SECURITY` | Bab 3 §3.5 |
| Proses persisten via Run key/service | Cross-check dari `printkey`/`hivelist` | Registry Run key, Services, Scheduled Task | Bab 3 |
| Aktivitas terakhir proses sebelum shutdown/crash | MEMORY.DMP/hiberfil.sys (§7.2.3) | Event Log shutdown terkait (EVTX 6006/6008) | Bab 4 |

> 💡 Tabel ini **bukan** pengganti timeline penuh — tujuannya cuma penunjuk cepat "kalau nemu A di memory, cek B di bab mana untuk konfirmasi silang". Penyatuan seluruh temuan jadi satu timeline kronologis lintas-sumber adalah pembahasan Bab 9.

---

### 7.12 Peta Cepat: Pertanyaan Investigasi → Plugin

Sebelum masuk ke cheat sheet lengkap per-tool (§7.13), ini peta cepat versi "aku butuh jawab pertanyaan X, plugin mana yang harus dijalankan" — berguna sebagai starting point pertama saat baru mulai investigasi dan belum tahu mau mulai dari mana:

| Pertanyaan Investigasi | Plugin (Windows) | Plugin (Linux) |
|---|---|---|
| Proses apa saja yang berjalan? | `windows.pslist` / `windows.psscan` (§7.4.1) | `linux.pslist` (§7.10.2) |
| Relasi parent-child proses? | `windows.pstree` (§7.4.1) | `linux.pstree` (§7.10.2) |
| Command line lengkap proses? | `windows.cmdline` (§7.4.2) | `linux.psaux` (§7.10.2) |
| Koneksi jaringan aktif? | `windows.netscan` (§7.4.3) | `linux.sockstat`/`linux.netstat` (§7.10.2) |
| DLL/shared library yang dimuat? | `windows.dlllist`, `windows.ldrmodules` (§7.5.2) | `linux.elfs` (§7.10.2) |
| Indikasi memory injection? | `windows.malfind` (§7.7.1) | `linux.malfind` (§7.10.2) |
| Isi registry key dari RAM? | `windows.registry.printkey` (§7.6.1) | *(tidak berlaku — Linux tidak punya Registry)* |
| SID/privilege proses (login/user context)? | `windows.getsids` (§7.4.5) | `linux.pslist` (kolom UID/namespace, §7.10.3) |
| Environment variable proses? | `windows.envars` (§7.4.5) | `linux.envars` (§7.10.3) |
| File handle terbuka (termasuk yang sudah dihapus)? | `windows.handles` (§7.5.1) | `linux.lsof` (§7.10.2) |
| Named pipe (C2/RAT channel)? | `windows.handles` filter `NamedPipe`, `windows.filescan` (§7.5.3) | *(jarang relevan — Linux umumnya pakai Unix domain socket, dicari lewat `linux.lsof`/`linux.sockstat`)* |
| Mutex (single-instance lock malware)? | `windows.handles` filter `Mutant` (§7.5.4) | *(konsep setara: file lock/lock socket, dicari lewat `linux.lsof`)* |
| Driver/kernel module mencurigakan? | `windows.driverscan`, `windows.modules` (§7.4.4) | `linux.lsmod`, `linux.check_modules` (§7.10.2) |
| Bash/command history yang belum ter-flush ke disk? | *(tidak berlaku)* | `linux.bash` (§7.10.3) |
| Scan dengan YARA rule? | `windows.yarascan` (§7.4.5) | `linux.yarascan` |

> 💡 Tabel ini murni **titik masuk cepat** — begitu satu plugin menunjukkan anomali, langkah lanjutannya tetap mengikuti alur cross-check yang sudah dibahas di tiap subbab (mis. `pslist` vs `psscan` untuk proses hidden, `dlllist` vs `ldrmodules` untuk DLL hidden) dan Korelasi Artefak di §7.11 untuk verifikasi silang ke bab lain.

---

### 7.13 Ringkasan Command & Tools Cheat Sheet

| Artefak | Tool | Command/Catatan |
|---|---|---|
| Akuisisi RAM live | **WinPmem** / **DumpIt** | `winpmem_mini_x64.exe output.raw` (§7.2.1) |
| Konversi hiberfil.sys | **hibr2bin** / Volatility 3 langsung | `vol -f hiberfil.sys windows.info` (§7.2.3) |
| Info dasar image | Volatility 3 | `vol -f image.raw windows.info` |
| Daftar proses (resmi vs scan) | Volatility 3 | `windows.pslist`, `windows.psscan` (§7.4.1) |
| Command line proses | Volatility 3 | `windows.cmdline` (§7.4.2) |
| Koneksi jaringan | Volatility 3 | `windows.netscan` (§7.4.3) |
| Driver/module kernel | Volatility 3 | `windows.driverscan`, `windows.modules` (§7.4.4) |
| SID, environment variable, service, YARA scan | Volatility 3 | `windows.getsids`, `windows.envars`, `windows.svcscan`, `windows.yarascan` (§7.4.5) |
| Handle proses (file, registry key, dll) | Volatility 3 | `windows.handles --pid <PID>` (§7.5.1) |
| DLL loaded/hidden/unlinked | Volatility 3 | `windows.dlllist`, `windows.ldrmodules`, `windows.vadinfo` (§7.5.2) |
| Named pipe (C2/RAT channel) | Volatility 3 | `windows.handles` filter `NamedPipe`, `windows.filescan` (§7.5.3) |
| Mutex (single-instance lock) | Volatility 3 | `windows.handles` filter `Mutant` (§7.5.4) |
| Registry dari memory | Volatility 3 | `windows.registry.hivelist`, `.printkey` (§7.6.1) |
| Recovery file dari cache memory | Volatility 3 | `windows.filescan`, `.dumpfiles` (§7.6.2) |
| Hash/kredensial dari LSASS | Volatility 3 | `windows.hashdump`, `.lsadump`, `.cachedump` (§7.6.4) |
| Kunci BitLocker/VeraCrypt di RAM | Plugin komunitas / **Elcomsoft Forensic Disk Decryptor** | (§7.6.5) |
| Deteksi injected code | Volatility 3 | `windows.malfind` (§7.7.1) |
| DLL unlinked | Volatility 3 | `windows.ldrmodules` (§7.7.2) |
| Process hollowing | Plugin komunitas `hollowfind` / manual VAD vs disk | (§7.7.3) |
| Ekspor proses ke disk | Volatility 3 | `windows.procdump --pid <PID>` (§7.7.4) |
| Clipboard/console/text editor | Volatility 3 | `windows.clipboard`, `windows.memmap --dump` (§7.7.5) |
| Eksplorasi interaktif | **MemProcFS** | `MemProcFS.exe -device image.raw -mount M:` (§7.8) |
| String/carving manual | `strings`, **bstrings**, **bulk_extractor** | (§7.9) |
| Symbol table Linux | `dwarf2json` | `dwarf2json linux --elf vmlinux-<versi> > symbol.json` (§7.10.1) |
| Proses/DLL/handle Linux | Volatility 3 | `linux.pslist`, `linux.elfs`, `linux.lsof` (§7.10.2) |
| Bash history dari memory Linux | Volatility 3 | `linux.bash` (§7.10.3) |
| Hidden kernel module Linux (rootkit LKM) | Volatility 3 | `linux.lsmod`, `linux.check_modules` (§7.10.2) |
| Akuisisi RAM Linux | **LiME** | `insmod lime.ko "path=ram.lime format=lime"` (§7.10.4) |

---

### 7.14 Mini Case Study — End-to-End: Disk + Registry + Memory

Skenario: *"Sistem korban ditemukan dalam keadaan menyala, dicurigai ada proses mencurigakan yang aktif dan berkomunikasi keluar jaringan. Investigator sempat melakukan live RAM capture sebelum mematikan sistem untuk disk imaging."*

```
Langkah 1 — Identifikasi proses mencurigakan dari memory
   └── windows.pslist + windows.psscan (§7.4.1) → bandingkan hasil keduanya
       → ditemukan PID 4321 (svchost.exe) muncul di psscan tapi TIDAK di pslist
         → indikasi proses di-unlink dari daftar aktif resmi

Langkah 2 — Verifikasi anomali di level struktur memory
   └── windows.malfind (§7.7.1) pada PID 4321 → ditemukan region RWX dengan
       PE header tanpa backing file yang jelas
   └── windows.ldrmodules (§7.7.2) → ada DLL yang muncul di VAD tapi tidak di PEB
       → dua indikasi terpisah saling menguatkan: proses ini anomali secara struktural

Langkah 3 — Trace balik ke bukti eksekusi di disk
   └── Amcache (Bab 3 §3.8) → cross-check hash file svchost.exe yang sebenarnya
       vs hash proses PID 4321 (lewat procdump, §7.7.4) → tidak cocok, indikasi
       proses ini BUKAN svchost.exe asli meski namanya sama (pola process hollowing,
       lihat §7.7.3 — analisis apakah ini benar hollowing tetap ranah Bab 8)
   └── Prefetch (Bab 4 §4.13) → cek apakah ada entry Prefetch untuk file mencurigakan
       yang jadi induk proses ini, dan RunCount/waktu eksekusi terakhir

Langkah 4 — Cross-check persistence di Registry
   └── windows.registry.printkey (§7.6.1) pada key Run → ditemukan entry yang
       mengarah ke path file mencurigakan
   └── Bandingkan dengan hive SOFTWARE di disk image (Bab 3) → entry yang sama
       terkonfirmasi ada di kedua sumber (memory & disk), menguatkan temuan

Langkah 5 — Cross-check komunikasi jaringan
   └── windows.netscan (§7.4.3) pada PID 4321 → ditemukan koneksi ESTABLISHED
       ke IP eksternal pada port tidak umum
   └── Cross-check Sysmon Event ID 3 (Bab 4 §4.6) → koneksi yang sama tercatat,
       dengan timestamp kapan koneksi pertama dibuka

Kesimpulan yang bisa ditulis di laporan:
"Proses dengan PID 4321 mengklaim diri sebagai svchost.exe namun terverifikasi ANOMALI
secara struktural: tidak muncul di pslist (indikasi unlinked dari daftar proses aktif),
memiliki region memory RWX dengan PE header tanpa backing file (malfind), dan DLL yang
unlinked dari PEB (ldrmodules). Hash file hasil procdump TIDAK COCOK dengan hash svchost.exe
resmi yang tercatat di Amcache, mengindikasikan proses ini bukan svchost.exe asli meski
menyamar dengan nama yang sama. Proses ini PERSISTEN via Registry Run key, dengan entry yang
terkonfirmasi ada baik di memory maupun di hive SOFTWARE pada disk image. Proses ini juga
tercatat melakukan KOMUNIKASI ke IP eksternal pada port tidak umum, terverifikasi silang
antara netscan (state koneksi saat snapshot) dan Sysmon Event ID 3 (histori pembukaan
koneksi)."
```

> ⚠️ **Batas berhenti case study ini:** Kesimpulan di atas sengaja berhenti di titik *"proses X terverifikasi berjalan (anomali struktural), persisten via Y (Registry Run key), komunikasi ke Z (IP eksternal)"* — **tanpa** menyimpulkan jenis/keluarga malware apa ini (Bab 8) dan **tanpa** menyusun timeline kronologis penuh yang menggabungkan urutan detik-per-detik seluruh kejadian dari awal infeksi sampai investigasi (Bab 9). Tiga temuan lintas-sumber (memory, registry, jaringan) di atas sudah cukup kuat sebagai bukti forensik, tapi analisis lanjutan atas ketiganya adalah pembahasan bab-bab berikutnya.

> 💡 **Prinsip umum:** Memory forensics paling kuat bukan saat berdiri sendiri, melainkan saat **anomali di memory dipakai sebagai titik masuk**, lalu ditelusuri balik ke artefak disk/registry/EVTX yang sudah dibahas di Bab 1–6 untuk verifikasi silang. Satu sumber saja (mis. cuma `malfind` tanpa cross-check Amcache/Prefetch/Registry) jauh lebih lemah sebagai bukti dibanding kombinasi lintas-sumber yang saling menguatkan seperti pada case study di atas.

---
