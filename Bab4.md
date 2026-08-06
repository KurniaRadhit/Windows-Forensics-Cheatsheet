## 📌 Daftar Isi — Bab 4

- [Bab 4 — EVTX & Event ID Forensics (Windows Event Log)](#bab-4--evtx--event-id-forensics-windows-event-log)
  - [4.1 Struktur & Konsep Dasar Event Log](#41-struktur--konsep-dasar-event-log)
    - [4.1.1 Apa itu EVTX & Evolusi dari EVT](#411-apa-itu-evtx--evolusi-dari-evt)
    - [4.1.2 Struktur Biner EVTX (Header, Chunk, Record)](#412-struktur-biner-evtx-header-chunk-record)
    - [4.1.3 Anatomi Sebuah Event Record](#413-anatomi-sebuah-event-record)
    - [4.1.4 Channel vs Provider vs Log](#414-channel-vs-provider-vs-log)
    - [4.1.5 Retensi Log — Wrap/Overwrite & Max Size](#415-retensi-log--wrapoverwrite--max-size)
  - [4.2 Lokasi File EVTX](#42-lokasi-file-evtx)
    - [4.2.1 Lokasi Utama (System32\\winevt\\Logs)](#421-lokasi-utama-system32winevtlogs)
    - [4.2.2 Log Utama vs Operational Logs](#422-log-utama-vs-operational-logs)
    - [4.2.3 Log yang Sering Dilupakan tapi Krusial](#423-log-yang-sering-dilupakan-tapi-krusial)
  - [4.3 Security.evtx — Log Autentikasi & Akses](#43-securityevtx--log-autentikasi--akses)
    - [4.3.1 4624 / 4625 — Logon Success/Failure & Logon Type](#431-4624--4625--logon-successfailure--logon-type)
    - [4.3.2 4634 / 4647 — Logoff](#432-4634--4647--logoff)
    - [4.3.3 4672 — Special Privileges Assigned](#433-4672--special-privileges-assigned)
    - [4.3.4 4688 — Process Creation](#434-4688--process-creation)
    - [4.3.5 Manajemen Akun User (4720/4722/4724/4725/4726)](#435-manajemen-akun-user-4720472247244725726)
    - [4.3.6 Manajemen Group Membership (4728/4732/4756)](#436-manajemen-group-membership-472847324756)
    - [4.3.7 Kerberos — 4768/4769/4770/4771](#437-kerberos--4768476947704771)
    - [4.3.8 4776 — NTLM Authentication](#438-4776--ntlm-authentication)
    - [4.3.9 Scheduled Task (4698/4699/4700/4701/4702)](#439-scheduled-task-4698469947004701702)
    - [4.3.10 5140/5145 — Network Share Access](#4310-51405145--network-share-access)
    - [4.3.11 1102 — Audit Log Cleared](#4311-1102--audit-log-cleared)
  - [4.4 System.evtx — Log Sistem & Service](#44-systemevtx--log-sistem--service)
    - [4.4.1 7045 / 7034 / 7036 — Service Installed/Crashed/State Change](#441-7045--7034--7036--service-installedcrashedstate-change)
    - [4.4.2 6005/6006/6008/6013 — Startup/Shutdown](#442-6005600660086013--startupshutdown)
    - [4.4.3 41 — Kernel-Power (Unexpected Reboot)](#443-41--kernel-power-unexpected-reboot)
    - [4.4.4 104 — Log File Cleared (System)](#444-104--log-file-cleared-system)
  - [4.5 PowerShell Logs — Operational & Analytic](#45-powershell-logs--operational--analytic)
    - [4.5.1 400/403 — Engine State](#451-400403--engine-state)
    - [4.5.2 4103 — Module Logging](#452-4103--module-logging)
    - [4.5.3 4104 — Script Block Logging](#453-4104--script-block-logging)
    - [4.5.4 800 — Pipeline Execution Detail](#454-800--pipeline-execution-detail)
  - [4.6 Sysmon — Visibilitas Tambahan](#46-sysmon--visibilitas-tambahan)
    - [4.6.1 Event ID 1 — Process Create](#461-event-id-1--process-create)
    - [4.6.2 Event ID 3 — Network Connection](#462-event-id-3--network-connection)
    - [4.6.3 Event ID 7 — Image Loaded](#463-event-id-7--image-loaded)
    - [4.6.4 Event ID 8 & 10 — CreateRemoteThread & ProcessAccess](#464-event-id-8--10--createremotethread--processaccess)
    - [4.6.5 Event ID 11 & 23 — FileCreate & FileDelete](#465-event-id-11--23--filecreate--filedelete)
    - [4.6.6 Event ID 12/13/14 — Registry Event](#466-event-id-121314--registry-event)
    - [4.6.7 Event ID 22 — DNS Query](#467-event-id-22--dns-query)
  - [4.7 Log Lain yang Relevan](#47-log-lain-yang-relevan)
    - [4.7.1 RDP — TerminalServices Logs](#471-rdp--terminalservices-logs)
    - [4.7.2 WMI-Activity Operational](#472-wmi-activity-operational)
    - [4.7.3 TaskScheduler Operational](#473-taskscheduler-operational)
    - [4.7.4 Windows Defender Operational](#474-windows-defender-operational)
  - [4.8 Timestamp & TimeZone di EVTX](#48-timestamp--timezone-di-evtx)
  - [4.9 Anti-Forensic: Log Dihapus/Dimatikan](#49-anti-forensic-log-dihapusdimatikan)
  - [4.10 Tools & Cara Analisa EVTX](#410-tools--cara-analisa-evtx)
  - [4.11 Tabel Korelasi Cepat — Event ID Penting](#411-tabel-korelasi-cepat--event-id-penting)
  - [4.12 Mini Case Study — Rekonstruksi Lateral Movement dari EVTX](#412-mini-case-study--rekonstruksi-lateral-movement-dari-evtx)

*(Bab 1: Struktur Drive & Direktori — `bab1.md`. Bab 2: File Sistem NTFS & $MFT — `bab2.md`. Bab 3: Windows Registry Forensics — `bab3.md`. Bab 5 dan seterusnya menyusul.)*

---

## Bab 4 — EVTX & Event ID Forensics (Windows Event Log)

Kalau registry (Bab 3) jawab "apa yang *ada*/*pernah dijalankan*", Event Log jawab "**apa yang *terjadi*, kapan, dan oleh siapa**" — dengan urutan waktu yang jelas. Di CTF/HTB Sherlock, EVTX biasanya jadi sumber utama buat bikin **timeline serangan** karena satu Event ID sering langsung mengonfirmasi satu tahap kill chain (initial access → privilege escalation → lateral movement → persistence → cleanup).

### 4.1 Struktur & Konsep Dasar Event Log

#### 4.1.1 Apa itu EVTX & Evolusi dari EVT

- **EVT** — format lama (Windows XP/2003 ke bawah), biner sederhana, tidak pakai XML.
- **EVTX** — format sejak Windows Vista/2008, berbasis **binary XML**, dipakai sampai Windows 11/Server 2025 saat ini.
- Setiap event record di EVTX pada dasarnya adalah **fragmen XML terkompresi biner** yang mengikuti skema tertentu per provider.

#### 4.1.2 Struktur Biner EVTX (Header, Chunk, Record)

```
[File EVTX]
├── File Header (4KB)         ← Signature "ElfFile\x00", chunk count, versi
├── Chunk #1 (64KB)            ← Header chunk + kumpulan Event Record
│     ├── Event Record #1      ← Signature "\x2a\x2a\x00\x00" + size + Record Number + Timestamp + Binary XML
│     ├── Event Record #2
│     └── ... dst
├── Chunk #2 (64KB)
└── ... dst (file bisa berisi ratusan chunk)
```

| Bagian | Isi |
|---|---|
| **File Header** | Signature, jumlah chunk, oldest/current chunk number |
| **Chunk** | Blok 64KB berisi banyak event record + template XML cache |
| **Event Record** | Satu entri log: Record Number (sequential, unik per file), Timestamp (FILETIME UTC), payload Binary XML |

> 💡 **Kenapa penting:** Karena tiap chunk 64KB **self-contained** dengan template XML sendiri, tool forensik (mis. `evtx_dump`) bisa **carving** record dari file EVTX yang corrupt/partial — bahkan dari *unallocated space* kalau file sudah dihapus tapi belum tertimpa.

#### 4.1.3 Anatomi Sebuah Event Record

```xml
<Event>
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
    <EventID>4624</EventID>
    <Version>2</Version>
    <Level>0</Level>                 ← 0=LogAlways,1=Critical,2=Error,3=Warning,4=Info,5=Verbose
    <Task>12544</Task>
    <Keywords>0x8020000000000000</Keywords>
    <TimeCreated SystemTime="2025-01-10T08:15:30.123Z"/>
    <EventRecordID>184920</EventRecordID>
    <Channel>Security</Channel>
    <Computer>WORKSTATION01</Computer>
    <Security UserID="S-1-5-18"/>
  </System>
  <EventData>
    <Data Name="TargetUserName">jdoe</Data>
    <Data Name="LogonType">3</Data>
    <Data Name="IpAddress">10.10.10.5</Data>
    ... field spesifik per Event ID
  </EventData>
</Event>
```

| Field | Kegunaan Forensik |
|---|---|
| **Provider** | Sumber log (mis. `Microsoft-Windows-Security-Auditing`, `Microsoft-Windows-Sysmon`) |
| **EventID** | Kode jenis kejadian — kunci utama pencarian |
| **TimeCreated** | Timestamp **UTC** (paling reliable dibanding timestamp registry) |
| **EventRecordID** | Nomor urut record dalam file — **gap** di sini indikasi kuat record dihapus/log rusak |
| **Channel** | Nama log (Security, System, Application, atau operational log spesifik) |
| **EventData** | Field detail spesifik tiap Event ID (username, IP, command line, dll) |

#### 4.1.4 Channel vs Provider vs Log

| Istilah | Pengertian |
|---|---|
| **Provider** | Komponen/service yang *menghasilkan* event (mis. Sysmon, LSA, Kernel-Power) |
| **Channel** | "Kategori tujuan" tempat event ditulis (mis. `Security`, `Microsoft-Windows-Sysmon/Operational`) |
| **Log file (.evtx)** | File fisik di disk — biasanya 1 channel = 1 file `.evtx`, tapi 1 provider bisa nulis ke banyak channel |

#### 4.1.5 Retensi Log — Wrap/Overwrite & Max Size

- Default: log bersifat **circular buffer** — begitu ukuran max tercapai, event **terlama otomatis tertimpa** (overwrite).
- Ukuran default sering kecil (mis. Security 20MB) → di sistem yang aktif/audit tinggi, retensi bisa **cuma beberapa hari**.
- Implikasi forensik: **selalu cek dulu rentang waktu (oldest timestamp) yang tersedia** sebelum menyimpulkan "tidak ada event X" — bisa jadi sudah ter-overwrite, bukan tidak pernah terjadi.

```
# Cek retensi & ukuran log (live system)
wevtutil gl Security
```

---

### 4.2 Lokasi File EVTX

#### 4.2.1 Lokasi Utama (System32\winevt\Logs)

```
C:\Windows\System32\winevt\Logs\
├── Security.evtx
├── System.evtx
├── Application.evtx
├── Windows PowerShell.evtx
├── Microsoft-Windows-PowerShell%4Operational.evtx
├── Microsoft-Windows-Sysmon%4Operational.evtx        (kalau Sysmon ter-install)
├── Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx
├── Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx
├── Microsoft-Windows-TaskScheduler%4Operational.evtx
├── Microsoft-Windows-WMI-Activity%4Operational.evtx
└── ... ratusan log operational lain per komponen
```

#### 4.2.2 Log Utama vs Operational Logs

| Jenis | Karakteristik |
|---|---|
| **Log Utama (Classic)** | `Security`, `System`, `Application` — selalu ada, enabled by default, retensi diatur manual |
| **Operational Logs** | Per-komponen (`%4Operational.evtx`), sering **disabled by default**, harus di-*enable* manual/via GPO sebelum kejadian — kalau belum aktif saat insiden, datanya **tidak ada** |
| **Analytic/Debug Logs** | Level paling detail, defaultnya hidden & disabled, dipakai buat debugging developer — jarang relevan DFIR kecuali sudah diaktifkan |

#### 4.2.3 Log yang Sering Dilupakan tapi Krusial

| Log | Kenapa Penting |
|---|---|
| `Microsoft-Windows-PowerShell%4Operational.evtx` | Script Block Logging (4104) — sering satu-satunya bukti isi payload PowerShell |
| `Microsoft-Windows-TaskScheduler%4Operational.evtx` | Detail scheduled task lebih lengkap dari Security log |
| `Microsoft-Windows-TerminalServices-*%4Operational.evtx` | Bukti RDP masuk/keluar lebih detail dari 4624 LogonType 10 |
| `Microsoft-Windows-WMI-Activity%4Operational.evtx` | Deteksi lateral movement via WMI (`wmic`, Impacket `wmiexec`) |
| `Microsoft-Windows-Windows Defender%4Operational.evtx` | Deteksi/blokir malware — sering jadi bukti awal insiden meski AV gagal cegah |
| `Microsoft-Windows-Sysmon%4Operational.evtx` | Kalau ter-install, **paling kaya** — command line, hash, network connection, registry, dll |

---

### 4.3 Security.evtx — Log Autentikasi & Akses

#### 4.3.1 4624 / 4625 — Logon Success/Failure & Logon Type

Event paling sering dicari di DFIR — konfirmasi **siapa login, dari mana, dan bagaimana caranya**.

| Field Penting | Keterangan |
|---|---|
| `TargetUserName` | Username yang login |
| `IpAddress` | Sumber koneksi (kosong/`-` kalau logon lokal) |
| `LogonType` | Cara login — lihat tabel di bawah |
| `SubjectUserName` vs `TargetUserName` | Subject = akun yang *melakukan* logon call, Target = akun yang *login* |

| LogonType | Arti |
|---|---|
| **2** | Interactive — login langsung di keyboard/console |
| **3** | Network — mis. akses share (`\\host\share`), umum di lateral movement |
| **4** | Batch — scheduled task |
| **5** | Service — service start dengan kredensial |
| **7** | Unlock — sesi yang di-*unlock* |
| **8** | NetworkCleartext — auth dengan password plaintext lewat network |
| **9** | NewCredentials — `runas /netonly` |
| **10** | RemoteInteractive — **RDP** |
| **11** | CachedInteractive — login pakai cached credential (offline domain) |

> 💡 4625 (failed logon) punya field `FailureReason`/`Status`/`Sub Status` — kombinasi banyak 4625 beruntun dari IP sama = indikasi **brute force**.

#### 4.3.2 4634 / 4647 — Logoff

- **4634** — Logoff (bisa oleh sistem, tidak selalu inisiatif user).
- **4647** — User initiated logoff (user klik logout secara sadar).
- Dipasangkan dengan 4624 untuk hitung **durasi sesi**.

#### 4.3.3 4672 — Special Privileges Assigned

Muncul bersamaan dengan 4624 kalau akun yang login punya privilege administratif (mis. `SeDebugPrivilege`). Kombinasi **4624 LogonType 3 + 4672** dari IP asing = sinyal kuat **akun admin dipakai untuk lateral movement**.

#### 4.3.4 4688 — Process Creation

Setara "Prefetch tapi live & real-time" — butuh **Audit Process Creation** + **"Include command line in process creation events"** diaktifkan (GPO) supaya `CommandLine` field terisi.

| Field | Isi |
|---|---|
| `NewProcessName` | Path lengkap executable |
| `CommandLine` | Command line penuh (kalau policy diaktifkan) — sangat krusial |
| `ParentProcessName` | Proses induk — buat rekonstruksi **process tree** |
| `SubjectUserName` | User yang menjalankan |

> 💡 Tanpa policy command-line auditing aktif, 4688 tetap catat proses apa dijalankan (existence + parent-child), tapi **tidak** catat argumen — jadi cek dulu apakah field `CommandLine` kosong sebelum menyimpulkan tidak ada payload berbahaya.

#### 4.3.5 Manajemen Akun User (4720/4722/4724/4725/4726)

| Event ID | Arti |
|---|---|
| **4720** | User account created |
| **4722** | User account enabled |
| **4724** | Password reset attempt |
| **4725** | User account disabled |
| **4726** | User account deleted |

Sering muncul di skenario **persistence via backdoor account** — attacker bikin user baru lalu tambahkan ke grup admin.

#### 4.3.6 Manajemen Group Membership (4728/4732/4756)

| Event ID | Arti |
|---|---|
| **4728** | Member added to **global** security group |
| **4732** | Member added to **local** security group (mis. Administrators) |
| **4756** | Member added to **universal** security group |

> 💡 **4732 dengan `Group Name = Administrators`** adalah salah satu event **privilege escalation** paling langsung dicari di CTF.

#### 4.3.7 Kerberos — 4768/4769/4770/4771

| Event ID | Arti | Relevansi Serangan |
|---|---|---|
| **4768** | TGT (Ticket Granting Ticket) requested | Baseline aktivitas Kerberos normal; volume tinggi ke satu akun = indikasi **AS-REP Roasting** kalau `Pre-Authentication Type` absen |
| **4769** | Service Ticket (TGS) requested | Volume tinggi dari satu user ke banyak SPN dalam waktu singkat = indikasi **Kerberoasting** |
| **4770** | Service ticket renewed | Umumnya normal |
| **4771** | Pre-authentication failed | Bisa indikasi password spraying via Kerberos |

#### 4.3.8 4776 — NTLM Authentication

Muncul saat autentikasi pakai NTLM (bukan Kerberos) — sering jadi indikator **pass-the-hash** kalau muncul di konteks yang seharusnya pakai Kerberos (mis. dalam domain).

#### 4.3.9 Scheduled Task (4698/4699/4700/4701/4702)

| Event ID | Arti |
|---|---|
| **4698** | Scheduled task created |
| **4699** | Scheduled task deleted |
| **4700** | Scheduled task enabled |
| **4701** | Scheduled task disabled |
| **4702** | Scheduled task updated |

`4698` menyimpan **XML task definition lengkap** di `EventData` — termasuk `Command`/`Arguments` yang dijalankan, sangat berguna untuk rekonstruksi payload persistence.

#### 4.3.10 5140/5145 — Network Share Access

| Event ID | Arti |
|---|---|
| **5140** | Network share accessed (nama share yang diakses) |
| **5145** | Detailed file share access check — termasuk **nama file** yang diakses di dalam share |

Berguna untuk bukti **file exfiltration** lewat SMB atau eksekusi payload dari share network.

#### 4.3.11 1102 — Audit Log Cleared

**Salah satu event paling penting di semua Security.evtx** — muncul saat seseorang menjalankan `wevtutil cl Security` atau klik "Clear Log" di Event Viewer. Event 1102 **selalu tercatat** karena ditulis *setelah* proses clear selesai — attacker tidak bisa menghapus jejak clear-nya sendiri lewat cara ini. Field `SubjectUserName` menunjukkan siapa yang melakukan clear.

---

### 4.4 System.evtx — Log Sistem & Service

#### 4.4.1 7045 / 7034 / 7036 — Service Installed/Crashed/State Change

| Event ID | Arti |
|---|---|
| **7045** | **Service baru diinstall** — field `Service Name`, `Image Path`, `Service Type`, `Start Type`. Sangat sering dipakai attacker untuk **persistence** (install service yang menjalankan payload). |
| **7034** | Service crashed/berhenti tidak normal |
| **7036** | Service berubah state (started/stopped) — volume tinggi, biasanya untuk konfirmasi kapan service tertentu aktif |

#### 4.4.2 6005/6006/6008/6013 — Startup/Shutdown

| Event ID | Arti |
|---|---|
| **6005** | Event Log service started (≈ sistem baru boot) |
| **6006** | Event Log service stopped (≈ shutdown normal) |
| **6008** | **Unexpected shutdown** (sebelumnya tidak ada 6006 — sistem mati paksa/crash) |
| **6013** | Uptime sistem sejak boot terakhir (dalam detik) |

#### 4.4.3 41 — Kernel-Power (Unexpected Reboot)

Provider `Microsoft-Windows-Kernel-Power`, Event ID **41** — sistem restart tanpa proses shutdown bersih (mati listrik, crash, atau **dipaksa attacker** untuk hilangkan jejak proses di memory).

#### 4.4.4 104 — Log File Cleared (System)

Sama konsepnya dengan **1102** di Security log, tapi untuk log `System`/log lain secara umum — dicatat oleh provider `Microsoft-Windows-Eventlog` setiap kali sebuah `.evtx` di-clear.

---

### 4.5 PowerShell Logs — Operational & Analytic

PowerShell adalah tool favorit attacker untuk **living-off-the-land** — lognya krusial karena sering satu-satunya cara lihat **isi script/command** yang dijalankan.

#### 4.5.1 400/403 — Engine State

Dari `Windows PowerShell.evtx` (log klasik). **400** = engine state jadi "Available" (sesi PowerShell dimulai), **403** = engine state jadi "Stopped" (sesi selesai). Cuma catat *bahwa* PowerShell dijalankan, bukan isi command.

#### 4.5.2 4103 — Module Logging

Dari `Microsoft-Windows-PowerShell%4Operational.evtx`. Mencatat detail eksekusi cmdlet & parameter yang dipakai — perlu **Module Logging** policy aktif.

#### 4.5.3 4104 — Script Block Logging

**Event paling krusial di kategori PowerShell.** Mencatat **isi penuh script block** yang dieksekusi, termasuk script yang di-*deobfuscate* otomatis oleh PowerShell engine sebelum dijalankan — jadi tetap tertangkap meski attacker pakai base64/obfuscation di command line aslinya. Kalau script panjang, terpecah jadi beberapa event dengan `MessageNumber`/`MessageTotal` yang harus digabung urut.

#### 4.5.4 800 — Pipeline Execution Detail

Mencatat command line pipeline yang dijalankan beserta hasil ringkas — pelengkap 4103/4104.

---

### 4.6 Sysmon — Visibilitas Tambahan

Sysmon (System Monitor) **bukan bawaan Windows** — harus diinstall manual (Sysinternals). Kalau ada di image, biasanya jadi **sumber data terkaya** karena field jauh lebih lengkap dari Security log native (full command line, hash file, parent-child process, network connection per proses, dll).

#### 4.6.1 Event ID 1 — Process Create

Setara 4688 tapi jauh lebih lengkap: `Hashes` (SHA1/MD5/SHA256/IMPHASH), `ParentCommandLine`, `CurrentDirectory`, `IntegrityLevel`, `User`.

#### 4.6.2 Event ID 3 — Network Connection

Koneksi TCP/UDP keluar per proses — `SourceIp`, `DestinationIp`, `DestinationPort`, `Image` (proses yang bikin koneksi). Kunci utama identifikasi **C2 traffic** & port yang dipakai.

#### 4.6.3 Event ID 7 — Image Loaded

DLL/module yang di-*load* ke proses — berguna deteksi **DLL sideloading/injection**, terutama kalau DLL tidak signed atau load dari path mencurigakan.

#### 4.6.4 Event ID 8 & 10 — CreateRemoteThread & ProcessAccess

| Event ID | Arti |
|---|---|
| **8** | CreateRemoteThread — indikasi kuat **process injection** (satu proses membuat thread di proses lain) |
| **10** | ProcessAccess — satu proses membuka handle ke proses lain (mis. `lsass.exe` diakses untuk **credential dumping**) |

#### 4.6.5 Event ID 11 & 23 — FileCreate & FileDelete

**11** = file baru dibuat (berguna tangkap *dropped payload*), **23** = file dihapus (butuh konfigurasi `FileDeleteLogged`) — berguna tangkap upaya **anti-forensic self-cleanup** attacker.

#### 4.6.6 Event ID 12/13/14 — Registry Event

**12** = key created/deleted, **13** = value set, **14** = key/value renamed — versi *real-time* dari analisa registry statis di Bab 3, berguna untuk pin-point **kapan tepatnya** sebuah key persistence dibuat.

#### 4.6.7 Event ID 22 — DNS Query

Mencatat query DNS per proses — `QueryName`, `QueryResults`, `Image`. Kunci identifikasi **domain C2** bahkan sebelum koneksi network (Event ID 3) terjadi.

---

### 4.7 Log Lain yang Relevan

#### 4.7.1 RDP — TerminalServices Logs

| Log / Event ID | Arti |
|---|---|
| `TerminalServices-RemoteConnectionManager%4Operational` — **1149** | Koneksi RDP berhasil (network-level), field `Param1` = username, `Param3` = source IP |
| `TerminalServices-LocalSessionManager%4Operational` — **21** | Session logon berhasil (session-level) |
| `TerminalServices-LocalSessionManager%4Operational` — **23** | Session logoff |
| `TerminalServices-LocalSessionManager%4Operational` — **24/25** | Session disconnect/reconnect |

> 💡 Kombinasikan dengan **4624 LogonType 10** di Security.evtx untuk konfirmasi silang RDP dari beberapa sudut pandang log yang berbeda.

#### 4.7.2 WMI-Activity Operational

Mencatat eksekusi via WMI — relevan untuk deteksi tool lateral movement seperti Impacket `wmiexec.py` atau `wmic process call create`. Event `5857/5860/5861` menunjukkan WMI provider dijalankan/consumer WMI (dipakai attacker untuk **WMI event subscription persistence**).

#### 4.7.3 TaskScheduler Operational

Log lebih lengkap dari Security 4698 — mencatat siklus hidup task (register, start, complete, action executed) dengan detail path task dan action.

#### 4.7.4 Windows Defender Operational

| Event ID | Arti |
|---|---|
| **1116** | Malware/threat terdeteksi |
| **1117** | Aksi terhadap threat berhasil dilakukan (quarantine/remove) |
| **5001/5010/5012** | Real-time protection / scan dimatikan (indikasi attacker **menonaktifkan AV**) |

---

### 4.8 Timestamp & TimeZone di EVTX

- Timestamp `TimeCreated SystemTime` di EVTX **selalu UTC**, tidak seperti sebagian artefak filesystem yang tergantung timezone lokal.
- **Selalu cross-check** dengan `TimeZoneInformation` dari SYSTEM hive (Bab 3, 3.3.4) supaya konversi ke waktu lokal korban akurat saat menyusun laporan/timeline.
- Kalau menggabungkan EVTX dengan Prefetch/$MFT (yang juga UTC di NTFS) dan RegistryLastWrite (lokal sistem, tapi disimpan sbg FILETIME UTC juga) — semuanya bisa disatukan di satu timeline UTC tanpa konversi manual per artefak.

---

### 4.9 Anti-Forensic: Log Dihapus/Dimatikan

| Indikator | Artinya |
|---|---|
| **Event 1102** (Security) / **104** (log lain) | Log di-*clear* secara eksplisit lewat `wevtutil cl` atau Event Viewer |
| **Gap besar di `EventRecordID`** | Record hilang — bisa karena overwrite alami (wrap) **atau** dihapus manual dari file mentah |
| **Service "Windows Event Log" dihentikan** (Event 6005 tidak diikuti restart wajar, atau service dimatikan lewat `sc stop eventlog`) | Attacker menonaktifkan logging sebelum beraksi — cek celah waktu tanpa event sama sekali |
| **File `.evtx` hilang/ukurannya jauh lebih kecil dari biasanya** | Kemungkinan file diganti/ditimpa manual |

**EVTX Recovery/Carving** — kalau file `.evtx` sudah dihapus dari filesystem tapi belum tertimpa, record individual masih bisa di-*carve* dari `$MFT`/unallocated space karena tiap Event Record punya signature sendiri (`2a 2a 00 00`). Tools seperti `bulk_extractor` atau modul carving di Eric Zimmerman/`python-evtx` bisa merekonstruksi record lepas ini walau struktur chunk-nya sudah tidak utuh.

---

### 4.10 Tools & Cara Analisa EVTX

| Tool | Fungsi | Contoh Command |
|---|---|---|
| **Event Viewer** (live system) | GUI bawaan Windows, filter dasar per Event ID | `eventvwr.msc` |
| **EvtxECmd.exe** (Eric Zimmerman) | Parser CLI utama — convert EVTX ke CSV/JSON dengan maps (field sudah di-*translate* human-readable) | `.\EvtxECmd.exe -f Security.evtx --csv output\ --csvf sec.csv` |
| **Timeline Explorer** | Buka hasil CSV EvtxECmd, filter/sort/pivot cepat, gabung banyak file jadi satu timeline | Drag-drop file CSV |
| **wevtutil** (live system, CLI) | Query/export log langsung dari command line | `wevtutil qe Security /q:"*[System[(EventID=4624)]]" /f:text` |
| **python-evtx** | Library Python parsing EVTX manual/scripting, berguna untuk carving/automasi custom | `evtx_dump.py Security.evtx > out.xml` |
| **Chainsaw** (WithSecure/countercept) | CLI cepat untuk hunting Event ID mencurigakan pakai Sigma rules bawaan | `chainsaw hunt evidence\ -s sigma_rules\ --mapping mapping.yml` |
| **Hayabusa** | Alternatif hunting tool berbasis Sigma, output timeline HTML/CSV siap pakai, sangat populer di CTF/DFIR kompetisi | `hayabusa csv-timeline -d evidence\ -o timeline.csv` |
| **DeepBlueCLI** | PowerShell script, deteksi pola serangan umum dari Security/PowerShell log | `.\DeepBlue.ps1 -log security` |

**Workflow umum offline analysis (image mati):**
```bash
# 1. Export semua .evtx dari image via FTK Imager, terutama:
#    Security, System, Application, Windows PowerShell,
#    *PowerShell%4Operational, *Sysmon%4Operational (kalau ada),
#    *TerminalServices-*%4Operational, *TaskScheduler%4Operational

# 2. Parsing massal semua EVTX sekaligus (satu folder) ke CSV terstandar
.\EvtxECmd.exe -d "C:\evidence\Logs" --csv output\ --csvf all_events.csv

# 3. Hunting cepat pakai Sigma rules untuk temukan anomali tanpa baca manual satu-satu
hayabusa csv-timeline -d "C:\evidence\Logs" -o hunt_timeline.csv

# 4. Buka all_events.csv & hunt_timeline.csv di Timeline Explorer
#    Filter per Event ID penting (4624/4688/7045/4104/1102 dll), sort by TimeCreated

# 5. Gabungkan dengan timeline Prefetch/$MFT (Bab 1-2) & Registry (Bab 3)
#    untuk timeline korelasi lintas-artefak
```

---

### 4.11 Tabel Korelasi Cepat — Event ID Penting

| Pertanyaan Umum CTF | Log | Event ID |
|---|---|---|
| Siapa login, kapan, dari mana, via cara apa? | Security | **4624 / 4625** (**4.3.1**) |
| Apakah ini RDP? | Security + TerminalServices | **4624 (LogonType 10)** + **1149/21** (**4.3.1**, **4.7.1**) |
| Command line apa yang dijalankan proses ini? | Security / Sysmon | **4688** (**4.3.4**) / **Sysmon 1** (**4.6.1**) |
| Isi lengkap script PowerShell yang dijalankan? | PowerShell Operational | **4104** (**4.5.3**) |
| Apakah attacker bikin service untuk persistence? | System | **7045** (**4.4.1**) |
| Apakah attacker bikin scheduled task? | Security / TaskScheduler | **4698** (**4.3.9**) |
| Apakah attacker bikin user/akun backdoor? | Security | **4720** (**4.3.5**) |
| Apakah attacker naikkan privilege ke Administrators? | Security | **4732** (**4.3.6**) |
| Indikasi Kerberoasting / AS-REP Roasting? | Security | **4769 / 4768** (**4.3.7**) |
| Apakah ada koneksi keluar mencurigakan (C2)? | Sysmon | **Event ID 3** (**4.6.2**) |
| Domain apa yang di-query proses ini? | Sysmon | **Event ID 22** (**4.6.7**) |
| Apakah ada indikasi credential dumping (lsass)? | Sysmon | **Event ID 10** (**4.6.4**) |
| Apakah ada process injection? | Sysmon | **Event ID 8** (**4.6.4**) |
| File apa yang diakses/diambil dari network share? | Security | **5145** (**4.3.10**) |
| Apakah attacker menghapus jejak log? | Security / semua log | **1102** / **104** (**4.3.11**, **4.4.4**) |
| Apakah sistem di-restart paksa buat hilangkan jejak? | System | **41 (Kernel-Power)** (**4.4.3**) |
| Apakah AV dimatikan sebelum serangan? | Defender Operational | **5001/5010/5012** (**4.7.4**) |
| Apakah ada lateral movement lewat WMI? | WMI-Activity Operational | **5857/5860/5861** (**4.7.2**) |

---

### 4.12 Mini Case Study — Rekonstruksi Lateral Movement dari EVTX

Skenario: *"Buktikan attacker melakukan lateral movement dari Host A ke Host B lewat RDP, menjalankan PowerShell payload, lalu bikin persistence, dan berusaha hapus jejak."*

```
Langkah 1 — Konfirmasi initial logon di Host B
   └── Security.evtx → 4624 LogonType 10 (4.3.1) → catat SubjectUserName, IpAddress asal (Host A)
   └── TerminalServices-LocalSessionManager%4Operational → Event 21 (4.7.1) → konfirmasi session RDP terbentuk

Langkah 2 — Cek privilege yang didapat attacker
   └── Security.evtx → 4672 (4.3.3) muncul bareng 4624 → konfirmasi akun punya privilege admin

Langkah 3 — Cari eksekusi payload PowerShell
   └── Microsoft-Windows-PowerShell%4Operational → 4104 (4.5.3) → dapatkan isi script block penuh
   └── Security.evtx → 4688 (4.3.4) → cross-check CommandLine & ParentProcessName (powershell.exe dari mana?)
   └── Sysmon Event ID 1 (4.6.1, kalau ada) → hash file payload + full command line lebih lengkap

Langkah 4 — Cek koneksi keluar dari payload (C2 / staging)
   └── Sysmon Event ID 22 (4.6.7) → domain yang di-resolve
   └── Sysmon Event ID 3 (4.6.2) → IP:port tujuan koneksi

Langkah 5 — Cek mekanisme persistence yang dipasang
   └── System.evtx → 7045 (4.4.1) → service baru dengan ImagePath mencurigakan
   └── Security.evtx → 4698 (4.3.9) → scheduled task baru, cek Command/Arguments di XML

Langkah 6 — Cek upaya anti-forensic
   └── Security.evtx → 1102 (4.3.11) → apakah attacker clear log sebelum keluar?
   └── System.evtx → 104 (4.4.4) → apakah log lain juga di-clear?
   └── Kalau 1102/104 ditemukan tapi EventRecordID sesudahnya masih berurutan rapi →
       konfirmasi log memang di-clear di titik waktu tersebut, bukan sekadar wrap alami

Kesimpulan yang bisa ditulis di laporan:
"Attacker login ke Host B dari Host A via RDP pada waktu X (4624 LogonType 10 + Event 21 RDP),
menggunakan akun dengan privilege admin (4672). Sesi tersebut menjalankan PowerShell dengan
script block Y (4104) yang melakukan koneksi ke domain C2 Z (Sysmon 22 + 3). Attacker kemudian
memasang service W sebagai mekanisme persistence (7045). Sebelum sesi berakhir, attacker
menjalankan wevtutil untuk clear Security log (1102), namun aktivitas ini sendiri tercatat
sehingga tetap dapat direkonstruksi."
```

> 💡 **Prinsip umum:** EVTX paling kuat saat **dikorelasikan lintas log** (Security + Sysmon + PowerShell + System) dan lintas bab (Prefetch/$MFT dari Bab 1-2, Registry dari Bab 3) — satu log tunggal jarang cukup untuk membuktikan keseluruhan kill chain, tapi kombinasinya membentuk timeline yang sulit dibantah.

---
