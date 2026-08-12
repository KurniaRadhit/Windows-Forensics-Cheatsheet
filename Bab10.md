## 📌 Daftar Isi — Bab 10

- [Bab 10 — Active Directory & Enterprise Windows Forensics](#bab-10--active-directory--enterprise-windows-forensics)
  - [10.1 Konsep Dasar Active Directory & Domain Environment](#101-konsep-dasar-active-directory--domain-environment)
    - [10.1.1 Domain, Forest, OU, Domain Controller — Peta Konsep Singkat](#1011-domain-forest-ou-domain-controller--peta-konsep-singkat)
    - [10.1.2 Kenapa Forensik Domain Beda dari Standalone (Bab 1-9)](#1012-kenapa-forensik-domain-beda-dari-standalone-bab-1-9)
    - [10.1.3 Peran Domain Controller vs Member Server/Workstation dalam Investigasi](#1013-peran-domain-controller-vs-member-serverworkstation-dalam-investigasi)
  - [10.2 NTDS.dit — Database Active Directory](#102-ntdsdit--database-active-directory)
    - [10.2.1 Struktur & Lokasi](#1021-struktur--lokasi)
    - [10.2.2 Ekstraksi — ntdsutil, VSS, secretsdump](#1022-ekstraksi--ntdsutil-vss-secretsdump)
    - [10.2.3 Parsing dengan DSInternals / esedbexport](#1023-parsing-dengan-dsinternals--esedbexport)
    - [10.2.4 Objek Kunci — User, Computer, Group, GPO Metadata](#1024-objek-kunci--user-computer-group-gpo-metadata)
  - [10.3 Kerberos Authentication Forensics](#103-kerberos-authentication-forensics)
    - [10.3.1 Alur Kerberos — AS-REQ/REP, TGS-REQ/REP](#1031-alur-kerberos--as-reqrep-tgs-reqrep)
    - [10.3.2 Event ID Autentikasi Domain (4768, 4769, 4770, 4771, 4776)](#1032-event-id-autentikasi-domain-4768-4769-4770-4771-4776)
    - [10.3.3 Deteksi Golden Ticket & Silver Ticket](#1033-deteksi-golden-ticket--silver-ticket)
    - [10.3.4 Deteksi Kerberoasting & AS-REP Roasting](#1034-deteksi-kerberoasting--as-rep-roasting)
    - [10.3.5 Pass-the-Ticket Detection](#1035-pass-the-ticket-detection)
  - [10.4 Credential Dumping & LSASS Forensics](#104-credential-dumping--lsass-forensics)
    - [10.4.1 LSASS Process & Kenapa Jadi Target](#1041-lsass-process--kenapa-jadi-target)
    - [10.4.2 Jejak Mimikatz & Tools Sejenis](#1042-jejak-mimikatz--tools-sejenis)
    - [10.4.3 Deteksi via Sysmon (Process Access ke lsass.exe) & EVTX](#1043-deteksi-via-sysmon-process-access-ke-lsassexe--evtx)
    - [10.4.4 Teknik comsvcs.dll MiniDump & Variasinya](#1044-teknik-comsvcsdll-minidump--variasinya)
  - [10.5 Group Policy Object (GPO) Forensics](#105-group-policy-object-gpo-forensics)
    - [10.5.1 Struktur SYSVOL](#1051-struktur-sysvol)
    - [10.5.2 GPO Abuse untuk Persistence/Lateral Movement](#1052-gpo-abuse-untuk-persistencelateral-movement)
    - [10.5.3 GPP Password (cpassword) — Kelemahan Klasik](#1053-gpp-password-cpassword--kelemahan-klasik)
    - [10.5.4 Event ID Perubahan GPO](#1054-event-id-perubahan-gpo)
  - [10.6 Domain Controller Event Log Deep-Dive](#106-domain-controller-event-log-deep-dive)
    - [10.6.1 Event ID Domain-Specific (di luar cakupan Bab 4)](#1061-event-id-domain-specific-di-luar-cakupan-bab-4)
    - [10.6.2 Replication & Directory Service Events](#1062-replication--directory-service-events)
  - [10.7 Lateral Movement Cross-Host dalam Domain](#107-lateral-movement-cross-host-dalam-domain)
    - [10.7.1 PsExec, WMI, WinRM Artifact per-Host](#1071-psexec-wmi-winrm-artifact-per-host)
    - [10.7.2 Pass-the-Hash Detection](#1072-pass-the-hash-detection)
    - [10.7.3 Korelasi Multi-Host (Extend §9.14.5)](#1073-korelasi-multi-host-extend-914-5)
  - [10.8 Domain Persistence & Privilege Escalation Techniques](#108-domain-persistence--privilege-escalation-techniques)
    - [10.8.1 DCSync](#1081-dcsync)
    - [10.8.2 AdminSDHolder Abuse](#1082-adminsdholder-abuse)
    - [10.8.3 Skeleton Key](#1083-skeleton-key)
    - [10.8.4 ACL Abuse (Relevansi ke BloodHound-Style Attack Path)](#1084-acl-abuse-relevansi-ke-bloodhound-style-attack-path)
  - [10.9 Sysmon & EDR Telemetry — Domain Context](#109-sysmon--edr-telemetry--domain-context)
    - [10.9.1 Konfigurasi Sysmon Relevan untuk Domain Environment](#1091-konfigurasi-sysmon-relevan-untuk-domain-environment)
    - [10.9.2 Korelasi Sysmon + Domain Event Log](#1092-korelasi-sysmon--domain-event-log)
  - [10.10 Master Correlation Matrix — AD Attack Chain vs Artefak](#1010-master-correlation-matrix--ad-attack-chain-vs-artefak)
  - [10.11 Cheat Sheet — Commands & Tools](#1011-cheat-sheet--commands--tools)
  - [10.12 Mini Case Study — Domain Compromise Investigation](#1012-mini-case-study--domain-compromise-investigation)

*(Bab 1: Struktur Drive & Direktori — `bab1.md`. Bab 2: File Sistem NTFS & $MFT — `bab2.md`. Bab 3: Windows Registry Forensics — `bab3.md`. Bab 4: EVTX & Event ID Forensics — `bab4.md`. Bab 5: User Activity Trail — `bab5.md`. Bab 6: Browser Forensics — `bab6.md`. Bab 7: Memory Forensics — `bab7.md`. Bab 8: Malware & Persistence Analysis — `bab8.md`. Bab 9: Timeline Correlation & Anti-Forensics — `bab9.md`.)*

---

## Bab 10 — Active Directory & Enterprise Windows Forensics

> 💡 **Posisi Bab 10 di seri ini:** Bab 1-9 seluruhnya berkonteks **satu mesin standalone** — satu disk, satu registry set, satu Event Log lokal. Bab 10 naik satu level ke **domain environment**, tempat identitas, autentikasi, dan kebijakan sistem dikelola terpusat lewat Active Directory (AD). Ini bukan bab yang menggantikan Bab 1-9 — semua teknik di sana (registry parsing, EVTX analysis, timeline correlation, dst) **tetap dipakai penuh** di sini, hanya targetnya bertambah: Domain Controller (DC) sebagai mesin baru yang perlu dianalisis, dan jenis artefak baru yang cuma ada di konteks domain (NTDS.dit, Kerberos ticket, GPO). Kalau kasusmu selalu standalone/tidak domain-joined, bab ini opsional — tapi kalau sering ketemu skenario HTB Sherlocks/CTF ber-Domain Controller, bab ini pelengkap penting.

### 10.1 Konsep Dasar Active Directory & Domain Environment

#### 10.1.1 Domain, Forest, OU, Domain Controller — Peta Konsep Singkat

**Pengertian & Fungsi:**
Sebelum masuk ke artefak teknis, perlu paham dulu hierarki logis AD — karena hampir semua istilah di bab ini (GPO, OU, trust) merujuk ke struktur ini.

```
Forest                              ← batas keamanan tertinggi, kumpulan 1+ domain yang saling trust
 │
 └── Domain (mis. corp.local)       ← unit administrasi utama, punya namespace DNS sendiri
      │
      ├── Domain Controller (DC)     ← server yang menyimpan & mereplikasi database AD (NTDS.dit)
      │
      ├── Organizational Unit (OU)   ← "folder" logis untuk mengelompokkan user/computer/group
      │    ├── OU=Finance
      │    ├── OU=IT
      │    └── OU=Servers
      │
      ├── User Objects                ← akun user domain
      ├── Computer Objects             ← akun mesin (workstation/server) yang domain-joined
      ├── Group Objects                ← security group (mis. Domain Admins) & distribution group
      └── Group Policy Object (GPO)    ← kebijakan yang diterapkan ke OU/domain (lihat §10.5)
```

| Istilah | Pengertian | Relevansi Forensik |
|---|---|---|
| **Forest** | Batas keamanan tertinggi; trust antar domain dalam satu forest bersifat otomatis (transitive) | Kalau ada multi-domain forest, kompromi di satu domain berpotensi merembet lewat trust |
| **Domain** | Unit administrasi dengan namespace sendiri, punya minimal 1 DC | Investigasi biasanya scoped per-domain dulu, baru diperluas ke forest kalau ada indikasi cross-domain |
| **Domain Controller (DC)** | Server yang meng-host database AD (`NTDS.dit`) dan melayani autentikasi Kerberos/LDAP | Mesin paling bernilai untuk investigator — kompromi DC = kompromi seluruh domain |
| **OU (Organizational Unit)** | Struktur folder logis untuk penerapan GPO & delegasi administrasi | GPO linked ke OU tertentu — perlu tahu OU untuk tahu kebijakan apa yang berlaku ke user/komputer target |
| **GPO** | Kumpulan kebijakan (registry, script, security setting) yang didorong dari DC ke semua mesin dalam scope-nya | Vektor persistence & lateral movement populer (§10.5.2) |

> 📌 **Kenapa ini penting sebelum lanjut:** Setiap artefak di §10.2-10.9 pada dasarnya menjawab pertanyaan seputar hierarki ini — "user mana", "di OU mana", "GPO apa yang berlaku", "DC mana yang mencatat event ini". Tanpa peta konsep ini, log domain akan terasa seperti kumpulan istilah lepas.

---

#### 10.1.2 Kenapa Forensik Domain Beda dari Standalone (Bab 1-9)

| Aspek | Standalone (Bab 1-9) | Domain Environment (Bab 10) |
|---|---|---|
| Sumber identitas user | Local SAM hive (Bab 3 §3.2) per-mesin | Terpusat di `NTDS.dit` di DC, direplikasi ke semua DC dalam domain |
| Autentikasi | NTLM lokal atau Kerberos terbatas | Kerberos penuh lewat DC (§10.3) — tiket, bukan cuma hash |
| Kebijakan sistem | Local Group Policy per-mesin | GPO terpusat dari DC, berlaku ke banyak mesin sekaligus (§10.5) |
| Event log relevan | Security.evtx per-mesin (Bab 4) | Security.evtx di **DC** (autentikasi domain) DITAMBAH Security.evtx di tiap mesin target (Bab 4 tetap dipakai) |
| Lateral movement | Antar 2 mesin, butuh kredensial lokal/dicuri | Bisa menyebar ke **banyak host sekaligus** karena satu kredensial domain valid di semua mesin domain-joined |
| Cakupan investigasi | Satu image disk | Berpotensi banyak image (DC + beberapa workstation/server) yang harus dikorelasikan (extend §9.14.5) |

> ⚠️ **Kesalahan umum:** Menganggap investigasi domain sama seperti mengalikan investigasi standalone sebanyak jumlah mesin. Kenyataannya, DC menyimpan **satu sumber kebenaran terpusat** (NTDS.dit, Kerberos log) yang justru mempercepat investigasi kalau tahu di mana mencarinya — bukan menambah beban linear per-mesin.

---

#### 10.1.3 Peran Domain Controller vs Member Server/Workstation dalam Investigasi

| Jenis Mesin | Artefak Unik yang Dimiliki | Artefak yang Tetap Sama (Bab 1-9) |
|---|---|---|
| **Domain Controller** | `NTDS.dit` (§10.2), Kerberos KDC log (§10.3.2), SYSVOL/GPO (§10.5), replication event (§10.6.2) | $MFT, Registry, EVTX, Prefetch — semua Bab 1-9 tetap berlaku untuk DC sebagai mesin Windows biasa |
| **Member Server** (mis. file server, app server) | Local SAM (kalau ada local account), service-specific log | Sama seperti standalone, DITAMBAH domain logon event (4624 Type 3 dari user domain) |
| **Workstation domain-joined** | Cache credential (LSA cache), local Kerberos ticket cache | Semua Bab 1-9 penuh berlaku — ini "mesin biasa" yang kebetulan ikut domain |

> 💡 **Prioritas investigasi di kasus domain-based:** Kalau punya akses ke image DC, **mulai dari DC dulu** — NTDS.dit dan Kerberos log di DC sering langsung menjawab "akun mana yang dipakai attacker" dan "kapan/dari mana login terjadi", baru diperdalam ke workstation/server spesifik yang terlibat pakai teknik Bab 1-9 penuh.

---

### 10.2 NTDS.dit — Database Active Directory

#### 10.2.1 Struktur & Lokasi

**Pengertian & Fungsi:**
`NTDS.dit` adalah database inti Active Directory — berformat ESE (Extensible Storage Engine, sama family dengan format yang dipakai Exchange). Berisi **seluruh objek domain**: user (termasuk password hash), computer, group, OU, GPO link, dan atribut Kerberos.

```
%SystemRoot%\NTDS\
├── ntds.dit          ← Database utama (ESE format)
├── edb.log            ← Transaction log (mirip $LogFile di NTFS, Bab 2 §2.4)
├── edb.chk             ← Checkpoint file
└── temp.edb             ← Temporary file saat maintenance
```

| Tabel Internal NTDS.dit | Isi |
|---|---|
| `datatable` | Seluruh objek AD (user, computer, group, dll) dan atributnya |
| `link_table` | Relasi antar objek (mis. keanggotaan group) |
| `sd_table` | Security Descriptor (ACL) per objek |

> ⚠️ **File terkunci saat DC live:** `NTDS.dit` selalu di-lock oleh proses `lsass.exe` selama DC berjalan — tidak bisa di-copy langsung seperti file biasa. Butuh salah satu metode ekstraksi di §10.2.2.

---

#### 10.2.2 Ekstraksi — ntdsutil, VSS, secretsdump

| Metode | Skenario | Command |
|---|---|---|
| **ntdsutil (live/local access ke DC)** | Punya akses admin langsung ke DC (RDP/console) | `ntdsutil "ac i ntds" "ifm" "create full C:\ntds_dump" q q` |
| **VSS/Shadow Copy (image forensik)** | Investigasi image DC offline — file terkunci saat live, tapi snapshot VSS (Bab 5 §5.1) tidak terpengaruh lock | Mount VSS lewat FTK Imager/Arsenal Image Mounter, export `NTDS\ntds.dit` dari dalam snapshot |
| **secretsdump.py (remote, kredensial admin domain)** | Punya kredensial domain admin, DC masih online, butuh ekstrak cepat tanpa akses console | `secretsdump.py -just-dc domain/admin@dc_ip` |
| **DCSync (lihat juga §10.8.1)** | Sama seperti secretsdump — teknik ini pada dasarnya MEMANFAATKAN replication protocol AD | `secretsdump.py -just-dc-ntlm domain/admin@dc_ip` (hanya NTLM hash, tanpa Kerberos key) |

```bash
# Ekstraksi via ntdsutil (perlu privilege administrator di DC)
ntdsutil "ac i ntds" "ifm" "create full C:\ntds_dump" q q

# Ekstraksi via VSS (untuk image offline) — enumerasi snapshot dulu
vssadmin list shadows
# lalu export ntds.dit dari path snapshot yang relevan via FTK Imager
```

> 💡 **Kenapa VSS jadi metode favorit di CTF/DFIR offline:** Kalau soal cuma kasih image disk DC (bukan akses live), `NTDS.dit` di lokasi normal kemungkinan besar tidak bisa dibuka langsung karena kondisi "dirty"/locked saat snapshot diambil. **Shadow copy** (Bab 5 §5.1) sering menyimpan salinan konsisten yang justru lebih mudah diparse — sama prinsipnya dengan VSS untuk file lain yang sudah dibahas Bab 9 §9.9.4.

---

#### 10.2.3 Parsing dengan DSInternals / esedbexport

```powershell
# DSInternals (PowerShell module) — cara paling praktis untuk ekstrak hash & metadata user
Import-Module DSInternals
$key = Get-BootKey -SystemHivePath 'C:\ntds_dump\registry\SYSTEM'
Get-ADDBAccount -All -DBPath 'C:\ntds_dump\Active Directory\ntds.dit' -BootKey $key |
    Select SamAccountName, NTHash, LastLogonDate | Export-Csv accounts.csv
```

```bash
# esedbexport (libesedb) — untuk parsing generik tabel ESE tanpa DSInternals
esedbexport -m tables ntds.dit
# Output: folder ntds.dit.export\ berisi tabel datatable, link_table, sd_table sebagai CSV mentah
```

| Tool | Kelebihan | Kapan Dipakai |
|---|---|---|
| **DSInternals** | Langsung decode hash NTLM/Kerberos key per-user, output rapi | Butuh cepat ekstrak kredensial & metadata akun untuk investigasi |
| **esedbexport** | Generik, bisa baca ESE database apapun (termasuk file Exchange) | Butuh akses raw ke semua tabel, termasuk atribut custom/kurang umum |
| **secretsdump.py (offline mode)** | Bisa jalan langsung dari file `ntds.dit` + `SYSTEM` hive tanpa live access | `secretsdump.py -ntds ntds.dit -system SYSTEM LOCAL` |

> 📖 **Cross-reference SYSTEM hive:** Ekstraksi hash dari NTDS.dit butuh **boot key** yang disimpan di registry hive `SYSTEM` (sama hive yang sudah dibahas cara parsing-nya di Bab 3 §3.9) — tanpa `SYSTEM` hive dari DC yang sama, `ntds.dit` tidak bisa didekripsi.

---

#### 10.2.4 Objek Kunci — User, Computer, Group, GPO Metadata

| Objek | Atribut Forensik Penting | Kegunaan Investigasi |
|---|---|---|
| **User** | `sAMAccountName`, `pwdLastSet`, `lastLogonTimestamp`, `userAccountControl`, `memberOf`, NT hash | Identifikasi akun yang dipakai/dibuat attacker, deteksi akun baru mencurigakan (§10.8) |
| **Computer** | `dNSHostName`, `operatingSystem`, `lastLogonTimestamp` | Daftar semua mesin domain-joined — dipakai untuk scoping investigasi ke host mana saja yang perlu dicek |
| **Group** | `member`, `groupType`, terutama keanggotaan **Domain Admins/Enterprise Admins** | Deteksi privilege escalation — user ditambahkan ke group privileged secara tidak wajar |
| **GPO metadata** | `gPCFileSysPath` (link ke SYSVOL), `versionNumber`, `whenChanged` | Korelasi ke isi GPO fisik di SYSVOL (§10.5.1) dan waktu perubahan terakhir |

> ⚠️ **`userAccountControl` sering diabaikan padahal krusial:** Atribut bitmask ini menyimpan status akun seperti `ACCOUNTDISABLE`, `DONT_REQUIRE_PREAUTH` (indikasi rentan AS-REP Roasting, §10.3.4), dan `DONT_EXPIRE_PASSWORD`. Kombinasi nilai yang tidak wajar (misal akun service dengan `DONT_REQUIRE_PREAUTH` aktif) sering jadi bukti awal celah yang dieksploitasi.

---

### 10.3 Kerberos Authentication Forensics

#### 10.3.1 Alur Kerberos — AS-REQ/REP, TGS-REQ/REP

**Pengertian & Fungsi:**
Kerberos adalah protokol autentikasi utama di domain (menggantikan NTLM untuk sebagian besar skenario). Memahami alurnya secukupnya untuk membaca Event ID di §10.3.2 — bukan detail kriptografi penuh.

```
User Login
   │
   ▼
[1] AS-REQ  → Client kirim request ke KDC (Key Distribution Center, service di DC) minta TGT
   │            (Ticket Granting Ticket), terenkripsi pakai hash password user
   ▼
[2] AS-REP  ← KDC balas dengan TGT (kalau autentikasi awal berhasil) — EVTX 4768 di DC
   │
   ▼
[3] TGS-REQ → Client pakai TGT untuk minta Service Ticket (akses ke resource spesifik,
   │            misal file server) — EVTX 4769 di DC
   ▼
[4] TGS-REP ← KDC balas dengan Service Ticket
   │
   ▼
[5] AP-REQ  → Client kirim Service Ticket ke server target (bukan ke DC lagi) untuk akses resource
```

| Istilah | Pengertian |
|---|---|
| **KDC (Key Distribution Center)** | Service yang berjalan di **setiap DC**, menangani AS-REQ/REP dan TGS-REQ/REP |
| **TGT (Ticket Granting Ticket)** | "Tiket induk" yang membuktikan user sudah login, dipakai untuk minta tiket lain tanpa re-enter password |
| **Service Ticket** | Tiket spesifik untuk satu resource/service, didapat dari TGT |
| **krbtgt account** | Akun khusus yang password hash-nya dipakai KDC untuk sign semua TGT — kompromi akun ini = Golden Ticket (§10.3.3) |

> 💡 **Kenapa Kerberos "lebih aman" secara desain tapi tetap sering diserang:** Karena semua kepercayaan berpusat di satu titik (krbtgt hash & KDC), begitu attacker mendapat akses ke titik itu (lewat DCSync §10.8.1 atau kompromi DC penuh), mereka bisa memalsukan tiket untuk akun manapun — inilah yang mendasari Golden Ticket attack.

---

#### 10.3.2 Event ID Autentikasi Domain (4768, 4769, 4770, 4771, 4776)

Semua event ini tercatat di **Security.evtx milik Domain Controller**, bukan di mesin client — beda lokasi dari EVTX yang sudah dibahas Bab 4 (yang fokus ke mesin individual).

| Event ID | Nama | Makna | Nilai Forensik |
|---|---|---|---|
| **4768** | Kerberos TGT Requested (AS-REQ/REP) | User berhasil/gagal minta TGT — titik awal autentikasi | Timestamp login pertama user ke domain, encryption type (RC4 vs AES — indikasi downgrade attack) |
| **4769** | Kerberos Service Ticket Requested (TGS-REQ/REP) | User minta akses ke service/resource spesifik | Resource apa yang diakses user, kapan — dasar deteksi Kerberoasting (§10.3.4) |
| **4770** | Kerberos Service Ticket Renewed | Tiket diperpanjang tanpa re-autentikasi penuh | Biasanya normal, tapi window renewal panjang tidak wajar bisa jadi indikasi Pass-the-Ticket |
| **4771** | Kerberos Pre-Authentication Failed | Percobaan autentikasi awal gagal (mirip 4625 tapi khusus Kerberos) | Brute force terhadap akun domain, terutama kalau beruntun ke banyak username berbeda (password spraying) |
| **4776** | Domain Controller Attempted to Validate Credentials (NTLM) | Autentikasi NTLM (bukan Kerberos) tervalidasi di DC | Indikasi NTLM masih dipakai (fallback) — sering muncul di skenario Pass-the-Hash |

```powershell
# Contoh filter EVTX DC untuk semua TGT request dari satu user mencurigakan
Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4768]]" |
    Where-Object { $_.Message -match "TargetUserName:\s*attacker_user" }
```

> ⚠️ **Encryption type di 4768/4769 sering luput dicek:** Field `Ticket Encryption Type` bernilai `0x17` (RC4) di lingkungan modern yang seharusnya AES (`0x12`) adalah red flag — bisa indikasi **downgrade attack** untuk mempermudah cracking tiket secara offline (relevan untuk §10.3.4 Kerberoasting, karena RC4 jauh lebih cepat di-crack daripada AES).

---

#### 10.3.3 Deteksi Golden Ticket & Silver Ticket

| Teknik | Cara Kerja | Indikator Deteksi |
|---|---|---|
| **Golden Ticket** | Attacker punya hash akun `krbtgt` (biasanya lewat DCSync, §10.8.1) → bisa forge TGT untuk akun manapun, termasuk yang tidak ada di AD, dengan masa berlaku sembarang | TGT dengan `lifetime` tidak wajar (default policy biasanya 10 jam, Golden Ticket sering di-set jauh lebih lama, mis. 10 tahun); user tercatat login (4624) tapi **TIDAK ADA 4768 yang cocok** sebelumnya di DC — tiket dipalsukan, bukan diminta lewat AS-REQ normal |
| **Silver Ticket** | Attacker punya hash akun **service** (bukan krbtgt) → bisa forge Service Ticket langsung untuk service itu, skip TGT sepenuhnya | Karena Service Ticket dipalsukan langsung, **TIDAK ADA 4769 di DC** yang menyertai akses ke service tsb — service log (di server target) menunjukkan akses valid, tapi DC "tidak tahu" pernah mengeluarkan tiketnya |

> 💡 **Prinsip deteksi umum kedua teknik ini:** Sama seperti anti-forensik di Bab 9 — teknik forge tiket "melewati" proses normal, sehingga selalu ada **kekosongan** di titik yang seharusnya mencatat proses tersebut (mirip prinsip "Absence of Evidence is Evidence", Bab 9 §9.9.1). Golden/Silver Ticket meninggalkan bukti PENGGUNAAN tiket (akses berhasil ke resource), tapi tidak ada bukti PERMINTAAN tiket yang sah di DC.

```powershell
# Cek lifetime tiket tidak wajar di EVTX 4769 (butuh Splunk/EDR untuk field lifetime,
# atau parse manual XML event data)
Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4769]]" |
    Select-Object TimeCreated, @{n='Lifetime';e={($_.Properties[8]).Value}}
```

---

#### 10.3.4 Deteksi Kerberoasting & AS-REP Roasting

| Teknik | Cara Kerja | Indikator di EVTX |
|---|---|---|
| **Kerberoasting** | Attacker minta Service Ticket (4769) untuk akun service (SPN — Service Principal Name) yang sering punya password lemah, lalu crack tiket itu **offline** | Banyak 4769 dari satu user dalam waktu singkat, ke banyak SPN berbeda; encryption type RC4 (§10.3.2) mempercepat cracking |
| **AS-REP Roasting** | Menyasar akun dengan flag `DONT_REQUIRE_PREAUTH` aktif (§10.2.4) — attacker bisa minta AS-REP (4768) **tanpa perlu tahu password**, lalu crack responsnya offline | 4768 untuk akun dengan pre-authentication disabled, sering dari IP/host yang tidak biasa melakukan request semacam ini |

```bash
# Sisi attacker (Impacket) — untuk pemahaman apa yang harus dicari di log, bukan panduan serang
GetUserSPNs.py domain/user:password -dc-ip <dc_ip> -request
GetNPUsers.py domain/ -usersfile users.txt -no-pass -dc-ip <dc_ip>
```

> ⚠️ **Kerberoasting jarang menghasilkan alert AV** karena secara teknis ini **permintaan tiket yang sah** menurut protokol — bedanya cuma pola volume (banyak SPN diminta sekaligus oleh satu user dalam waktu singkat) yang tidak wajar dibanding pola pemakaian normal. Deteksi realistis butuh baseline "berapa banyak TGS-REQ normal per-user per-hari" untuk bisa spot anomali.

---

#### 10.3.5 Pass-the-Ticket Detection

**Pengertian & Fungsi:**
Attacker mencuri tiket Kerberos (TGT atau Service Ticket) yang sudah ada di memori mesin korban (lewat LSASS dump, §10.4) lalu **inject** tiket itu ke sesi mereka sendiri di mesin lain — tanpa perlu password sama sekali.

| Indikator | Cek Di |
|---|---|
| Login (4624) dari IP/host yang tidak konsisten dengan lokasi fisik user biasanya | Correlation matrix (§10.10) |
| Tiket dipakai dari 2 mesin berbeda dalam window waktu yang secara fisik tidak masuk akal (mis. New York lalu London dalam 5 menit) | Cross-host correlation, extend §9.14.5 |
| Sysmon Event ID 1 untuk tools seperti `Rubeus.exe`/`Mimikatz` dengan argumen `ptt` (pass-the-ticket) | §10.9 |

---

### 10.4 Credential Dumping & LSASS Forensics

#### 10.4.1 LSASS Process & Kenapa Jadi Target

**Pengertian & Fungsi:**
`lsass.exe` (Local Security Authority Subsystem Service) adalah proses yang **menyimpan kredensial di memori** — termasuk NTLM hash dan Kerberos ticket/key milik semua user yang pernah login di mesin tsb (termasuk domain admin kalau pernah RDP ke mesin itu). Ini menjadikannya target nomor satu untuk credential dumping di lingkungan domain.

> ⚠️ **Kenapa satu workstation bisa jadi titik kompromi seluruh domain:** Kalau seorang Domain Admin pernah login (RDP/console) ke satu workstation biasa yang kemudian dikompromikan, kredensial mereka **tertinggal di memori LSASS mesin itu** sampai reboot/logoff. Attacker yang berhasil dump LSASS di workstation "kecil" ini bisa mendapat kredensial setara admin domain penuh — prinsip ini mendasari kenapa §10.4 relevan bahkan untuk mesin yang bukan DC.

---

#### 10.4.2 Jejak Mimikatz & Tools Sejenis

| Tool | Teknik | Jejak yang Tersisa |
|---|---|---|
| **Mimikatz** (`sekurlsa::logonpasswords`) | Baca memori LSASS langsung via API debug privilege | Prefetch/Amcache untuk `mimikatz.exe` (Bab 3 §3.8, Bab 4 §4.13); Sysmon 10 (ProcessAccess) dengan target `lsass.exe` |
| **procdump.exe (Sysinternals)** | Dump LSASS ke file `.dmp` legit (LOLBin — tool resmi Microsoft disalahgunakan) | `procdump.exe -ma lsass.exe lsass.dmp` — command line tercatat di EVTX 4688/Sysmon 1; file `.dmp` tertinggal di disk kalau tidak dihapus |
| **Task Manager (GUI)** | Klik kanan `lsass.exe` → Create Dump File — cara paling "manual", butuh akses interaktif | File dump tersimpan otomatis di `%LOCALAPPDATA%\Temp\lsass.DMP`, UserAssist mencatat penggunaan Task Manager (Bab 3 §3.6.1) |

```powershell
# Contoh command procdump yang sering dipakai (LOLBin, karena signed Microsoft binary)
procdump.exe -accepteula -ma lsass.exe C:\Windows\Temp\lsass.dmp
```

> 💡 **Ironi klasik yang sama seperti Bab 9 §9.8.1:** LSASS dumping, seaman apapun teknik yang dipakai untuk mengekstrak isinya nanti secara offline, **selalu meninggalkan jejak proses akses ke `lsass.exe`** — baik lewat evidence of execution tool-nya (Prefetch/Amcache) maupun lewat telemetry akses proses (Sysmon 10, §10.4.3).

---

#### 10.4.3 Deteksi via Sysmon (Process Access ke lsass.exe) & EVTX

```
Sysmon Event ID 10 (ProcessAccess) — event paling relevan untuk deteksi LSASS access
├── TargetImage: C:\Windows\System32\lsass.exe
├── SourceImage: proses yang melakukan akses (mimikatz.exe, procdump.exe, dll)
├── GrantedAccess: level akses yang diminta (0x1010 / 0x1438 sering dikaitkan dengan credential dumping)
└── CallTrace: stack trace — bisa menunjukkan DLL yang dipakai untuk akses (mis. dbgcore.dll, dbghelp.dll)
```

| Indikator | Signifikansi |
|---|---|
| `GrantedAccess` dengan kombinasi `PROCESS_VM_READ` + `PROCESS_QUERY_INFORMATION` | Pola akses tipikal untuk membaca memori proses lain — dasar teknik dumping |
| `SourceImage` bukan proses sistem yang biasa mengakses LSASS (mis. bukan `wininit.exe`, `services.exe`) | Proses tidak dikenal mengakses LSASS = kandidat kuat credential dumping |
| Tidak ada Sysmon 10 sama sekali padahal ada indikasi lain LSASS diakses | Sysmon mungkin belum terpasang saat insiden, atau di-disable sengaja — cross-check §10.9 |

> 📖 **Cross-reference Sysmon dasar sudah dibahas Bab 4 §4.6** dan **Bab 8 §8.12.3** (fileless malware) — bagian ini fokus khusus ke Event ID 10 dalam konteks credential theft, bukan mengulang setup Sysmon dari awal.

---

#### 10.4.4 Teknik comsvcs.dll MiniDump & Variasinya

**Pengertian & Fungsi:**
Teknik LOLBin lanjutan yang memanfaatkan fungsi `MiniDump` di dalam `comsvcs.dll` (komponen bawaan Windows) lewat `rundll32.exe`, sehingga **tidak perlu mendownload tool eksternal apapun** (Mimikatz/procdump) — sepenuhnya memakai binary yang sudah ada di sistem.

```bash
# Command yang dipakai attacker (edukasi/deteksi)
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <PID_lsass> C:\Windows\Temp\lsass.dmp full
```

| Indikator Deteksi | Detail |
|---|---|
| EVTX 4688 / Sysmon 1 dengan `CommandLine` mengandung `comsvcs.dll` DAN `MiniDump` | Kombinasi ini sangat spesifik — hampir tidak ada penggunaan legitimate untuk pola command ini |
| `ParentImage` yang tidak wajar untuk `rundll32.exe` (mis. dari `cmd.exe`/`powershell.exe` interaktif, bukan dari proses sistem) | Bab 8 §8.12 (parent-child process anomaly) berlaku sama di sini |
| File `.dmp` tertinggal di path yang dituju (`C:\Windows\Temp\` pada contoh di atas) | Evidence of existence tambahan — cek $MFT Created time file `.dmp` (Bab 2) |

> ⚠️ **Kenapa teknik LOLBin seperti ini lebih sulit dideteksi AV signature-based:** Karena `rundll32.exe` dan `comsvcs.dll` adalah binary Microsoft yang sah dan signed, AV berbasis signature sering tidak flag eksekusinya. Deteksi realistis mengandalkan **command line logging** (EVTX 4688 dengan command line detail diaktifkan, atau Sysmon 1) — bukan reputasi file.

---

### 10.5 Group Policy Object (GPO) Forensics

#### 10.5.1 Struktur SYSVOL

**Pengertian & Fungsi:**
`SYSVOL` adalah share jaringan yang direplikasi ke semua DC, berisi isi fisik dari semua GPO dalam domain — file yang benar-benar didorong (di-push) ke tiap mesin client.

```
\\<domain>\SYSVOL\<domain>\Policies\
└── {GUID-GPO}\                          ← satu folder per GPO, nama = GUID
    ├── GPT.INI                           ← versi GPO, dibandingkan dengan versionNumber di NTDS.dit
    ├── Machine\
    │   ├── Registry.pol                  ← setting registry yang di-push ke HKLM tiap mesin
    │   └── Scripts\Startup\               ← startup script (persistence populer, §10.5.2)
    └── User\
        ├── Registry.pol                  ← setting registry yang di-push ke HKCU
        ├── Scripts\Logon\                 ← logon script
        └── Preferences\Groups\Groups.xml  ← lokasi klasik GPP password (§10.5.3)
```

| Path Fisik | Lokasi | Isi |
|---|---|---|
| Physical location di DC | `%SystemRoot%\SYSVOL\domain\Policies\` | Sumber asli sebelum direplikasi via DFS-R |
| Network share | `\\<domain>\SYSVOL\` | Yang diakses client saat startup/logon untuk apply policy |

> 💡 **Kenapa GPT.INI penting untuk timeline:** Setiap kali GPO diedit, `versionNumber` di `GPT.INI` bertambah — dibandingkan dengan histori replikasi/backup, ini bisa jadi indikator kapan GPO terakhir diubah, dikombinasikan dengan Event ID di §10.5.4 untuk tahu siapa yang mengubahnya.

---

#### 10.5.2 GPO Abuse untuk Persistence/Lateral Movement

| Teknik | Cara Kerja | Deteksi |
|---|---|---|
| **Startup/Logon Script Injection** | Attacker dengan hak edit GPO menambahkan script berbahaya ke `Scripts\Startup\` atau `Scripts\Logon\` — otomatis jalan di SEMUA mesin dalam scope GPO tsb | Bandingkan isi script dengan baseline/backup lama; cek `whenChanged` di metadata GPO (§10.2.4) |
| **Scheduled Task via GPO Preferences** | GPO Preferences bisa mendorong Scheduled Task ke banyak mesin sekaligus — persistence skala domain, extend Bab 8 §8.9 | Task muncul di banyak mesin secara bersamaan (indikasi push terpusat, bukan buat manual satu-satu) |
| **Registry.pol Modification** | Menyuntik key registry persistence (mis. Run key, Bab 8 §8.2) lewat `Registry.pol`, otomatis apply ke semua mesin scope GPO | Parse `Registry.pol` (format binary khusus, bisa pakai `Parse-PolFile` PowerShell) dan bandingkan dengan histori |
| **GPO Linking ke OU Baru** | Attacker link GPO berbahaya ke OU yang berisi banyak workstation/server penting | Cek event 5136 (§10.6.1) untuk perubahan atribut `gPLink` pada OU |

> ⚠️ **Kenapa ini teknik "high value" bagi attacker:** Satu GPO yang berhasil dimodifikasi bisa memberi persistence/eksekusi ke **ratusan mesin sekaligus** tanpa perlu compromise satu-satu — inilah alasan GPO abuse jadi salah satu teknik post-compromise paling berbahaya di lingkungan domain besar.

---

#### 10.5.3 GPP Password (cpassword) — Kelemahan Klasik

**Pengertian & Fungsi:**
Sebelum MS14-025 (patch 2014), Group Policy Preferences (GPP) menyimpan password (misal untuk local account, mapped drive, scheduled task) dalam atribut `cpassword` di file XML — terenkripsi AES, tapi **AES key-nya dipublikasikan Microsoft di dokumentasi** (karena awalnya dianggap cukup untuk "obfuscation" internal domain saja). Hasilnya, siapapun dengan akses baca SYSVOL bisa dekripsi password itu dalam hitungan detik.

```xml
<!-- Contoh isi Groups.xml yang mengandung GPP password -->
<Groups>
  <User clsid="{...}" name="localadmin" ...>
    <Properties cpassword="j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw" .../>
  </User>
</Groups>
```

| Lokasi File | Jenis Kredensial |
|---|---|
| `Groups\Groups.xml` | Local user/group password |
| `Drives\Drives.xml` | Mapped drive credential |
| `ScheduledTasks\ScheduledTasks.xml` | Scheduled task "run as" credential |
| `Services\Services.xml` | Service account credential |

> 📌 **Meski sudah dipatch sejak 2014, kenapa masih relevan di CTF/real-world:** Domain lama yang dibuat sebelum patch atau GPO lama yang tidak pernah dibersihkan masih bisa menyimpan file XML ini di SYSVOL — bahkan setelah patch diterapkan (patch hanya mencegah GPO **baru** dibuat dengan cpassword, tidak otomatis menghapus yang sudah ada). Selalu cek SYSVOL untuk file XML mencurigakan ini sebagai langkah cepat di awal investigasi domain.

---

#### 10.5.4 Event ID Perubahan GPO

| Event ID | Nama | Makna |
|---|---|---|
| **5136** | Directory Service Object Modified | Atribut objek AD berubah — termasuk `gPCFileSysPath`, `versionNumber` GPO, atau `gPLink` di OU |
| **5137** | Directory Service Object Created | Objek AD baru dibuat, termasuk GPO baru |
| **5141** | Directory Service Object Deleted | GPO atau objek AD dihapus — kombinasikan dengan §9.9.1 (absence of evidence) kalau GPO yang dicurigai tiba-tiba hilang |

```powershell
# Filter 5136 khusus perubahan terkait GPO (butuh Advanced Audit Policy - Directory Service Changes aktif di DC)
Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=5136]]" |
    Where-Object { $_.Message -match "groupPolicyContainer" }
```

> ⚠️ **Prasyarat penting:** Event 5136/5137/5141 **tidak muncul secara default** — DC harus punya **Advanced Audit Policy: DS Access → Audit Directory Service Changes** diaktifkan secara eksplisit. Kalau tidak ada event ini sama sekali di DC, cek dulu apakah audit policy-nya memang aktif sebelum menyimpulkan "tidak ada perubahan GPO".

---

### 10.6 Domain Controller Event Log Deep-Dive

#### 10.6.1 Event ID Domain-Specific (di luar cakupan Bab 4)

Bab 4 sudah membahas Event ID umum (4624, 4625, 4688, dst) yang berlaku di **semua mesin Windows**, termasuk DC. Tabel ini fokus ke Event ID yang **cuma relevan/sering muncul di konteks domain**.

| Event ID | Nama | Nilai Forensik |
|---|---|---|
| **4648** | Logon Using Explicit Credentials | User menjalankan proses dengan kredensial berbeda dari sesi login-nya (`runas`, atau lateral movement tool) — sering muncul bersamaan dengan Pass-the-Hash |
| **4672** | Special Privileges Assigned to New Logon | Login dengan privilege administratif (setara Domain Admin) — anchor point yang baik untuk mulai investigasi privilege escalation |
| **4720** | User Account Created | Akun domain baru dibuat — cek apakah dibuat lewat proses admin normal atau muncul tiba-tiba tanpa change request |
| **4728 / 4732** | Member Added to Global/Local Security-Enabled Group | User ditambahkan ke group (terutama kalau group-nya **Domain Admins**) — indikator kuat privilege escalation |
| **4738** | User Account Changed | Atribut akun berubah, termasuk `userAccountControl` (mis. `DONT_REQUIRE_PREAUTH` diaktifkan untuk mempersiapkan AS-REP Roasting, §10.3.4) |
| **4662** | An Operation Was Performed on an Object | Operasi generik terhadap objek AD — relevan khusus untuk deteksi DCSync (butuh GUID spesifik, lihat §10.8.1) |

```powershell
# Cari semua penambahan member ke Domain Admins — salah satu query paling penting di investigasi domain
Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4728 or EventID=4732]]" |
    Where-Object { $_.Message -match "Domain Admins" }
```

> 📌 **Prioritas cepat untuk investigasi domain compromise:** Kalau waktu terbatas, tiga event ID paling bernilai untuk dicek duluan adalah **4672** (siapa yang login dengan privilege tinggi), **4728/4732** (perubahan keanggotaan group privileged), dan **4662** (indikasi DCSync, §10.8.1) — ketiganya sering langsung mengarah ke akun dan waktu kejadian utama.

---

#### 10.6.2 Replication & Directory Service Events

**Pengertian & Fungsi:**
DC saling mereplikasi database AD satu sama lain (multi-master replication) — event terkait replikasi berguna untuk mendeteksi anomali seperti DC rogue/tidak sah, atau untuk memahami propagasi perubahan (termasuk perubahan berbahaya) antar DC dalam domain besar.

| Sumber | Kegunaan |
|---|---|
| `Directory Service` event log (terpisah dari `Security.evtx`, ada di DC) | Event terkait kesehatan AD, replikasi, NTDS database operations |
| `repadmin /showrepl` (live command) | Menampilkan status replikasi antar DC saat ini |
| Event ID 1000-1999 di `Directory Service` log | Berbagai event operasional AD (start/stop service, database maintenance, dll) |

```bash
# Cek status replikasi antar DC (live system)
repadmin /showrepl

# Cek riwayat metadata replikasi objek tertentu — kapan & dari DC mana terakhir diubah
repadmin /showobjmeta <DC_name> "<DistinguishedName_objek>"
```

> 💡 **Kegunaan utama di investigasi:** Kalau domain punya lebih dari satu DC, `repadmin /showobjmeta` bisa menunjukkan **DC mana** yang jadi sumber originating write untuk perubahan objek tertentu (misal penambahan user ke Domain Admins) — berguna untuk mempersempit investigasi ke DC spesifik yang perlu diperiksa lebih dalam kalau kompromi terjadi di salah satu DC saja, bukan seluruhnya.

---

### 10.7 Lateral Movement Cross-Host dalam Domain

#### 10.7.1 PsExec, WMI, WinRM Artifact per-Host

> 📖 **Dasar teknik ini (per satu pasang host) sudah dibahas Bab 9 §9.14.5.** Bagian ini menambahkan konteks khusus domain: kenapa teknik yang sama jadi jauh lebih berbahaya, dan artefak tambahan yang cuma relevan kalau ada domain di belakangnya.

| Teknik | Artefak per-Host (Bab 9 §9.14.5) | Tambahan Konteks Domain |
|---|---|---|
| **PsExec** | Service install EVTX 7045, named pipe artifact | Kredensial yang dipakai untuk PsExec biasanya **kredensial domain**, bukan lokal — bisa dicocokkan ke 4624 Type 3 di semua host target sekaligus, bukan cuma satu |
| **WMI** | EVTX 4688 CommandLine `wmic.exe`/`wmiprvse.exe` | WMI remote execution antar host domain-joined tidak butuh service baru (beda dari PsExec) — lebih "senyap", deteksi bergantung penuh pada Sysmon/command line logging |
| **WinRM/PowerShell Remoting** | Event ID 4103/4104 (Script Block Logging, Bab 4 §4.5.3) | Sesi WinRM antar host domain memakai Kerberos secara default — bisa dikorelasikan ke 4769 di DC (§10.3.2) untuk konfirmasi tiket service `WSMAN` diminta |

---

#### 10.7.2 Pass-the-Hash Detection

**Pengertian & Fungsi:**
Attacker memakai NTLM hash yang dicuri (dari LSASS, §10.4) langsung untuk autentikasi — **tanpa perlu crack password aslinya**. Ini teknik lateral movement klasik yang mendahului banyak insiden domain compromise.

| Indikator | Detail |
|---|---|
| EVTX 4624 Logon Type 3 (network) dengan **NTLM**, bukan Kerberos, padahal lingkungan seharusnya full-Kerberos | Field `Authentication Package` di detail event 4624 |
| 4648 (Explicit Credentials) sesaat sebelum 4624 di host target | Pola umum saat tool Pass-the-Hash (mis. `psexec.py`, `crackmapexec`) dijalankan |
| Logon dari akun yang sama ke **banyak host berbeda** dalam waktu sangat singkat | Pola tidak wajar untuk aktivitas user manusia biasa — lebih cocok pola otomatisasi tool |

> ⚠️ **Kenapa Pass-the-Hash tetap ampuh walau password dirotasi:** Selama NTLM hash lama masih valid (belum ada perubahan password/rotasi), hash yang dicuri bertahun-tahun lalu tetap bisa dipakai. Ini beda dengan Pass-the-Ticket (§10.3.5) yang tiketnya punya masa berlaku terbatas (biasanya jam, bukan tahun).

---

#### 10.7.3 Korelasi Multi-Host (Extend §9.14.5)

Playbook lateral movement di Bab 9 §9.14.5 tetap berlaku penuh sebagai kerangka langkah — tambahan berikut adalah kolom ekstra yang perlu dimasukkan ke tabel multi-host saat konteksnya domain:

```
[ ] 1-8. Ikuti langkah playbook §9.14.5 seperti biasa
[ ] 9. TAMBAHAN: Untuk tiap host yang terlibat, catat juga:
       - Akun DOMAIN apa yang dipakai (bukan cuma nama proses/tool)
       - Apakah ada 4768/4769 di DC yang berkorelasi dengan waktu akses ke host itu
       - Apakah akun tsb anggota group privileged (cross-check NTDS.dit, §10.2.4)
[ ] 10. Bangun tabel: Host | Waktu Compromise | Akun Domain Dipakai | Metode | Privilege Akun
[ ] 11. Cek apakah pola pergerakan mengikuti hierarki privilege (workstation biasa → server →
        DC) — pola ini khas domain compromise klasik menuju Domain Admin/DCSync (§10.8.1)
```

> 💡 **Kenapa kolom "Akun Domain" krusial:** Di investigasi standalone (Bab 9), fokus korelasi ada di nama proses/tool. Di domain, **identitas akun** yang dipakai justru sering jadi thread penghubung paling kuat antar host — satu akun domain yang sama muncul di banyak host dalam waktu berdekatan adalah sinyal lateral movement yang jauh lebih meyakinkan daripada sekadar nama tool yang mirip.

---

### 10.8 Domain Persistence & Privilege Escalation Techniques

#### 10.8.1 DCSync

**Pengertian & Fungsi:**
Teknik yang menyalahgunakan **Directory Replication Service (DRS) Remote Protocol** — protokol resmi yang dipakai DC untuk saling replikasi. Attacker dengan hak replikasi yang cukup (`Replicating Directory Changes` + `Replicating Directory Changes All`) bisa **berpura-pura jadi DC** dan meminta data (termasuk password hash semua user, termasuk krbtgt) langsung dari DC asli — tanpa perlu akses fisik/RDP ke DC sama sekali.

```bash
# Command attacker (Impacket/Mimikatz) — untuk pemahaman pola yang dicari di log
secretsdump.py -just-dc domain/user:password@dc_ip
# atau di Mimikatz: lsadump::dcsync /domain:corp.local /user:krbtgt
```

| Indikator Deteksi | Detail |
|---|---|
| **Event ID 4662** dengan GUID spesifik `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2` (Replicating Directory Changes) dan `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2` (Replicating Directory Changes All) di `Properties` | Ini signature paling definitif — dua GUID ini HANYA relevan untuk operasi replikasi, request dari mesin yang bukan DC sah adalah red flag besar |
| Source computer bukan hostname DC yang sah | DCSync secara teknis bisa dijalankan dari mesin manapun asal akun yang dipakai punya hak replikasi — cek `Account Name` dan `Source Network Address` di event 4662 |

> ⚠️ **Kenapa DCSync jadi salah satu teknik paling berbahaya di seri bab ini:** Sekali berhasil, attacker mendapat **hash krbtgt** — yang berarti mereka bisa forge Golden Ticket (§10.3.3) kapanpun, bahkan setelah akses awal mereka ditutup dan password semua user direset. Satu-satunya remediasi penuh setelah DCSync sukses adalah **reset password krbtgt dua kali berurutan** (bukan sekali) plus rotasi semua kredensial domain.

---

#### 10.8.2 AdminSDHolder Abuse

**Pengertian & Fungsi:**
`AdminSDHolder` adalah objek AD khusus yang ACL-nya secara periodik (default tiap 60 menit lewat proses `SDProp`) **di-copy paksa** ke semua akun/group "protected" (Domain Admins, Enterprise Admins, dll). Attacker yang berhasil memodifikasi ACL `AdminSDHolder` bisa menanamkan **backdoor permission** (mis. `WriteDACL` untuk akun mereka sendiri) yang otomatis ter-apply ulang ke akun privileged manapun tiap 60 menit — bahkan kalau admin membersihkan ACL akun target secara manual.

| Indikator Deteksi | Detail |
|---|---|
| Event 5136 pada objek `CN=AdminSDHolder,CN=System,...` | Perubahan ACL pada objek ini SANGAT jarang terjadi secara legitimate — hampir selalu layak diselidiki |
| ACL pada akun Domain Admins berisi entry aneh yang "muncul lagi" walau sudah dibersihkan | Ciri khas SDProp — kalau sumbernya (AdminSDHolder) tidak dibersihkan, ACL akan ter-restore otomatis |

> 💡 **Kenapa teknik ini "tahan lama":** Berbeda dari kebanyakan persistence yang bisa dibersihkan sekali dan selesai, backdoor di `AdminSDHolder` **memperbaiki dirinya sendiri** tiap jam lewat mekanisme AD bawaan — investigator perlu tahu untuk cek objek ini secara spesifik, bukan cuma akun target yang kelihatan bermasalah.

---

#### 10.8.3 Skeleton Key

**Pengertian & Fungsi:**
Malware yang di-inject ke proses `lsass.exe` di DC, menambahkan **master password universal** yang berfungsi untuk akun MANAPUN — tanpa mengganti password asli user (jadi user tetap bisa login normal dengan password mereka, tidak sadar ada backdoor).

| Indikator Deteksi | Detail |
|---|---|
| Sysmon 10 (ProcessAccess) — proses tidak dikenal mengakses `lsass.exe` **di DC** dengan pola injection | Sama prinsip deteksi dengan §10.4.3, tapi target host-nya DC, bukan workstation biasa |
| Skeleton Key **hilang saat DC reboot** (murni memory-resident, tidak ada persistence disk) | Kalau dicurigai tapi DC sudah pernah reboot sejak insiden, kemungkinan besar tidak akan ditemukan lagi di live memory — cek memory image/dump SEBELUM reboot kalau memungkinkan (Bab 7) |
| Login berhasil dengan password yang jelas bukan password asli user (dilaporkan user sendiri) tapi tidak ada indikasi password reset di NTDS.dit (§10.2.4) | Anomali paling jelas kalau user melapor "saya tidak pernah pakai password itu" |

> ⚠️ **Kenapa memory forensics (Bab 7) jadi krusial untuk teknik ini:** Karena Skeleton Key murni resident di memori LSASS tanpa jejak disk, satu-satunya cara mendeteksinya secara pasti adalah analisis memory dump DC (Bab 7) yang diambil **sebelum** DC di-reboot — begitu reboot, backdoor hilang sepenuhnya tapi begitu juga bukti langsungnya.

---

#### 10.8.4 ACL Abuse (Relevansi ke BloodHound-Style Attack Path)

**Pengertian & Fungsi:**
Selain `AdminSDHolder` (§10.8.2) yang spesifik, AD secara umum punya sistem ACL granular di setiap objek — attacker (atau tool seperti BloodHound dari sisi defender/pentester) memetakan **rantai permission tidak langsung** yang berujung ke privilege tinggi, meski tidak ada satupun langkah individual yang terlihat "berbahaya" sendirian.

```
Contoh attack path (disederhanakan):
User A (compromised, permission rendah)
   │  punya GenericWrite ke...
   ▼
User B (member of "Help Desk" group)
   │  Help Desk group punya ResetPassword ke...
   ▼
User C (member of Domain Admins)
   │  Reset password User C → login sebagai User C
   ▼
Domain Admin access tercapai — TANPA exploit teknis apapun, murni rantai permission AD
```

| Indikator Deteksi | Detail |
|---|---|
| Event 4738 (User Account Changed) — indikasi password di-reset untuk akun privileged, cek siapa yang melakukan | Cross-check dengan siapa yang punya permission `ResetPassword` di ACL akun tsb |
| Event 5136 pada ACL objek (bukan cuma pada `AdminSDHolder`) — perubahan permission granular | Perubahan ACL kecil yang individually terlihat tidak berbahaya, tapi jadi satu link dalam rantai attack path |

> 📌 **Kenapa ini paling sulit dideteksi dari semua teknik di §10.8:** ACL abuse murni memanfaatkan konfigurasi yang **sudah ada secara sah** — tidak ada malware, tidak ada exploit, tidak ada command line mencurigakan. Deteksi realistis butuh pemetaan proaktif attack path (tools seperti BloodHound dari sisi defensif) SEBELUM insiden, karena post-mortem forensics murni dari log sering hanya menemukan "user login normal, reset password normal" tanpa konteks rantai permission yang membuatnya berbahaya.

---

### 10.9 Sysmon & EDR Telemetry — Domain Context

#### 10.9.1 Konfigurasi Sysmon Relevan untuk Domain Environment

> 📖 **Setup dasar Sysmon sudah dibahas Bab 4 §4.6 dan Bab 8 §8.12.3** — bagian ini fokus ke Event ID yang jadi prioritas khusus di lingkungan domain (LSASS access, DC-specific process activity).

| Event ID | Nama | Prioritas di Konteks Domain |
|---|---|---|
| **1** | Process Creation | Sama pentingnya seperti standalone (Bab 8), TAMBAH filter khusus untuk tools domain (mimikatz, secretsdump, dsquery, dll) |
| **3** | Network Connection | Krusial untuk deteksi lateral movement — koneksi ke port Kerberos (88), LDAP (389/636), SMB (445) antar host domain |
| **10** | ProcessAccess | **Prioritas tertinggi** untuk domain — deteksi akses ke `lsass.exe` (§10.4.3) |
| **12/13/14** | Registry Event | Deteksi perubahan `Registry.pol` lokal hasil GPO push (§10.5.2) yang mencurigakan |
| **22** | DNS Query | Deteksi query ke domain internal yang tidak wajar — bisa indikasi enumerasi AD lewat tools seperti `dsquery`/`AdFind` |

```xml
<!-- Contoh potongan Sysmon config untuk prioritas domain (ilustratif, bukan config lengkap) -->
<ProcessAccess onmatch="include">
  <TargetImage condition="end with">lsass.exe</TargetImage>
</ProcessAccess>
<NetworkConnect onmatch="include">
  <DestinationPort condition="is">88</DestinationPort>   <!-- Kerberos -->
  <DestinationPort condition="is">389</DestinationPort>  <!-- LDAP -->
</NetworkConnect>
```

---

#### 10.9.2 Korelasi Sysmon + Domain Event Log

**Pengertian & Fungsi:**
Prinsip dari Bab 9 (kombinasi banyak sumber independen > satu sumber) berlaku penuh di sini — Sysmon di **host individual** dan Security.evtx di **DC** adalah dua sumber yang sepenuhnya independen dan saling menguatkan.

```
Contoh korelasi:
[Host Workstation] Sysmon 1 — mimikatz.exe dijalankan jam 14:05:12
        │
        ▼
[Host Workstation] Sysmon 10 — akses ke lsass.exe jam 14:05:15
        │
        ▼
[DC] EVTX 4768 — TGT baru diminta untuk akun "svc_backup" (akun yang barusan di-dump) jam 14:07:30
        │
        ▼
[DC] EVTX 4769 — TGS diminta untuk resource di Host Server-B jam 14:07:45
        │
        ▼
[Host Server-B] Sysmon 1 / EVTX 4624 Type 3 — login berhasil dengan akun "svc_backup" jam 14:07:50

→ REKONSTRUKSI: LSASS dump di workstation → kredensial svc_backup dicuri → dipakai
  untuk lateral movement ke Server-B, semua dalam window <3 menit
```

> 💡 **Kenapa korelasi lintas-host + DC ini bentuk paling kuat dari prinsip Bab 9:** Empat sumber di atas (Sysmon host A proses, Sysmon host A akses LSASS, EVTX DC autentikasi, EVTX host B login) berasal dari **tiga mesin fisik berbeda** yang sepenuhnya independen satu sama lain. Memalsukan cerita ini secara konsisten di keempat sumber jauh lebih sulit daripada memalsukan satu log di satu mesin — extend langsung dari prinsip inti Bab 9 §9.1.1, hanya skalanya sekarang lintas-host dalam domain.

---

### 10.10 Master Correlation Matrix — AD Attack Chain vs Artefak

> 📖 Mengikuti format Bab 9 §9.11, tabel ini versi khusus domain — dipetakan sepanjang **attack chain khas domain compromise**, dari initial foothold sampai domain dominance.

| Tahap Attack Chain | Teknik Umum | Artefak Primer | Artefak Sekunder | Rujukan |
|---|---|---|---|---|
| Initial Foothold | Phishing/exploit di satu workstation | Sama seperti Bab 8-9 (evidence of execution) | — | Bab 8, 9 |
| Credential Harvesting | LSASS dump (Mimikatz/procdump/comsvcs.dll) | Sysmon 10, Prefetch/Amcache tool dumping | File `.dmp` tertinggal di disk | §10.4 |
| Reconnaissance Domain | `dsquery`/`AdFind`/BloodHound collector | Sysmon 1 (CommandLine), Sysmon 22 (DNS query LDAP) | Volume LDAP query tidak wajar (butuh DC-side logging) | §10.9.1 |
| Kerberoasting/AS-REP Roasting | Request SPN/TGT massal | EVTX 4769/4768 volume tinggi dari satu user | Encryption type RC4 (indikasi downgrade) | §10.3.2, §10.3.4 |
| Lateral Movement | PsExec/WMI/WinRM/Pass-the-Hash | EVTX 4624 Type 3, 4648, Sysmon 1/3 di host target | EVTX 4769 di DC berkorelasi waktu | §10.7 |
| Privilege Escalation | Group membership abuse, ACL abuse | EVTX 4728/4732, 4738 | 5136 pada ACL objek terkait | §10.6.1, §10.8.4 |
| Domain Dominance | DCSync | EVTX 4662 dengan GUID replikasi spesifik | Source computer bukan DC sah | §10.8.1 |
| Persistence Domain-Wide | Golden Ticket, GPO abuse, AdminSDHolder | Tiket tanpa 4768 pendahulu (§10.3.3), 5136 pada AdminSDHolder | GPO version number berubah tanpa change request resmi | §10.3.3, §10.5.2, §10.8.2 |
| Anti-Forensik Domain | Log DC dihapus/dimatikan, reboot DC untuk hapus Skeleton Key | EVTX 1102 di DC (sama seperti Bab 9 §9.9.1) | Directory Service log gap, replikasi metadata hilang | Bab 9 §9.9, §10.8.3 |

> ⚠️ **Cara pakai tabel ini:** Attack chain domain jarang berhenti di satu tahap — investigasi yang baik menelusuri **dari bawah tabel ke atas** (mulai dari indikasi domain dominance yang biasanya paling jelas/mencolok, mundur ke initial foothold) SEKALIGUS **dari atas ke bawah** (dari titik masuk yang diketahui, maju untuk cari dampak) — persis prinsip §9.5.1, hanya sekarang tahapannya lebih banyak dan melibatkan lebih dari satu mesin.

---

### 10.11 Cheat Sheet — Commands & Tools

```bash
# ===== NTDS.dit EXTRACTION =====
ntdsutil "ac i ntds" "ifm" "create full C:\ntds_dump" q q
secretsdump.py -just-dc domain/admin@dc_ip
secretsdump.py -ntds ntds.dit -system SYSTEM LOCAL

# ===== NTDS.dit PARSING =====
esedbexport -m tables ntds.dit
# PowerShell (DSInternals):
# Import-Module DSInternals
# Get-ADDBAccount -All -DBPath ntds.dit -BootKey $key

# ===== KERBEROS EVENT QUERY (jalankan di DC) =====
Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4768]]"
Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4769]]"
Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4771]]"

# ===== PRIVILEGE ESCALATION EVENT QUERY =====
Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4672]]"
Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4728 or EventID=4732]]"

# ===== DCSYNC DETECTION =====
Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4662]]" |
    Where-Object { $_.Message -match "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2" }

# ===== REPLICATION STATUS =====
repadmin /showrepl
repadmin /showobjmeta <DC_name> "<DN_objek>"

# ===== LSASS DUMPING DETECTION (Sysmon) =====
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -FilterXPath "*[System[EventID=10]]" |
    Where-Object { $_.Message -match "lsass.exe" }

# ===== GPP PASSWORD SEARCH (SYSVOL) =====
Get-ChildItem -Path "\\domain\SYSVOL\domain\Policies" -Recurse -Include *.xml |
    Select-String -Pattern "cpassword"
```

---

### 10.12 Mini Case Study — Domain Compromise Investigation

**Skenario:** Sebuah workstation finance (`FIN-WS01`) dilaporkan menunjukkan aktivitas mencurigakan. Investigasi awal ditugaskan cuma untuk workstation itu, tapi menemukan indikasi domain compromise yang lebih luas.

```
[1] Anchor Point — Sysmon 1 di FIN-WS01
    Ditemukan eksekusi procdump.exe dengan argumen "-ma lsass.exe" jam 09:14:22
    CommandLine lengkap tercatat: LOLBin abuse (§10.4.2)

[2] Cross-check Sysmon 10
    ProcessAccess ke lsass.exe dari proses yang sama, GrantedAccess 0x1438 jam 09:14:23
    → konfirmasi credential dumping berhasil, bukan cuma percobaan

[3] Perluas ke DC — cari EVTX 4768/4769 dalam window setelah [2]
    Ditemukan 4768 untuk akun "svc_backup" (bukan user pemilik FIN-WS01) jam 09:16:05
    → indikasi kredensial svc_backup yang di-dump langsung dipakai untuk minta TGT baru

[4] Cek userAccountControl akun svc_backup di NTDS.dit (§10.2.4)
    Ditemukan akun ini anggota grup "Backup Operators" — privilege cukup tinggi
    untuk akses banyak file server, walau bukan Domain Admins

[5] Cek 4769 lanjutan — svc_backup minta Service Ticket ke tiga server berbeda
    dalam rentang 09:16-09:20 (FILE-SRV01, FILE-SRV02, DC01 sendiri)
    → pola lateral movement cepat ke banyak host (§10.7.3)

[6] Cross-check tiap host target — Sysmon/EVTX 4624 Type 3 dengan akun svc_backup
    FILE-SRV01: login berhasil 09:16:30 — akses ke share finance
    FILE-SRV02: login berhasil 09:18:10 — akses ke share HR
    DC01: request TGS ke service LDAP jam 09:20:44 — mencurigakan, svc_backup
    tidak seharusnya butuh akses LDAP langsung ke DC

[7] Cek EVTX 4662 di DC01 sekitar jam 09:20:44
    DITEMUKAN — GUID 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2 (Replicating Directory
    Changes) pada request dari svc_backup — INDIKASI DCSYNC (§10.8.1)

[8] Root cause — kembali ke [1], perluas ke belakang
    Cek asal LSASS dumping: LNK/Prefetch di FIN-WS01 menunjukkan file "invoice.exe"
    dibuka dari email attachment (Bab 6, Bab 8) jam 09:10:00 — initial foothold

REKONSTRUKSI TIMELINE FINAL:
09:10:00 → Malware "invoice.exe" dieksekusi via email attachment di FIN-WS01
09:14:22 → LSASS dump via procdump.exe (LOLBin)
09:16:05 → TGT baru diminta untuk akun svc_backup (kredensial hasil dump)
09:16:30 → Lateral movement ke FILE-SRV01 (akses share finance)
09:18:10 → Lateral movement ke FILE-SRV02 (akses share HR)
09:20:44 → DCSync dijalankan dari svc_backup terhadap DC01 — domain dominance tercapai

KESIMPULAN: Meski svc_backup bukan Domain Admin, keanggotaannya di "Backup Operators"
cukup untuk mengakses banyak file server DAN (dalam kasus ini) memiliki hak replikasi
yang salah dikonfigurasi (over-privileged service account) — memungkinkan DCSync
penuh. Investigasi yang dimulai dari SATU workstation berujung pada domain compromise
menyeluruh karena rantai privilege yang tidak diaudit dengan baik (§10.8.4).
```

> 📌 **Pelajaran utama studi kasus ini:** Investigasi domain yang baik **tidak pernah berhenti di satu mesin** begitu ditemukan indikasi kredensial domain dicuri (§10.4) — prinsip dari Bab 9 §9.5.1 (perluas window ke belakang DAN ke depan) di sini diterapkan lintas-host, dengan DC sebagai titik kunci yang WAJIB dicek begitu ada dugaan lateral movement menggunakan akun domain. Kombinasi Sysmon per-host + EVTX autentikasi di DC (§10.9.2) adalah pasangan sumber paling bernilai untuk merekonstruksi attack chain domain secara meyakinkan — sama seperti prinsip korelasi multi-artefak di Bab 9, hanya sekarang skalanya lintas mesin dalam satu domain.
