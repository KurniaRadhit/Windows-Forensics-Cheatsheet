## 📌 Daftar Isi — Bab 6

- [Bab 6 — Browser Forensics](#bab-6--browser-forensics)
  - [6.1 Arsitektur Profil Browser](#61-arsitektur-profil-browser)
    - [6.1.1 Struktur Folder Profil Chromium-based](#615-struktur-folder-profil-chromium-based)
    - [6.1.2 Struktur Folder Profil Firefox](#616-struktur-folder-profil-firefox)
    - [6.1.3 Kenapa Semua Database-nya SQLite](#613-kenapa-semua-database-nya-sqlite)
  - [6.2 History & Downloads](#62-history--downloads)
    - [6.2.1 Struktur Tabel Chromium](#621-struktur-tabel-chromium)
    - [6.2.2 Struktur Tabel Firefox](#622-struktur-tabel-firefox)
    - [6.2.3 Interpretasi visit_count & typed_count](#623-interpretasi-visit_count--typed_count)
    - [6.2.4 Timestamp Gotcha](#624-timestamp-gotcha)
    - [6.2.5 Downloads](#625-downloads)
    - [6.2.6 Tools & Command](#626-tools--command)
  - [6.3 Cookies](#63-cookies)
    - [6.3.1 Struktur Cookies DB](#631-struktur-cookies-db)
    - [6.3.2 Enkripsi Cookie Value](#632-enkripsi-cookie-value)
    - [6.3.3 Session vs Persistent Cookie](#633-session-vs-persistent-cookie)
  - [6.4 Login Data (Saved Password)](#64-login-data-saved-password)
    - [6.4.1 Struktur Login Data DB](#641-struktur-login-data-db)
    - [6.4.2 Dekripsi via DPAPI](#642-dekripsi-via-dpapi)
    - [6.4.3 Firefox — key4.db & logins.json](#643-firefox--key4db--loginsjson)
  - [6.5 Cache](#65-cache)
    - [6.5.1 Format Cache Chromium (Simple Cache)](#651-format-cache-chromium-simple-cache)
    - [6.5.2 Format Cache Firefox (cache2)](#652-format-cache-firefox-cache2)
    - [6.5.3 Extract File dari Cache](#653-extract-file-dari-cache)
  - [6.6 Session Restore & Tabs](#66-session-restore--tabs)
    - [6.6.1 Chrome Sessions/Tabs (SNSS)](#661-chrome-sessionstabs-snss)
    - [6.6.2 Firefox sessionstore.jsonlz4](#662-firefox-sessionstorejsonlz4)
    - [6.6.3 Nilai Forensik Session Restore](#663-nilai-forensik-session-restore)
  - [6.7 Bookmarks & Extensions](#67-bookmarks--extensions)
    - [6.7.1 Chrome Bookmarks (JSON)](#671-chrome-bookmarks-json)
    - [6.7.2 Firefox moz_bookmarks](#672-firefox-moz_bookmarks)
    - [6.7.3 Extensions](#673-extensions)
  - [6.8 Chromium Preferences & Secure Preferences](#68-chromium-preferences--secure-preferences)
    - [6.8.1 Lokasi & Struktur](#681-lokasi--struktur)
    - [6.8.2 Field Penting untuk Investigasi](#682-field-penting-untuk-investigasi)
    - [6.8.3 Secure Preferences & Proteksi Anti-Tamper](#683-secure-preferences--proteksi-anti-tamper)
  - [6.9 Service Workers & Progressive Web App (PWA) Data](#69-service-workers--progressive-web-app-pwa-data)
    - [6.9.1 Lokasi Chromium](#691-lokasi-chromium)
    - [6.9.2 Lokasi Firefox](#692-lokasi-firefox)
    - [6.9.3 Nilai Forensik](#693-nilai-forensik)
  - [6.10 DNS-over-HTTPS / Secure DNS](#610-dns-over-https--secure-dns)
  - [6.11 Browser Sync Artefacts](#611-browser-sync-artefacts)
    - [6.11.1 Chrome/Edge Sync](#6111-chromeedge-sync)
    - [6.11.2 Firefox Sync](#6112-firefox-sync)
    - [6.11.3 Nilai Forensik Sync](#6113-nilai-forensik-sync)
  - [6.12 Private/Incognito Browsing](#612-privateincognito-browsing)
    - [6.12.1 Yang Tidak Disimpan vs Yang Tetap Tersisa](#6121-yang-tidak-disimpan-vs-yang-tetap-tersisa)
    - [6.12.2 Sumber Jejak Alternatif](#6122-sumber-jejak-alternatif)
  - [6.13 Perbandingan Cepat Chromium vs Firefox](#613-perbandingan-cepat-chromium-vs-firefox)
  - [6.14 Korelasi Artefak (Tabel Cepat)](#614-korelasi-artefak-tabel-cepat)
  - [6.15 Ringkasan Command & Tools Cheat Sheet](#615-ringkasan-command--tools-cheat-sheet)
  - [6.16 Mini Case Study — Rekonstruksi Aktivitas Browsing](#616-mini-case-study--rekonstruksi-aktivitas-browsing)

*(Bab 1: Struktur Drive & Direktori — `bab1.md`. Bab 2: File Sistem NTFS & $MFT — `bab2.md`. Bab 3: Windows Registry Forensics — `bab3.md`. Bab 4: EVTX & Event ID — `bab4.md`. Bab 5: User Activity Trail — `bab5.md`.)*

---

## Bab 6 — Browser Forensics

Browser adalah salah satu aplikasi paling sering dipakai user — dan paling sering jadi **vektor infeksi awal** (drive-by download, phishing link, malicious extension). Bedanya dengan Bab 1–5: hampir semua artefak di bab ini tersimpan dalam **database SQLite** atau format terkompresi (bukan filesystem/registry biasa), jadi butuh pendekatan parsing yang berbeda.

Bab ini fokus ke dua browser paling umum ditemui di kasus DFIR/CTF: **Chromium-based** (Chrome, Edge, Brave — semuanya berbagi format database yang sama persis karena berbasis engine Chromium) dan **Firefox** (format Mozilla/Gecko, berbeda total dari Chromium).

> 💡 **Cross-reference:** Lokasi folder profil browser sudah disebut sekilas di Bab 1 §1.2.6 sebagai peta lokasi cepat — bab ini yang membahas isi & cara parsing mendalamnya.

---

### 6.1 Arsitektur Profil Browser

#### 6.1.1 Struktur Folder Profil Chromium-based

```
C:\Users\<user>\AppData\Local\Google\Chrome\User Data\
├── Local State                        ← Config global (termasuk AES key terenkripsi utk DPAPI)
└── Default\                           ← Profil default (bisa ada Profile 1\, Profile 2\, dst kalau multi-akun)
    ├── History                        ← SQLite: history, downloads, visit
    ├── Cookies                        ← SQLite: cookies
    ├── Login Data                     ← SQLite: saved password
    ├── Web Data                       ← SQLite: autofill, form data, payment card
    ├── Bookmarks                      ← JSON
    ├── Preferences                    ← JSON: setting user, termasuk extension terinstall
    ├── Cache\ atau Cache_Data\        ← Simple Cache format
    ├── Sessions\ / Tabs\              ← SNSS format, current & last session
    ├── Extensions\<extension_id>\     ← Source code extension terinstall
    └── IndexedDB\, Local Storage\     ← Web storage per-origin (termasuk per-extension)
```

Edge (Chromium) dan Brave punya struktur **identik**, cuma beda folder root: `AppData\Local\Microsoft\Edge\User Data\` dan `AppData\Local\BraveSoftware\Brave-Browser\User Data\`.

> 💡 **Multi-profile:** Kalau user pakai beberapa akun Google/Microsoft di browser yang sama, tiap akun dapat folder sendiri (`Profile 1`, `Profile 2`, dst). Selalu cek **semua** folder profil, jangan cuma `Default\` — attacker/user bisa sengaja pakai profile kedua yang jarang dicek.

#### 6.1.2 Struktur Folder Profil Firefox

Firefox berbeda total — nama folder profil memakai **string acak** (salt), bukan nama tetap seperti `Default`:

```
C:\Users\<user>\AppData\Roaming\Mozilla\Firefox\
├── profiles.ini                       ← Index semua profil & profil mana yang default
└── Profiles\
    └── xxxxxxxx.default-release\      ← Nama folder = 8 karakter acak + suffix
        ├── places.sqlite              ← SQLite: history + bookmarks jadi SATU file (beda dari Chrome!)
        ├── cookies.sqlite             ← SQLite: cookies
        ├── key4.db, logins.json       ← Saved password (NSS-encrypted)
        ├── formhistory.sqlite         ← Autofill form
        ├── sessionstore.jsonlz4       ← Session restore (LZ4-compressed JSON)
        ├── cache2\                    ← Cache
        └── storage\default\           ← IndexedDB, Local Storage per-origin
```

```bash
# Cara cepat cari nama folder profil dari profiles.ini
type profiles.ini
# Cari baris "Path=" untuk tahu folder profil mana yang aktif/default
```

> ⚠️ **Beda penting:** Firefox menyatukan History **dan** Bookmarks dalam **satu file** (`places.sqlite`), sementara Chrome memisahkannya jadi dua file berbeda (`History` dan `Bookmarks`). Jangan bingung kalau di Firefox nggak nemu file terpisah untuk bookmark.

#### 6.1.3 Kenapa Semua Database-nya SQLite

Hampir semua database browser (Chrome maupun Firefox) memakai format **SQLite** — database file tunggal, bisa dibuka langsung tanpa server database terpisah. Konsekuensi forensiknya:

> ⚠️ **Penting — Copy Dulu Sebelum Dibuka:** Kalau browser masih berjalan (live system), file database SQLite ini **terkunci** (locked) karena Chrome/Firefox memakai mode **WAL (Write-Ahead Logging)** — perubahan data ditulis dulu ke file `-wal` companion sebelum di-commit ke database utama. Kalau kamu buka `History` langsung sementara Chrome masih jalan, hasilnya bisa **tidak lengkap** (belum ter-commit dari WAL) atau gagal dibuka sama sekali (locked). Selalu:
> 1. **Copy** file database + file companion-nya (`-wal`, `-shm` kalau ada) ke lokasi terpisah
> 2. Baru dibuka dari salinan tersebut

```bash
# Contoh: copy History beserta companion WAL/SHM-nya (kalau ada)
copy "History" "History-shm" "History-wal" C:\evidence\browser\ 2>nul
```

> 💡 **Untuk image mati** (browser sudah tidak jalan saat akuisisi), masalah locking ini biasanya tidak muncul karena tidak ada proses aktif yang mengunci file — tapi tetap disarankan copy dulu sebelum parsing, bukan langsung analisa dari mount point read-only kalau tool parsing butuh write access untuk file temp.

---

### 6.2 History & Downloads

#### 6.2.1 Struktur Tabel Chromium

File `History` (SQLite) punya beberapa tabel penting:

| Tabel | Kolom Penting | Isi |
|---|---|---|
| `urls` | `id`, `url`, `title`, `visit_count`, `typed_count`, `last_visit_time` | Daftar unik semua URL yang pernah dikunjungi |
| `visits` | `id`, `url` (FK ke `urls.id`), `visit_time`, `transition` | Setiap **kunjungan individual** (satu URL bisa punya banyak visit) |
| `downloads` | `id`, `target_path`, `start_time`, `end_time`, `danger_type`, `opened` | Riwayat download |
| `downloads_url_chains` | `id`, `url` | URL sumber tiap download (termasuk redirect chain) |

```sql
-- Query contoh: history diurutkan dari yang paling baru
SELECT url, title, datetime(last_visit_time/1000000-11644473600, 'unixepoch') AS visit_time, visit_count
FROM urls ORDER BY last_visit_time DESC;
```

> 💡 Kolom `transition` di tabel `visits` menyimpan **bagaimana** user sampai ke URL tersebut (encoded sebagai integer) — nilai umum: `LINK` (klik link), `TYPED` (ketik manual di address bar), `AUTO_BOOKMARK`, `RELOAD`, dll. Berguna buat bedakan "user sengaja ketik URL ini" vs "cuma ke-klik dari halaman lain".

#### 6.2.2 Struktur Tabel Firefox

File `places.sqlite`:

| Tabel | Kolom Penting | Isi |
|---|---|---|
| `moz_places` | `id`, `url`, `title`, `visit_count`, `last_visit_date` | Sama seperti `urls` di Chrome |
| `moz_historyvisits` | `id`, `place_id` (FK), `visit_date`, `visit_type` | Sama seperti `visits` di Chrome |
| `moz_annos` | `place_id`, `content` | Anotasi tambahan (termasuk metadata download di versi lama) |

Untuk download di Firefox versi modern, dicatat terpisah di `AppData\Roaming\Mozilla\Firefox\Profiles\<profile>\downloads.json` atau lewat `moz_annos` (tergantung versi).

#### 6.2.3 Interpretasi visit_count & typed_count

| Field | Arti |
|---|---|
| `visit_count` | Total berapa kali URL ini dikunjungi (lewat cara apa pun — klik link, redirect, dll) |
| `typed_count` | Berapa kali URL ini **diketik manual** di address bar |

> 💡 **Tip CTF:** Kalau soal minta *"buktikan user sengaja mengunjungi situs X (bukan cuma ke-redirect)"* — cek `typed_count > 0`. URL dengan `visit_count` tinggi tapi `typed_count = 0` kemungkinan besar cuma hasil klik link/redirect otomatis (mis. iklan, tracking pixel), bukan navigasi sengaja user.

#### 6.2.4 Timestamp Gotcha

Ini kesalahan **paling umum** di forensik browser — format epoch Chrome dan Firefox **beda basis dan beda satuan**:

| Browser | Basis Epoch | Satuan | Formula Konversi ke Unix Epoch |
|---|---|---|---|
| **Chrome/Chromium** (WebKit timestamp) | 1 Januari **1601** UTC | Mikrodetik | `(webkit_timestamp / 1000000) - 11644473600` |
| **Firefox** (PRTime) | 1 Januari **1970** UTC (sama seperti Unix) | Mikrodetik | `prtime / 1000000` (tinggal dibagi, tanpa offset tambahan) |

```bash
# Python — convert Chrome WebKit timestamp
python3 -c "
import datetime
webkit_ts = 13350000000000000  # contoh nilai dari kolom last_visit_time
unix_ts = webkit_ts / 1000000 - 11644473600
print(datetime.datetime.utcfromtimestamp(unix_ts))
"

# Python — convert Firefox PRTime
python3 -c "
import datetime
prtime = 1700000000000000  # contoh nilai dari kolom visit_date
print(datetime.datetime.utcfromtimestamp(prtime / 1000000))
"
```

> ⚠️ **Jangan asumsikan format timestamp sama cuma karena sama-sama SQLite dan sama-sama "mikrodetik".** Salah pakai formula Chrome ke data Firefox (atau sebaliknya) akan menghasilkan tanggal yang **jauh meleset** (biasanya nyasar ke tahun 1600-an atau nilai negatif) — kalau ketemu tanggal aneh seperti itu, itu tanda formula konversi yang dipakai salah.

#### 6.2.5 Downloads

Field penting di tabel `downloads` (Chrome) yang sering jadi kunci jawaban CTF:

| Field | Kegunaan |
|---|---|
| `target_path` | Lokasi file hasil download disimpan |
| `tab_url` / `downloads_url_chains` | Halaman/link sumber file di-download (termasuk redirect chain — bisa nunjukin file "sebenarnya" download dari mana meski link awal beda) |
| `danger_type` | Klasifikasi Chrome sendiri (mis. `DANGEROUS_FILE`, `DANGEROUS_URL`) kalau Chrome sempat flag file ini sebagai mencurigakan |
| `opened` | Apakah file yang di-download **dibuka** oleh user setelah selesai download (bukan cuma didownload) |

> 💡 Cross-reference: `target_path` di sini bisa langsung dicocokkan ke `$MFT` (Bab 2 §2.2.7) untuk verifikasi apakah file hasil download tersebut **masih ada**, sudah **dipindah**, atau sudah **dihapus** (lanjut cek Recycle Bin — Bab 5 §5.2).

#### 6.2.6 Tools & Command

```bash
# sqlite3 CLI — query manual langsung
sqlite3 History "SELECT url, datetime(last_visit_time/1000000-11644473600,'unixepoch') FROM urls;"

# Hindsight — parser khusus Chromium, otomatis convert timestamp & gabung semua tabel relevan
python3 hindsight.py -i "C:\evidence\Default" -o output --format jsonl

# NirSoft ChromeHistoryView / MZHistoryView (Firefox) — GUI ringan, gratis
```

---

### 6.3 Cookies

#### 6.3.1 Struktur Cookies DB

Tabel `cookies` (Chrome) / `moz_cookies` (Firefox) — kolom penting:

| Kolom | Keterangan |
|---|---|
| `host_key` | Domain pemilik cookie |
| `name`, `value` | Nama & isi cookie (value **terenkripsi** di Chrome modern — lihat 6.3.2) |
| `expires_utc` | Kapan cookie kedaluwarsa |
| `is_secure`, `is_httponly` | Flag keamanan cookie |
| `last_access_utc` | Kapan cookie terakhir dipakai — bisa jadi indikasi "user masih aktif login" di waktu tersebut |

#### 6.3.2 Enkripsi Cookie Value

Sejak Chrome versi baru, kolom `value` di tabel `cookies` **tidak lagi plaintext** — isinya terenkripsi dengan prefix yang menandakan metode enkripsi:

| Prefix | Metode |
|---|---|
| `v10` | AES-GCM dengan key dari **DPAPI** (Windows Data Protection API) — terikat ke user account Windows yang membuatnya |
| `v20` | AES-GCM dengan key tambahan proteksi App-Bound Encryption (Chrome versi lebih baru) — lebih sulit didekripsi tanpa proses Chrome asli |

> ⚠️ **Implikasi forensik:** Dekripsi cookie (dan Login Data, §6.4) butuh akses ke **DPAPI master key** milik user Windows tersebut — yang tersimpan di `AppData\Roaming\Microsoft\Protect\<SID>\`, dan hanya bisa didekripsi dengan konteks user yang sama (atau dengan password/hash user itu). Ini artinya kalau kamu cuma punya file `Cookies`/`Login Data` **tanpa** disk image lengkap (termasuk folder `Protect\` dan akses ke akun user), dekripsi isi cookie/password **tidak akan berhasil** — cuma metadata (host, timestamp, nama cookie) yang tetap bisa dibaca tanpa dekripsi.

#### 6.3.3 Session vs Persistent Cookie

| Jenis | `expires_utc` | Bertahan setelah browser ditutup? |
|---|---|---|
| **Session cookie** | `0` atau tidak diset | Tidak — hilang begitu browser ditutup |
| **Persistent cookie** | Ada nilai tanggal spesifik | Ya — tersimpan sampai expired atau dihapus manual |

> 💡 **Tip CTF:** Cookie dengan nama seperti `session_id`, `auth_token`, `PHPSESSID` yang masih ada di database (belum expired) bisa jadi bukti **sesi login aktif** pada waktu snapshot diambil — kombinasikan dengan `last_access_utc` untuk estimasi waktu terakhir user aktif di situs tersebut.

---

### 6.4 Login Data (Saved Password)

#### 6.4.1 Struktur Login Data DB

File `Login Data` (Chrome) — tabel `logins`:

| Kolom | Keterangan |
|---|---|
| `origin_url` | URL halaman login |
| `username_value` | Username/email yang disimpan |
| `password_value` | Password — **terenkripsi**, format sama seperti cookie (`v10`/`v20`, lihat 6.3.2) |
| `date_created`, `date_last_used` | Kapan kredensial disimpan & terakhir dipakai |

#### 6.4.2 Dekripsi via DPAPI

Alur dekripsi password Chrome (kalau kamu punya akses penuh ke akun/image user):

```
1. Baca "Local State" (JSON) di folder User Data\ → ambil field
   os_crypt.encrypted_key (base64, prefix "DPAPI" setelah decode base64)

2. Decrypt encrypted_key ini pakai DPAPI (butuh konteks user Windows yang sama,
   atau password/hash user via tool seperti Mimikatz/impacket-dpapi)
   → hasilnya adalah AES key final

3. Pakai AES key tersebut untuk decrypt password_value di Login Data
   (AES-GCM, prefix v10/v20 menentukan skema)
```

> 💡 **Bukan target utama CTF DFIR biasanya:** Dekripsi penuh butuh privilege tinggi/akses live system, jadi soal CTF forensik lebih sering minta identifikasi **metadata** (situs apa yang credential-nya disimpan, kapan terakhir dipakai) daripada minta plaintext password aktual. Tapi kalau soal eksplisit minta dekripsi, tool seperti `DonPAPI` atau script `chrome_decrypt.py` (banyak versi open-source) mengotomasi alur di atas.

#### 6.4.3 Firefox — key4.db & logins.json

Firefox memakai skema berbeda, berbasis **NSS (Network Security Services)**:

```
key4.db        ← SQLite, menyimpan master key terenkripsi (NSS format)
logins.json    ← JSON, menyimpan username + password terenkripsi per-situs
```

> 💡 Kalau user set **Master Password** di Firefox, dekripsi butuh password tersebut. Kalau tidak diset (default kebanyakan user), key di `key4.db` bisa didekripsi tanpa password tambahan — tool seperti `firefox_decrypt.py` (open-source) mengotomasi proses ini.

---

### 6.5 Cache

#### 6.5.1 Format Cache Chromium (Simple Cache)

```
Cache\ atau Cache_Data\
├── index                  ← Index semua entry cache
├── data_0, data_1, ...    ← Block file lama (format lawas)
└── <hash>_0, <hash>_s     ← Simple Cache format (modern) — satu file per entry cache
```

Setiap entry cache menyimpan: URL sumber, response header (termasuk `Content-Type`), dan **konten mentah** (gambar, script, CSS, dll) yang pernah di-load browser.

#### 6.5.2 Format Cache Firefox (cache2)

```
cache2\
├── entries\      ← Satu file per entry cache, nama = hash dari URL
└── doomed\       ← Entry yang sedang dihapus/expired
```

#### 6.5.3 Extract File dari Cache

> 💡 **Nilai forensik utama Cache:** Bisa **recovery konten** (gambar, script, halaman) yang pernah diakses user meskipun history sudah dihapus — cache dan history adalah dua mekanisme terpisah, menghapus salah satu tidak otomatis menghapus yang lain.

```bash
# ChromeCacheView (NirSoft) — GUI, otomatis extract & preview isi cache Chromium
# MozillaCacheView (NirSoft) — versi Firefox

# Hindsight juga bisa parsing cache Chromium sekalian dengan history (§6.2.6)
```

---

### 6.6 Session Restore & Tabs

#### 6.6.1 Chrome Sessions/Tabs (SNSS)

```
Sessions\
├── Session_<timestamp>    ← Snapshot tab yang terbuka di sesi ini
└── Tabs_<timestamp>       ← Snapshot per-tab
```

Format **SNSS (Session/Sessions Native Storage)** — binary custom, berisi command log berurutan (buka tab, navigasi, tutup tab) yang bisa di-replay untuk rekonstruksi tab apa saja yang terbuka.

#### 6.6.2 Firefox sessionstore.jsonlz4

```
sessionstore.jsonlz4    ← JSON di-compress pakai LZ4, prefix magic bytes "mozLz40\0"
```

```bash
# Decompress manual pakai Python (butuh library lz4)
python3 -c "
import lz4.block, json
with open('sessionstore.jsonlz4', 'rb') as f:
    data = f.read()
    decompressed = lz4.block.decompress(data[8:])  # skip 8-byte magic header 'mozLz40\0'
    session = json.loads(decompressed)
    for window in session.get('windows', []):
        for tab in window.get('tabs', []):
            entries = tab.get('entries', [])
            if entries:
                print(entries[-1].get('url'))
"
```

#### 6.6.3 Nilai Forensik Session Restore

> 💡 **Tip CTF:** Session restore adalah salah satu **jejak paling "real-time"** — mencatat kondisi tab **persis sebelum** browser ditutup (baik normal maupun crash/dipaksa mati oleh Task Manager). Kalau soal minta *"tab apa yang terbuka saat insiden terjadi"*, ini artefak pertama yang harus dicek, sebelum masuk ke History yang cuma catat kunjungan historis tanpa konteks "tab mana yang aktif terakhir".

---

### 6.7 Bookmarks & Extensions

#### 6.7.1 Chrome Bookmarks (JSON)

File `Bookmarks` — plaintext JSON, berisi struktur folder bookmark lengkap dengan `date_added` (WebKit timestamp, sama seperti §6.2.4) per item.

#### 6.7.2 Firefox moz_bookmarks

Tabel `moz_bookmarks` di `places.sqlite` (§6.1.2) — ingat, Firefox gabung history & bookmark dalam satu file database.

#### 6.7.3 Extensions

```
Extensions\<extension_id>\<version>\    ← Source code lengkap extension (manifest.json, JS, dll)
```

| Yang Dicek | Kenapa Penting |
|---|---|
| `manifest.json` — field `permissions` | Extension dengan permission luas (`<all_urls>`, `webRequest`, `tabs`) berpotensi jadi **vektor exfiltrasi data** atau **injection** |
| Nama & publisher extension | Extension tidak dikenal / sideload manual (bukan dari Web Store resmi) patut dicurigai |
| `IndexedDB\` / `Local Storage\` per-origin extension | Bisa menyimpan data yang di-exfiltrate extension malicious sebelum dikirim ke C2 |

> 💡 **Tip CTF:** Kasus infeksi lewat **malicious browser extension** makin umum — kalau soal minta identifikasi "bagaimana attacker mencuri cookie/kredensial", cek folder `Extensions\` untuk extension yang tidak familiar, baca `manifest.json`-nya untuk lihat permission yang diminta, lalu cross-check `background.js`/service worker untuk logic exfiltrasi.

---

### 6.8 Chromium Preferences & Secure Preferences

#### 6.8.1 Lokasi & Struktur

Dua file JSON di folder profil yang sering terlewat padahal isinya padat artefak:

```
Default\
├── Preferences           ← JSON: setting per-profil, tidak dilindungi tanda tangan
└── Secure Preferences    ← JSON: setting sensitif, dilindungi HMAC (lihat 6.8.3)
```

Keduanya **plaintext JSON** (bukan SQLite), jadi bisa langsung dibaca tanpa tool khusus — tinggal `cat`/`type` atau parse dengan `json.load` di Python. Ukurannya bisa besar dan sangat nested, jadi lebih praktis pakai `jq` atau Python daripada baca manual.

#### 6.8.2 Field Penting untuk Investigasi

| Field (JSON path, disederhanakan) | Isi | Relevansi Investigasi |
|---|---|---|
| `homepage`, `homepage_is_newtabpage` | URL homepage yang diset | **Browser hijacking** — homepage diubah paksa oleh malware/extension |
| `session.restore_on_startup` + `session.startup_urls` | Perilaku saat browser dibuka & daftar URL startup | Startup page mencurigakan yang dipaksa oleh adware |
| `default_search_provider_data` | Search engine default & daftar search engine custom | Search hijacking — search engine diganti ke domain phishing/redirect ads |
| `extensions.settings.<extension_id>` | State tiap extension: `state` (1=enabled, 0=disabled), `install_time`, `manifest`, `granted_permissions` | Cross-check dengan folder `Extensions\` (§6.7.3) — kapan extension terpasang & permission apa yang di-*grant* |
| `download.default_directory` | Folder default hasil download | Kalau attacker ubah ke folder tersembunyi, indikasi upaya sembunyikan hasil download |
| `safebrowsing.enabled` | Status Safe Browsing (proteksi bawaan Chrome) | Kalau dinonaktifkan tanpa sepengetahuan user, indikasi malware melumpuhkan proteksi browser |
| `dns_over_https.mode`, `dns_over_https.templates` | Konfigurasi Secure DNS | Lihat detail di §6.10 |
| `account_info`, `signin.*` | Akun Google yang login ke profil | Lihat detail di §6.11 |

```bash
# jq — ambil beberapa field kunci sekaligus dari Preferences
jq '{homepage, search: .default_search_provider_data.template_url_data.short_name, dns_over_https}' Preferences
```

> 💡 **Tip CTF:** Kalau soal minta *"buktikan browser di-hijack, homepage/search engine diganti attacker"* — `Preferences` biasanya lebih cepat dicek daripada menelusuri `History` satu-satu. Bandingkan `default_search_provider_data` dengan default browser resmi (Google/Bing/dll) untuk mendeteksi search engine custom yang mencurigakan.

#### 6.8.3 Secure Preferences & Proteksi Anti-Tamper

`Secure Preferences` menyimpan setting yang dianggap sensitif (extension list, startup URLs, default search) dengan **HMAC signature** (disebut `protection.macs` di dalam file) untuk mencegah modifikasi diam-diam oleh malware — kalau Chrome mendeteksi field terproteksi berubah tanpa signature yang valid, Chrome akan mereset field itu ke default saat dibuka.

> ⚠️ **Implikasi forensik:** Justru **karena** ada proteksi ini, kalau ditemukan field di `Secure Preferences` yang isinya mencurigakan (mis. extension asing dengan `state: 1`) **dan** signature-nya tetap valid, itu artinya perubahan dilakukan **lewat mekanisme resmi Chrome** (API extension, bukan modifikasi file manual) — berguna untuk membedakan antara "malware mengedit file langsung" (biasanya bikin signature invalid, field ke-reset) vs "malware masuk lewat extension resmi yang terinstall" (signature tetap valid).

---

### 6.9 Service Workers & Progressive Web App (PWA) Data

Browser modern menjalankan **Service Worker** — script background per-origin yang memungkinkan web app bekerja offline, caching custom, dan push notification. Artefaknya sering luput dari pemeriksaan karena bukan bagian dari Cache biasa (§6.5).

#### 6.9.1 Lokasi Chromium

```
Service Worker\
├── CacheStorage\<hash>\    ← Cache API storage per-origin (mirip Cache biasa tapi dikontrol script SW)
├── ScriptCache\            ← Cache file JS service worker itu sendiri
└── Database\               ← LevelDB, metadata registrasi service worker per-origin
```

Path lengkap ada di dalam folder profil: `Default\Service Worker\...` — sejajar dengan `IndexedDB\` dan `Local Storage\` yang sudah disebut di §6.1.1.

#### 6.9.2 Lokasi Firefox

```
storage\default\<origin>\   ← Termasuk sub-folder "serviceworker" per-origin
```

Firefox juga mencatat daftar registrasi service worker di file terpisah di root profil (format bisa berubah antar versi — cek dengan `grep -r "serviceworker"` di folder profil kalau butuh lokasi pasti pada sampel yang dianalisis).

#### 6.9.3 Nilai Forensik

Karena berbasis **LevelDB** (sama seperti IndexedDB/Local Storage), Service Worker dan cache-nya sering menyimpan **data aplikasi web yang sudah di-cache untuk offline** — termasuk konten yang mungkin sudah tidak ada lagi di Cache biasa maupun History.

Paling sering relevan untuk **web app berbasis PWA**:

```
Discord Web
Microsoft Teams
Slack
Outlook Web
```

Untuk aplikasi-aplikasi ini, Service Worker cache bisa menyimpan potongan pesan, metadata channel/percakapan, atau token sesi yang di-cache app untuk mode offline — bahkan setelah user logout dari tab biasa, sisa data masih bisa ada di CacheStorage sampai di-*purge* manual oleh browser.

```bash
# LevelDB (Database\, IndexedDB) butuh parser khusus, bukan sqlite3
pip install plyvel   # atau pakai ccl_chrome_indexeddb (khusus IndexedDB Chromium)
python3 -c "
import plyvel
db = plyvel.DB('Service Worker/Database', create_if_missing=False)
for key, value in db:
    print(key, value[:100])
"
```

> ⚠️ **Hati-hati parsing LevelDB dari live/locked profile** — sama seperti SQLite (§6.1.3), LevelDB juga bisa terkunci kalau browser masih berjalan. Selalu copy folder `Service Worker\` dan `IndexedDB\` dulu sebelum dibuka.

> 💡 **Tip CTF:** Kalau soal minta bukti *"user pernah login ke aplikasi chat berbasis web tertentu"* atau *"token API tersimpan di sisi client"* dan Local Storage/Cookies sudah bersih, cek Service Worker CacheStorage & IndexedDB — sering jadi tempat terakhir data itu bertahan.

---

### 6.10 DNS-over-HTTPS / Secure DNS

Bukan artefak "besar" seperti History atau Cookies, tapi makin sering relevan karena bisa mengubah cara investigasi jaringan dilakukan.

**Lokasi:** field `dns_over_https` di dalam `Preferences` (§6.8.2).

```json
"dns_over_https": {
  "mode": "secure",
  "templates": "https://chrome.cloudflare-dns.com/dns-query"
}
```

| Nilai `mode` | Arti |
|---|---|
| `off` | Secure DNS dimatikan, resolusi DNS lewat jalur normal sistem operasi |
| `automatic` | Browser pakai DoH kalau provider DNS saat ini mendukung, fallback ke normal kalau tidak |
| `secure` | DoH dipaksa aktif, tidak fallback ke DNS normal |

Provider umum yang muncul di `templates`:

```
Cloudflare  → https://chrome.cloudflare-dns.com/dns-query
Google DNS  → https://dns.google/dns-query
Quad9       → https://dns.quad9.net/dns-query
NextDNS     → https://dns.nextdns.io/<id-unik-user>
```

Firefox menyimpan setting yang sama di `prefs.js` dalam folder profil, dengan key `network.trr.mode` (0=off, 2=automatic dengan fallback, 3=strict/secure) dan `network.trr.uri` untuk URL provider-nya.

> ⚠️ **Relevan untuk investigasi jaringan:** Kalau `mode` di-set `secure`/`3` (strict), resolusi DNS **tidak akan tercatat** di DNS cache sistem operasi maupun DNS server lokal jaringan — karena query-nya dibungkus HTTPS langsung ke provider DoH, bukan lewat UDP port 53 biasa. Ini artinya asumsi di §6.12.2 bahwa `ipconfig /displaydns` selalu mencatat domain yang diakses **tidak berlaku** kalau DoH aktif dalam mode strict — domain yang di-resolve lewat DoH cuma akan terlihat di traffic HTTPS ke endpoint provider DoH itu sendiri (kalau ada packet capture), bukan di DNS cache biasa.

> 💡 **Tip CTF:** Kalau ada gap antara "situs pasti diakses (ada di History/Cache)" tapi "DNS cache sistem tidak mencatat domain tersebut sama sekali", cek dulu status DoH di `Preferences`/`prefs.js` sebelum menyimpulkan DNS cache "dimanipulasi" atau "tidak lengkap" — bisa jadi memang query-nya lewat DoH.

---

### 6.11 Browser Sync Artefacts

#### 6.11.1 Chrome/Edge Sync

```
Sync Data\              ← LevelDB, data yang disinkronkan ke akun Google/Microsoft
```

Info akun yang sedang login ke profil browser juga tercatat di `Preferences`/`Local State` lewat field seperti `account_info` dan `signin.*` (lihat §6.8.2) — berguna untuk **atribusi**, yaitu akun mana yang dipakai di profil tersebut, tanpa perlu buka `Sync Data\` itu sendiri.

Edge (berbasis Chromium) memakai struktur serupa, terhubung ke akun Microsoft:

```
Sync Data\              ← Sama seperti Chrome, tapi tersinkron ke Microsoft Account
```

#### 6.11.2 Firefox Sync

```
signedInUser.json    ← Info akun Firefox Sync yang login (email, UID)
.fxaccounts\          ← Token & metadata Firefox Account
```

#### 6.11.3 Nilai Forensik Sync

> 💡 **Dua nilai forensik utama:**
> 1. **Atribusi akun** — field akun (`account_info` di Chrome, `signedInUser.json` di Firefox) menunjukkan identitas Google/Microsoft/Firefox Account mana yang dipakai login di browser tersebut, berguna untuk mengaitkan aktivitas browsing ke identitas spesifik.
> 2. **Potensi artefak lintas perangkat** — kalau sync aktif, data seperti History, Bookmarks, saved password, bahkan **extension yang terpasang** bisa ikut tersinkron ke perangkat lain yang login dengan akun yang sama. Ini penting kalau investigasi terbatas ke satu perangkat: data yang "hilang" di perangkat ini (mis. sudah dihapus) berpotensi masih ada di salinan tersinkron pada perangkat lain, atau sebaliknya — extension malicious yang terpasang di satu perangkat bisa ikut ter-push ke semua perangkat lain yang sync ke akun yang sama, memperluas cakupan investigasi.

> ⚠️ **Batasan:** Isi `Sync Data\` (LevelDB) sendiri biasanya berupa data terenkripsi/terserialisasi untuk protokol sync internal Chrome, bukan format yang langsung dibaca manusia — nilai forensik utamanya lebih ke *keberadaan* sync & *field akun* di `Preferences`, bukan parsing isi `Sync Data\` secara mendalam.

---

### 6.12 Private/Incognito Browsing

#### 6.12.1 Yang Tidak Disimpan vs Yang Tetap Tersisa

| **Tidak disimpan** saat mode privat | **Tetap tersisa** meski mode privat |
|---|---|
| History (`urls`/`visits`, `moz_places`) | DNS cache sistem (di memory, sampai reboot/flush) |
| Cookies baru (dibuang begitu window privat ditutup) | Bookmark yang sengaja disimpan manual |
| Cache baru | File yang di-download (kecuali browser diset auto-delete) |
| Form data / autofill baru | Prefetch/Amcache — bukti **browser-nya sendiri dijalankan** (Bab 4 §4.13, Bab 3 §3.8), meski isi browsing-nya tidak |

#### 6.12.2 Sumber Jejak Alternatif

Karena data **di dalam** browser mode privat memang didesain untuk tidak tersimpan, investigasi jejak browsing privat mengandalkan artefak **di luar** browser itu sendiri:

- **DNS Cache** (live system): `ipconfig /displaydns` — mencatat domain yang di-resolve, termasuk saat mode privat (⚠️ tidak berlaku kalau DNS-over-HTTPS aktif dalam mode strict, lihat §6.10)
- **Prefetch & Amcache** (Bab 4 §4.13, Bab 3 §3.8): membuktikan browser dijalankan, walau bukan bukti situs yang dikunjungi
- **Network-level artifact**: proxy log, firewall log, DNS server log (di luar cakupan disk forensics — biasanya didapat dari sisi jaringan, bukan endpoint)
- **Memory forensics**: Data mode privat yang belum di-flush masih ada di RAM selama browser berjalan — analisa mendalam butuh bab Memory Forensics tersendiri (mendatang)

> ⚠️ **Jangan overclaim:** Kalau cuma modal disk image (tanpa memory dump atau network log), forensik disk **tidak bisa** membuktikan konten spesifik yang diakses lewat mode privat — paling jauh cuma bisa membuktikan "browser dijalankan pada waktu X" lewat Prefetch/Amcache. Jangan simpulkan lebih dari yang bukti sebenarnya dukung.

---

### 6.13 Perbandingan Cepat Chromium vs Firefox

| Artefak | Chromium (Chrome/Edge/Brave) | Firefox |
|---|---|---|
| History | `History` (SQLite, terpisah) | `places.sqlite` (gabung dgn bookmark) |
| Bookmarks | `Bookmarks` (JSON, terpisah) | `places.sqlite` (tabel `moz_bookmarks`) |
| Cookies | `Cookies` (SQLite) | `cookies.sqlite` |
| Saved Password | `Login Data` (SQLite) + DPAPI | `key4.db` + `logins.json` (NSS) |
| Cache | `Cache_Data\` (Simple Cache) | `cache2\` |
| Session Restore | `Sessions\`/`Tabs\` (SNSS, binary) | `sessionstore.jsonlz4` (LZ4 JSON) |
| Basis Timestamp | 1601 (mikrodetik) | 1970 (mikrodetik, sama seperti Unix) |
| Nama Folder Profil | Tetap (`Default`, `Profile 1`) | Acak (`xxxxxxxx.default-release`) |
| Settings/Preferences | `Preferences` + `Secure Preferences` (JSON) | `prefs.js` |
| Secure DNS | `Preferences` → `dns_over_https` | `prefs.js` → `network.trr.*` |
| Service Worker Cache | `Service Worker\CacheStorage\`, `Service Worker\Database\` (LevelDB) | `storage\default\<origin>\` |
| Sync | `Sync Data\` (LevelDB) + `account_info` di `Preferences` | `signedInUser.json` + `.fxaccounts\` |

---

### 6.14 Korelasi Artefak (Tabel Cepat)

| Pertanyaan Umum CTF | Artefak Utama | Bagian |
|---|---|---|
| Situs apa yang dikunjungi & kapan | History (`urls`/`visits` atau `moz_places`) | 6.2.1, 6.2.2 |
| User sengaja ketik URL vs cuma diklik | `typed_count` | 6.2.3 |
| File apa yang di-download, dari mana | `downloads` + `downloads_url_chains` | 6.2.5 |
| Sesi login aktif pada waktu tertentu | Cookies (`last_access_utc`, cookie session) | 6.3.3 |
| Kredensial situs apa yang disimpan (tanpa perlu plaintext) | Login Data metadata (`origin_url`, `date_last_used`) | 6.4.1 |
| Recovery konten yang pernah diakses meski history dihapus | Cache | 6.5 |
| Tab apa yang terbuka persis sebelum insiden/crash | Session Restore | 6.6 |
| Malicious extension sebagai vektor infeksi | `Extensions\`, `manifest.json` | 6.7.3 |
| Bukti browser dijalankan meski history mode privat kosong | Prefetch (Bab 4 §4.13), Amcache (Bab 3 §3.8) | 6.12.2 |
| File hasil download masih ada/sudah dihapus | `target_path` → cross-check `$MFT` (Bab 2) & Recycle Bin (Bab 5 §5.2) | 6.2.5 |
| Homepage/search engine diubah paksa (browser hijacking) | `Preferences` (`homepage`, `default_search_provider_data`) | 6.8.2 |
| Token/JWT aplikasi web tersimpan di sisi client | Local Storage / IndexedDB, termasuk `Service Worker\CacheStorage\` | 6.9 |
| Pesan/data PWA (Discord Web, Teams, Slack, Outlook Web) yang di-cache offline | Service Worker (`CacheStorage\`, `Database\`) | 6.9 |
| Resolusi DNS "hilang" dari DNS cache sistem | Cek status DoH di `Preferences`/`prefs.js` | 6.10 |
| Akun mana yang login ke browser & potensi artefak di perangkat lain | `Sync Data\`, `account_info`, `signedInUser.json` | 6.11 |

**Tabel ringkas — pertanyaan umum vs artefak (referensi cepat CTF):**

| Pertanyaan | Artefak Browser |
|---|---|
| Situs dikunjungi | History |
| File didownload | Downloads |
| URL sumber download | `downloads_url_chains` |
| Password tersimpan | Login Data |
| Login session aktif | Cookies |
| Form pernah diisi | Web Data |
| Token aplikasi web | Local Storage / IndexedDB |
| Tab terakhir | Session Restore |
| Extension terpasang | Extensions / `Preferences` |
| History sudah dihapus | Cache / Favicons / VSS |
| Homepage/search engine di-hijack | Preferences / Secure Preferences |
| Data PWA offline (chat, dsb.) | Service Worker |
| DNS disembunyikan dari log jaringan | DNS-over-HTTPS config |
| Akun & artefak lintas perangkat | Sync Data |

---

### 6.15 Ringkasan Command & Tools Cheat Sheet

| Artefak | Tool | Command/Catatan |
|---|---|---|
| History + Cache + Downloads (Chromium) | **Hindsight** | `python3 hindsight.py -i <profile_dir> -o output --format jsonl` — paling komprehensif, satu tool banyak artefak |
| History (manual/cross-check) | `sqlite3` CLI | `sqlite3 History "SELECT ... FROM urls;"` |
| History/Cookies GUI (Chromium) | **NirSoft ChromeHistoryView / ChromeCookiesView** | GUI ringan, cepat untuk overview |
| History/Cookies GUI (Firefox) | **NirSoft MZHistoryView / MZCookiesView** | Versi Firefox dari tool di atas |
| Cache viewer | **ChromeCacheView / MozillaCacheView** (NirSoft) | Extract & preview konten cache |
| Password decrypt (Chromium) | `chrome_decrypt.py` / **DonPAPI** | Butuh akses DPAPI/konteks user |
| Password decrypt (Firefox) | `firefox_decrypt.py` | Butuh `key4.db` + `logins.json` |
| Session restore (Firefox) | Python `lz4.block` | Decompress manual (§6.6.2) |
| Generic cross-browser | **browser-history** (Python package) | Ekstraksi cepat multi-browser sekaligus, kurang detail dibanding Hindsight |
| Preferences/Secure Preferences | `jq` / Python `json` | Parsing cepat field homepage, search engine, extension state, DoH (§6.8, §6.10) |
| Service Worker / IndexedDB / Sync Data (LevelDB) | Python `plyvel`, **ccl_chrome_indexeddb** | LevelDB butuh parser khusus, bukan `sqlite3` (§6.9, §6.11) |

---

### 6.16 Mini Case Study — Rekonstruksi Aktivitas Browsing

Skenario: *"User diduga mengunduh file berbahaya dari email phishing lewat browser, membuka file tersebut, lalu mencoba menutup jejak dengan menghapus history — tapi masih menyisakan artefak lain."*

```
Langkah 1 — Cek apakah History memang sudah dikosongkan/dimanipulasi
   └── Buka "History" (copy dulu, 6.1.3) → cek urls/visits (6.2.1)
       → kalau kosong/rentang waktu janggal (ada gap besar sebelum insiden) → indikasi dihapus manual

Langkah 2 — Cari bukti alternatif kunjungan situs meski History kosong
   └── Cache (6.5) → cari entry dengan URL/timestamp yang cocok rentang waktu insiden
       → extract konten cache untuk verifikasi (mis. halaman phishing landing page)
   └── Session Restore (6.6) → kalau browser sempat crash/dipaksa tutup sebelum history
       sempat dibersihkan, tab yang terbuka saat itu mungkin masih terekam

Langkah 3 — Cari bukti download file berbahaya
   └── Kalau "downloads" table di History juga sudah dihapus → cross-check target_path
       dari Cache metadata, atau langsung cari lewat $MFT (Bab 2, §2.2.7) untuk file
       dengan FullPath di folder Downloads\ pada rentang waktu yang relevan

Langkah 4 — Konfirmasi file tersebut dibuka setelah didownload
   └── LNK di folder Recent\ (Bab 5, §5.3) → kalau ada LNK auto-created menunjuk ke
       file tersebut, itu bukti file dibuka setelah download
   └── Prefetch (Bab 4, §4.13) → kalau file adalah executable, cek run count & waktu eksekusi

Langkah 5 — Cek command line/artefak lanjutan pasca eksekusi
   └── EVTX 4688 / Sysmon Event ID 1 (Bab 4) → proses anak yang dibuat setelah file
       tersebut dieksekusi, korelasi ke waktu dari Prefetch/LNK di atas

Kesimpulan yang bisa ditulis di laporan:
"Meski tabel History pada 'History' db kosong untuk rentang waktu insiden (indikasi dihapus
manual), ditemukan entry Cache dengan timestamp X yang cocok dengan halaman phishing landing
page (URL Y). File attachment Z ditemukan di $MFT dengan FullPath 'Downloads\invoice.exe' pada
waktu X+2 menit. LNK auto-created di folder Recent\ mengonfirmasi file tersebut dibuka pada
waktu X+3 menit, dikuatkan oleh entry Prefetch INVOICE.EXE-XXXXXXXX.pf dengan RunCount=1 pada
waktu yang sama. Sysmon Event ID 1 mencatat proses anak cmd.exe/powershell.exe dijalankan oleh
invoice.exe tak lama setelahnya, mengindikasikan payload aktif dieksekusi."
```

> 💡 **Prinsip umum:** History yang kosong/dihapus **bukan akhir investigasi** — Cache, Session Restore, LNK (Bab 5), Prefetch & Amcache (Bab 3, 4) semuanya bisa jadi bukti pengganti yang saling menguatkan. Browser forensics paling kuat justru ketika dikombinasikan dengan artefak filesystem-level dan registry-level yang sudah dibahas di bab-bab sebelumnya — jangan pernah berhenti di satu sumber saja.

---
