# SQLite3 Forensics Cheatsheet — Analisa File Database untuk CTF & DFIR

> Referensi cepat untuk menganalisa file `.db` / `.sqlite` / `.sqlite3` yang ditemukan saat forensik (disk image, memory dump, aplikasi mobile/desktop, browser artifact, dsb). Struktur mengikuti seri DFIR (Windows/Linux/Network Forensics) — gunakan §X.Y untuk cross-reference internal.

---

## §1. Persiapan & Identifikasi Awal

### §1.1 Cek apakah file benar-benar SQLite

```bash
file evidence.db
```

Header SQLite3 valid selalu diawali magic string di 16 byte pertama:

```
53 51 4C 69 74 65 20 66 6F 72 6D 61 74 20 33 00   # "SQLite format 3\0"
```

Cek manual pakai hex:

```bash
xxd evidence.db | head -n 1
```

> 💡 **Tip:** Kalau `file` mengenali sebagai "data" bukan SQLite padahal kamu yakin itu database (misal ekstensi disamarkan jadi `.log`, `.tmp`, `.cache`), cek magic bytes manual. Banyak aplikasi (WhatsApp, Telegram, browser) menyimpan SQLite dengan ekstensi non-standar.

### §1.2 Cek integritas file

```bash
sqlite3 evidence.db "PRAGMA integrity_check;"
```

⚠️ **Warning:** Kalau file corrupt/truncated (misal hasil carving dari unallocated space), `sqlite3` CLI bisa gagal buka normal. Gunakan mode recovery:

```bash
sqlite3 evidence.db ".recover" > recovered.sql
sqlite3 recovered.db < recovered.sql
```

### §1.3 Selalu kerja di atas COPY

```bash
cp evidence.db evidence_work.db
```

⚠️ Jangan pernah buka file asli dengan aplikasi yang bisa auto-write (browser, app asli). SQLite bisa auto-checkpoint WAL dan mengubah state file evidence. Selalu kerja di copy + read-only mode:

```bash
sqlite3 -readonly evidence_work.db
```

---

## §2. Eksplorasi Struktur Database

### §2.1 Masuk ke shell interaktif

```bash
sqlite3 evidence_work.db
```

### §2.2 List semua tabel — `.tables`

```sql
.tables
```

Menampilkan semua tabel user (bukan tabel sistem `sqlite_*` secara default). Untuk melihat termasuk tabel sistem:

```sql
SELECT name FROM sqlite_master WHERE type='table';
```

### §2.3 List semua objek (tabel, index, trigger, view)

```sql
SELECT type, name, tbl_name FROM sqlite_master;
```

| type    | Keterangan                                  |
|---------|----------------------------------------------|
| table   | Tabel data                                    |
| index   | Index (termasuk auto-index dari PRIMARY KEY/UNIQUE) |
| trigger | Trigger — **penting**, bisa mengungkap logic aplikasi |
| view    | Virtual table hasil query tersimpan          |

> 💡 **Tip:** Trigger sering menyimpan logic "hapus/update otomatis" — misal aplikasi chat yang men-trigger pemindahan pesan ke tabel `deleted_messages` saat user hapus chat. Cek `sql` kolom dari `sqlite_master` untuk baca isi trigger.

### §2.4 Lihat skema lengkap suatu tabel

```sql
.schema nama_tabel
```

atau semua tabel sekaligus:

```sql
.schema
```

Info kolom (nama, tipe, constraint, primary key):

```sql
PRAGMA table_info(nama_tabel);
```

Foreign key relationships (penting untuk rekonstruksi relasi antar tabel):

```sql
PRAGMA foreign_key_list(nama_tabel);
```

### §2.5 Cek metadata database

```sql
PRAGMA database_list;      -- path file & attached DB
PRAGMA user_version;       -- versi skema custom aplikasi, sering dipakai app untuk migrasi
PRAGMA application_id;     -- magic number khusus aplikasi (contoh: WAL apps)
PRAGMA page_size;
PRAGMA page_count;
```

> 💡 `application_id` dan `user_version` sering jadi fingerprint untuk identifikasi aplikasi asal database (misal Signal, Chrome, Firefox punya nilai spesifik).

---

## §3. Ekstraksi & Query Data

### §3.1 Format output biar rapi

```sql
.headers on
.mode column
.width 20 20 40
```

Mode lain yang berguna:

```sql
.mode csv        -- untuk export
.mode json        -- sqlite3 >= 3.33
.mode markdown     -- untuk laporan langsung
.mode box          -- tabel rapi ala box-drawing
```

### §3.2 Dump semua isi tabel

```sql
SELECT * FROM nama_tabel;
```

Export ke CSV untuk analisa lanjut (misal di pandas/Excel):

```bash
sqlite3 -header -csv evidence_work.db "SELECT * FROM messages;" > messages.csv
```

### §3.3 Dump seluruh database jadi SQL script

```bash
sqlite3 evidence_work.db .dump > full_dump.sql
```

> 💡 **Tip forensik:** `.dump` sangat berguna karena ikut men-dump `INSERT` statement mentah — kadang bisa mengungkap kolom yang di-hide di UI aplikasi tapi masih ada datanya.

### §3.4 Query dengan kondisi waktu (umum di CTF)

Kebanyakan aplikasi menyimpan timestamp sebagai:
- Unix epoch (detik) → `datetime(kolom, 'unixepoch')`
- Unix epoch (milidetik) → `datetime(kolom/1000, 'unixepoch')`
- Unix epoch (mikrodetik, khas Chrome/WebKit) → §3.5
- Julian Day (default SQLite `CURRENT_TIMESTAMP`) → `datetime(kolom)`

```sql
SELECT *, datetime(timestamp, 'unixepoch') AS waktu_lokal
FROM messages
ORDER BY timestamp DESC;
```

### §3.5 Timestamp Chrome / WebKit (µs sejak 1601-01-01)

⚠️ Ini beda dari Unix epoch biasa — sering jadi jebakan di CTF forensik browser.

```sql
SELECT *, datetime(last_visit_time/1000000 - 11644473600, 'unixepoch') AS waktu
FROM urls;
```

Referensi cross-check ke §Windows Forensics Bab (FILETIME) kalau kamu perlu bandingkan dengan artifact NTFS/registry yang pakai epoch 1601 juga.

---

## §4. Mencari Data yang Dihapus (Deleted Record Recovery)

Ini bagian paling sering dipakai di CTF forensik SQLite — "user sudah hapus chat/history, temukan isinya".

### §4.1 Konsep dasar

Saat baris (row) di-`DELETE`, SQLite **tidak langsung menghapus data dari file** — halaman (page) tempat data itu berada ditandai sebagai *freelist page* dan bisa ditimpa nanti (overwrite) oleh transaksi berikutnya. Selama belum ditimpa, data lama masih **utuh secara byte** di file.

### §4.2 Cek freelist page

```sql
PRAGMA freelist_count;
```

Kalau nilainya > 0, kemungkinan ada data sisa yang bisa direcover.

### §4.3 Tools recovery otomatis

**Cara 1 — built-in `.recover` (sqlite3 >= 3.29):**

```bash
sqlite3 evidence_work.db ".recover" > recovered.sql
```

`.recover` mencoba rekonstruksi baris dari b-tree yang masih valid termasuk dari freelist, lalu tulis ulang jadi tabel `lost_and_found` kalau skema aslinya tidak diketahui.

**Cara 2 — `sqlparse`/`strings` manual carving:**

```bash
strings -n 8 evidence.db | grep -i "keyword_yang_dicari"
```

⚠️ **Warning:** `strings` tidak tahu batas row/kolom, jadi hasilnya perlu diverifikasi manual dan sering terpotong.

**Cara 3 — tools khusus:**

| Tool | Fungsi |
|------|--------|
| `sqlite_deleted_records_recovery` (Python) | Parse freelist page & unallocated space untuk cari record lama |
| `SQLiteFleet` / `DB Browser for SQLite` (mode Hex/Analyze) | GUI, bisa lihat page raw + freelist |
| `undark` | Recovery WAL-based deleted record |
| Autopsy (SQLite module) | Otomatis parse deleted row saat triage disk image |

### §4.4 Manual page walking (kalau tools otomatis gagal)

```bash
sqlite3 evidence.db "PRAGMA freelist_count;"
xxd -s $(( (PAGE_NUM-1) * PAGE_SIZE )) -l PAGE_SIZE evidence.db
```

Cari struktur cell b-tree (leaf table page header `0x0D`) untuk decode manual payload varint → serial type → value.

> 💡 **Tip:** Kalau butuh super teliti, baca spesifikasi format file resmi di https://sqlite.org/fileformat2.html — page header, cell pointer array, varint encoding semua terdokumentasi presisi di sana. Sangat berguna untuk CTF forensik tingkat lanjut yang minta kamu decode page mentah.

---

## §5. WAL (Write-Ahead Log) & Rollback Journal

### §5.1 Kenapa penting

Kalau kamu menemukan `evidence.db`, cek juga apakah ada file pendamping:

```
evidence.db-wal      # Write-Ahead Log — transaksi belum di-checkpoint
evidence.db-shm      # Shared memory index untuk WAL
evidence.db-journal  # Rollback journal (mode journal lama, bukan WAL)
```

⚠️ **Warning penting:** Data terbaru (termasuk yang "sudah dihapus" dari sudut pandang UI tapi belum checkpoint) sering **hanya ada di file `-wal`**, bukan di `.db` utama! Banyak orang salah cuma analisa `.db` saja dan miss data krusial.

### §5.2 Cara membaca WAL

Cara paling aman — biarkan sqlite3 sendiri yang checkpoint (READ-ONLY, jangan di file asli):

```bash
cp evidence.db evidence.db-wal evidence.db-shm /tmp/work/
cd /tmp/work
sqlite3 evidence.db "PRAGMA wal_checkpoint(FULL);"
sqlite3 evidence.db "SELECT * FROM messages;"
```

Untuk parse WAL manual tanpa checkpoint (murni forensik, tidak modifikasi apapun):

```bash
python3 -m pip install sqlite-wal-parser  # atau tool sejenis
```

Struktur WAL secara umum: WAL header (32 byte) → berulang [frame header 24 byte + page data].

> 💡 **Tip:** Frame di WAL punya salt & checksum sendiri — kalau ada beberapa frame untuk page yang sama, frame **terakhir** adalah versi paling baru. Ini bisa dipakai untuk rekonstruksi *timeline* perubahan data (versi lama vs baru dari row yang sama).

### §5.3 Rollback journal (`-journal`)

Kalau mode jurnal DELETE/TRUNCATE/PERSIST (bukan WAL), file `-journal` berisi snapshot page **sebelum** transaksi terakhir — kebalikan dari WAL. Ini berguna untuk lihat "state sebelum diubah".

---

## §6. Checklist Investigasi SQLite Forensik

- [ ] Verifikasi magic bytes / `file` command
- [ ] Jalankan `PRAGMA integrity_check`
- [ ] Kerja di atas copy, mode `-readonly`
- [ ] `.tables` + `SELECT * FROM sqlite_master` untuk full inventory objek
- [ ] Baca `.schema` tiap tabel relevan — cek foreign key & trigger
- [ ] Cek `PRAGMA user_version` / `application_id` untuk fingerprint aplikasi
- [ ] Konversi semua timestamp ke format yang bisa dibaca — cek jenis epoch-nya (unix/ms/µs Chrome/Julian)
- [ ] Cek keberadaan file `-wal`, `-shm`, `-journal` di sebelah file utama
- [ ] Checkpoint WAL (di copy!) sebelum menyimpulkan "data tidak ada"
- [ ] Cek `PRAGMA freelist_count` untuk potensi recovery data terhapus
- [ ] Jalankan `.recover` kalau curiga ada row terhapus / file corrupt
- [ ] Cross-check hasil dengan `strings` untuk data yang mungkin lolos dari parser SQL

---

## §7. Aplikasi Umum yang Pakai SQLite (Referensi Cepat)

| Aplikasi | File | Tabel Kunci |
|----------|------|--------------|
| Chrome/Edge/Brave History | `History` | `urls`, `visits`, `downloads` |
| Chrome Cookies | `Cookies` | `cookies` |
| Firefox History | `places.sqlite` | `moz_places`, `moz_historyvisits` |
| WhatsApp (Android) | `msgstore.db` (sering terenkripsi, lihat §DB khusus WA) | `message`, `chat`, `jid` |
| Telegram Desktop | `cache4.db` | bervariasi per versi (custom encoding) |
| Signal Desktop | `db.sqlite` (SQLCipher — perlu key!) | `messages`, `conversations` |
| iOS SMS | `sms.db` | `message`, `handle`, `chat` |
| Skype | `main.db` | `Messages`, `Conversations` |
| Android Call Log | `contacts2.db` / `calllog.db` | `calls` |

⚠️ **Warning:** Beberapa (Signal, WhatsApp Android versi baru) menggunakan **SQLCipher**, bukan SQLite biasa — file terenkripsi dan `sqlite3` CLI standar tidak bisa buka langsung. Perlu decrypt key dulu (misal dari Android keystore / backup key) sebelum bisa treat sebagai SQLite biasa.

---

## §8. One-liner Cepat untuk Triase Awal

```bash
# Info cepat semua tabel + jumlah row
for t in $(sqlite3 evidence.db ".tables"); do
  echo "== $t =="; sqlite3 evidence.db "SELECT COUNT(*) FROM $t;"
done

# Cari kolom yang kemungkinan berisi timestamp
sqlite3 evidence.db "SELECT sql FROM sqlite_master WHERE sql LIKE '%time%' OR sql LIKE '%date%';"

# Full-text search isi seluruh database untuk keyword tertentu (mentah, semua tabel)
sqlite3 evidence.db .dump | grep -i "flag{"
```

> 💡 **Tip CTF:** Flag di challenge forensik SQLite sering "disembunyikan" bukan di tabel utama, tapi di: (1) row yang sudah di-`DELETE` (§4), (2) data di `-wal` yang belum checkpoint (§5), (3) kolom BLOB yang butuh decode tambahan (base64/hex/custom encoding), atau (4) trigger/view yang isinya bukan data biasa tapi SQL string berisi clue.

---

**Referensi lanjut:**
- SQLite File Format spec: https://sqlite.org/fileformat2.html
- WAL format spec: https://sqlite.org/fileformat2.html#walformat
- Cross-ref: Windows Forensics Bab (FILETIME epoch), Network Forensics (kalau SQLite ditemukan dalam PCAP transfer/carving)
