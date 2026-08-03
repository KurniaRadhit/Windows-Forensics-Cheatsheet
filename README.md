# 🧠 Windows Disk Forensics Cheatsheet
> Untuk HTB Sherlock / CTF DFIR — FTK Imager, KAPE, PECmd, EvtxECmd, MFTECmd, RBCmd, SQLECmd, dll.

---

## 📌 Daftar Isi — Bab 1

- [Bab 1 — Struktur Windows & Filesystem](#bab-1--struktur-windows--filesystem)
  - [1.1 Struktur Drive & Partisi](#11-struktur-drive--partisi)
    - [1.1.1 Physical Disk vs Partition vs Volume](#111-physical-disk-vs-partition-vs-volume)
    - [1.1.2 MBR vs GPT](#112-mbr-vs-gpt)
    - [1.1.3 Partisi Umum di Disk Windows](#113-partisi-umum-di-disk-windows)
    - [1.1.4 VBR (Volume Boot Record)](#114-vbr-volume-boot-record)
    - [1.1.5 Cara Analisa di FTK Imager / KAPE](#115-cara-analisa-di-ftk-imager--kape)
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

*(Bab 2 dan seterusnya menyusul — akan fokus ke NTFS internals, $MFT, Registry, EVTX, dst.)*

---
