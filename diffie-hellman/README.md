# Mini Handshake HTTPS — Diffie-Hellman & ElGamal

Simulasi terminal yang meniru proses saat browser membuka situs `https://`.
Setiap tahap Diffie-Hellman dan ElGamal ditampilkan satu per satu (rumus, angka, hasil).
Semua perhitungan kriptografi ditulis sendiri **tanpa library kriptografi**.

## Cara menjalankan

```bash
python main.py
```

Butuh Python 3.8 ke atas. Tidak perlu `pip install` apa pun.
Di setiap input angka rahasia, ketik angka sendiri **atau** tekan Enter supaya dipilih acak.

## Struktur file

| File | Isi |
|---|---|
| `matematika.py` | Fungsi dasar: cek prima, pangkat modulo (square-and-multiply), faktor prima, cek/cari generator, FPB, invers modulo (Fermat dan Extended Euclid) |
| `diffie_hellman.py` | Tahapan DH: `buat_kunci_publik`, `hitung_kunci_sesi`, serta enkripsi teks sederhana memakai kunci sesi |
| `elgamal.py` | Tahapan ElGamal: pembuatan kunci, enkripsi (`hitung_c1`, `hitung_s_pengirim`, `hitung_c2`), dekripsi (`hitung_s_penerima`, `pulihkan_pesan`), dan tanda tangan digital (`hitung_r`, `hitung_s_tanda_tangan`, `verifikasi`) |
| `main.py` | Menu, tampilan, dan skenario simulasi |

## Menu

| No | Menu | Yang dipelajari | Padanan di dunia nyata |
|---|---|---|---|
| 1 | Handshake HTTPS normal | Seluruh tahap Diffie-Hellman sampai kunci sesi sama, lalu dipakai mengenkripsi data login | ClientHello/ServerHello di TLS 1.3 (DHE/ECDHE) |
| 2 | Kirim data dengan ElGamal | Pembuatan kunci, enkripsi, dekripsi, serta hubungan ElGamal dengan DH | Enkripsi memakai kunci publik di sertifikat server (seperti TLS versi lama dan GnuPG) |
| 3 | Serangan Man-in-the-Middle | Kenapa DH tanpa autentikasi bisa dibobol; threat actor membaca **dan mengubah** perintah transfer | Wi-Fi publik palsu; dicegah oleh sertifikat dan tanda tangan digital |
| 4 | Threat actor pasif (brute force) | Masalah logaritma diskrit; kenapa p harus sangat besar | p 2048-bit pada grup standar RFC 7919 |
| 5 | Ganti parameter publik | Syarat p prima dan g generator | — |
| 6 | Handshake aman (DH + tanda tangan ElGamal) | Server menandatangani B; dua cara MITM oleh threat actor sama-sama ditolak browser | Sertifikat CA + CertificateVerify di TLS 1.3 |

## Rumus ringkas

**Diffie-Hellman**
```
A = g^a mod p          B = g^b mod p
K = B^a mod p = A^b mod p = g^(ab) mod p
```

**ElGamal**
```
Kunci     : y = g^x mod p                (x privat, y publik)
Enkripsi  : c1 = g^k mod p,  s = y^k mod p,  c2 = m·s mod p
Dekripsi  : s = c1^x mod p,  m = c2·s^(-1) mod p,  s^(-1) = s^(p-2) mod p
```

**Tanda tangan ElGamal** (k acak dengan fpb(k, p-1) = 1)
```
Tanda tangan : r = g^k mod p,  s = (h - x·r)·k^(-1) mod (p-1)
Verifikasi   : sah jika g^h mod p == y^r · r^s mod p
```

## Batasan (sengaja, demi kemudahan belajar)

- Angka dibuat kecil (default `p = 467`) agar bisa dicek manual. Di dunia nyata panjangnya 2048 bit.
- Enkripsi dengan kunci sesi DH memakai rumus sederhana `c = m·K mod p` per karakter.
  TLS asli memakai AES-GCM atau ChaCha20. Karena rumusnya sederhana, karakter yang sama
  menghasilkan ciphertext yang sama (beda dengan ElGamal yang memakai `k` baru).
- Tanda tangan di menu 6 langsung atas nilai B. Di dunia nyata yang ditandatangani adalah
  hash (misalnya SHA-256) dari seluruh pesan handshake.
- Modul `random` hanya dipakai untuk memilih angka acak. Di sistem nyata dipakai
  pembangkit acak yang aman secara kriptografis.
