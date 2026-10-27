"""
diffie_hellman.py
Tahapan Diffie-Hellman, satu fungsi untuk setiap tahap.

Alur singkat:
  1. Sepakati parameter publik p (prima) dan g (generator).
  2. Masing-masing pihak memilih angka rahasia (a untuk browser, b untuk server).
  3. Hitung kunci publik:  A = g^a mod p,  B = g^b mod p   -> saling dikirim.
  4. Hitung kunci sesi:    K = B^a mod p = A^b mod p       -> hasilnya SAMA.
"""

from matematika import pangkat_mod, invers_mod


def buat_kunci_publik(rahasia, p, g):
    """Tahap 3: kunci publik = g^rahasia mod p."""
    return pangkat_mod(g, rahasia, p)


def hitung_kunci_sesi(kunci_publik_lawan, rahasia_sendiri, p):
    """
    Tahap 4: kunci sesi = (kunci publik lawan)^(rahasia sendiri) mod p.
    Hasilnya sama untuk kedua pihak karena (g^b)^a = (g^a)^b = g^(ab).
    """
    return pangkat_mod(kunci_publik_lawan, rahasia_sendiri, p)


# ---------------------------------------------------------------------------
# Enkripsi sederhana memakai kunci sesi K.
# Di TLS asli, kunci sesi dipakai oleh AES/ChaCha20. Di sini kita pakai rumus
# sederhana  c = m x K mod p  supaya fokus tetap pada Diffie-Hellman.
# ---------------------------------------------------------------------------

def enkripsi_teks(teks, K, p):
    """Setiap karakter diubah ke kode ASCII (m), lalu c = m x K mod p."""
    return [(ord(huruf) * K) % p for huruf in teks]


def dekripsi_teks(daftar_cipher, K, p):
    """Kebalikan enkripsi: m = c x K^-1 mod p, lalu kode ASCII diubah ke karakter."""
    K_invers = invers_mod(K, p)
    return "".join(chr((c * K_invers) % p) for c in daftar_cipher)
