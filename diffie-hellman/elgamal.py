"""
elgamal.py
Tahapan ElGamal, satu fungsi untuk setiap tahap.

Alur singkat:
  1. Pembuatan kunci (penerima/server):
       kunci privat x (rahasia), kunci publik y = g^x mod p
  2. Enkripsi (pengirim/browser), pesan m dan angka acak k:
       c1 = g^k mod p
       s  = y^k mod p          <- "kunci bersama" versi pengirim
       c2 = m x s mod p
     yang dikirim: pasangan (c1, c2)
  3. Dekripsi (penerima/server):
       s   = c1^x mod p        <- "kunci bersama" versi penerima (sama!)
       s^-1 = s^(p-2) mod p
       m   = c2 x s^-1 mod p
"""

from matematika import invers_mod, invers_mod_euclid, pangkat_mod


# ---------- Tahap 1: pembuatan kunci ----------

def buat_kunci_publik(x, p, g):
    """y = g^x mod p"""
    return pangkat_mod(g, x, p)


# ---------- Tahap 2: enkripsi ----------

def hitung_c1(k, p, g):
    """c1 = g^k mod p (dikirim agar penerima bisa menghitung s)."""
    return pangkat_mod(g, k, p)


def hitung_s_pengirim(y, k, p):
    """s = y^k mod p (kunci penyamar, TIDAK dikirim)."""
    return pangkat_mod(y, k, p)


def hitung_c2(m, s, p):
    """c2 = m x s mod p (pesan yang sudah 'disamarkan' oleh s)."""
    return (m * s) % p


def enkripsi(m, p, g, y, k):
    """Gabungan tahap enkripsi. Mengembalikan pasangan (c1, c2)."""
    c1 = hitung_c1(k, p, g)
    s = hitung_s_pengirim(y, k, p)
    c2 = hitung_c2(m, s, p)
    return c1, c2


# ---------- Tahap 3: dekripsi ----------

def hitung_s_penerima(c1, x, p):
    """s = c1^x mod p. Sama dengan s pengirim karena (g^k)^x = (g^x)^k."""
    return pangkat_mod(c1, x, p)


def pulihkan_pesan(c2, s, p):
    """m = c2 x s^-1 mod p"""
    return (c2 * invers_mod(s, p)) % p


def dekripsi(c1, c2, p, x):
    """Gabungan tahap dekripsi. Mengembalikan pesan asli m."""
    s = hitung_s_penerima(c1, x, p)
    return pulihkan_pesan(c2, s, p)


# =====================================================================
# Tanda tangan digital ElGamal
# Membuktikan bahwa sebuah nilai h benar-benar dikirim oleh pemilik kunci
# privat x. Dipakai untuk mencegah serangan Man-in-the-Middle.
#   Tanda tangan : r = g^k mod p,  s = (h - x.r) . k^-1 mod (p-1)
#   Verifikasi   : sah jika  g^h mod p == y^r . r^s mod p
# =====================================================================

def hitung_r(k, p, g):
    """r = g^k mod p (k acak dengan fpb(k, p-1) = 1)."""
    return pangkat_mod(g, k, p)


def hitung_s_tanda_tangan(h, x, r, k, p):
    """s = (h - x.r) . k^-1 mod (p-1). Perhatikan: modulusnya p-1, bukan p."""
    k_invers = invers_mod_euclid(k, p - 1)
    return ((h - x * r) * k_invers) % (p - 1)


def tanda_tangan(h, p, g, x, k):
    """Gabungan tahap tanda tangan. Mengembalikan pasangan (r, s)."""
    r = hitung_r(k, p, g)
    s = hitung_s_tanda_tangan(h, x, r, k, p)
    return r, s


def ruas_kiri_verifikasi(h, p, g):
    """g^h mod p"""
    return pangkat_mod(g, h, p)


def ruas_kanan_verifikasi(r, s, p, y):
    """y^r . r^s mod p. Jika sah, hasilnya g^(x.r + k.s) = g^h."""
    return (pangkat_mod(y, r, p) * pangkat_mod(r, s, p)) % p


def verifikasi(h, r, s, p, g, y):
    """Tanda tangan sah jika 0 < r < p dan kedua ruas sama."""
    if not 0 < r < p:
        return False
    return ruas_kiri_verifikasi(h, p, g) == ruas_kanan_verifikasi(r, s, p, y)
