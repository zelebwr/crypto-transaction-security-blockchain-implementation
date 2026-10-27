"""
matematika.py
Fungsi matematika dasar yang dibutuhkan Diffie-Hellman dan ElGamal.
Semua ditulis sendiri, TANPA library kriptografi.
"""


def cek_prima(n):
    """Mengecek apakah n bilangan prima (coba bagi dari 2 sampai akar n)."""
    if n < 2:
        return False
    pembagi = 2
    while pembagi * pembagi <= n:
        if n % pembagi == 0:
            return False
        pembagi += 1
    return True


def pangkat_mod(basis, eksponen, modulus):
    """
    Menghitung (basis ^ eksponen) mod modulus dengan metode Square-and-Multiply.

    Kenapa tidak langsung basis ** eksponen % modulus?
    Di dunia nyata eksponennya ratusan digit, sehingga basis ** eksponen menjadi
    angka raksasa. Square-and-multiply selalu melakukan mod di setiap langkah,
    jadi angkanya tetap kecil.
    """
    hasil = 1
    basis = basis % modulus
    while eksponen > 0:
        if eksponen % 2 == 1:                  # bit paling kanan = 1 -> kalikan
            hasil = (hasil * basis) % modulus
        basis = (basis * basis) % modulus      # kuadratkan basis
        eksponen = eksponen // 2               # geser ke bit berikutnya
    return hasil


def langkah_pangkat_mod(basis, eksponen, modulus):
    """
    Sama seperti pangkat_mod, tetapi mencatat setiap langkah agar bisa ditampilkan.
    Mengembalikan daftar (bit, basis_saat_ini, hasil_sementara).
    """
    langkah = []
    hasil = 1
    basis = basis % modulus
    while eksponen > 0:
        bit = eksponen % 2
        if bit == 1:
            hasil = (hasil * basis) % modulus
        langkah.append((bit, basis, hasil))
        basis = (basis * basis) % modulus
        eksponen = eksponen // 2
    return langkah


def faktor_prima(n):
    """Mengembalikan daftar faktor prima unik dari n. Contoh: 12 -> [2, 3]."""
    faktor = []
    pembagi = 2
    while pembagi * pembagi <= n:
        if n % pembagi == 0:
            faktor.append(pembagi)
            while n % pembagi == 0:
                n = n // pembagi
        pembagi += 1
    if n > 1:
        faktor.append(n)
    return faktor


def adalah_generator(g, p):
    """
    g disebut generator (akar primitif) modulo p jika g^1, g^2, ..., g^(p-1)
    menghasilkan SEMUA angka 1 sampai p-1.

    Cara cepat mengeceknya: untuk setiap faktor prima q dari (p-1),
    g^((p-1)/q) mod p TIDAK BOLEH sama dengan 1.
    """
    if not 2 <= g < p:
        return False
    for q in faktor_prima(p - 1):
        if pangkat_mod(g, (p - 1) // q, p) == 1:
            return False
    return True


def cari_generator(p):
    """Mencari generator terkecil untuk bilangan prima p."""
    for g in range(2, p):
        if adalah_generator(g, p):
            return g
    return None


def fpb(a, b):
    """Faktor Persekutuan Terbesar dengan algoritma Euclid."""
    while b != 0:
        a, b = b, a % b
    return a


def invers_mod_euclid(a, n):
    """
    Mencari a^-1 mod n dengan Extended Euclid.
    Berbeda dengan invers_mod (Fermat), cara ini tetap berlaku walaupun n
    BUKAN prima (misalnya n = p-1), asalkan fpb(a, n) = 1.
    Mengembalikan None jika invers tidak ada.
    """
    r_lama, r = a % n, n
    t_lama, t = 1, 0
    while r != 0:
        hasil_bagi = r_lama // r
        r_lama, r = r, r_lama - hasil_bagi * r
        t_lama, t = t, t_lama - hasil_bagi * t
    if r_lama != 1:
        return None
    return t_lama % n


def invers_mod(a, p):
    """
    Mencari a^-1 mod p, yaitu angka yang jika dikali a hasilnya 1 (mod p).

    Memakai Teorema Kecil Fermat (berlaku jika p prima):
        a^(p-1) = 1 (mod p)  ->  a x a^(p-2) = 1 (mod p)
    jadi a^-1 = a^(p-2) mod p.
    """
    return pangkat_mod(a, p - 2, p)
