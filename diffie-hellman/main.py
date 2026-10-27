"""
main.py
Mini Handshake HTTPS: simulasi untuk memahami Diffie-Hellman dan ElGamal
seperti yang terjadi saat browser membuka situs https://.

Jalankan:  python main.py
"""

import os
import random  # hanya untuk memilih angka acak, BUKAN library kriptografi

import diffie_hellman as dh
import elgamal
from matematika import (adalah_generator, cari_generator, cek_prima, faktor_prima, fpb,
                        invers_mod, invers_mod_euclid, langkah_pangkat_mod, pangkat_mod)

os.system("")  # trik kecil agar warna ANSI juga muncul di terminal Windows

# ---------- Warna dan label tokoh ----------
RESET = "\033[0m"
TEBAL = "\033[1m"
REDUP = "\033[2m"
MERAH = "\033[91m"
HIJAU = "\033[92m"
KUNING = "\033[93m"
BIRU = "\033[94m"
CYAN = "\033[96m"

BROWSER = f"{BIRU}{TEBAL}[BROWSER]{RESET}"
SERVER = f"{HIJAU}{TEBAL}[SERVER bank.com]{RESET}"
THREAT = f"{MERAH}{TEBAL}[THREAT ACTOR]{RESET}"
JARINGAN = f"{KUNING}{TEBAL}[JARINGAN]{RESET}"

# ---------- Parameter publik ----------
# p = bilangan prima, g = generator. Sengaja kecil agar bisa dicek manual.
# p harus > 255 supaya setiap karakter (kode 0-255) bisa menjadi satu angka m < p.
P = 467
G = 2

MAKS_BARIS = 6  # jumlah baris tabel yang ditampilkan detail


# =====================================================================
# Fungsi bantu tampilan
# =====================================================================

def jeda():
    input(f"\n{REDUP}   [Enter] lanjut...{RESET}")


def judul(teks):
    print("\n" + "=" * 70)
    print(TEBAL + teks.center(70) + RESET)
    print("=" * 70)


def tahap(nomor, teks):
    print(f"\n{CYAN}{TEBAL}[TAHAP {nomor}] {teks}{RESET}")


def catatan(teks):
    print(f"   {KUNING}Catatan:{RESET} {teks}")


def minta_rahasia(label, bawah, atas):
    """Minta angka dari pengguna. Enter kosong = dipilih acak."""
    while True:
        jawab = input(f"   Masukkan {label} ({bawah}-{atas}, Enter = acak): ").strip()
        if jawab == "":
            angka = random.randint(bawah, atas)
            print(f"   -> dipilih acak: {angka}")
            return angka
        if jawab.isdigit() and bawah <= int(jawab) <= atas:
            return int(jawab)
        print(f"   {MERAH}Masukkan angka antara {bawah} dan {atas}.{RESET}")


def minta_pesan(bawaan):
    """Minta pesan dari pengguna. Enter kosong = pakai pesan bawaan."""
    while True:
        jawab = input(f'   Pesan (Enter = "{bawaan}"): ')
        pesan = jawab if jawab != "" else bawaan
        if all(ord(huruf) < 256 for huruf in pesan):
            return pesan
        print(f"   {MERAH}Gunakan huruf/angka/simbol biasa (ASCII) saja.{RESET}")


def tampilkan_pangkat(basis, eksponen):
    """Menampilkan tabel square-and-multiply untuk basis^eksponen mod P."""
    print(f"   Square-and-multiply {basis}^{eksponen} mod {P}, "
          f"eksponen biner = {bin(eksponen)[2:]} (dibaca dari kanan)")
    print(f"   {REDUP}{'bit':>6} | {'basis saat ini':>14} | {'hasil sementara':>15}{RESET}")
    for bit, basis_saat_ini, hasil in langkah_pangkat_mod(basis, eksponen, P):
        aksi = "kalikan ke hasil" if bit == 1 else "lewati"
        print(f"   {bit:>6} | {basis_saat_ini:>14} | {hasil:>15}   {REDUP}({aksi}){RESET}")


def tampilkan_parameter_publik():
    tahap(1, "Parameter publik disepakati (boleh diketahui SIAPA PUN)")
    print(f"   p = {P}  -> bilangan prima? {'YA' if cek_prima(P) else 'TIDAK'}")
    print(f"   g = {G}  -> generator modulo p")
    faktor = faktor_prima(P - 1)
    print(f"   Cek generator: p-1 = {P - 1}, faktor primanya {faktor}")
    for q in faktor:
        hasil = pangkat_mod(G, (P - 1) // q, P)
        print(f"     g^((p-1)/{q}) = {G}^{(P - 1) // q} mod {P} = {hasil}  (bukan 1 -> lolos)")
    catatan("Di TLS asli, p dan g diambil dari grup standar (RFC 7919), p sepanjang 2048 bit.")


def tampilkan_tabel_sesi(pesan, cipher, K):
    """Tabel enkripsi c = m x K mod p untuk beberapa karakter pertama."""
    print(f"   {REDUP}{'karakter':>8} | {'m':>4} | perhitungan c{RESET}")
    for i in range(min(len(pesan), MAKS_BARIS)):
        m = ord(pesan[i])
        print(f"   {repr(pesan[i]):>8} | {m:>4} | {m} x {K} mod {P} = {cipher[i]}")
    if len(pesan) > MAKS_BARIS:
        print(f"   ... ({len(pesan) - MAKS_BARIS} karakter lainnya dihitung dengan cara yang sama)")


def ringkas(daftar):
    """Menampilkan daftar angka panjang secara ringkas."""
    if len(daftar) <= 10:
        return str(daftar)
    return str(daftar[:10])[:-1] + f", ... (total {len(daftar)})]"


# =====================================================================
# Menu 1: handshake HTTPS normal (Diffie-Hellman)
# =====================================================================

def menu_handshake():
    judul("1. HANDSHAKE HTTPS NORMAL (DIFFIE-HELLMAN)")
    print("   Skenario: kamu membuka https://bank.com lalu login.")
    print("   Browser dan server harus punya KUNCI SESI yang sama")
    print("   tanpa pernah mengirim kunci itu lewat jaringan.")
    tampilkan_parameter_publik()
    jeda()

    tahap(2, "ClientHello: browser membuat kunci publik sementara")
    a = minta_rahasia("rahasia browser a", 2, P - 2)
    A = dh.buat_kunci_publik(a, P, G)
    print(f"   {BROWSER} A = g^a mod p = {G}^{a} mod {P}")
    tampilkan_pangkat(G, a)
    print(f"   {BROWSER} A = {TEBAL}{A}{RESET} -> dikirim ke server bersama ClientHello")
    print(f"   {BROWSER} a = {a} disimpan sendiri, TIDAK dikirim")
    jeda()

    tahap(3, "ServerHello: server membuat kunci publik sementara")
    b = minta_rahasia("rahasia server b", 2, P - 2)
    B = dh.buat_kunci_publik(b, P, G)
    print(f"   {SERVER} B = g^b mod p = {G}^{b} mod {P}")
    tampilkan_pangkat(G, b)
    print(f"   {SERVER} B = {TEBAL}{B}{RESET} -> dikirim ke browser bersama ServerHello")
    print(f"   {SERVER} b = {b} disimpan sendiri, TIDAK dikirim")
    jeda()

    tahap(4, "Apa yang terlihat oleh penyadap di jaringan?")
    print(f"   {THREAT} melihat   : p = {P}, g = {G}, A = {A}, B = {B}")
    print(f"   {THREAT} TIDAK tahu: a, b, dan kunci sesi K")
    jeda()

    tahap(5, "Masing-masing menghitung kunci sesi")
    K_browser = dh.hitung_kunci_sesi(B, a, P)
    K_server = dh.hitung_kunci_sesi(A, b, P)
    print(f"   {BROWSER} K = B^a mod p = {B}^{a} mod {P} = {TEBAL}{K_browser}{RESET}")
    print(f"   {SERVER} K = A^b mod p = {A}^{b} mod {P} = {TEBAL}{K_server}{RESET}")
    if K_browser == K_server:
        print(f"   {HIJAU}{TEBAL}BERHASIL: kunci sesi sama = {K_browser}{RESET}")
    print("   Kenapa sama?  B^a = (g^b)^a = g^(ab) = (g^a)^b = A^b")
    jeda()

    tahap(6, "Browser mengirim data login yang terenkripsi")
    pesan = minta_pesan("POST /login user=budi&password=rahasia123")
    cipher = dh.enkripsi_teks(pesan, K_browser, P)
    print("   Rumus tiap karakter: c = m x K mod p   (m = kode ASCII karakter)")
    tampilkan_tabel_sesi(pesan, cipher, K_browser)
    print(f"   {JARINGAN} terkirim: {ringkas(cipher)}")
    print(f"   {THREAT} hanya melihat deretan angka di atas -> tidak bisa dibaca")
    catatan("Di TLS asli, kunci sesi dipakai algoritma simetris seperti AES-GCM.")
    jeda()

    tahap(7, "Server mendekripsi data")
    K_invers = invers_mod(K_server, P)
    print(f"   {SERVER} K^-1 = K^(p-2) mod p = {K_server}^{P - 2} mod {P} = {K_invers}")
    print(f"   {SERVER} rumus tiap karakter: m = c x K^-1 mod p")
    c0 = cipher[0]
    print(f"   {SERVER} contoh: {c0} x {K_invers} mod {P} = {(c0 * K_invers) % P}"
          f" -> karakter {chr((c0 * K_invers) % P)!r}")
    hasil = dh.dekripsi_teks(cipher, K_server, P)
    print(f"   {SERVER} pesan diterima: {HIJAU}{TEBAL}{hasil}{RESET}")
    jeda()


# =====================================================================
# Menu 2: kirim data dengan ElGamal
# =====================================================================

def menu_elgamal():
    judul("2. KIRIM DATA DENGAN ELGAMAL (KUNCI PUBLIK DI SERTIFIKAT)")
    print("   Skenario: server bank.com punya pasangan kunci TETAP. Kunci publiknya")
    print("   ditaruh di sertifikat. Browser memakai kunci publik itu untuk")
    print("   mengenkripsi data yang hanya bisa dibuka server.")
    print("   (Mirip TLS versi lama: browser mengenkripsi rahasia dengan kunci publik server.)")
    tampilkan_parameter_publik()
    jeda()

    tahap(2, "Pembuatan kunci oleh server")
    x = minta_rahasia("kunci privat server x", 2, P - 2)
    y = elgamal.buat_kunci_publik(x, P, G)
    print(f"   {SERVER} y = g^x mod p = {G}^{x} mod {P}")
    tampilkan_pangkat(G, x)
    print(f"   {SERVER} kunci privat x = {x}  (disimpan, TIDAK pernah dikirim)")
    print(f"   {SERVER} kunci publik y = {TEBAL}{y}{RESET}")
    jeda()

    tahap(3, "Server mengirim sertifikat ke browser")
    print("   +------------------ SERTIFIKAT ------------------+")
    print(f"   |  Domain       : {'bank.com':<31}|")
    print(f"   |  Algoritma    : {'ElGamal':<31}|")
    print(f"   |  Kunci publik : {f'p = {P}, g = {G}, y = {y}':<31}|")
    print("   +------------------------------------------------+")
    print(f"   {BROWSER} menyimpan kunci publik server: (p, g, y) = ({P}, {G}, {y})")
    jeda()

    tahap(4, "Enkripsi oleh browser")
    pesan = minta_pesan("nomor kartu=4111-2222-3333-4444")
    print("   Setiap karakter dienkripsi memakai angka acak k yang BARU.")
    print("   Rumus:  c1 = g^k mod p    s = y^k mod p    c2 = m x s mod p")

    m = ord(pesan[0])
    print(f"\n   Contoh detail karakter pertama {pesan[0]!r} (m = {m}):")
    k = minta_rahasia("angka acak k", 2, P - 2)
    c1 = elgamal.hitung_c1(k, P, G)
    s = elgamal.hitung_s_pengirim(y, k, P)
    c2 = elgamal.hitung_c2(m, s, P)
    print(f"   {BROWSER} c1 = g^k mod p = {G}^{k} mod {P} = {c1}")
    print(f"   {BROWSER} s  = y^k mod p = {y}^{k} mod {P} = {s}   (TIDAK dikirim)")
    print(f"   {BROWSER} c2 = m x s mod p = {m} x {s} mod {P} = {c2}")
    print(f"   {BROWSER} hasil: ({c1}, {c2})")

    cipher = [(c1, c2)]
    daftar_k = [k]
    for huruf in pesan[1:]:
        k_baru = random.randint(2, P - 2)
        cipher.append(elgamal.enkripsi(ord(huruf), P, G, y, k_baru))
        daftar_k.append(k_baru)

    print(f"\n   {REDUP}{'karakter':>8} | {'m':>4} | {'k':>6} | {'c1':>6} | {'c2':>6}{RESET}")
    for i in range(min(len(pesan), MAKS_BARIS)):
        print(f"   {repr(pesan[i]):>8} | {ord(pesan[i]):>4} | {daftar_k[i]:>6} | "
              f"{cipher[i][0]:>6} | {cipher[i][1]:>6}")
    if len(pesan) > MAKS_BARIS:
        print(f"   ... ({len(pesan) - MAKS_BARIS} karakter lainnya)")
    jeda()

    tahap(5, "Apa yang terlihat di jaringan?")
    print(f"   {JARINGAN} terkirim: {ringkas(cipher)}")
    print(f"   {THREAT} melihat (c1, c2) dan kunci publik y = {y}, tapi tidak tahu x maupun k")
    # tunjukkan bahwa karakter yang sama menghasilkan ciphertext berbeda
    for i in range(len(pesan)):
        j = pesan.find(pesan[i], i + 1)
        if j != -1:
            print(f"   Karakter {pesan[i]!r} muncul dua kali, tapi ciphertext-nya berbeda:")
            print(f"     posisi {i + 1}: {cipher[i]}   posisi {j + 1}: {cipher[j]}")
            print("   -> karena k selalu baru, threat actor tidak bisa menebak dari pola.")
            break
    jeda()

    tahap(6, "Dekripsi oleh server")
    print("   Rumus:  s = c1^x mod p    s^-1 = s^(p-2) mod p    m = c2 x s^-1 mod p")
    c1, c2 = cipher[0]
    s = elgamal.hitung_s_penerima(c1, x, P)
    s_invers = invers_mod(s, P)
    m = elgamal.pulihkan_pesan(c2, s, P)
    print(f"\n   Contoh detail karakter pertama ({c1}, {c2}):")
    print(f"   {SERVER} s    = c1^x mod p = {c1}^{x} mod {P} = {s}   (sama dengan s milik browser!)")
    print(f"   {SERVER} s^-1 = {s}^{P - 2} mod {P} = {s_invers}")
    print(f"   {SERVER} m    = c2 x s^-1 mod p = {c2} x {s_invers} mod {P} = {m} -> {chr(m)!r}")
    hasil = "".join(chr(elgamal.dekripsi(c1, c2, P, x)) for c1, c2 in cipher)
    print(f"   {SERVER} pesan utuh: {HIJAU}{TEBAL}{hasil}{RESET}")
    jeda()

    tahap(7, "Hubungan ElGamal dengan Diffie-Hellman")
    print("   ElGamal sebenarnya = Diffie-Hellman + 'menyamarkan' pesan dengan kunci bersama.")
    print(f"   {REDUP}{'Diffie-Hellman':<28} | ElGamal{RESET}")
    print(f"   {'rahasia server b':<28} | kunci privat x")
    print(f"   {'B = g^b mod p':<28} | kunci publik y = g^x mod p")
    print(f"   {'rahasia browser a':<28} | angka acak k")
    print(f"   {'A = g^a mod p':<28} | c1 = g^k mod p")
    print(f"   {'K = g^(ab) mod p':<28} | s = g^(xk) mod p")
    print(f"   {'(K dipakai enkripsi)':<28} | c2 = m x s mod p")
    jeda()


# =====================================================================
# Menu 3: serangan Man-in-the-Middle
# =====================================================================

def menu_mitm():
    judul("3. SERANGAN MAN-IN-THE-MIDDLE OLEH THREAT ACTOR")
    print("   Skenario: kamu memakai Wi-Fi gratis di kafe. Ternyata Wi-Fi itu dipasang")
    print("   threat actor, jadi semua paket browser <-> server lewat perangkatnya.")
    print("   Di sini Diffie-Hellman dipakai TANPA sertifikat dan tanda tangan digital.")
    tampilkan_parameter_publik()
    jeda()

    tahap(2, "Browser mengirim A, tapi dicegat")
    a = minta_rahasia("rahasia browser a", 2, P - 2)
    A = dh.buat_kunci_publik(a, P, G)
    print(f"   {BROWSER} kirim A = {G}^{a} mod {P} = {A} ke server...")
    t1 = minta_rahasia("rahasia threat actor t1", 2, P - 2)
    T1 = dh.buat_kunci_publik(t1, P, G)
    print(f"   {THREAT} mencegat A = {A}, lalu membuat kunci palsu T1 = {G}^{t1} mod {P} = {T1}")
    print(f"   {THREAT} meneruskan T1 = {T1} ke server, menyamar sebagai browser")
    jeda()

    tahap(3, "Server membalas B, juga dicegat")
    b = minta_rahasia("rahasia server b", 2, P - 2)
    B = dh.buat_kunci_publik(b, P, G)
    print(f"   {SERVER} kirim B = {G}^{b} mod {P} = {B} ke browser...")
    t2 = minta_rahasia("rahasia threat actor t2", 2, P - 2)
    T2 = dh.buat_kunci_publik(t2, P, G)
    print(f"   {THREAT} mencegat B = {B}, lalu membuat kunci palsu T2 = {G}^{t2} mod {P} = {T2}")
    print(f"   {THREAT} meneruskan T2 = {T2} ke browser, menyamar sebagai server")
    jeda()

    tahap(4, "Kunci sesi yang terbentuk")
    K1_browser = dh.hitung_kunci_sesi(T2, a, P)
    K1_threat = dh.hitung_kunci_sesi(A, t2, P)
    K2_server = dh.hitung_kunci_sesi(T1, b, P)
    K2_threat = dh.hitung_kunci_sesi(B, t1, P)
    print(f"   {BROWSER} K1 = T2^a mod p = {T2}^{a} mod {P} = {K1_browser}")
    print(f"   {THREAT} K1 = A^t2 mod p = {A}^{t2} mod {P} = {K1_threat}")
    print(f"   {SERVER} K2 = T1^b mod p = {T1}^{b} mod {P} = {K2_server}")
    print(f"   {THREAT} K2 = B^t1 mod p = {B}^{t1} mod {P} = {K2_threat}")
    print("\n   Browser dan server MENGIRA saling berbagi kunci. Kenyataannya:")
    print(f"     Browser <--K1={K1_browser}--> THREAT ACTOR <--K2={K2_server}--> Server")
    jeda()

    tahap(5, "Browser mengirim perintah transfer")
    pesan = minta_pesan("POST /transfer ke=Budi&jumlah=500000")
    cipher1 = dh.enkripsi_teks(pesan, K1_browser, P)
    print(f"   {BROWSER} kirim (dienkripsi dengan K1): {ringkas(cipher1)}")
    dibaca = dh.dekripsi_teks(cipher1, K1_threat, P)
    print(f"   {THREAT} dekripsi dengan K1 -> {MERAH}{TEBAL}{dibaca}{RESET}")
    if "Budi" in dibaca:
        palsu = dibaca.replace("Budi", "Hacker")
        print(f"   {THREAT} mengubah tujuan transfer -> {MERAH}{TEBAL}{palsu}{RESET}")
    else:
        palsu = dibaca
        print(f"   {THREAT} meneruskan pesan apa adanya (tapi sudah membacanya)")
    cipher2 = dh.enkripsi_teks(palsu, K2_threat, P)
    print(f"   {THREAT} enkripsi ulang dengan K2, kirim ke server: {ringkas(cipher2)}")
    diterima = dh.dekripsi_teks(cipher2, K2_server, P)
    print(f"   {SERVER} dekripsi dengan K2 -> {diterima}")
    print(f"   {SERVER} tidak curiga sama sekali, perintah diproses!")
    jeda()

    tahap(6, "Kenapa bisa terjadi, dan bagaimana HTTPS asli mencegahnya?")
    print("   Masalahnya: Diffie-Hellman TIDAK membuktikan identitas.")
    print("   Browser tidak bisa membedakan B asli dari server dengan T2 palsu.")
    print()
    print("   Solusi di HTTPS asli:")
    print("   1. Server punya SERTIFIKAT digital yang ditandatangani Certificate Authority (CA).")
    print("   2. Server MENANDATANGANI nilai B dengan kunci privatnya (CertificateVerify di TLS 1.3).")
    print("   3. Browser memverifikasi tanda tangan itu memakai kunci publik di sertifikat.")
    print("   4. Threat actor tidak punya kunci privat server -> tidak bisa memalsukan tanda tangan.")
    print("      Browser akan menampilkan peringatan 'Your connection is not private'.")
    print(f"\n   {HIJAU}Simulasi solusi ini ada di menu 6.{RESET}")
    jeda()


# =====================================================================
# Menu 6: handshake aman dengan tanda tangan digital ElGamal
# =====================================================================

def minta_k_tanda_tangan():
    """k untuk tanda tangan harus memenuhi fpb(k, p-1) = 1 agar k punya invers mod (p-1)."""
    while True:
        jawab = input(f"   Masukkan angka acak k (2-{P - 2}, fpb(k, {P - 1}) harus 1, "
                      f"Enter = acak): ").strip()
        if jawab == "":
            k = random.randint(2, P - 2)
            while fpb(k, P - 1) != 1:
                k = random.randint(2, P - 2)
            print(f"   -> dipilih acak: {k}")
            return k
        if jawab.isdigit() and 2 <= int(jawab) <= P - 2 and fpb(int(jawab), P - 1) == 1:
            return int(jawab)
        print(f"   {MERAH}k harus antara 2 dan {P - 2} serta fpb(k, {P - 1}) = 1.{RESET}")


def tampilkan_verifikasi(nilai, r, s, y):
    """Browser mengecek apakah (r, s) tanda tangan sah atas nilai, memakai kunci publik y."""
    h = nilai % (P - 1)
    kiri = elgamal.ruas_kiri_verifikasi(h, P, G)
    kanan = elgamal.ruas_kanan_verifikasi(r, s, P, y)
    sah = elgamal.verifikasi(h, r, s, P, G, y)
    print(f"   {BROWSER} kiri  = g^h mod p       = {G}^{h} mod {P} = {kiri}")
    print(f"   {BROWSER} kanan = y^r x r^s mod p = {y}^{r} x {r}^{s} mod {P} = {kanan}")
    if sah:
        print(f"   {HIJAU}{TEBAL}   -> SAH: nilai ini benar-benar dari bank.com{RESET}")
    else:
        print(f"   {MERAH}{TEBAL}   -> TIDAK SAH: nilai ini bukan dari bank.com!{RESET}")
    return sah


def menu_handshake_aman():
    judul("6. HANDSHAKE AMAN: DH + TANDA TANGAN DIGITAL ELGAMAL")
    print("   Skenario: sama seperti menu 3 (Wi-Fi palsu di kafe), tapi kali ini server")
    print("   MENANDATANGANI kunci publik DH-nya. Apakah threat actor masih bisa menyusup?")
    tampilkan_parameter_publik()
    jeda()

    tahap(2, "Server punya kunci tanda tangan jangka panjang")
    x = minta_rahasia("kunci privat tanda tangan server x", 2, P - 2)
    y = elgamal.buat_kunci_publik(x, P, G)
    print(f"   {SERVER} y = g^x mod p = {G}^{x} mod {P} = {y}")
    print("   +------------------ SERTIFIKAT ------------------+")
    print(f"   |  Domain         : {'bank.com':<29}|")
    print(f"   |  Kunci publik   : {f'y = {y}':<29}|")
    print(f"   |  Ditandatangani : {'CA Terpercaya':<29}|")
    print("   +------------------------------------------------+")
    catatan("Browser sudah menyimpan daftar CA terpercaya, jadi browser yakin y milik bank.com.")
    jeda()

    tahap(3, "ClientHello: browser mengirim A")
    a = minta_rahasia("rahasia browser a", 2, P - 2)
    A = dh.buat_kunci_publik(a, P, G)
    print(f"   {BROWSER} A = g^a mod p = {G}^{a} mod {P} = {A} -> dikirim ke server")
    jeda()

    tahap(4, "ServerHello: server mengirim B beserta tanda tangannya")
    b = minta_rahasia("rahasia server b", 2, P - 2)
    B = dh.buat_kunci_publik(b, P, G)
    h = B % (P - 1)
    print(f"   {SERVER} B = g^b mod p = {G}^{b} mod {P} = {B}")
    print(f"   Yang ditandatangani: h = B mod (p-1) = {h}")
    print("   Rumus:  r = g^k mod p      s = (h - x.r) . k^-1 mod (p-1)")
    while True:
        k = minta_k_tanda_tangan()
        r = elgamal.hitung_r(k, P, G)
        s = elgamal.hitung_s_tanda_tangan(h, x, r, k, P)
        if s != 0:
            break
        print(f"   {KUNING}s kebetulan 0, tanda tangan seperti ini lemah. Pilih k lain.{RESET}")
    k_invers = invers_mod_euclid(k, P - 1)
    print(f"   {SERVER} r    = g^k mod p = {G}^{k} mod {P} = {r}")
    print(f"   {SERVER} k^-1 = {k_invers} (mod {P - 1}) dengan Extended Euclid, "
          f"cek: {k} x {k_invers} mod {P - 1} = {(k * k_invers) % (P - 1)}")
    print(f"   {SERVER} s    = ({h} - {x} x {r}) x {k_invers} mod {P - 1} = {s}")
    print(f"   {SERVER} kirim: B = {B} dan tanda tangan (r, s) = ({r}, {s})")
    jeda()

    tahap(5, "Browser memverifikasi tanda tangan (belum ada serangan)")
    print("   Syarat sah:  g^h mod p  ==  y^r x r^s mod p")
    print("   Kenapa?  y^r x r^s = g^(x.r) x g^(k.s) = g^(x.r + h - x.r) = g^h")
    if tampilkan_verifikasi(B, r, s, y):
        K_browser = dh.hitung_kunci_sesi(B, a, P)
        K_server = dh.hitung_kunci_sesi(A, b, P)
        print(f"   {BROWSER} K = B^a mod p = {K_browser}     {SERVER} K = A^b mod p = {K_server}")
        print(f"   {HIJAU}Kunci sesi sama dan identitas server terbukti.{RESET}")
    jeda()

    tahap(6, "Threat actor mencoba Man-in-the-Middle")
    t2 = random.randint(2, P - 2)
    while t2 == b:
        t2 = random.randint(2, P - 2)
    T2 = dh.buat_kunci_publik(t2, P, G)
    print(f"   {THREAT} mencegat B = {B}, menggantinya dengan T2 = {G}^{t2} mod {P} = {T2}")

    print(f"\n   {TEBAL}Percobaan 1:{RESET} kirim T2 bersama tanda tangan ASLI milik server")
    sah_1 = tampilkan_verifikasi(T2, r, s, y)

    print(f"\n   {TEBAL}Percobaan 2:{RESET} tanda tangani T2 memakai kunci privat threat actor sendiri")
    x_ta = random.randint(2, P - 2)
    k_ta = random.randint(2, P - 2)
    while fpb(k_ta, P - 1) != 1:
        k_ta = random.randint(2, P - 2)
    r_ta, s_ta = elgamal.tanda_tangan(T2 % (P - 1), P, G, x_ta, k_ta)
    print(f"   {THREAT} kunci privat sendiri = {x_ta}, tanda tangan palsu (r, s) = ({r_ta}, {s_ta})")
    print(f"   {BROWSER} tetap memakai y = {y} dari sertifikat bank.com, bukan kunci threat actor")
    sah_2 = tampilkan_verifikasi(T2, r_ta, s_ta, y)

    if not sah_1 and not sah_2:
        print(f"\n   {MERAH}{TEBAL}+------------------------------------------------+{RESET}")
        print(f"   {MERAH}{TEBAL}|  PERINGATAN: Your connection is not private    |{RESET}")
        print(f"   {MERAH}{TEBAL}|  Browser membatalkan koneksi.                  |{RESET}")
        print(f"   {MERAH}{TEBAL}+------------------------------------------------+{RESET}")
        print(f"   {HIJAU}{TEBAL}Serangan GAGAL. Data login tidak pernah dikirim.{RESET}")
    else:
        catatan(f"Tanda tangan palsu kebetulan lolos karena p = {P} sangat kecil "
                f"(peluang sekitar 1/{P}). Dengan p 2048 bit peluangnya praktis nol.")
    jeda()

    tahap(7, "Kesimpulan")
    print("   - Tanda tangan mengikat nilai B dengan pemilik kunci privat x (bank.com).")
    print("   - Threat actor bisa MENGGANTI B, tapi tidak bisa membuat tanda tangan sah tanpa x.")
    print("   - Threat actor juga tidak bisa memalsukan sertifikat karena sertifikat ditandatangani CA.")
    print("   - Di TLS 1.3 asli, server menandatangani hash (SHA-256) seluruh handshake")
    print("     dengan RSA atau ECDSA pada pesan CertificateVerify. Prinsipnya sama.")
    print("     Tanda tangan ElGamal sendiri adalah dasar dari algoritma DSA.")
    jeda()


# =====================================================================
# Menu 4: threat actor pasif, brute force
# =====================================================================

def menu_brute_force():
    judul("4. THREAT ACTOR PASIF: MEMBOBOL DH DENGAN BRUTE FORCE")
    print("   Skenario: threat actor hanya MENYADAP (tidak mengubah apa pun), lalu")
    print("   mencoba menebak rahasia browser dari angka yang lewat di jaringan.")

    # handshake normal yang disadap (angka rahasia dipilih acak)
    a = random.randint(2, P - 2)
    b = random.randint(2, P - 2)
    A = dh.buat_kunci_publik(a, P, G)
    B = dh.buat_kunci_publik(b, P, G)
    K = dh.hitung_kunci_sesi(B, a, P)
    cipher = dh.enkripsi_teks("POST /login user=budi&password=rahasia123", K, P)

    tahap(1, "Data hasil sadapan")
    print(f"   {THREAT} p = {P}, g = {G}, A = {A}, B = {B}")
    print(f"   {THREAT} data terenkripsi: {ringkas(cipher)}")
    jeda()

    tahap(2, "Mencoba semua kemungkinan a sampai g^a mod p = A")
    nilai = 1
    tebakan = None
    for x in range(1, P - 1):
        nilai = (nilai * G) % P  # g^x didapat dari g^(x-1) x g
        cocok = nilai == A
        if x <= 5 or cocok:
            if cocok and x > 6:
                print("   ...")
            status = f"{HIJAU}{TEBAL}COCOK!{RESET}" if cocok else "bukan"
            print(f"   coba a = {x:>4}: {G}^{x} mod {P} = {nilai:>4}  {status}")
        if cocok:
            tebakan = x
            break
    print(f"   {THREAT} rahasia browser ditemukan: a = {tebakan} setelah {tebakan} percobaan")
    jeda()

    tahap(3, "Menghitung kunci sesi dan membaca pesan")
    K_curian = dh.hitung_kunci_sesi(B, tebakan, P)
    print(f"   {THREAT} K = B^a mod p = {B}^{tebakan} mod {P} = {K_curian}")
    print(f"   {THREAT} isi pesan: {MERAH}{TEBAL}{dh.dekripsi_teks(cipher, K_curian, P)}{RESET}")
    jeda()

    tahap(4, "Kenapa di dunia nyata ini tidak mungkin?")
    print(f"   Di simulasi ini p = {P}, jadi paling banyak {P - 2} percobaan.")
    print("   Di TLS asli p panjangnya 2048 bit (sekitar 617 digit desimal).")
    print("   Jumlah kemungkinan a sekitar 2^2048 (kira-kira 3 x 10^616).")
    print("   Bahkan dengan algoritma tercepat yang dikenal, waktunya jauh melebihi umur alam semesta.")
    print("   Masalah mencari a dari g^a mod p ini disebut LOGARITMA DISKRIT,")
    print("   dan kesulitannya adalah dasar keamanan Diffie-Hellman maupun ElGamal.")
    jeda()


# =====================================================================
# Menu 5: ganti parameter publik
# =====================================================================

def menu_parameter():
    global P, G
    judul("5. GANTI PARAMETER PUBLIK (p, g)")
    print(f"   Sekarang: p = {P}, g = {G}")
    print("   Syarat p: bilangan prima, lebih dari 255 (agar semua karakter muat),")
    print("   dan maksimal 1000000 (agar simulasi brute force tetap cepat).")
    print("   Contoh prima: 263, 467, 1019, 2027, 7919, 65537")
    jawab = input("   p baru (Enter = tidak diubah): ").strip()
    if jawab == "":
        return
    if not jawab.isdigit() or not 256 <= int(jawab) <= 1_000_000 or not cek_prima(int(jawab)):
        print(f"   {MERAH}p tidak valid (harus prima, 256 sampai 1000000).{RESET}")
        jeda()
        return
    p_baru = int(jawab)

    g_saran = cari_generator(p_baru)
    print(f"   p-1 = {p_baru - 1}, faktor primanya {faktor_prima(p_baru - 1)}")
    print(f"   Generator terkecil untuk p = {p_baru} adalah {g_saran}")
    jawab = input(f"   g baru (Enter = {g_saran}): ").strip()
    g_baru = g_saran if jawab == "" else int(jawab) if jawab.isdigit() else 0
    if not adalah_generator(g_baru, p_baru):
        print(f"   {MERAH}{jawab} bukan generator modulo {p_baru}.{RESET}")
        jeda()
        return

    P, G = p_baru, g_baru
    print(f"   {HIJAU}Parameter publik sekarang: p = {P}, g = {G}{RESET}")
    jeda()


# =====================================================================
# Program utama
# =====================================================================

def main():
    daftar_menu = {
        "1": menu_handshake,
        "2": menu_elgamal,
        "3": menu_mitm,
        "4": menu_brute_force,
        "5": menu_parameter,
        "6": menu_handshake_aman,
    }
    while True:
        judul("MINI HANDSHAKE HTTPS - Diffie-Hellman & ElGamal")
        print(f"   Parameter publik saat ini: p = {P}, g = {G}\n")
        print("   1. Handshake HTTPS normal (Diffie-Hellman)")
        print("   2. Kirim data dengan ElGamal (kunci publik di sertifikat)")
        print("   3. Serangan Man-in-the-Middle oleh threat actor")
        print("   4. Threat actor pasif: brute force kunci DH")
        print("   5. Ganti parameter publik (p, g)")
        print("   6. Handshake aman: DH + tanda tangan digital ElGamal")
        print("   0. Keluar")
        pilihan = input("\n   Pilih menu: ").strip()
        if pilihan == "0":
            print("   Sampai jumpa!")
            break
        if pilihan in daftar_menu:
            daftar_menu[pilihan]()
        else:
            print(f"   {MERAH}Pilihan tidak dikenal.{RESET}")


if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        print("\n   Program dihentikan.")
