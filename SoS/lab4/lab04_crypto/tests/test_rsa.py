import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from crypto_lab.rsa_edu import (fast_pow_mod, is_probable_prime, gen_prime,
                                egcd, modinv, keygen, encrypt, decrypt)


def test_fast_pow_matches_builtin():
    val, _ = fast_pow_mod(7, 13, 100)
    assert val == pow(7, 13, 100) == 7  # 7^4 ≡ 1 (mod 100)


def test_miller_rabin_known_primes():
    for p in (2, 3, 97, 7919, 104729):
        assert is_probable_prime(p)
    for c in (1, 4, 100, 7917, 104730):
        assert not is_probable_prime(c)


def test_gen_prime_is_prime():
    p = gen_prime(16)
    assert is_probable_prime(p) and p.bit_length() == 16


def test_egcd_and_modinv():
    g, x, y = egcd(240, 46)
    assert g == 2 and 240 * x + 46 * y == 2
    assert (17 * modinv(17, 3120)) % 3120 == 1


def test_rsa_roundtrip():
    k = keygen(bits=20)
    for m in (0, 1, 2, 42, k["n"] - 1):
        assert decrypt(encrypt(m, k["e"], k["n"]), k["d"], k["n"]) == m


def test_textbook_example():
    # Приклад RSA p=61, q=53, e=17 (ключ d обчислено за φ=3120).
    p, q, e = 61, 53, 17
    n, phi = p * q, (p - 1) * (q - 1)
    d = modinv(e, phi)
    assert d == 2753  # за функцією Ейлера φ=3120 (413 — за λ Кармайкла)
    assert decrypt(encrypt(65, e, n), d, n) == 65
