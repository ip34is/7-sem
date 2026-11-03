"""Тести варіанта 14: RSA 28 біт, AES-128-GCM, ECB, хеш без солі, RSA-PSS 2048."""
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from crypto_lab import aead, misuse_ecb, misuse_hash, sign_demo
from crypto_lab.rsa_analysis import multiplications, pollard_rho, trial_division
from crypto_lab.rsa_edu import decrypt, encrypt, fast_pow_mod, is_probable_prime, keygen, modinv

KEY = b"0123456789abcdef"   # ТЕСТОВИЙ КЛЮЧ — не використовувати поза стендом


# ---------- навчальний RSA ----------

def test_demo_keys_have_28_bit_prime_factors():
    k = keygen(bits=28)
    for f in (k["p"], k["q"]):
        assert f.bit_length() == 28 and is_probable_prime(f)
    assert k["n"] == k["p"] * k["q"] and k["phi"] == (k["p"] - 1) * (k["q"] - 1)
    assert (k["e"] * k["d"]) % k["phi"] == 1
    for m in (0, 42, k["n"] - 1):
        assert decrypt(encrypt(m, k["e"], k["n"]), k["d"], k["n"]) == m


def test_control_question_9():
    n, phi = 11 * 23, 10 * 22
    assert (n, phi) == (253, 220)
    d = modinv(3, phi)
    assert d == 147 and (3 * d) % phi == 1
    assert decrypt(encrypt(100, 3, n), d, n) == 100


def test_textbook_ciphertext_value():
    assert encrypt(65, 17, 3233) == 2790 and decrypt(2790, 2753, 3233) == 65


def test_carmichael_number_rejected():
    assert not is_probable_prime(561)          # 3·11·17: тест Ферма за основою 2 його пропускає
    assert pow(2, 560, 561) == 1


def test_fast_pow_multiplication_count():
    assert multiplications(65537) == (17, 2)   # 17 квадратів + 2 множення замість 65536
    sq, mul = multiplications(0b1011)
    assert (sq, mul) == (4, 3)
    assert fast_pow_mod(5, 0b1011, 1000)[0] == pow(5, 11, 1000)


def test_small_modulus_is_factored_and_key_recovered():
    k = keygen(bits=28)
    f = pollard_rho(k["n"])
    assert f in (k["p"], k["q"])
    assert modinv(k["e"], (f - 1) * (k["n"] // f - 1)) == k["d"]


def test_trial_division_finds_smallest_factor():
    assert trial_division(61 * 53) == 53 and trial_division(7919) == 7919


# ---------- AES-128-GCM ----------

def test_aead_roundtrip_and_layout():
    blob = aead.encrypt(b"secret payload", KEY, associated=b"hdr")
    assert len(blob) == 12 + len(b"secret payload") + 16
    assert aead.decrypt(blob, KEY, associated=b"hdr") == b"secret payload"


def test_aead_requires_128_bit_key():
    with pytest.raises(ValueError):
        aead.encrypt(b"x", b"0" * 32)


@pytest.mark.parametrize("where", ["tag", "ciphertext", "nonce"])
def test_aead_detects_bit_flip(where):
    blob = bytearray(aead.encrypt(b"secret payload", KEY, associated=b"hdr"))
    blob[{"tag": -1, "ciphertext": 12, "nonce": 0}[where]] ^= 1
    with pytest.raises(aead.InvalidTag):
        aead.decrypt(bytes(blob), KEY, associated=b"hdr")


def test_aead_binds_associated_data():
    blob = aead.encrypt(b"secret payload", KEY, associated=b"hdr")
    with pytest.raises(aead.InvalidTag):
        aead.decrypt(blob, KEY, associated=b"hdR")
    with pytest.raises(aead.InvalidTag):
        aead.decrypt(blob, KEY)


def test_aead_wrong_key_and_truncated_blob():
    blob = aead.encrypt(b"x", KEY)
    with pytest.raises(aead.InvalidTag):
        aead.decrypt(blob, aead.generate_key())
    with pytest.raises(aead.InvalidTag):
        aead.decrypt(blob[:20], KEY)


def test_aead_nonce_unique_and_encryption_randomized():
    nonces = {aead.encrypt(b"x", KEY)[:12] for _ in range(2000)}
    assert len(nonces) == 2000
    assert aead.encrypt(b"same", KEY) != aead.encrypt(b"same", KEY)


def test_nonce_budget_enforces_limit():
    enc = aead.NonceBudget(KEY, limit=3)
    for _ in range(3):
        enc.encrypt(b"x")
    with pytest.raises(RuntimeError):
        enc.encrypt(b"x")


# ---------- помилка 1: ECB ----------

def test_ecb_reveals_repeated_blocks_gcm_does_not():
    data = b"ATTACK AT DAWN!!" * 4
    ecb = misuse_ecb.ecb_encrypt(data, KEY)
    assert misuse_ecb.repeated_blocks(ecb) == 3               # 4 однакові блоки → 3 повтори
    assert misuse_ecb.repeated_blocks(aead.encrypt(data, KEY)[12:-16]) == 0


def test_ecb_is_deterministic():
    assert misuse_ecb.ecb_encrypt(b"same message", KEY) == misuse_ecb.ecb_encrypt(b"same message", KEY)


def test_ecb_cut_and_paste_succeeds_gcm_rejects():
    victim = misuse_ecb.ecb_encrypt(misuse_ecb.record("mallory", "student"), KEY)
    donor = misuse_ecb.ecb_encrypt(misuse_ecb.record("alice", "admin"), KEY)
    forged = misuse_ecb.ecb_decrypt(misuse_ecb.cut_and_paste(victim, donor), KEY)
    assert forged.startswith(b"user=mallory") and b"role=admin" in forged
    v = aead.encrypt(misuse_ecb.record("mallory", "student"), KEY)
    d = aead.encrypt(misuse_ecb.record("alice", "admin"), KEY)
    with pytest.raises(aead.InvalidTag):
        aead.decrypt(v[:28] + d[28:44] + v[44:], KEY)


def test_ecb_image_structure_survives():
    img = misuse_ecb.synthetic_image()
    assert misuse_ecb.repeated_blocks(misuse_ecb.ecb_encrypt_raw(img, KEY)) == misuse_ecb.repeated_blocks(img) > 1000
    assert misuse_ecb.repeated_blocks(aead.encrypt(img, KEY)[12:-16]) == 0


# ---------- помилка 2: хеш пароля без солі ----------

def test_unsalted_equal_passwords_equal_hashes_and_table_cracks():
    db = {"alice": misuse_hash.hash_unsalted("qwerty123"), "bob": misuse_hash.hash_unsalted("qwerty123"),
          "carol": misuse_hash.hash_unsalted("Tr0ub4dor&3")}
    assert db["alice"] == db["bob"]
    cracked = misuse_hash.crack_with_table(db, misuse_hash.precompute_table(["123456", "qwerty123"]))
    assert cracked == {"alice": "qwerty123", "bob": "qwerty123"}


def test_salted_hashes_differ_and_table_is_useless():
    a, b = misuse_hash.hash_salted("qwerty123"), misuse_hash.hash_salted("qwerty123")
    assert a != b and a.split("$")[4] != b.split("$")[4]
    table = misuse_hash.precompute_table(["qwerty123"])
    assert misuse_hash.crack_with_table({"alice": a, "bob": b}, table) == {}


def test_salted_verify():
    h = misuse_hash.hash_salted("qwerty123")
    assert misuse_hash.verify_salted(h, "qwerty123") and not misuse_hash.verify_salted(h, "qwerty124")
    assert misuse_hash.crack_salted(h, ["123456", "qwerty123"]) == "qwerty123"


# ---------- RSA-PSS 2048 ----------

@pytest.fixture(scope="module")
def keypair():
    priv = sign_demo.generate_keypair()
    return priv, priv.public_key()


def test_signature_valid_and_parameters(keypair):
    priv, pub = keypair
    sig = sign_demo.sign(priv, b"lab4 demo message")
    assert pub.key_size == 2048 and len(sig) == 256
    assert sign_demo.verify(pub, sig, b"lab4 demo message")
    assert sign_demo.max_salt_length() == 222


def test_signature_rejects_modified_message_or_signature(keypair):
    priv, pub = keypair
    msg = b"lab4 demo message"
    sig = sign_demo.sign(priv, msg)
    assert not sign_demo.verify(pub, sig, msg + b"x")
    assert not sign_demo.verify(pub, sig, bytes([msg[0] ^ 1]) + msg[1:])
    assert not sign_demo.verify(pub, sig[:-1] + bytes([sig[-1] ^ 1]), msg)


def test_pss_is_randomized_and_bound_to_key(keypair):
    priv, pub = keypair
    s1, s2 = sign_demo.sign(priv, b"m"), sign_demo.sign(priv, b"m")
    assert s1 != s2 and sign_demo.verify(pub, s1, b"m") and sign_demo.verify(pub, s2, b"m")
    assert not sign_demo.verify(sign_demo.generate_keypair().public_key(), s1, b"m")
