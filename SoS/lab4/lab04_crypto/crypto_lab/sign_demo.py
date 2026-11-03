"""Електронний підпис — ЛР4, варіант 14: RSA-PSS (2048 біт, SHA-256, MGF1-SHA256).

Запуск з каталогу lab04_crypto:  python -m crypto_lab.sign_demo
Ключ генерується щоразу заново й ніде не зберігається (ТЕСТОВИЙ КЛЮЧ — не використовувати поза стендом).
"""
from __future__ import annotations

import sys
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

KEY_BITS = 2048
PUBLIC_EXPONENT = 65537
PSS = padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                  salt_length=padding.PSS.MAX_LENGTH)
HASH = hashes.SHA256()


def generate_keypair() -> rsa.RSAPrivateKey:
    # ТЕСТОВИЙ КЛЮЧ — не використовувати поза стендом
    return rsa.generate_private_key(public_exponent=PUBLIC_EXPONENT,
                                    key_size=KEY_BITS)


def sign(priv: rsa.RSAPrivateKey, message: bytes) -> bytes:
    return priv.sign(message, PSS, HASH)


def verify(pub: rsa.RSAPublicKey, signature: bytes, message: bytes) -> bool:
    """True — підпис дійсний; False — дані або підпис змінено."""
    try:
        pub.verify(signature, message, PSS, HASH)
        return True
    except InvalidSignature:
        return False


def max_salt_length(key_bits: int = KEY_BITS, hash_len: int = 32) -> int:
    """PSS.MAX_LENGTH = emLen − hLen − 2 (RFC 8017, п. 9.1.1), emLen = ⌈(modBits − 1) / 8⌉."""
    return (key_bits - 1 + 7) // 8 - hash_len - 2


def main() -> None:
    sys.stdout.reconfigure(encoding="utf-8")
    t = time.perf_counter()
    priv = generate_keypair()
    t_gen = time.perf_counter() - t
    pub = priv.public_key()
    msg = b"lab4 demo message: order #2026-14 approved"
    t = time.perf_counter()
    sig = sign(priv, msg)
    t_sign = time.perf_counter() - t
    t = time.perf_counter()
    ok = verify(pub, sig, msg)
    t_verify = time.perf_counter() - t

    print(f"Ключ RSA: {pub.key_size} біт, e = {pub.public_numbers().e}; генерація {t_gen * 1000:.0f} мс")
    print(f"Повідомлення: {msg!r}")
    print(f"Підпис: {len(sig)} Б, сіль PSS {max_salt_length()} Б; підпис {t_sign * 1000:.2f} мс, "
          f"перевірка {t_verify * 1000:.2f} мс")
    print(f"Підпис (перші 32 байти): {sig[:32].hex()}…")
    print("Перевірка коректного підпису:        ", ok)
    print("Повідомлення + b'x':                 ", verify(pub, sig, msg + b"x"))
    flipped_msg = bytes([msg[0] ^ 1]) + msg[1:]
    print("Змінено 1 біт повідомлення:          ", verify(pub, sig, flipped_msg))
    flipped_sig = sig[:-1] + bytes([sig[-1] ^ 1])
    print("Змінено 1 біт підпису:               ", verify(pub, flipped_sig, msg))
    sig2 = sign(priv, msg)
    print("Повторний підпис того самого тексту: ", "інший" if sig2 != sig else "той самий",
          "| дійсний:", verify(pub, sig2, msg))
    other = generate_keypair().public_key()
    print("Перевірка чужим відкритим ключем:    ", verify(other, sig, msg))
    pem = pub.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    print(f"Відкритий ключ (PEM, {len(pem)} Б): {pem.decode().splitlines()[1][:48]}…")


if __name__ == "__main__":
    main()
