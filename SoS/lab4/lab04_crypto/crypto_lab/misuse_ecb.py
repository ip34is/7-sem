"""Помилка 1 варіанта 14: режим ECB замість AEAD.

ECB шифрує кожен 16-байтовий блок незалежно тим самим ключем, тому:
  1) однакові блоки відкритого тексту дають однакові блоки шифротексту — структура проступає;
  2) цілісності немає: блоки можна переставляти й підставляти з інших шифротекстів
     того самого ключа, і розшифрування пройде без помилки.
AES-128-GCM (crypto_lab.aead) усуває обидва недоліки.
"""
from __future__ import annotations

from collections import Counter

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

BLOCK = 16


# ВРАЗЛИВО: ECB — детермінований, без nonce і без контролю цілісності.
def ecb_encrypt(data: bytes, key: bytes) -> bytes:
    padder = padding.PKCS7(8 * BLOCK).padder()
    padded = padder.update(data) + padder.finalize()
    enc = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return enc.update(padded) + enc.finalize()


# ВРАЗЛИВО: розшифрування ECB не може виявити підміну блоків.
def ecb_decrypt(ct: bytes, key: bytes) -> bytes:
    dec = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
    padded = dec.update(ct) + dec.finalize()
    unpadder = padding.PKCS7(8 * BLOCK).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def ecb_encrypt_raw(data: bytes, key: bytes) -> bytes:
    """ECB без доповнення (довжина кратна 16) — для шифрування растрового зображення."""
    enc = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return enc.update(data) + enc.finalize()


def blocks(data: bytes) -> list[bytes]:
    return [data[i:i + BLOCK] for i in range(0, len(data), BLOCK)]


def repeated_blocks(data: bytes) -> int:
    """Скільки блоків повторюють уже наявні (0 — усі блоки різні)."""
    counts = Counter(blocks(data))
    return sum(c - 1 for c in counts.values())


def record(user: str, role: str) -> bytes:
    """Запис із полями фіксованої довжини, вирівняними на межу блока."""
    return f"user={user}".ljust(BLOCK, ".").encode() + f"role={role}".ljust(BLOCK, ".").encode()


def cut_and_paste(victim_ct: bytes, donor_ct: bytes) -> bytes:
    """Замінити блок ролі шифротексту жертви блоком із чужого шифротексту."""
    return victim_ct[:BLOCK] + donor_ct[BLOCK:2 * BLOCK] + victim_ct[2 * BLOCK:]


def synthetic_image(size: int = 256) -> bytes:
    """Синтетичне зображення (відтінки сірого) з великими однотонними ділянками."""
    px = bytearray(size * size)
    for y in range(size):
        for x in range(size):
            v = 235                                             # світле тло
            if (x - 80) ** 2 + (y - 90) ** 2 < 55 ** 2:
                v = 40                                          # темне коло
            if 140 <= x < 230 and 40 <= y < 210:
                v = 120                                         # сірий прямокутник
            if 30 <= x < 230 and 225 <= y < 245:
                v = 0                                           # чорна смуга
            px[y * size + x] = v
    return bytes(px)
