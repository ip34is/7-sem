"""Симетричне автентифіковане шифрування — ЛР4, варіант 14: AES-128-GCM.

Формат результату encrypt:  nonce (12 байтів) ‖ шифротекст ‖ тег (16 байтів).
- nonce — 96 випадкових бітів з os.urandom для КОЖНОГО повідомлення. За випадкових nonce
  NIST SP 800-38D обмежує кількість повідомлень на один ключ величиною 2^32: так імовірність
  повторення nonce лишається нехтовно малою. Ліміт контролює NonceBudget.
- асоційовані дані (заголовок, ідентифікатор) не шифруються, але входять у тег:
  розшифрування з іншими асоційованими даними завершується винятком InvalidTag.
"""
from __future__ import annotations

import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY_SIZE = 16          # AES-128
NONCE_SIZE = 12        # 96 біт — рекомендований розмір nonce для GCM
TAG_SIZE = 16          # 128-бітовий тег
MAX_MESSAGES = 2 ** 32 # межа для випадкових nonce на один ключ (NIST SP 800-38D)

__all__ = ["encrypt", "decrypt", "generate_key", "InvalidTag", "NonceBudget"]


def generate_key() -> bytes:
    return AESGCM.generate_key(bit_length=8 * KEY_SIZE)


def _check_key(key: bytes) -> None:
    if len(key) != KEY_SIZE:
        raise ValueError(f"AES-128-GCM потребує ключ {KEY_SIZE} байтів, отримано {len(key)}")


def encrypt(plaintext: bytes, key: bytes, associated: bytes = b"") -> bytes:
    """БЕЗПЕЧНО: новий випадковий nonce, асоційовані дані входять у тег."""
    _check_key(key)
    nonce = os.urandom(NONCE_SIZE)
    return nonce + AESGCM(key).encrypt(nonce, plaintext, associated)


def decrypt(blob: bytes, key: bytes, associated: bytes = b"") -> bytes:
    """Відокремлює nonce і перевіряє тег; за розбіжності — InvalidTag."""
    _check_key(key)
    if len(blob) < NONCE_SIZE + TAG_SIZE:
        raise InvalidTag()
    nonce, body = blob[:NONCE_SIZE], blob[NONCE_SIZE:]
    return AESGCM(key).decrypt(nonce, body, associated)


class NonceBudget:
    """Шифратор з лічильником повідомлень: не дає перевищити MAX_MESSAGES на один ключ."""

    def __init__(self, key: bytes, limit: int = MAX_MESSAGES) -> None:
        _check_key(key)
        self.key, self.limit, self.used = key, limit, 0

    def encrypt(self, plaintext: bytes, associated: bytes = b"") -> bytes:
        if self.used >= self.limit:
            raise RuntimeError("вичерпано ліміт повідомлень для ключа — потрібна ротація ключа")
        self.used += 1
        return encrypt(plaintext, self.key, associated)
