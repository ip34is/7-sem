"""Помилка 2 варіанта 14: хешування пароля без солі.

Без солі хеш — детермінована функція пароля: однакові паролі дають однакові хеші,
а заздалегідь обчислена таблиця «хеш → пароль» зламує всі слабкі паролі бази одним пошуком.
Виправлення — унікальна сіль на кожен пароль і повільна KDF (тут scrypt зі стандартної
бібліотеки, N = 2^14, r = 8, p = 1) з порівнянням за сталий час.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os

SCRYPT_N, SCRYPT_R, SCRYPT_P = 2 ** 14, 8, 1
SALT_SIZE = 16


# ВРАЗЛИВО: швидкий хеш без солі — однакові паролі → однакові хеші.
def hash_unsalted(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


def precompute_table(dictionary: list[str]) -> dict[str, str]:
    """Таблиця «хеш → пароль», яку порушник будує ОДИН раз — до отримання бази."""
    return {hash_unsalted(w): w for w in dictionary}


def crack_with_table(db: dict[str, str], table: dict[str, str]) -> dict[str, str]:
    """Зламати базу пошуком у готовій таблиці (без жодного обчислення хешу)."""
    return {user: table[h] for user, h in db.items() if h in table}


# БЕЗПЕЧНО: унікальна сіль + повільна KDF; формат scrypt$N$r$p$сіль$ключ.
def hash_salted(password: str) -> str:
    salt = os.urandom(SALT_SIZE)
    dk = hashlib.scrypt(password.encode(), salt=salt,
                        n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)
    s, k = base64.b64encode(salt).decode(), base64.b64encode(dk).decode()
    return f"scrypt${SCRYPT_N}${SCRYPT_R}${SCRYPT_P}${s}${k}"


def verify_salted(stored: str, password: str) -> bool:
    _, n, r, p, salt_b64, dk_b64 = stored.split("$")
    salt, expected = base64.b64decode(salt_b64), base64.b64decode(dk_b64)
    dk = hashlib.scrypt(password.encode(), salt=salt, n=int(n), r=int(r), p=int(p))
    return hmac.compare_digest(dk, expected)


def crack_salted(stored: str, dictionary: list[str]) -> str | None:
    """Із сіллю таблиця марна: кожен запис доводиться перебирати окремо, з повільною KDF."""
    for w in dictionary:
        if verify_salted(stored, w):
            return w
    return None
