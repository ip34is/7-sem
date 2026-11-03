"""Зберігання та перевірка паролів — ЛР3, варіант 14: bcrypt.

Формат збереженого рядка:  bcrypt$2b$<cost>$<сіль 22 симв.>$<хеш 31 симв.>
Сіль (16 байтів) і хеш записано в алфавіті bcrypt (./A-Za-z0-9), як їх видає бібліотека.

Вхід bcrypt — не сам пароль, а base64(HMAC-SHA256(перець, пароль)):
  – перець не потрапляє в базу, тож злита база без сервера непридатна для перебору;
  – 44 ASCII-байти без NUL обходять обмеження bcrypt (72 байти, обрізання довших паролів).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os

import bcrypt

PEPPER = os.environ.get("AUTH_PEPPER", "").encode()

COST = 12                      # коефіцієнт складності: 2^12 раундів (рекомендація ≥ 12)
SCHEME, VERSION = "bcrypt", "2b"


# ВРАЗЛИВИЙ зразок (для порівняння у звіті) — НЕ використовувати:
def hash_password_insecure(password: str) -> str:
    # ВРАЗЛИВО: швидка хеш-функція без солі — вразлива до райдужних таблиць.
    return hashlib.sha256(password.encode()).hexdigest()


def hash_password(password: str, cost: int = COST) -> str:
    """БЕЗПЕЧНО: сіль (gensalt, 16 байтів з os.urandom) + перець + bcrypt."""
    salt = bcrypt.gensalt(rounds=cost)
    full = bcrypt.hashpw(_bcrypt_input(password), salt).decode()
    # full = "$2b$12$" + 22 символи солі + 31 символ хешу
    _, version, cost_s, rest = full.split("$")
    return f"{SCHEME}${version}${cost_s}${rest[:22]}${rest[22:]}"


def verify_password(stored: str, password: str) -> bool:
    """Перевірка пароля; хеші порівнюються лише за сталий час."""
    parsed = _parse(stored)
    if parsed is None:
        return False
    version, cost, salt, expected = parsed
    setting = f"${version}${cost:02d}${salt}".encode()
    computed = bcrypt.hashpw(_bcrypt_input(password), setting).decode()[-31:]
    return hmac.compare_digest(computed.encode(), expected.encode())


def needs_rehash(stored: str, cost: int = COST) -> bool:
    """True, якщо рядок створено зі слабшими параметрами, ніж чинні."""
    parsed = _parse(stored)
    return parsed is None or parsed[1] < cost


def _parse(stored: str) -> tuple[str, int, str, str] | None:
    parts = stored.split("$")
    if len(parts) != 5 or parts[0] != SCHEME or parts[1] != VERSION:
        return None
    _, version, cost_s, salt, digest = parts
    if not cost_s.isdigit() or not 4 <= int(cost_s) <= 31 or len(salt) != 22 or len(digest) != 31:
        return None
    return version, int(cost_s), salt, digest


def _bcrypt_input(password: str) -> bytes:
    data = _peppered(password.encode("utf-8"))
    if not PEPPER:
        # без перцю — попереднє хешування, щоб bcrypt не обрізав довгий пароль
        data = hashlib.sha256(data).digest()
    return base64.b64encode(data)    # 44 байти, без NUL


def _peppered(data: bytes) -> bytes:
    return hmac.new(PEPPER, data, hashlib.sha256).digest() if PEPPER else data
