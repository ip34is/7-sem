"""Другий фактор — ЛР3, варіант 14: одноразові коди відновлення.

- 10 кодів по 10 символів алфавіту Crockford Base32 (без I, L, O, U): 10 · 5 = 50 біт кожен;
  показуються у вигляді XXXXX-XXXXX один раз, під час генерації.
- Зберігаються лише HMAC-SHA256(перець, обліковий запис ‖ код): злив бази не розкриває кодів,
  а прив'язка до облікового запису не дає використати чужий хеш.
- Перевірка порівнює кандидата з УСІМА невикористаними хешами за сталий час і не зупиняється
  на першому збігу; використаний код видаляється — повторно він не приймається.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
from collections.abc import Callable

from auth.passwords import PEPPER

ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"   # Crockford Base32
CODE_LEN = 10
COUNT = 10
_NORMALIZE = str.maketrans({"O": "0", "I": "1", "L": "1", "-": None, " ": None})


def generate_codes(count: int = COUNT,
                   randbelow: Callable[[int], int] = secrets.randbelow,
                   ) -> list[str]:
    """Список одноразових кодів; randbelow — криптографічний ГВЧ."""
    codes = []
    while len(codes) < count:
        raw = "".join(ALPHABET[randbelow(len(ALPHABET))] for _ in range(CODE_LEN))
        code = f"{raw[:5]}-{raw[5:]}"
        if code not in codes:
            codes.append(code)
    return codes


def normalize(code: str) -> str:
    return code.upper().translate(_NORMALIZE)


def code_hash(account: str, code: str) -> str:
    msg = f"{account}\x00{normalize(code)}".encode()
    return hmac.new(PEPPER, msg, hashlib.sha256).hexdigest()


class RecoveryCodes:
    """Невикористані коди облікового запису (лише хеші)."""

    def __init__(self, account: str, codes: list[str]) -> None:
        self.account = account
        self._hashes: list[str] = [code_hash(account, c) for c in codes]

    @classmethod
    def issue(cls, account: str, count: int = COUNT) -> tuple["RecoveryCodes", list[str]]:
        """Нові коди: повертає сховище хешів і відкриті коди для показу користувачеві."""
        codes = generate_codes(count)
        return cls(account, codes), codes

    def remaining(self) -> int:
        return len(self._hashes)

    def verify_and_consume(self, code: str) -> bool:
        candidate = code_hash(self.account, code).encode()
        match = -1
        for i, h in enumerate(self._hashes):          # без раннього виходу
            if hmac.compare_digest(h.encode(), candidate) and match < 0:
                match = i
        if match < 0:
            return False
        del self._hashes[match]                       # одноразовість
        return True
