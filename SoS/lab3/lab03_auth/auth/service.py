"""Підсистема автентифікації: пароль (bcrypt) → код відновлення, з квотою спроб.

Обидва кроки рахуються в одну квоту облікового запису: інакше, знаючи пароль,
можна було б перебирати коди без обмеження. Для неіснуючого облікового запису
виконується перевірка з фіктивним хешем, щоб час відповіді не розкривав, чи існує запис,
і повідомлення про помилку однакові.
"""
from __future__ import annotations

import dataclasses
import enum

from auth.lockout import SlidingWindowLockout
from auth.passwords import hash_password, needs_rehash, verify_password
from auth.recovery import RecoveryCodes


class Result(enum.Enum):
    LOCKED = "забагато невдалих спроб, спробуйте пізніше"
    BAD_CREDENTIALS = "неправильне ім'я або пароль"
    NEED_SECOND_FACTOR = "пароль прийнято, введіть код відновлення"
    BAD_CODE = "код недійсний або вже використаний"
    NO_PENDING = "спершу введіть пароль"
    OK = "вхід виконано"


@dataclasses.dataclass
class Account:
    password_hash: str
    codes: RecoveryCodes


class Authenticator:
    def __init__(self, lockout: SlidingWindowLockout | None = None) -> None:
        self.lockout = lockout or SlidingWindowLockout()
        self._accounts: dict[str, Account] = {}
        self._pending: set[str] = set()          # пароль прийнято, чекаємо другий фактор
        self._dummy = hash_password("dummy-password-for-timing")

    def register(self, account: str, password: str) -> list[str]:
        """Створює обліковий запис; повертає коди відновлення (показати один раз)."""
        codes, plain = RecoveryCodes.issue(account)
        self._accounts[account] = Account(hash_password(password), codes)
        return plain

    def login_password(self, account: str, password: str, now: float) -> Result:
        if not self.lockout.is_allowed(account, now):
            return Result.LOCKED
        acc = self._accounts.get(account)
        stored = acc.password_hash if acc else self._dummy
        ok = verify_password(stored, password) and acc is not None
        if not ok:
            self.lockout.record_attempt(account, False, now)
            return Result.BAD_CREDENTIALS
        if needs_rehash(acc.password_hash):
            acc.password_hash = hash_password(password)
        self._pending.add(account)
        return Result.NEED_SECOND_FACTOR

    def login_code(self, account: str, code: str, now: float) -> Result:
        if not self.lockout.is_allowed(account, now):
            return Result.LOCKED
        if account not in self._pending:
            return Result.NO_PENDING
        if not self._accounts[account].codes.verify_and_consume(code):
            self.lockout.record_attempt(account, False, now)
            return Result.BAD_CODE
        self._pending.discard(account)
        self.lockout.record_attempt(account, True, now)
        return Result.OK

    def remaining_codes(self, account: str) -> int:
        return self._accounts[account].codes.remaining()
