"""Блокування облікового запису — ЛР3, варіант 14: квота спроб у ковзному вікні.

Обліковому запису дозволено не більше `max_failures` невдалих спроб за будь-які
`window` секунд. Невдача в момент t враховується, поки now - t < window, тобто
рівно через window секунд вона «виходить» із вікна. Успішний вхід очищує лічильник.
Спроби, відхилені через блокування, пароль не перевіряють і в лічильник не потрапляють.
Стан — у пам'яті процесу.
"""
from __future__ import annotations

import collections

MAX_FAILURES = 5          # квота невдалих спроб
WINDOW = 15 * 60          # ковзне вікно, с


class SlidingWindowLockout:
    def __init__(self, max_failures: int = MAX_FAILURES, window: float = WINDOW) -> None:
        self.max_failures = max_failures
        self.window = window
        self._failures: dict[str, collections.deque[float]] = collections.defaultdict(collections.deque)

    def _prune(self, account: str, now: float) -> collections.deque[float]:
        q = self._failures[account]
        while q and now - q[0] >= self.window:
            q.popleft()
        return q

    def record_attempt(self, account: str, ok: bool, now: float) -> None:
        if ok:
            self._failures.pop(account, None)
        else:
            self._prune(account, now).append(now)

    def is_allowed(self, account: str, now: float) -> bool:
        return len(self._prune(account, now)) < self.max_failures

    def failures(self, account: str, now: float) -> int:
        return len(self._prune(account, now))

    def retry_after(self, account: str, now: float) -> float:
        """Через скільки секунд буде дозволена наступна спроба (0 — уже дозволена)."""
        q = self._prune(account, now)
        if len(q) < self.max_failures:
            return 0.0
        # має вийти з вікна стільки найстаріших невдач, щоб їх лишилося max_failures - 1
        return q[len(q) - self.max_failures] + self.window - now


_default = SlidingWindowLockout()


def record_attempt(account: str, ok: bool, now: float) -> None:
    _default.record_attempt(account, ok, now)


def is_allowed(account: str, now: float) -> bool:
    return _default.is_allowed(account, now)
