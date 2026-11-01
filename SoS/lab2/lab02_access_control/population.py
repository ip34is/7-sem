"""Наповнення політики варіанта 14: 10 суб'єктів, 23 об'єкти (усі дані вигадані).

Предметна область — СЕД кафедри з ЛР1. Ієрархія ролей (старша ≻ молодша):

    head ≻ lecturer ≻ employee
    head ≻ secretary ≻ employee
    hr ≻ employee
    student, auditor — окремі кореневі ролі

Тимчасові права (D2):
  - dave — в. о. завідувача (роль head) лише 09:00–12:00 26.10.2026;
  - роль lecturer має WRITE на відомості лише під час сесії, до 16:00 26.10.2026.
"""
from __future__ import annotations

import datetime as dt

from accesscontrol.monitor import Permission
from mypolicy import KYIV, Clock, OperationLog, VariantPolicy

R, W, D = Permission.READ, Permission.WRITE, Permission.DELETE


def at(hour: int, minute: int = 0, second: int = 0, day: int = 26) -> float:
    """Синтетичний час 2026-10-<day> hh:mm:ss (Київ) як мітка часу."""
    return dt.datetime(2026, 10, day, hour, minute, second, tzinfo=KYIV).timestamp()


SUBJECTS = ["alice", "bob", "carol", "dave", "erin", "frank", "grace", "heidi", "mallory", "trent"]

ORDERS = [f"order{i:02d}" for i in range(1, 6)]        # накази щодо здобувачів
GRADES = [f"grades{i:02d}" for i in range(1, 7)]       # екзаменаційні відомості
PROTOCOLS = [f"protocol{i:02d}" for i in range(1, 5)]  # протоколи засідань кафедри
PLANS = [f"plan{i:02d}" for i in range(1, 5)]          # індивідуальні плани викладачів
HR = [f"hr{i:02d}" for i in range(1, 5)]               # кадрові документи
OBJECTS = ORDERS + GRADES + PROTOCOLS + PLANS + HR

ACTING_HEAD = (at(9), at(12))       # dave: в. о. завідувача
SESSION_END = at(16)                # кінець сесії: lecturer більше не редагує відомості


def build_policy(clock: Clock, oplog: OperationLog | None = None,
                 temporal: bool = True) -> VariantPolicy:
    """temporal=False — та сама політика без правила D2 (для порівняння з базовою моделлю)."""
    p = VariantPolicy(clock, oplog)
    for role in ("employee", "student", "auditor"):
        p.add_role(role)
    p.add_role("lecturer", inherits=["employee"])
    p.add_role("secretary", inherits=["employee"])
    p.add_role("hr", inherits=["employee"])
    p.add_role("head", inherits=["lecturer", "secretary"])

    def period(start, end):
        return (start, end) if temporal else (None, None)

    for o in ORDERS + PROTOCOLS:
        p.permit("employee", o, R)
    for o in ORDERS + PROTOCOLS:
        p.permit("secretary", o, W)
    for o in PLANS:
        p.permit("lecturer", o, R | W)
    for o in GRADES:
        p.permit("lecturer", o, R)
        p.permit("lecturer", o, W, *period(None, SESSION_END))
        p.permit("head", o, W)
    for o in ORDERS:
        p.permit("head", o, D)
    for o in HR:
        p.permit("head", o, R)
        p.permit("hr", o, R | W | D)
    p.permit("student", "order01", R)     # опублікований наказ
    for o in OBJECTS:
        p.permit("auditor", o, R)

    p.assign("alice", "head")
    p.assign("bob", "secretary")
    p.assign("carol", "lecturer")
    p.assign("dave", "lecturer")
    p.assign("dave", "head", *period(*ACTING_HEAD))
    p.assign("erin", "lecturer")
    p.assign("frank", "hr")
    for s in ("grace", "heidi", "mallory"):
        p.assign(s, "student")
    p.assign("trent", "auditor")
    return p


class FakeClock:
    """Керований годинник для демонстрації та тестів."""

    def __init__(self, t: float) -> None:
        self.t = t

    def __call__(self) -> float:
        return self.t

    def set(self, t: float) -> None:
        self.t = t
