"""ЛР2, варіант 14: RBAC з ієрархією ролей і тимчасовими правами (D2).

Модель (Sandhu et al., 1996; лекція 6):
  UA — призначення «суб'єкт → роль», PA — призначення «роль → права на об'єкт»,
  RH — ієрархія ролей: старша роль успадковує всі права молодших.
Додаткове правило D2: кожне призначення UA і PA може мати інтервал дії
[valid_from, valid_until). Поза інтервалом призначення не дає прав.

Рішення (формула 3.1 практикуму, deny-записів у варіанті немає):
  allow(s, o, a) = a ⊆ ⋃ { perm(r, o) : r ∈ RH*(active_roles(s, t)), PA(r, o) чинне в t }
Якщо дозволу немає — відмова (safe default).
"""
from __future__ import annotations

import dataclasses
import datetime as dt
import json
import time
from collections.abc import Callable, Iterable

from accesscontrol.monitor import AuditLog, Decision, Permission, Policy, ReferenceMonitor

Clock = Callable[[], float]
KYIV = dt.timezone(dt.timedelta(hours=2), "EET")   # синтетичні дані — лише для показу часу


def fmt_ts(ts: float) -> str:
    return dt.datetime.fromtimestamp(ts, KYIV).strftime("%Y-%m-%d %H:%M")


@dataclasses.dataclass(frozen=True)
class Interval:
    """Інтервал дії [start, end); None — без обмеження з цього боку."""

    start: float | None = None
    end: float | None = None

    def contains(self, t: float) -> bool:
        return (self.start is None or self.start <= t) and (self.end is None or t < self.end)

    def describe(self, t: float) -> str:
        if self.end is not None and t >= self.end:
            return f"термін дії сплив {fmt_ts(self.end)}"
        return f"діє лише з {fmt_ts(self.start)}"


ALWAYS = Interval()


@dataclasses.dataclass(frozen=True)
class Assignment:
    role: str
    interval: Interval = ALWAYS


@dataclasses.dataclass(frozen=True)
class Grant:
    perm: Permission
    interval: Interval = ALWAYS


def _via(assigned: str, role: str) -> str:
    """Як отримано право: «head» або «lecturer ← employee» (успадкування)."""
    return assigned if assigned == role else f"{assigned} ← {role}"


def _why(a: Assignment, role: str, obj: str, g: Grant, now: float) -> str:
    """Причина, з якої наявне право неактивне в момент now."""
    if not a.interval.contains(now):
        return f"призначення ролі {a.role}: {a.interval.describe(now)}"
    return f"право {role} на {obj}: {g.interval.describe(now)}"


class OperationLog:
    """Операційний журнал: лише виконані зміни стану (політики й об'єктів)."""

    def __init__(self, clock: Clock = time.time) -> None:
        self._clock = clock
        self._records: list[dict] = []

    def record(self, actor: str, operation: str, target: str, details: str = "") -> None:
        self._records.append({"ts": self._clock(), "actor": actor,
                              "operation": operation, "target": target, "details": details})

    def entries(self) -> list[dict]:
        return list(self._records)

    def dump(self) -> str:
        return "\n".join(json.dumps(r, ensure_ascii=False) for r in self._records)


class ClockedAuditLog(AuditLog):
    """Реєстраційний журнал каркаса з тим самим годинником, що й політика."""

    def __init__(self, clock: Clock = time.time) -> None:
        super().__init__()
        self._clock = clock

    def _now(self) -> float:
        return self._clock()


class VariantPolicy(Policy):
    """RBAC з ієрархією ролей і тимчасовими призначеннями."""

    def __init__(self, clock: Clock = time.time, oplog: OperationLog | None = None) -> None:
        self._clock = clock
        self._oplog = oplog or OperationLog(clock)
        self._roles: set[str] = set()
        self._juniors: dict[str, set[str]] = {}               # RH: старша → безпосередні молодші
        self._ua: dict[str, list[Assignment]] = {}            # UA: суб'єкт → призначені ролі
        self._pa: dict[tuple[str, str], list[Grant]] = {}     # PA: (роль, об'єкт) → права

    # ---------- адміністрування політики (кожна зміна — в операційний журнал) ----------

    def add_role(self, role: str, inherits: Iterable[str] = ()) -> None:
        self._roles.add(role)
        self._juniors.setdefault(role, set())
        self._oplog.record("admin", "add_role", role)
        for junior in inherits:
            self.add_inheritance(role, junior)

    def add_inheritance(self, senior: str, junior: str) -> None:
        self._require_role(senior)
        self._require_role(junior)
        if senior in self._closure(junior):
            raise ValueError(f"цикл в ієрархії ролей: {junior} уже старша за {senior}")
        self._juniors[senior].add(junior)
        self._oplog.record("admin", "add_inheritance", senior, f"успадковує {junior}")

    def assign(self, subject: str, role: str, valid_from: float | None = None,
               valid_until: float | None = None) -> None:
        self._require_role(role)
        interval = Interval(valid_from, valid_until)
        self._ua.setdefault(subject, []).append(Assignment(role, interval))
        self._oplog.record("admin", "assign", subject, f"роль {role}{self._period(interval)}")

    def revoke(self, subject: str, role: str) -> None:
        self._ua[subject] = [a for a in self._ua.get(subject, []) if a.role != role]
        self._oplog.record("admin", "revoke", subject, f"роль {role}")

    def permit(self, role: str, obj: str, perm: Permission, valid_from: float | None = None,
               valid_until: float | None = None) -> None:
        self._require_role(role)
        interval = Interval(valid_from, valid_until)
        self._pa.setdefault((role, obj), []).append(Grant(perm, interval))
        self._oplog.record("admin", "permit", obj, f"{role}: {perm.name}{self._period(interval)}")

    # ---------- рішення (довірена частина: evaluate і _closure) ----------

    def evaluate(self, subject: str, obj: str, action: Permission) -> Decision:
        now = self._clock()
        effective = Permission.NONE   # права, чинні зараз
        inactive = Permission.NONE    # права поза інтервалом дії (D2)
        why_inactive, sources = "", []
        for a in self._ua.get(subject, []):
            for role in sorted(self._closure(a.role)):
                for g in self._pa.get((role, obj), []):
                    if not g.perm & action:
                        continue
                    if a.interval.contains(now) and g.interval.contains(now):
                        effective |= g.perm
                        sources.append(_via(a.role, role))
                    else:
                        inactive |= g.perm
                        why_inactive = why_inactive or _why(a, role, obj, g, now)
        if action & effective == action:
            via = ", ".join(dict.fromkeys(sources))
            return Decision(True, "надано через роль " + via)
        if action & (effective | inactive) == action:
            return Decision(False, "тимчасове право неактивне — " + why_inactive)
        return Decision(False, "явного дозволу немає (safe default)")

    def _closure(self, role: str) -> set[str]:
        """Роль разом з усіма молодшими (транзитивне замикання RH)."""
        seen, stack = set(), [role]
        while stack:
            r = stack.pop()
            if r not in seen:
                seen.add(r)
                stack.extend(self._juniors.get(r, ()))
        return seen

    # ---------- запити, природні для RBAC ----------

    def active_roles(self, subject: str) -> set[str]:
        """Ролі, чинні зараз, з урахуванням успадкування."""
        now = self._clock()
        roles: set[str] = set()
        for a in self._ua.get(subject, []):
            if a.interval.contains(now):
                roles |= self._closure(a.role)
        return roles

    def accessible_objects(self, subject: str, action: Permission) -> list[str]:
        """«До чого має доступ суб'єкт»: суб'єкт → ролі → PA, без обходу всіх об'єктів."""
        roles = self.active_roles(subject)
        candidates = {obj for (role, obj) in self._pa if role in roles}
        return sorted(o for o in candidates if self.evaluate(subject, o, action).allowed)

    @property
    def subjects(self) -> list[str]:
        return sorted(self._ua)

    @staticmethod
    def _period(interval: Interval) -> str:
        if interval == ALWAYS:
            return ""
        start = fmt_ts(interval.start) if interval.start is not None else "…"
        end = fmt_ts(interval.end) if interval.end is not None else "…"
        return f" [{start} – {end})"

    def _require_role(self, role: str) -> None:
        if role not in self._roles:
            raise KeyError(f"невідома роль {role}")


def objects_accessible_by(policy: Policy, subject: str, objects: Iterable[str],
                          action: Permission) -> list[str]:
    """«До чого має доступ суб'єкт» повним обходом об'єктів (двоїсте subjects_with_access)."""
    return [o for o in objects if policy.evaluate(subject, o, action).allowed]


class DocumentService:
    """Підсистема зберігання документів. Має лише монітор — не політику.

    Кожна операція спершу проходить ReferenceMonitor.enforce (повне посередництво);
    у операційний журнал потрапляють лише виконані зміни (WRITE, DELETE).
    """

    def __init__(self, monitor: ReferenceMonitor, oplog: OperationLog,
                 documents: dict[str, str]) -> None:
        self._monitor = monitor
        self._oplog = oplog
        self._docs = dict(documents)

    def read(self, subject: str, obj: str) -> str:
        self._monitor.enforce(subject, obj, Permission.READ)
        return self._docs[obj]

    def write(self, subject: str, obj: str, text: str) -> None:
        self._monitor.enforce(subject, obj, Permission.WRITE)
        self._docs[obj] = text
        self._oplog.record(subject, "write", obj, f"довжина {len(text)}")

    def delete(self, subject: str, obj: str) -> None:
        self._monitor.enforce(subject, obj, Permission.DELETE)
        del self._docs[obj]
        self._oplog.record(subject, "delete", obj)
