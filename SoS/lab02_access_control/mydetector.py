"""Детектори аномалій варіанта 14 (лекція 7).

А1 — сплеск відмов у доступі від одного суб'єкта;
А5 — використання прав, не задіяних раніше.
Пороги передаються параметрами, як у FanInDetector навчального прикладу.
"""
from __future__ import annotations

import collections
import re

from accesscontrol.monitor import AnomalyDetector, AuditLog
from mypolicy import fmt_ts


class DenialSpikeDetector(AnomalyDetector):
    """А1: не менше `threshold` відмов одному суб'єкту за `window` секунд."""

    def __init__(self, threshold: int = 5, window: float = 60.0) -> None:
        self.threshold = threshold
        self.window = window

    def scan(self, log: AuditLog) -> list[str]:
        denials: dict[str, list[float]] = collections.defaultdict(list)
        for r in log.entries():
            if not r["allowed"]:
                denials[r["subject"]].append(r["ts"])
        alerts = []
        for subject, times in sorted(denials.items()):
            times.sort()
            best, best_start, left = 0, 0.0, 0
            for right, t in enumerate(times):          # ковзне вікно двома вказівниками
                while t - times[left] > self.window:
                    left += 1
                if right - left + 1 > best:
                    best, best_start = right - left + 1, times[left]
            if best >= self.threshold:
                alerts.append(f"А1: {subject} — {best} відмов за {self.window:.0f} с "
                              f"(від {fmt_ts(best_start)})")
        return alerts


def object_group(obj: str) -> str:
    """grades03 → grades: тип документа без номера."""
    return re.sub(r"\d+$", "", obj)


class NewPermissionDetector(AnomalyDetector):
    """А5: дозволене звернення з правом, якого суб'єкт не використовував у базовому періоді.

    Базовий період — записи з ts < baseline_until (навчання профілю).
    granularity="action" — профіль «суб'єкт → дія»;
    granularity="object" — «суб'єкт → (дія, тип документа)», чутливіший.
    """

    def __init__(self, baseline_until: float, granularity: str = "action") -> None:
        if granularity not in ("action", "object"):
            raise ValueError("granularity: 'action' або 'object'")
        self.baseline_until = baseline_until
        self.granularity = granularity

    def _key(self, r: dict) -> tuple[str, ...]:
        if self.granularity == "action":
            return (r["action"],)
        return (r["action"], object_group(r["object"]))

    def scan(self, log: AuditLog) -> list[str]:
        used: dict[str, set[tuple[str, ...]]] = collections.defaultdict(set)
        alerts = []
        for r in sorted(log.entries(), key=lambda e: e["ts"]):
            if not r["allowed"]:
                continue
            key = self._key(r)
            if r["ts"] >= self.baseline_until and key not in used[r["subject"]]:
                alerts.append(f"А5: {r['subject']} уперше використав {'/'.join(key)} "
                              f"({r['object']}, {fmt_ts(r['ts'])})")
            used[r["subject"]].add(key)
        return alerts


class VariantDetector(AnomalyDetector):
    """Обидві аномалії варіанта в одному скануванні."""

    def __init__(self, baseline_until: float, threshold: int = 5, window: float = 60.0,
                 granularity: str = "action") -> None:
        self.detectors = [DenialSpikeDetector(threshold, window),
                          NewPermissionDetector(baseline_until, granularity)]

    def scan(self, log: AuditLog) -> list[str]:
        return [alert for d in self.detectors for alert in d.scan(log)]
