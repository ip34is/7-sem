"""Критерій проходження (quality gate) — ЛР6, варіант 14.

Критерій варіанта: блокувати складання за появи НОВИХ знахідок відносно базової лінії.

    g = (кількість нових знахідок SAST відносно baseline.json) > 0

Базова лінія (baseline.json) — зафіксований окремим комітом набір відбитків знахідок
Semgrep (власні правила + реєстр p/python) і Bandit. Знахідки, що вже є в базовій лінії
(технічний борг), складання не зупиняють; будь-яка знахідка, якої там немає, — зупиняє.

Відбиток знахідки не містить номера рядка: (інструмент, правило, файл, нормалізований
текст рядка знахідки). Тому зсув коду через сторонні правки не робить стару знахідку
«новою», а однакові знахідки рахуються кратно (multiset).

Запуск:
  python gate.py                    # рішення: код 0 — пройдено, 1 — заблоковано
  python gate.py --update-baseline  # перезаписати baseline.json поточними знахідками
Звіти bandit.json і semgrep.json мають лежати поряд (їх формує стадія sast).
"""
from __future__ import annotations

import json
import os
import re
import sys
from collections import Counter

BASELINE = "baseline.json"


def load(path: str) -> dict | None:
    """Читає JSON-звіт. Повертає None, якщо звіту немає або його пошкоджено."""
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError):
        return None


def bandit_high(report: dict) -> int:
    return sum(1 for r in report.get("results", [])
               if r.get("issue_severity") == "HIGH")


def _norm(text: str) -> str:
    """Нормалізація тексту знахідки: без зайвих пробілів і переносів."""
    return re.sub(r"\s+", " ", text).strip()


def _source_line(path: str, line: int) -> str:
    try:
        with open(path, encoding="utf-8") as fh:
            return fh.read().splitlines()[line - 1]
    except (OSError, IndexError):
        return ""


def semgrep_findings(report: dict) -> list[dict]:
    out = []
    for r in report.get("results", []):
        rule = r["check_id"].split(".")[-1]
        out.append({"tool": "semgrep", "rule": rule, "path": r["path"],
                    "line": r["start"]["line"], "severity": r["extra"].get("severity", ""),
                    "text": _norm(r["extra"].get("lines", ""))})
    return out


def bandit_findings(report: dict) -> list[dict]:
    out = []
    for r in report.get("results", []):
        out.append({"tool": "bandit", "rule": r["test_id"], "path": r["filename"],
                    "line": r["line_number"], "severity": r.get("issue_severity", ""),
                    "text": _norm(_source_line(r["filename"], r["line_number"]))})
    return out


def fingerprint(f: dict) -> str:
    return f'{f["tool"]}|{f["rule"]}|{f["path"]}|{f["text"]}'


def new_findings(current: list[dict], baseline: Counter) -> list[dict]:
    """Знахідки, яких немає в базовій лінії (з урахуванням кратності)."""
    seen: Counter = Counter()
    new = []
    for f in current:
        fp = fingerprint(f)
        seen[fp] += 1
        if seen[fp] > baseline.get(fp, 0):
            new.append(f)
    return new


def collect() -> tuple[list[dict] | None, str]:
    """Знахідки обох інструментів або (None, причина) — якщо звіт відсутній чи збій сканера."""
    semgrep, bandit = load("semgrep.json"), load("bandit.json")
    if semgrep is None or bandit is None:
        return None, "звіт semgrep.json або bandit.json відсутній чи пошкоджений"
    fatal = [e for e in semgrep.get("errors", []) if e.get("level") == "error"]
    if fatal:
        return None, f"Semgrep повідомив про {len(fatal)} помилок виконання (правила не застосовано)"
    return semgrep_findings(semgrep) + bandit_findings(bandit), ""


def update_baseline() -> int:
    current, why = collect()
    if current is None:
        print(f"::error::Базову лінію не створено: {why}")
        return 1
    counts = Counter(fingerprint(f) for f in current)
    data = {"criterion": "new findings vs baseline (variant 14)",
            "total": len(current),
            "findings": [{"fingerprint": fp, "count": n} for fp, n in sorted(counts.items())]}
    with open(BASELINE, "w", encoding="utf-8") as fh:
        json.dump(data, fh, ensure_ascii=False, indent=2)
        fh.write("\n")
    print(f"Базову лінію записано: {len(current)} знахідок, {len(counts)} відбитків → {BASELINE}")
    return 0


def main() -> int:
    current, why = collect()
    if current is None:
        # Fail closed: відсутній звіт — це збій сканера, а не «0 знахідок».
        print(f"::error::Quality gate: {why} — складання заблоковано")
        return 1
    base = load(BASELINE)
    if base is None:
        print(f"::error::Quality gate: {BASELINE} відсутній — створіть базову лінію "
              "окремим комітом (python gate.py --update-baseline)")
        return 1
    baseline = Counter({e["fingerprint"]: e["count"] for e in base["findings"]})

    semgrep_n = sum(1 for f in current if f["tool"] == "semgrep")
    print(f"Знахідок Semgrep: {semgrep_n}, Bandit: {len(current) - semgrep_n} "
          f"(з них Bandit HIGH: {bandit_high(load('bandit.json'))}); у базовій лінії: {base['total']}")

    new = new_findings(current, baseline)
    gone = sum((baseline - Counter(fingerprint(f) for f in current)).values())
    if gone:
        print(f"Усунено знахідок відносно базової лінії: {gone} (базову лінію можна оновити)")

    # Сумісність із каркасом: явно заданий MAX_HIGH додатково обмежує кількість HIGH.
    if "MAX_HIGH" in os.environ:
        high, threshold = bandit_high(load("bandit.json")), int(os.environ["MAX_HIGH"])
        if high > threshold:
            print(f"::error::Quality gate: {high} знахідок HIGH перевищує поріг {threshold}")
            return 1

    if new:
        for f in new:
            print(f'::error file={f["path"]},line={f["line"]}::Нова знахідка {f["tool"]}/{f["rule"]} '
                  f'[{f["severity"]}]: {f["text"][:90]}')
        print(f"::error::Quality gate: {len(new)} нових знахідок відносно базової лінії — "
              "складання заблоковано")
        return 1
    print("Нових знахідок відносно базової лінії: 0")
    print("Quality gate: пройдено")
    return 0


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    sys.exit(update_baseline() if "--update-baseline" in sys.argv else main())
