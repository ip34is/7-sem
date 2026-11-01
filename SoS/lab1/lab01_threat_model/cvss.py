"""Спрощений калькулятор базової оцінки CVSS v3.1 (лекція 2).

Для навчальних цілей: приймає вектор і повертає базову оцінку.
Приклад: python cvss.py "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
"""
from __future__ import annotations

import sys

AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
AC = {"L": 0.77, "H": 0.44}
UI = {"N": 0.85, "R": 0.62}
PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}
PR_C = {"N": 0.85, "L": 0.68, "H": 0.5}
CIA = {"H": 0.56, "L": 0.22, "N": 0.0}


def _roundup(x: float) -> float:
    import math
    return math.ceil(x * 10) / 10


def base_score(vector: str) -> float:
    m = dict(part.split(":") for part in vector.replace("CVSS:3.1/", "").split("/"))
    scope_changed = m["S"] == "C"
    pr = (PR_C if scope_changed else PR_U)[m["PR"]]
    iss = 1 - (1 - CIA[m["C"]]) * (1 - CIA[m["I"]]) * (1 - CIA[m["A"]])
    impact = (7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
              if scope_changed else 6.42 * iss)
    exploit = 8.22 * AV[m["AV"]] * AC[m["AC"]] * pr * UI[m["UI"]]
    if impact <= 0:
        return 0.0
    raw = min((1.08 if scope_changed else 1.0) * (impact + exploit), 10)
    return _roundup(raw)


if __name__ == "__main__":
    v = sys.argv[1] if len(sys.argv) > 1 else "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
    print(f"{v}\nбазова оцінка: {base_score(v)}")
