"""Доповнення звіту pip-audit оцінками CVSS (для аналізу стадії SCA).

pip-audit 2.7.3 подає ідентифікатори вразливостей (PYSEC/GHSA/CVE), але не оцінку CVSS.
Скрипт для кожного GHSA-аліасу бере вектор CVSS v3 з публічної бази OSV
(https://api.osv.dev) і обчислює базову оцінку за формулами CVSS v3.1 (як cvss.py з ЛР1).

Запуск після стадії sca:  python sca_cvss.py   (читає pip-audit.json, пише sca_cvss.json)
"""
from __future__ import annotations

import json
import math
import sys
import urllib.request

AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
AC = {"L": 0.77, "H": 0.44}
UI = {"N": 0.85, "R": 0.62}
PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}
PR_C = {"N": 0.85, "L": 0.68, "H": 0.5}
CIA = {"H": 0.56, "L": 0.22, "N": 0.0}


def base_score(vector: str) -> float:
    m = dict(p.split(":") for p in vector.split("/")[1:])
    changed = m["S"] == "C"
    iss = 1 - (1 - CIA[m["C"]]) * (1 - CIA[m["I"]]) * (1 - CIA[m["A"]])
    impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if changed else 6.42 * iss
    exploit = 8.22 * AV[m["AV"]] * AC[m["AC"]] * (PR_C if changed else PR_U)[m["PR"]] * UI[m["UI"]]
    if impact <= 0:
        return 0.0
    return math.ceil(min((1.08 if changed else 1.0) * (impact + exploit), 10) * 10) / 10


def osv_severity(ghsa: str) -> tuple[str | None, str | None, str]:
    """(вектор CVSS v3, вектор CVSS v4, рівень за базою GHSA)."""
    with urllib.request.urlopen(f"https://api.osv.dev/v1/vulns/{ghsa}", timeout=15) as resp:
        data = json.load(resp)
    v3 = next((s["score"] for s in data.get("severity", []) if s.get("type") == "CVSS_V3"), None)
    v4 = next((s["score"] for s in data.get("severity", []) if s.get("type") == "CVSS_V4"), None)
    return v3, v4, data.get("database_specific", {}).get("severity", "")


def main() -> int:
    audit = json.load(open("pip-audit.json", encoding="utf-8"))
    rows = []
    for dep in audit["dependencies"]:
        for v in dep.get("vulns", []):
            ghsa = next((a for a in v.get("aliases", []) if a.startswith("GHSA-")), None)
            cve = next((a for a in v.get("aliases", []) if a.startswith("CVE-")), "")
            vector, v4, level = osv_severity(ghsa) if ghsa else (None, None, "")
            score = base_score(vector) if vector else None
            rows.append({"package": dep["name"], "version": dep["version"], "id": v["id"],
                         "cve": cve, "ghsa": ghsa, "vector": vector, "cvss": score,
                         "vector_v4": v4, "level": level,
                         "fix": ", ".join(v.get("fix_versions", []))})
    rows.sort(key=lambda r: -(r["cvss"] or 0))
    for r in rows:
        shown = r["vector"] or f'лише v4: {r["vector_v4"]}'
        print(f'{r["package"]:7} {r["version"]:7} {r["cve"]:15} CVSS {r["cvss"]} [{r["level"]}]  '
              f'{shown}  fix {r["fix"]}')
    print(f"Максимальна оцінка: {max(r['cvss'] or 0 for r in rows)}; "
          f"з CVSS ≥ 7.0: {sum(1 for r in rows if (r['cvss'] or 0) >= 7.0)}; "
          f"з CVSS ≥ 4.0: {sum(1 for r in rows if (r['cvss'] or 0) >= 4.0)} з {len(rows)}")
    json.dump(rows, open("sca_cvss.json", "w", encoding="utf-8"), ensure_ascii=False, indent=2)
    return 0


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    sys.exit(main())
