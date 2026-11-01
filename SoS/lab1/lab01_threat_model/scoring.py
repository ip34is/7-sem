"""scoring.py — оцінювання переліку загроз за CVSS v3.1 (ЛР1, варіант 14).

Система: електронний документообіг кафедри (СЕД).
Пріоритетна категорія STRIDE: розкриття інформації (Information disclosure).

Для кожної загрози задано:
  - елемент DFD (див. звіт_лр1/dfd.mmd) і категорію STRIDE;
  - вектор CVSS до впровадження контрзаходу (vector);
  - вектор після впровадження контрзаходу з реєстру ризиків (residual);
  - експертні ймовірність і вплив (Н/С/В) для матриці «ймовірність × вплив».

Запуск (з каталогу lab01_threat_model):
  python scoring.py          # таблиця оцінок і зведена статистика
  python scoring.py --md     # таблиця розділу 4 у форматі Markdown
"""
from __future__ import annotations

import sys
from collections import Counter

from cvss import base_score

MIN_THREATS = 12
MIN_HIGH_RISK = 3
HIGH_RISK = 7.0
FOCUS = "I"

STRIDE = {
    "S": "Spoofing",
    "T": "Tampering",
    "R": "Repudiation",
    "I": "Information disclosure",
    "D": "Denial of service",
    "E": "Elevation of privilege",
}

# (id, елемент DFD, STRIDE, коротка назва, вектор, залишковий вектор, ймовірність, вплив)
THREATS = [
    ("T-01", "D3", "I", "Відкритий REST API пошукового індексу з повними текстами",
     "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L", "AV:A/AC:H/PR:H/UI:N/S:U/C:L/I:N/A:N", "В", "В"),
    ("T-02", "P2", "I", "IDOR під час завантаження файлу документа",
     "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", "AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N", "В", "В"),
    ("T-03", "P2", "I", "Фрагменти й кількість збігів недоступних документів у пошуку",
     "AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N", "AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N", "С", "С"),
    ("T-04", "D2", "I", "Анонімний доступ до бакета документів у MinIO",
     "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "AV:N/AC:H/PR:H/UI:N/S:U/C:L/I:N/A:N", "С", "В"),
    ("T-05", "F2", "I", "Витік довгоживучих pre-signed URL",
     "AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N", "AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N", "С", "С"),
    ("T-06", "F14", "I", "Вміст документів у листах-сповіщеннях",
     "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", "AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N", "С", "С"),
    ("T-07", "F3/F4", "I", "Перехоплення нешифрованого трафіку P1↔P2",
     "AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:L/A:N", "AV:A/AC:H/PR:H/UI:N/S:U/C:L/I:N/A:N", "Н", "В"),
    ("T-08", "P2", "I", "Детальні повідомлення про помилки (режим налагодження)",
     "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N", "В", "Н"),
    ("T-09", "P3", "I", "Приховані метадані та «зафарбований» текст в опублікованих файлах",
     "AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N", "AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N", "С", "С"),
    ("T-10", "D4", "I", "Токени сесій і персональні дані в журналах",
     "AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N", "AV:L/AC:H/PR:H/UI:N/S:U/C:L/I:N/A:N", "Н", "С"),
    ("T-11", "D5", "I", "Нешифровані резервні копії у хмарі",
     "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", "AV:N/AC:H/PR:H/UI:N/S:U/C:L/I:N/A:N", "Н", "В"),
    ("T-12", "D1", "I", "Обліковий запис застосунку в БД — суперкористувач, пароль у .env",
     "AV:A/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N", "AV:A/AC:H/PR:H/UI:N/S:U/C:L/I:L/A:N", "Н", "В"),
    ("T-13", "E1", "S", "Викрадення сесії завідувача через збережений XSS",
     "AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:L/A:N", "AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:N", "С", "В"),
    ("T-14", "E4", "S", "Підстановка ID-токена, виданого іншому клієнту SSO",
     "AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N", "AV:N/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:N", "Н", "В"),
    ("T-15", "D2", "T", "Заміна файлу вже підписаного документа",
     "AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:H/A:N", "AV:N/AC:H/PR:H/UI:N/S:U/C:N/I:L/A:N", "Н", "В"),
    ("T-16", "P2", "T", "CSRF на погодження документа",
     "AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N", "AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N", "С", "С"),
    ("T-17", "E1", "R", "Заперечення факту погодження документа",
     "AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N", "AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:L/A:N", "С", "С"),
    ("T-18", "D4", "R", "Редагування журналу аудиту; перегляди не журналюються",
     "AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:H/A:N", "AV:L/AC:H/PR:H/UI:N/S:U/C:N/I:L/A:N", "Н", "С"),
    ("T-19", "P3", "D", "Файли-«бомби» виснажують обробник",
     "AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H", "AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L", "С", "С"),
    ("T-20", "F1", "D", "Перевантаження запитами в пікові періоди",
     "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L", "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L", "С", "Н"),
    ("T-21", "P3", "E", "Виконання коду через вразливість конвертера документів",
     "AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:H", "AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:L", "С", "В"),
    ("T-22", "P2", "E", "Секретар призначає будь-які ролі, зокрема «завідувач»",
     "AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:N", "AV:N/AC:H/PR:H/UI:N/S:U/C:L/I:L/A:N", "Н", "В"),
]

LEVEL_POINTS = {"Н": 1, "С": 2, "В": 3}


def severity(score: float) -> str:
    """Якісний рівень за таблицею 2.3 практикуму."""
    if score == 0.0:
        return "немає"
    if score < 4.0:
        return "низький"
    if score < 7.0:
        return "середній"
    if score < 9.0:
        return "високий"
    return "критичний"


def matrix_level(likelihood: str, impact: str) -> str:
    """Матриця 3×3 «ймовірність × вплив»: добуток балів 1–2 / 3–4 / 6–9."""
    product = LEVEL_POINTS[likelihood] * LEVEL_POINTS[impact]
    if product >= 6:
        return "високий"
    if product >= 3:
        return "середній"
    return "низький"


def score(vector: str) -> float:
    return base_score("CVSS:3.1/" + vector)


def evaluate() -> list[dict]:
    rows = []
    for tid, element, cat, title, vector, residual, lik, imp in THREATS:
        rows.append({
            "id": tid, "element": element, "cat": cat, "title": title,
            "vector": vector, "score": score(vector),
            "residual": residual, "residual_score": score(residual),
            "lik": lik, "imp": imp, "matrix": matrix_level(lik, imp),
        })
    # Ранг: спершу за базовою оцінкою, за рівних — за матрицею, далі за номером.
    order = sorted(rows, key=lambda r: (-r["score"],
                                        -LEVEL_POINTS[r["lik"]] * LEVEL_POINTS[r["imp"]],
                                        r["id"]))
    for rank, r in enumerate(order, start=1):
        r["rank"] = rank
    return rows


def print_table(rows: list[dict]) -> None:
    print(f"{'ID':4} {'Ел.':5} S {'Вектор CVSS':35} {'Бал':>4} {'Рівень':9} "
          f"{'Зал.':>4} {'Ранг':>4}")
    for r in rows:
        mark = " *" if r["score"] >= HIGH_RISK else ""
        print(f"{r['id']:4} {r['element']:5} {r['cat']} {r['vector']:35} "
              f"{r['score']:4.1f} {severity(r['score']):9} {r['residual_score']:4.1f} "
              f"{r['rank']:4}{mark}")
    print("* — загроза високого ризику (CVSS ≥ 7.0); Зал. — оцінка після контрзаходу")


def print_markdown(rows: list[dict]) -> None:
    print("| № загрози | Вектор CVSS | Базова оцінка | Імовірність | Вплив | Ранг ризику |")
    print("|-----------|-------------|---------------|-------------|-------|-------------|")
    for r in rows:
        s = f"{r['score']:.1f}"
        if r["score"] >= HIGH_RISK:
            s = f"**{s}**"
        print(f"| {r['id']} | `CVSS:3.1/{r['vector']}` | {s} ({severity(r['score'])}) | "
              f"{r['lik']} | {r['imp']} | {r['rank']} — {r['matrix']} |")


def print_summary(rows: list[dict]) -> bool:
    by_cat = Counter(r["cat"] for r in rows)
    by_elem = Counter(r["element"] for r in rows)
    high = [r for r in rows if r["score"] >= HIGH_RISK]
    top = min(rows, key=lambda r: r["rank"])

    print("\nЗагрози за категоріями STRIDE (кількість, середня оцінка):")
    for c in STRIDE:
        scores = [r["score"] for r in rows if r["cat"] == c]
        avg = sum(scores) / len(scores) if scores else 0.0
        print(f"  {c} {STRIDE[c]:23} {by_cat[c]:2}  {avg:4.2f}  {'#' * by_cat[c]}")
    print("Загрози за елементами DFD:\n  " +
          ", ".join(f"{e}: {n}" for e, n in by_elem.most_common()))
    print(f"Середня базова оцінка: {sum(r['score'] for r in rows) / len(rows):.2f} → "
          f"після контрзаходів: {sum(r['residual_score'] for r in rows) / len(rows):.2f}")
    print("Загрози високого ризику (CVSS ≥ 7.0):\n  " +
          ", ".join(f"{r['id']} ({r['score']})" for r in sorted(high, key=lambda r: r["rank"])))
    print(f"Найкритичніша загроза: {top['id']} ({top['score']})\n  {top['title']}")

    focus_ok = all(by_cat[FOCUS] > n for c, n in by_cat.items() if c != FOCUS)
    checks = {
        f"загроз не менше {MIN_THREATS}": len(rows) >= MIN_THREATS,
        f"загроз високого ризику не менше {MIN_HIGH_RISK}": len(high) >= MIN_HIGH_RISK,
        "охоплено щонайменше 3 категорії STRIDE": len(by_cat) >= 3,
        f"пріоритетна категорія {FOCUS} переважає": focus_ok,
        "залишкова оцінка не перевищує вихідну": all(r["residual_score"] <= r["score"] for r in rows),
        "контрольний вектор дає 9.8": base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == 9.8,
    }
    print("\nСамоперевірка:")
    for name, ok in checks.items():
        print(f"  [{'OK' if ok else '!!'}] {name}")
    return all(checks.values())


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    results = evaluate()
    if "--md" in sys.argv:
        print_markdown(results)
    else:
        print_table(results)
        sys.exit(0 if print_summary(results) else 1)
