# Безпека програмного забезпечення · Варіант 14

Скачков І. О., група ІП-34. Лабораторні роботи з дисципліни «Безпека програмного забезпечення» (КПІ ім. Ігоря Сікорського, ФІОТ).

Папка `SoS` (Security of Software) монорепозиторію 7-sem. Структура повторює [репозиторій курсу](https://github.com/sokolusha/software-security-course): `common/variants.py`, `lab01_threat_model/cvss.py` і каркас `lab02_access_control/accesscontrol`, `examples`, `tests/test_example.py` скопійовано звідти без змін. Кожна робота лежить у власній папці й запускається з неї незалежно від інших.

| № | Тема | Каталог | Звіт і артефакти |
|---|------|---------|------------------|
| 1 | Побудова моделі загроз програмного застосунку | `lab1/lab01_threat_model` | `lab1/звіт_лр1` |
| 2 | Розроблення підсистеми розмежування доступу | `lab2/lab02_access_control` | `lab2/звіт_лр2` |

У кожному `звіт_лрN` є PDF/DOCX звіту і `захист_лрN.md` — план відеозахисту та відповіді на контрольні запитання варіанта.

## ЛР1 — модель загроз СЕД кафедри

Варіант 14: система електронного документообігу кафедри, пріоритетна категорія STRIDE — розкриття інформації.

- `звіт_лр1/threat_model.md` — модель загроз (розділи 1–7);
- `звіт_лр1/dfd.mmd`, `dfd.png` — діаграма потоків даних із межами довіри;
- `звіт_лр1/attack_tree.mmd`, `attack_tree.png` — дерево атак для найкритичнішої загрози T-01;
- `lab01_threat_model/scoring.py` — 22 загрози з векторами CVSS, матриця «ймовірність × вплив», самоперевірка вимог варіанта;
- `звіт_лр1/scoring_output.txt` — вивід `scoring.py`.

Запуск (Python 3.11+) з папки `lab1`:

```
cd lab1
python -m common.variants 14 --lab 1
cd lab01_threat_model
python cvss.py "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
python scoring.py
python scoring.py --md
```

`scoring.py` завершується з кодом 1, якщо порушено хоч одну вимогу варіанта (не менше 12 загроз, 3 загроз високого ризику тощо).

Діаграми перерендерюються з `.mmd` утилітою [mermaid-cli](https://github.com/mermaid-js/mermaid-cli) (з папки `lab1`):

```
npx -p @mermaid-js/mermaid-cli mmdc -i звіт_лр1/dfd.mmd -o звіт_лр1/dfd.png -s 3 -b white
```

## ЛР2 — підсистема розмежування доступу

Варіант 14: RBAC з ієрархією ролей, тимчасові права (D2), аномалії «сплеск відмов» (А1) і «використання прав, не задіяних раніше» (А5); 10 суб'єктів, 23 об'єкти.

- `lab02_access_control/mypolicy.py` — `VariantPolicy` (RBAC + D2), операційний журнал, `DocumentService`;
- `lab02_access_control/population.py` — ролі, суб'єкти, об'єкти та призначення;
- `lab02_access_control/mydetector.py` — детектори А1 і А5;
- `lab02_access_control/demo.py` — демонстрація всіх кроків; `tests/test_variant.py` — 29 тестів;
- `звіт_лр2/scheme.mmd`, `scheme.png` — структурна схема; `demo_output.txt`, `pytest_output.txt`, `audit_log.jsonl`, `operation_log.jsonl`.

```
cd lab2
python -m common.variants 14 --lab 2
cd lab02_access_control
pip install -r requirements.txt
PYTHONPATH=. pytest tests/ -q        # 39 passed
python demo.py --save ../звіт_лр2
```
