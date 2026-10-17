# Безпека програмного забезпечення · Варіант 14

Скачков І. О., група ІП-34. Лабораторні роботи з дисципліни «Безпека програмного забезпечення» (КПІ ім. Ігоря Сікорського, ФІОТ).

Папка `SoS` (Security of Software) монорепозиторію 7-sem. Структура повторює [репозиторій курсу](https://github.com/sokolusha/software-security-course): `common/variants.py` і `lab01_threat_model/cvss.py` скопійовано звідти без змін.

| № | Тема | Каталог | Звіт і артефакти |
|---|------|---------|------------------|
| 1 | Побудова моделі загроз програмного застосунку | `lab01_threat_model` | `звіт_лр1` |

## ЛР1 — модель загроз СЕД кафедри

Варіант 14: система електронного документообігу кафедри, пріоритетна категорія STRIDE — розкриття інформації.

- `звіт_лр1/threat_model.md` — модель загроз (розділи 1–7);
- `звіт_лр1/dfd.mmd`, `dfd.png` — діаграма потоків даних із межами довіри;
- `звіт_лр1/attack_tree.mmd`, `attack_tree.png` — дерево атак для найкритичнішої загрози T-01;
- `lab01_threat_model/scoring.py` — 22 загрози з векторами CVSS, матриця «ймовірність × вплив», самоперевірка вимог варіанта;
- `звіт_лр1/scoring_output.txt` — вивід `scoring.py`.

Запуск (Python 3.11+):

```
python -m common.variants 14 --lab 1
cd lab01_threat_model
python cvss.py "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
python scoring.py
python scoring.py --md
```

`scoring.py` завершується з кодом 1, якщо порушено хоч одну вимогу варіанта (не менше 12 загроз, 3 загроз високого ризику тощо).

Діаграми перерендерюються з `.mmd` утилітою [mermaid-cli](https://github.com/mermaid-js/mermaid-cli):

```
npx -p @mermaid-js/mermaid-cli mmdc -i звіт_лр1/dfd.mmd -o звіт_лр1/dfd.png -s 3 -b white
```
