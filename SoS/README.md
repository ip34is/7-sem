# Безпека програмного забезпечення · Варіант 14

Скачков І. О., група ІП-34. Лабораторні роботи з дисципліни «Безпека програмного забезпечення» (КПІ ім. Ігоря Сікорського, ФІОТ).

Папка `SoS` (Security of Software) монорепозиторію 7-sem. Структура повторює [репозиторій курсу](https://github.com/sokolusha/software-security-course): `common/variants.py`, `lab01_threat_model/cvss.py` і каркас `lab02_access_control/accesscontrol`, `examples`, `tests/test_example.py` скопійовано звідти без змін. Кожна робота лежить у власній папці й запускається з неї незалежно від інших.

| № | Тема | Каталог | Звіт і артефакти |
|---|------|---------|------------------|
| 1 | Побудова моделі загроз програмного застосунку | `lab1/lab01_threat_model` | `lab1/звіт_лр1` |
| 2 | Розроблення підсистеми розмежування доступу | `lab2/lab02_access_control` | `lab2/звіт_лр2` |
| 3 | Розроблення підсистеми ідентифікації та автентифікації | `lab3/lab03_auth` | `lab3/звіт_лр3` |
| 4 | Дослідження та реалізація криптографічних механізмів | `lab4/lab04_crypto` | `lab4/звіт_лр4` |
| 5 | Виявлення та усунення вразливостей за OWASP Top 10 | `lab5/lab05_vulnapp` | `lab5/звіт_лр5` |

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

## ЛР3 — підсистема ідентифікації та автентифікації

Варіант 14: bcrypt, одноразові коди відновлення, квота спроб у ковзному вікні; формула Андерсона для T = 120 діб, R = 12 спроб/хв, P = 1e-6.

- `lab03_auth/auth/passwords.py` — `hash_password` / `verify_password` (bcrypt cost 12, сіль, перець через HMAC-SHA256);
- `lab03_auth/auth/lockout.py` — квота 5 невдач за 15 хв;
- `lab03_auth/auth/recovery.py` — 10 одноразових кодів відновлення (зберігаються лише HMAC-хеші);
- `lab03_auth/auth/service.py` — вхід «пароль → код» зі спільною квотою;
- `lab03_auth/demo.py` — розрахунок Андерсона, заміри часу, сценарії; `tests/test_variant.py` — 33 тести;
- `звіт_лр3/scheme.mmd`, `scheme.png`, `anderson_plot.png`, `demo_output.txt`, `pytest_output.txt`.

Перець задається змінною середовища `AUTH_PEPPER`; у тестах і демонстрації — лише тестове значення.

```
cd lab3
python -m common.variants 14 --lab 3
cd lab03_auth
pip install -r requirements.txt
PYTHONPATH=. pytest tests/ -q        # 33 passed
python demo.py --plot ../звіт_лр3/anderson_plot.png
```

## ЛР4 — криптографічні механізми

Варіант 14: AES-128-GCM, RSA-PSS (2048), навчальний RSA з 28-бітовими множниками; помилки «ECB замість AEAD» і «хешування пароля без солі».

- `lab04_crypto/crypto_lab/aead.py` — AES-128-GCM: випадковий 96-бітовий nonce, асоційовані дані, ліміт повідомлень на ключ;
- `lab04_crypto/crypto_lab/misuse_ecb.py` — ECB: повтори блоків, зображення, атака перестановкою блоків;
- `lab04_crypto/crypto_lab/misuse_hash.py` — SHA-256 без солі проти scrypt із сіллю;
- `lab04_crypto/crypto_lab/sign_demo.py` — підпис і перевірка RSA-PSS 2048;
- `lab04_crypto/crypto_lab/rsa_analysis.py` — факторизація (перебір, ρ-метод Полларда), кількість множень;
- `lab04_crypto/demo.py` — усі кроки роботи; `tests/test_variant.py` — 26 тестів (разом з еталонними — 32);
- `звіт_лр4/factor_time.png`, `ecb_image.png`, `demo_output.txt`, `pytest_output.txt`.

```
cd lab4
python -m common.variants 14 --lab 4
cd lab04_crypto
python -m pip install -r requirements.txt
PYTHONPATH=. pytest tests/ -q        # 32 passed
python demo.py --figs ../звіт_лр4
python -m crypto_lab.sign_demo
```

## ЛР5 — вразливості за OWASP Top 10

Варіант 14: п'ять вразливостей у навчальному застосунку «Документообіг» — SQL-ін'єкція (CWE-89, /login), відображений XSS (CWE-79, /search), CSRF (CWE-352, /profile), IDOR (CWE-639, /document/<id>), відсутність перевірки прав (CWE-862, /admin/users). Кожну підтверджено, усунено й закрито регресійним тестом.

Потрібен Docker. Стенд публікується **лише** на `127.0.0.1:8080`; внутрішня служба портів назовні не має.

- `lab05_vulnapp/app.py`, `templates/` — виправлений застосунок (маркери `ВИПРАВЛЕНО N`);
- `lab05_vulnapp/test_regression.py` — 5 регресійних тестів (requests + pytest);
- `docker-compose.yml`, `.env.example` — опис стенда;
- `звіт_лр5/proof_*.png` — докази експлуатації (форма Д1), `scheme.png`, `pytest_before.txt`, `pytest_after.txt`, `compose_ps.txt`.

```
cd lab5
cp .env.example .env
docker compose up -d --build         # 127.0.0.1:8080
python -m venv .venv && .venv/Scripts/pip install requests pytest
cd lab05_vulnapp
PYTHONPATH=. ../.venv/Scripts/python -m pytest -q test_regression.py   # 5 passed
docker compose down -v
```
