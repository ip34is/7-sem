"""Регресійні тести ЛР5, варіант 14 (В1, В3, В4, В5, В10).

Кожен тест відтворює корисне навантаження відповідної вразливості й перевіряє,
що її БІЛЬШЕ НЕМАЄ. На вразливому коді тест падає (червоний), на виправленому —
проходить (зелений). Запуск проти працюючого стенда на 127.0.0.1:

    cd lab05_vulnapp
    PYTHONPATH=. python -m pytest -q test_regression.py

Усі дані синтетичні; жодних цілей, крім локального стенда 127.0.0.1.
"""
from __future__ import annotations

import requests

BASE = "http://127.0.0.1:8080"          # ЛИШЕ локальний стенд
TIMEOUT = 5
USER = ("kovalenko", "koval-2026")      # звичайний користувач, id=2 (синтетичний)


def _session(login: str, password: str) -> requests.Session:
    s = requests.Session()
    s.post(f"{BASE}/login", data={"login": login, "password": password}, timeout=TIMEOUT)
    return s


def _is_authenticated(s: requests.Session) -> bool:
    """/documents віддає список лише автентифікованому; інакше 302 на /login."""
    r = s.get(f"{BASE}/documents", allow_redirects=False, timeout=TIMEOUT)
    return r.status_code == 200


# ── В1: SQL-ін'єкція у формі входу (CWE-89 / A03), маркер ВРАЗЛИВІСТЬ 2 ──────────
def test_v1_sql_injection_login_bypass():
    s = requests.Session()
    r = s.post(f"{BASE}/login", data={"login": "admin' -- ", "password": "будь-що"},
               allow_redirects=False, timeout=TIMEOUT)
    # На виправленому коді ін'єкція не автентифікує: немає переходу на /documents
    assert not (r.status_code == 302 and r.headers.get("Location", "").endswith("/documents")), \
        "SQL-ін'єкція admin' -- автентифікувала без пароля"
    assert not _is_authenticated(s), "ін'єкція створила дійсну сесію"
    # Класичне ' OR 1=1 -- теж не має проходити
    s2 = requests.Session()
    s2.post(f"{BASE}/login", data={"login": "' OR 1=1 -- ", "password": "x"}, timeout=TIMEOUT)
    assert not _is_authenticated(s2), "ін'єкція ' OR 1=1 -- автентифікувала"
    # Штатний вхід правильними даними має й далі працювати
    assert _is_authenticated(_session(*USER)), "легальний вхід зламано виправленням"


# ── В3: відображений XSS у пошуку (CWE-79 / A03), маркер ВРАЗЛИВІСТЬ 6 ───────────
def test_v3_reflected_xss_search():
    payload = "<script>alert(1)</script>"
    r = requests.get(f"{BASE}/search", params={"q": payload}, timeout=TIMEOUT)
    assert payload not in r.text, "рядок запиту виводиться без екранування (відображений XSS)"
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in r.text, "немає екранованого вигляду запиту"


# ── В4: CSRF у зміні профілю (CWE-352 / A01), маркер ВРАЗЛИВІСТЬ 8 ───────────────
def test_v4_csrf_profile_update():
    s = _session(*USER)
    before = s.get(f"{BASE}/profile", timeout=TIMEOUT).text
    # Міжсайтовий запит: стороння сторінка, без CSRF-токена
    r = s.post(f"{BASE}/profile",
               data={"full_name": "CSRF-PWNED", "email": "attacker@evil.example"},
               headers={"Referer": "http://evil.example/attack.html"},
               allow_redirects=False, timeout=TIMEOUT)
    assert r.status_code in (400, 403), \
        f"зміну профілю без CSRF-токена прийнято (код {r.status_code})"
    after = s.get(f"{BASE}/profile", timeout=TIMEOUT).text
    assert "attacker@evil.example" not in after and before == after, \
        "профіль змінено міжсайтовим запитом (CSRF)"


# ── В5: IDOR у перегляді документів (CWE-639 / A01), маркер ВРАЗЛИВІСТЬ 5 ─────────
def test_v5_idor_document():
    s = _session(*USER)                                   # kovalenko, id=2
    r = s.get(f"{BASE}/document/8", allow_redirects=False, timeout=TIMEOUT)  # власник — melnyk
    assert r.status_code in (403, 404), \
        f"доступ до чужого документа дозволено (код {r.status_code}, IDOR)"
    assert "Результати перевірки" not in r.text, "вміст чужого документа розкрито"
    # Власний документ має лишатися доступним
    own = s.get(f"{BASE}/document/2", timeout=TIMEOUT)    # документ kovalenko
    assert own.status_code == 200 and "Кошторис" in own.text, "власний документ став недоступним"


# ── В10: відсутність перевірки прав в адмінмаршруті (CWE-862 / A01), ВРАЗЛИВІСТЬ 12 ─
def test_v10_admin_requires_authorization():
    # Анонім
    r = requests.get(f"{BASE}/admin/users", allow_redirects=False, timeout=TIMEOUT)
    assert r.status_code in (302, 403), f"адмінсторінка доступна анонімно (код {r.status_code})"
    assert "melnyk@stand.local" not in r.text, "список користувачів витік анонімно"
    # Звичайний користувач (не admin) теж не має доступу
    s = _session(*USER)
    r2 = s.get(f"{BASE}/admin/users", allow_redirects=False, timeout=TIMEOUT)
    assert r2.status_code in (302, 403), "звичайний користувач отримав адмінсторінку"
    # Адміністратор доступ зберігає
    adm = _session("admin", "Adm1n-stand-2026")
    r3 = adm.get(f"{BASE}/admin/users", timeout=TIMEOUT)
    assert r3.status_code == 200 and "melnyk" in r3.text, "адміністратор втратив доступ"
