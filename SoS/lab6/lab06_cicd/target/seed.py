"""Наповнення бази навчального стенда синтетичними даними.

Усі особи, паролі та документи вигадані. Жодних реальних персональних даних.
"""
from __future__ import annotations

import hashlib
import os
import sqlite3

SCHEMA = """
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS documents;
DROP TABLE IF EXISTS comments;

CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    login TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    full_name TEXT,
    email TEXT,
    role TEXT NOT NULL DEFAULT 'user'
);

CREATE TABLE documents (
    id INTEGER PRIMARY KEY,
    owner_id INTEGER NOT NULL REFERENCES users(id),
    title TEXT NOT NULL,
    body TEXT NOT NULL,
    classification TEXT NOT NULL DEFAULT 'internal'
);

CREATE TABLE comments (
    id INTEGER PRIMARY KEY,
    doc_id INTEGER NOT NULL REFERENCES documents(id),
    author_id INTEGER NOT NULL REFERENCES users(id),
    body TEXT NOT NULL
);
"""

# Тестові облікові записи стенда. Паролі навмисно слабкі — це частина завдання.
USERS = [
    ("admin",   "Adm1n-stand-2026", "Адміністратор стенда", "admin@stand.local",  "admin"),
    ("kovalenko", "koval-2026",     "Коваленко О. П.",      "kovalenko@stand.local", "user"),
    ("tkachuk",   "tkach-2026",     "Ткачук І. С.",         "tkachuk@stand.local",   "user"),
    ("bondar",    "bondar-2026",    "Бондар М. В.",         "bondar@stand.local",    "user"),
    ("melnyk",    "melnyk-2026",    "Мельник Л. А.",        "melnyk@stand.local",    "auditor"),
]

DOCUMENTS = [
    (1, "Регламент доступу до стенда", "Порядок отримання прав у навчальному стенді.", "internal"),
    (2, "Кошторис кафедри на 2026 рік", "Синтетичні дані кошторису.", "confidential"),
    (2, "Протокол засідання № 4", "Розглянуто питання успішності.", "internal"),
    (3, "Договір на постачання обладнання", "Вигаданий договір із вигаданим контрагентом.", "confidential"),
    (3, "План лабораторних робіт", "Перелік робіт на семестр.", "public"),
    (4, "Персональна картка співробітника", "Синтетичні дані картки.", "confidential"),
    (4, "Заявка на відрядження", "Заявка на участь у конференції.", "internal"),
    (5, "Звіт внутрішнього аудиту", "Результати перевірки навчального стенда.", "confidential"),
]


def seed(db_path: str) -> None:
    os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.executescript(SCHEMA)
    for login, password, name, email, role in USERS:
        conn.execute(
            "INSERT INTO users (login, password_hash, full_name, email, role) VALUES (?, ?, ?, ?, ?)",
            (login, hashlib.md5(password.encode()).hexdigest(), name, email, role),
        )
    for owner, title, body, classification in DOCUMENTS:
        conn.execute(
            "INSERT INTO documents (owner_id, title, body, classification) VALUES (?, ?, ?, ?)",
            (owner, title, body, classification),
        )
    conn.execute(
        "INSERT INTO comments (doc_id, author_id, body) VALUES (?, ?, ?)",
        (1, 2, "Ознайомлений."),
    )
    conn.commit()
    conn.close()


if __name__ == "__main__":
    path = os.environ.get("VULNAPP_DB", "/tmp/vulnapp.db")
    seed(path)
    print(f"Базу створено: {path}")
