"""НАВМИСНО ВРАЗЛИВИЙ навчальний вебзастосунок «Документообіг».

    ⚠️  ЦЕЙ КОД МІСТИТЬ НАВМИСНІ ВРАЗЛИВОСТІ І ПРИЗНАЧЕНИЙ ВИКЛЮЧНО ДЛЯ
        ЛАБОРАТОРНОЇ РОБОТИ 5 В ІЗОЛЬОВАНОМУ СЕРЕДОВИЩІ DOCKER.

        Заборонено: запускати поза контейнером, публікувати порт за межі
        127.0.0.1, розгортати на віддаленому вузлі чи в мережі Університету.
        Несанкціоноване втручання в чужі системи — кримінальне правопорушення
        (ст. 361–363-1 Кримінального кодексу України).

Кожна вразливість позначена коментарем "ВРАЗЛИВІСТЬ N (CWE-XXX):" (усього 13).
Завдання здобувача — підтвердити експлуатацію, усунути дефект і написати
регресійний тест, що не дозволить йому повернутися.

Усі дані синтетичні. Паролі, ключі та імена вигадані.
"""

from __future__ import annotations

import base64
import os
import pickle  # noqa: S403 — навмисно вразливе, див. маршрут /prefs
import sqlite3
import subprocess  # noqa: S404 — навмисно вразливе, див. маршрут /admin/ping
import urllib.request

from flask import Flask, g, redirect, render_template, request, session, url_for

DB_PATH = os.environ.get("VULNAPP_DB", "/tmp/vulnapp.db")
UPLOAD_DIR = "/app/storage"

app = Flask(__name__)
# ВРАЗЛИВІСТЬ 1 (CWE-798): жорстко закодований передбачуваний секрет сесії.
app.secret_key = os.environ.get("VULNAPP_SECRET", "dev-secret")


# ── Доступ до бази даних ─────────────────────────────────────────────────────

def db() -> sqlite3.Connection:
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()


def current_user():
    uid = session.get("uid")
    if uid is None:
        return None
    return db().execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()


# ── Автентифікація ───────────────────────────────────────────────────────────

@app.route("/", methods=["GET"])
def index():
    return render_template("index.html", user=current_user())


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        login_name = request.form.get("login", "")
        password = request.form.get("password", "")
        # ВИПРАВЛЕНО В1 (CWE-89): параметризований запит — дані відокремлено від коду SQL,
        # тому значення login/пароля не можуть змінити структуру запиту.
        try:
            row = db().execute(
                "SELECT * FROM users WHERE login = ? AND password_hash = ?",
                (login_name, _weak_hash(password)),
            ).fetchone()
        except sqlite3.Error:
            # Узагальнене повідомлення без тексту запиту (також закриває CWE-209).
            return render_template("login.html", error="Невірний логін або пароль")
        if row:
            session["uid"] = row["id"]
            # Ідентифікатор сесії не оновлюється після входу — фіксація сесії (CWE-384).
            return redirect(url_for("documents"))
        error = "Невірний логін або пароль"
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


def _csrf_token() -> str:
    """Синхронізований токен сесії (генерується один раз на сесію)."""
    import secrets
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
    return token


def _valid_csrf(sent: str) -> bool:
    import hmac
    expected = session.get("csrf_token", "")
    return bool(expected) and hmac.compare_digest(sent, expected)


def _weak_hash(password: str) -> str:
    """ВРАЗЛИВІСТЬ 4 (CWE-916): непридатна для паролів швидка хеш-функція без солі."""
    import hashlib
    return hashlib.md5(password.encode()).hexdigest()  # noqa: S324


# ── Документи ────────────────────────────────────────────────────────────────

@app.route("/documents")
def documents():
    user = current_user()
    if user is None:
        return redirect(url_for("login"))
    rows = db().execute("SELECT * FROM documents WHERE owner_id = ?", (user["id"],)).fetchall()
    return render_template("documents.html", user=user, documents=rows)


@app.route("/document/<int:doc_id>")
def document(doc_id: int):
    user = current_user()
    if user is None:
        return redirect(url_for("login"))
    # ВИПРАВЛЕНО В5 (CWE-639): перевірка власника об'єкта. Документ бачить лише власник;
    # привілейовані ролі (admin, auditor) зберігають легітимний нагляд. Для решти — 404,
    # щоб не розкривати навіть факт існування чужого документа.
    row = db().execute("SELECT * FROM documents WHERE id = ?", (doc_id,)).fetchone()
    if row is None:
        return "Документ не знайдено", 404
    if row["owner_id"] != user["id"] and user["role"] not in ("admin", "auditor"):
        return "Документ не знайдено", 404
    comments = db().execute(
        "SELECT * FROM comments WHERE doc_id = ? ORDER BY id", (doc_id,)
    ).fetchall()
    return render_template("document.html", user=user, doc=row, doc_comments=comments)


@app.route("/search")
def search():
    query = request.args.get("q", "")
    rows = db().execute(
        "SELECT * FROM documents WHERE title LIKE ?", (f"%{query}%",)
    ).fetchall()
    # ВИПРАВЛЕНО В3 (CWE-79): відображений XSS усунено в шаблоні search.html —
    # прибрано фільтр |safe, тож Jinja2 автоматично екранує рядок запиту q.
    return render_template("search.html", user=current_user(), q=query, documents=rows)


@app.route("/comment/<int:doc_id>", methods=["POST"])
def comment(doc_id: int):
    user = current_user()
    if user is None:
        return redirect(url_for("login"))
    text = request.form.get("text", "")
    # ВРАЗЛИВІСТЬ 7 (CWE-79): збережений XSS — вміст зберігається й виводиться без екранування.
    db().execute(
        "INSERT INTO comments (doc_id, author_id, body) VALUES (?, ?, ?)",
        (doc_id, user["id"], text),
    )
    db().commit()
    return redirect(url_for("document", doc_id=doc_id))


@app.route("/profile", methods=["GET", "POST"])
def profile():
    user = current_user()
    if user is None:
        return redirect(url_for("login"))
    if request.method == "POST":
        # ВИПРАВЛЕНО В4 (CWE-352): синхронізований токен. Форма несе прихований токен
        # із сесії; міжсайтовий запит його не знає, тому зміну стану відхилено.
        if not _valid_csrf(request.form.get("csrf_token", "")):
            return "Недійсний CSRF-токен", 403
        db().execute(
            "UPDATE users SET full_name = ?, email = ? WHERE id = ?",
            (request.form.get("full_name", ""), request.form.get("email", ""), user["id"]),
        )
        db().commit()
        return redirect(url_for("profile"))
    return render_template("profile.html", user=user, csrf_token=_csrf_token())


# ── Файли ────────────────────────────────────────────────────────────────────

@app.route("/download")
def download():
    name = request.args.get("name", "")
    # ВРАЗЛИВІСТЬ 9 (CWE-22): шлях будується від параметра без нормалізації —
    # обхід каталогів (?name=../../etc/passwd).
    path = os.path.join(UPLOAD_DIR, name)
    try:
        with open(path, "rb") as fh:
            return fh.read(), 200, {"Content-Type": "text/plain; charset=utf-8"}
    except OSError as exc:
        return f"Не вдалося прочитати {path}: {exc}", 404


@app.route("/fetch")
def fetch():
    url = request.args.get("url", "")
    # ВРАЗЛИВІСТЬ 10 (CWE-918): запит за довільною адресою з боку сервера (SSRF).
    # Ціль у стенді — внутрішня служба http://internal:5001/secret
    if not url:
        return "Вкажіть параметр url", 400
    try:
        with urllib.request.urlopen(url, timeout=3) as resp:  # noqa: S310
            return resp.read()[:4096], 200, {"Content-Type": "text/plain; charset=utf-8"}
    except Exception as exc:  # noqa: BLE001
        return f"Помилка запиту: {exc}", 502


@app.route("/prefs")
def prefs():
    raw = request.cookies.get("prefs")
    if not raw:
        return "Налаштування не задано", 200
    # ВРАЗЛИВІСТЬ 11 (CWE-502): десеріалізація недовіреного вмісту cookie.
    data = pickle.loads(base64.b64decode(raw))  # noqa: S301
    return f"Налаштування: {data}", 200


# ── Адміністративна частина ──────────────────────────────────────────────────

@app.route("/admin/users")
def admin_users():
    # ВИПРАВЛЕНО В10 (CWE-862): явна перевірка прав на захищеному маршруті.
    user = current_user()
    if user is None:
        return redirect(url_for("login"))          # анонім — на вхід
    if user["role"] != "admin":
        return "Недостатньо прав", 403              # автентифікований, але не адміністратор
    rows = db().execute("SELECT id, login, full_name, email, role FROM users").fetchall()
    return render_template("admin_users.html", user=user, users=rows)


@app.route("/admin/ping")
def admin_ping():
    host = request.args.get("host", "127.0.0.1")
    # ВРАЗЛИВІСТЬ 13 (CWE-78): ін'єкція команди операційної системи.
    out = subprocess.run(  # noqa: S602
        f"ping -c 1 {host}", shell=True, capture_output=True, text=True, timeout=5
    )
    return f"<pre>{out.stdout}{out.stderr}</pre>"


if __name__ == "__main__":
    if not os.path.exists(DB_PATH):
        from seed import seed
        seed(DB_PATH)
    # Прив'язка до 0.0.0.0 всередині контейнера; назовні порт публікується
    # лише на 127.0.0.1 (див. docker-compose.yml).
    app.run(host="0.0.0.0", port=5000, debug=False)  # noqa: S104
