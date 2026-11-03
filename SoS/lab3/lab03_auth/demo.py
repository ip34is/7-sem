"""Демонстрація підсистеми автентифікації (ЛР3, варіант 14).

Запуск з каталогу lab03_auth:
  python demo.py                 # вивід у консоль
  python demo.py --plot FILE     # додатково графік L(A) у PNG (потрібен matplotlib)
"""
from __future__ import annotations

import hashlib
import math
import os
import statistics
import sys
import time

# ТЕСТОВИЙ КЛЮЧ — не використовувати поза стендом
os.environ.setdefault("AUTH_PEPPER", "demo-pepper-lab3-not-a-secret")

from auth.anderson import entropy_bits, min_length, required_space  # noqa: E402
from auth.lockout import SlidingWindowLockout  # noqa: E402
import bcrypt  # noqa: E402

from auth.passwords import _bcrypt_input, hash_password, hash_password_insecure, verify_password  # noqa: E402
from auth.recovery import RecoveryCodes  # noqa: E402
from auth.service import Authenticator  # noqa: E402

R, T_DAYS, P = 12, 120, 1e-6          # трійка Андерсона варіанта 14
MAX_FAILURES, WINDOW_MIN = 5, 15
R_EFF = MAX_FAILURES / WINDOW_MIN     # спроб/хв, які дозволяє квота
ALPHABETS = (26, 62, 95)
T0 = 1_800_000_000.0


def anderson() -> None:
    print("== 1. Формула Андерсона (R = 12 спроб/хв, T = 120 діб, P = 1e-6)")
    minutes = T_DAYS * 24 * 60
    G = required_space(R, T_DAYS, P)
    print(f"T = 120 · 24 · 60 = {minutes} хв; R · T = 12 · {minutes} = {R * minutes}")
    print(f"G ≥ R·T / P = {R * minutes} / 1e-6 = {G:.4e}")
    for a in ALPHABETS:
        L = min_length(G, a)
        print(f"  A = {a:2}: L = ⌈ln G / ln A⌉ = ⌈{math.log(G):.3f} / {math.log(a):.3f}⌉ = "
              f"⌈{math.log(G) / math.log(a):.3f}⌉ = {L}; H = {L} · log2 {a} = {entropy_bits(a, L):.1f} біт")
    G_eff = required_space(R_EFF, T_DAYS, P)
    print(f"З квотою {MAX_FAILURES} невдач / {WINDOW_MIN} хв: R_eff = {R_EFF:.3f} спроб/хв, G ≥ {G_eff:.4e}")
    for a in ALPHABETS:
        L = min_length(G_eff, a)
        print(f"  A = {a:2}: L = ⌈{math.log(G_eff) / math.log(a):.3f}⌉ = {L}; H = {entropy_bits(a, L):.1f} біт")


def storage() -> None:
    print("\n== 2. Захищене зберігання (bcrypt, cost 12, сіль, перець)")
    h1, h2 = hash_password("correct horse"), hash_password("correct horse")
    print("hash_password('correct horse') =", h1)
    print("ще раз                         =", h2)
    print("verify(правильний):", verify_password(h1, "correct horse"),
          "| verify(хибний):", verify_password(h1, "wrong"),
          "| солі різні:", h1.split("$")[3] != h2.split("$")[3])
    print("\n== 3. Вразливе зберігання (SHA-256 без солі)")
    a, b = hash_password_insecure("password123"), hash_password_insecure("password123")
    print("hash_password_insecure('password123') =", a)
    print("однакові паролі → однаковий хеш:", a == b)
    print("hash_password дає різні рядки:   ", hash_password("password123") != hash_password("password123"))
    print("Експеримент: два облікові записи, однаковий пароль 'password123'")
    salt = bcrypt.gensalt(rounds=12)
    same = [bcrypt.hashpw(_bcrypt_input("password123"), salt).decode()[-31:] for _ in range(2)]
    print("  спільна сіль, спільний перець → хеші однакові:", same[0] == same[1])
    print("  різні солі, спільний перець   → хеші однакові:",
          hash_password("password123").split("$")[4] == hash_password("password123").split("$")[4])


def timing() -> None:
    print("\n== 4. Час обчислення (середнє)")
    n = 5
    times = []
    for _ in range(n):
        t = time.perf_counter()
        hash_password("correct horse")
        times.append(time.perf_counter() - t)
    bc = statistics.mean(times)
    reps = 200_000
    t = time.perf_counter()
    for _ in range(reps):
        hashlib.sha256(b"correct horse").hexdigest()
    sha = (time.perf_counter() - t) / reps
    print(f"hash_password (bcrypt, cost 12): {bc * 1000:.1f} мс (n = {n}, σ = {statistics.stdev(times) * 1000:.1f} мс)")
    print(f"SHA-256:                         {sha * 1e6:.2f} мкс (n = {reps})")
    print(f"bcrypt повільніший у ≈ {bc / sha:,.0f} разів".replace(",", " "))
    print(f"Перебір 1e9 паролів на 1 ядрі: SHA-256 ≈ {1e9 * sha / 60:.0f} хв, "
          f"bcrypt ≈ {1e9 * bc / 86400 / 365:.1f} років")
    for cost in (10, 11, 12, 13):
        t = time.perf_counter()
        hash_password("x", cost=cost)
        print(f"  cost {cost}: {(time.perf_counter() - t) * 1000:.0f} мс")


def lockout() -> None:
    print("\n== 5. Квота спроб у ковзному вікні (5 невдач / 15 хв)")
    lk = SlidingWindowLockout(MAX_FAILURES, WINDOW_MIN * 60)
    for i in range(5):
        t = T0 + 60 * i
        print(f"  t = {60 * i:4} с: дозволено = {lk.is_allowed('alice', t)}, невдача №{i + 1}")
        lk.record_attempt("alice", False, t)
    for dt in (240.5, 899.9, 900.0, 959.9, 960.0):
        t = T0 + dt
        print(f"  t = {dt:6} с: дозволено = {lk.is_allowed('alice', t)}, невдач у вікні = "
              f"{lk.failures('alice', t)}, чекати {lk.retry_after('alice', t):.1f} с")


def recovery() -> None:
    print("\n== 6. Одноразові коди відновлення (синтетичні, лише для демонстрації)")
    store, codes = RecoveryCodes.issue("alice")
    print("Згенеровано:", ", ".join(codes))
    print(f"Збережено хешів: {store.remaining()}, приклад: {store._hashes[0][:32]}…")
    print("Пред'явлення codes[0]:", store.verify_and_consume(codes[0]), "→ залишилось", store.remaining())
    print("Повторно codes[0]:   ", store.verify_and_consume(codes[0]), "→ залишилось", store.remaining())
    print("Код з малими літерами і пробілом:", store.verify_and_consume(codes[1].lower().replace("-", " ")),
          "→ залишилось", store.remaining())

    print("\n== 7. Повний вхід: пароль → код, спільна квота")
    auth = Authenticator()
    codes = auth.register("alice", "Tr0ub4dor&3")
    steps = [("пароль", "wrong"), ("пароль", "wrong"), ("пароль", "Tr0ub4dor&3"),
             ("код", "00000-00000"), ("код", "11111-11111"), ("код", "22222-22222"),
             ("пароль", "Tr0ub4dor&3")]
    for i, (kind, value) in enumerate(steps):
        t = T0 + 10 * i
        r = (auth.login_password("alice", value, t) if kind == "пароль"
             else auth.login_code("alice", value, t))
        print(f"  t = {10 * i:3} с {kind:6} {value:13} → {r.name}")
    t = T0 + 900
    print(f"  t = 900 с пароль → {auth.login_password('alice', 'Tr0ub4dor&3', t).name}, "
          f"код → {auth.login_code('alice', codes[0], t + 1).name}, залишилось кодів {auth.remaining_codes('alice')}")


def plot(path: str) -> None:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    xs = list(range(10, 96))
    plt.figure(figsize=(7, 3.6), dpi=200)
    for rate, label, style in ((R, "R = 12 спроб/хв (варіант)", "-"),
                               (R_EFF, "R_eff = 1/3 спроби/хв (квота 5 / 15 хв)", "--")):
        G = required_space(rate, T_DAYS, P)
        plt.step(xs, [min_length(G, a) for a in xs], style, where="post", label=label)
    for a in ALPHABETS:
        plt.axvline(a, color="0.8", lw=0.8)
    plt.xlabel("Потужність алфавіту A")
    plt.ylabel("Мінімальна довжина L")
    plt.yticks(range(5, 14))
    plt.legend()
    plt.tight_layout()
    plt.savefig(path)
    print(f"\nГрафік L(A) збережено: {path}")


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    anderson()
    storage()
    timing()
    lockout()
    recovery()
    if "--plot" in sys.argv:
        plot(sys.argv[sys.argv.index("--plot") + 1])
