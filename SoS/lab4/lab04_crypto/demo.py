"""Демонстрація ЛР4, варіант 14 (AES-128-GCM, RSA-PSS 2048, RSA 28 біт, ECB, хеш без солі).

Запуск з каталогу lab04_crypto:
  python demo.py              # вивід у консоль
  python demo.py --figs DIR   # додатково рисунки ecb_image.png і factor_time.png (matplotlib)
"""
from __future__ import annotations

import statistics
import sys
import time

from crypto_lab import aead, misuse_ecb, misuse_hash, sign_demo
from crypto_lab.rsa_analysis import multiplications, pollard_rho, time_it, trial_division
from crypto_lab.rsa_edu import (decrypt, egcd, encrypt, fast_pow_mod, gen_prime,
                                is_probable_prime, keygen, modinv)

RSA_BITS = 28
TEST_KEY = b"0123456789abcdef"   # ТЕСТОВИЙ КЛЮЧ — не використовувати поза стендом


def egcd_trace(a: int, m: int) -> list[tuple[int, int, int]]:
    """Ітеративний розширений Евклід: рядки (залишок r, частка q, x), де r ≡ a·x (mod m)."""
    rows, (r0, r1), (x0, x1) = [], (m, a), (0, 1)
    while r1:
        q = r0 // r1
        rows.append((r1, q, x1))
        r0, r1 = r1, r0 - q * r1
        x0, x1 = x1, x0 - q * x1
    return rows


def section(title: str) -> None:
    print(f"\n== {title}")


def rsa_verification() -> None:
    section("1. Покрокова верифікація навчального RSA")
    val, steps = fast_pow_mod(7, 13, 100)
    print(f"fast_pow_mod(7, 13, 100) = {val} (pow: {pow(7, 13, 100)}); протокол «квадрат і множення»:")
    for s in steps:
        print("   ", s)
    for n in (7919, 7917, 561, 104729):
        print(f"is_probable_prime({n}) = {is_probable_prime(n)}"
              + ("  (число Кармайкла 561 = 3·11·17)" if n == 561 else ""))
    g, x, y = egcd(240, 46)
    print(f"egcd(240, 46) = ({g}, {x}, {y}): 240·{x} + 46·{y} = {240 * x + 46 * y}")
    print("Розширений Евклід для 17⁻¹ mod 3120 (q — частка, r — залишок, x — коефіцієнт при 17):")
    rows = egcd_trace(17, 3120)
    for r, q, xx in rows:
        print(f"    r = {r:5}  q = {q:4}  x = {xx}")
    x_last = rows[-1][2]
    print(f"    1 = 17·({x_last}) + 3120·{(1 - 17 * x_last) // 3120} → d = {x_last} mod 3120 = {x_last % 3120}")
    print(f"modinv(17, 3120) = {modinv(17, 3120)}")
    p, q, e = 61, 53, 17
    n, phi = p * q, (p - 1) * (q - 1)
    d = modinv(e, phi)
    c = encrypt(65, e, n)
    print(f"Контрольний приклад: p = {p}, q = {q}, n = {n}, φ = {phi}, e = {e}, d = {d}; "
          f"65^17 mod 3233 = {c}; {c}^{d} mod 3233 = {decrypt(c, d, n)}")
    p, q, e = 11, 23, 3
    n, phi = p * q, (p - 1) * (q - 1)
    d = modinv(e, phi)
    print(f"Контрольне запитання 9: p = 11, q = 23 → n = {n}, φ = {phi}; d = 3⁻¹ mod {phi} = {d}; "
          f"e·d = {e * d} = {(e * d) // phi}·{phi} + {(e * d) % phi}")


def rsa_demo_keys() -> None:
    section(f"2. Демонстраційні ключі RSA (множники по {RSA_BITS} біт)")
    k = keygen(bits=RSA_BITS)
    p, q, n, phi, e, d = k["p"], k["q"], k["n"], k["phi"], k["e"], k["d"]
    print(f"p = {p} ({p.bit_length()} біт, просте: {is_probable_prime(p)})")
    print(f"q = {q} ({q.bit_length()} біт, просте: {is_probable_prime(q)})")
    print(f"n = p·q = {n} ({n.bit_length()} біт)")
    print(f"φ(n) = (p−1)(q−1) = {phi}")
    print(f"e = {e}, d = {d}; e·d mod φ(n) = {(e * d) % phi}")
    m = 42
    c = encrypt(m, e, n)
    print(f"m = {m} → c = {c} → {decrypt(c, d, n)}")
    for name, exp in (("e", e), ("d", d)):
        sq, mul = multiplications(exp)
        print(f"fast_pow_mod для {name} ({exp.bit_length()} біт): квадратів {sq}, множень на основу {mul}, "
              f"разом {sq + mul} (наївно: {exp - 1})")
    f, t = time_it(pollard_rho, n)
    d_rec = modinv(e, (f - 1) * (n // f - 1))
    print(f"Атака: ρ-метод Полларда розклав n за {t * 1000:.2f} мс: {f} · {n // f}; "
          f"відновлений d = {d_rec} (збігається: {d_rec == d})")


def factor_timing(figs: str | None) -> None:
    section("3. Час генерації простих і факторизації n залежно від розрядності множників")
    bits_list = (12, 16, 20, 24, 28, 32, 36, 40, 44)
    rows = []
    print(f"{'біт p':>6} {'біт n':>6} {'gen_prime, мс':>14} {'перебір, мс':>12} {'ρ Полларда, мс':>15}")
    for bits in bits_list:
        t_gen, t_trial, t_rho, nb = [], [], [], 0
        for rep in range(3):
            p, tg = time_it(gen_prime, bits)
            q = gen_prime(bits)
            while q == p:
                q = gen_prime(bits)
            n = p * q
            nb = max(nb, n.bit_length())
            t_gen.append(tg)
            t_rho.append(time_it(pollard_rho, n, rep + 1)[1])
            if bits <= 24:
                t_trial.append(time_it(trial_division, n)[1])
        row = (bits, nb, statistics.median(t_gen) * 1000,
               statistics.median(t_trial) if t_trial else None, statistics.median(t_rho))
        rows.append(row)
        tr = f"{row[3] * 1000:12.2f}" if row[3] is not None else f"{'—':>12}"
        print(f"{bits:6} {nb:6} {row[2]:14.3f} {tr} {row[4] * 1000:15.2f}")
    for bits in (512, 1024):
        _, t = time_it(gen_prime, bits)
        print(f"gen_prime({bits}) = {t * 1000:.0f} мс  (для RSA-{2 * bits})")
    if figs:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        plt.figure(figsize=(7, 3.6), dpi=200)
        tr = [(r[0], r[3]) for r in rows if r[3] is not None]
        plt.semilogy([b for b, _ in tr], [t for _, t in tr], "o-", label="повний перебір дільників")
        plt.semilogy([r[0] for r in rows], [r[4] for r in rows], "s-", label="ρ-метод Полларда")
        plt.axvline(RSA_BITS, color="0.6", ls="--", lw=1)
        plt.text(RSA_BITS + 0.4, 1e-4, "варіант: 28 біт", fontsize=8, color="0.3")
        plt.xlabel("Розрядність кожного множника p, q, біт")
        plt.ylabel("Час факторизації n, с")
        plt.legend()
        plt.grid(True, which="both", ls=":", lw=0.5)
        plt.tight_layout()
        plt.savefig(f"{figs}/factor_time.png")
        print(f"Графік: {figs}/factor_time.png")


def aead_demo() -> None:
    section("4. AES-128-GCM (crypto_lab/aead.py)")
    key = aead.generate_key()
    blob = aead.encrypt(b"secret payload", key, associated=b"hdr")
    print(f"ключ {len(key)} Б; blob = nonce {aead.NONCE_SIZE} + шифротекст {len(blob) - 28} "
          f"+ тег {aead.TAG_SIZE} = {len(blob)} Б")
    print("розшифрування:", aead.decrypt(blob, key, associated=b"hdr"))

    def attempt(label, fn):
        try:
            fn()
            print(f"  {label:38} ПОМИЛКА: підміну не виявлено")
        except aead.InvalidTag:
            print(f"  {label:38} InvalidTag — дані не повернено")

    attempt("змінено 1 біт тегу", lambda: aead.decrypt(blob[:-1] + bytes([blob[-1] ^ 1]), key, b"hdr"))
    attempt("змінено 1 біт шифротексту", lambda: aead.decrypt(
        blob[:12] + bytes([blob[12] ^ 1]) + blob[13:], key, b"hdr"))
    attempt("змінено асоційовані дані (hdr → hdR)", lambda: aead.decrypt(blob, key, b"hdR"))
    attempt("змінено nonce", lambda: aead.decrypt(bytes([blob[0] ^ 1]) + blob[1:], key, b"hdr"))
    attempt("інший ключ", lambda: aead.decrypt(blob, aead.generate_key(), b"hdr"))
    nonces = {aead.encrypt(b"x", key)[:12] for _ in range(10_000)}
    print(f"10 000 шифрувань: унікальних nonce {len(nonces)}")
    print("той самий текст двічі → однакові blob:", aead.encrypt(b"same", key) == aead.encrypt(b"same", key))


def ecb_demo(figs: str | None) -> None:
    section("5. Помилка 1: ECB замість AEAD")
    data = b"ATTACK AT DAWN!!" * 4 + b"RETREAT AT DUSK!" + b"ATTACK AT DAWN!!"
    ecb = misuse_ecb.ecb_encrypt(data, TEST_KEY)
    gcm = aead.encrypt(data, TEST_KEY)
    print(f"відкритий текст: {len(misuse_ecb.blocks(data))} блоків, з них повторів: {misuse_ecb.repeated_blocks(data)}")
    print("ECB, блоки шифротексту:")
    for i, b in enumerate(misuse_ecb.blocks(ecb)):
        print(f"    {i}: {b.hex()}")
    print(f"ECB: повторів блоків у шифротексті {misuse_ecb.repeated_blocks(ecb)}; "
          f"GCM: {misuse_ecb.repeated_blocks(gcm[12:-16])}")
    print("Атака перестановкою блоків (cut-and-paste):")
    victim = misuse_ecb.ecb_encrypt(misuse_ecb.record("mallory", "student"), TEST_KEY)
    donor = misuse_ecb.ecb_encrypt(misuse_ecb.record("alice", "admin"), TEST_KEY)
    forged = misuse_ecb.cut_and_paste(victim, donor)
    print("    ECB розшифровує підробку без помилки:", misuse_ecb.ecb_decrypt(forged, TEST_KEY))
    v = aead.encrypt(misuse_ecb.record("mallory", "student"), TEST_KEY)
    dn = aead.encrypt(misuse_ecb.record("alice", "admin"), TEST_KEY)
    forged_gcm = v[:12 + 16] + dn[12 + 16:12 + 32] + v[12 + 32:]
    try:
        aead.decrypt(forged_gcm, TEST_KEY)
        print("    GCM: ПОМИЛКА — підробку прийнято")
    except aead.InvalidTag:
        print("    GCM: InvalidTag — підробку відхилено")
    img = misuse_ecb.synthetic_image()
    img_ecb = misuse_ecb.ecb_encrypt_raw(img, TEST_KEY)
    img_gcm = aead.encrypt(img, TEST_KEY)[12:-16]
    print(f"зображення 256×256 ({len(img)} байтів): повторів блоків — відкрите {misuse_ecb.repeated_blocks(img)}, "
          f"ECB {misuse_ecb.repeated_blocks(img_ecb)}, GCM {misuse_ecb.repeated_blocks(img_gcm)}")
    if figs:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        import numpy as np
        fig, axes = plt.subplots(1, 3, figsize=(7, 2.6), dpi=200)
        for ax, raw, title in zip(axes, (img, img_ecb, img_gcm),
                                  ("відкрите зображення", "AES-128-ECB", "AES-128-GCM")):
            ax.imshow(np.frombuffer(raw, dtype=np.uint8).reshape(256, 256), cmap="gray", vmin=0, vmax=255)
            ax.set_title(title, fontsize=9)
            ax.axis("off")
        plt.tight_layout()
        plt.savefig(f"{figs}/ecb_image.png")
        print(f"Рисунок: {figs}/ecb_image.png")


def hash_demo() -> None:
    section("6. Помилка 2: хешування пароля без солі")
    users = {"alice": "qwerty123", "bob": "qwerty123", "carol": "Tr0ub4dor&3", "dave": "password1"}
    dictionary = ["123456", "password", "123456789", "12345678", "qwerty", "qwerty123", "111111",
                  "password1", "iloveyou", "admin", "welcome", "monkey", "dragon", "letmein", "abc123"]
    db = {u: misuse_hash.hash_unsalted(pw) for u, pw in users.items()}
    for u, h in db.items():
        print(f"  ВРАЗЛИВО {u:6} {h}")
    print("  alice і bob мають однаковий хеш:", db["alice"] == db["bob"])
    t0 = time.perf_counter()
    table = misuse_hash.precompute_table(dictionary)
    t_table = time.perf_counter() - t0
    t0 = time.perf_counter()
    cracked = misuse_hash.crack_with_table(db, table)
    t_crack = time.perf_counter() - t0
    print(f"  таблиця з {len(table)} хешів (будується заздалегідь, {t_table * 1e3:.2f} мс); "
          f"пошук: {t_crack * 1e6:.1f} мкс → зламано {len(cracked)} з {len(db)}: {cracked}")
    salted = {u: misuse_hash.hash_salted(pw) for u, pw in users.items()}
    for u, h in salted.items():
        print(f"  БЕЗПЕЧНО {u:6} {h[:60]}…")
    print("  alice і bob мають однаковий запис:", salted["alice"] == salted["bob"])
    print("  зламано тією самою таблицею:", len(misuse_hash.crack_with_table(salted, table)), "з", len(salted))
    t0 = time.perf_counter()
    found = misuse_hash.crack_salted(salted["dave"], dictionary)
    t_one = time.perf_counter() - t0
    print(f"  перебір словника для одного запису (dave) зі scrypt: знайдено {found!r} за {t_one:.2f} с "
          f"(≈ {t_one / (dictionary.index('password1') + 1) * 1000:.0f} мс на кандидата)")
    _, t_sha = time_it(lambda: [misuse_hash.hash_unsalted("x") for _ in range(100_000)])
    print(f"  SHA-256: {t_sha / 100_000 * 1e6:.2f} мкс на кандидата")


def nonce_reuse_demo() -> None:
    section("8. Додатково (контрольне запитання 3): повторний nonce у GCM")
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    nonce = bytes(12)                          # ВРАЗЛИВО: той самий nonce для двох повідомлень
    p1, p2 = b"pay 100 UAH to alice", b"pay 999 UAH to mallo"
    c1 = AESGCM(TEST_KEY).encrypt(nonce, p1, b"")[:-16]
    c2 = AESGCM(TEST_KEY).encrypt(nonce, p2, b"")[:-16]
    xor = lambda a, b: bytes(x ^ y for x, y in zip(a, b))
    print("C1 ⊕ C2 == P1 ⊕ P2:", xor(c1, c2) == xor(p1, p2))
    print("знаючи P1, порушник відновлює P2:", xor(xor(c1, c2), p1))
    print("гама (keystream) однакова:", xor(c1, p1) == xor(c2, p2))


def signature_demo() -> None:
    section("7. Електронний підпис RSA-PSS (crypto_lab/sign_demo.py)")
    sign_demo.main()


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    figs = sys.argv[sys.argv.index("--figs") + 1] if "--figs" in sys.argv else None
    rsa_verification()
    rsa_demo_keys()
    factor_timing(figs)
    aead_demo()
    ecb_demo(figs)
    hash_demo()
    signature_demo()
    nonce_reuse_demo()
