"""Навчальна реалізація RSA з малими числами (лекція 11) — КАРКАС + робочі утиліти.

Призначено для покрокової верифікації: генерація великих простих чисел
(тест Міллера–Рабіна), розрахунок ключів (розширений алгоритм Евкліда),
швидке піднесення до степеня за модулем. НЕ для реального захисту.
"""
from __future__ import annotations

import secrets


def fast_pow_mod(base: int, exp: int, mod: int) -> tuple[int, list[str]]:
    """Швидке піднесення до степеня за модулем; повертає результат і протокол кроків."""
    result, steps = 1, []
    b = base % mod
    e = exp
    while e > 0:
        bit = e & 1
        if bit:
            result = (result * b) % mod
        steps.append(f"e={e:>4b} bit={bit} b={b} result={result}")
        b = (b * b) % mod
        e >>= 1
    return result, steps


def is_probable_prime(n: int, rounds: int = 20) -> bool:
    """Тест простоти Міллера–Рабіна (лекція 11)."""
    if n < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % p == 0:
            return n == p
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def gen_prime(bits: int) -> int:
    """Генерація ймовірно простого числа заданої розрядності."""
    while True:
        candidate = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if is_probable_prime(candidate):
            return candidate


def egcd(a: int, b: int) -> tuple[int, int, int]:
    """Розширений алгоритм Евкліда: повертає (g, x, y), де a·x + b·y = g."""
    if b == 0:
        return a, 1, 0
    g, x1, y1 = egcd(b, a % b)
    return g, y1, x1 - (a // b) * y1


def modinv(a: int, m: int) -> int:
    g, x, _ = egcd(a % m, m)
    if g != 1:
        raise ValueError("Оберненого не існує")
    return x % m


def keygen(bits: int = 16, e: int = 65537) -> dict:
    """Генерація ключів RSA. bits — розрядність КОЖНОГО простого множника."""
    while True:
        p, q = gen_prime(bits), gen_prime(bits)
        if p == q:
            continue
        n = p * q
        phi = (p - 1) * (q - 1)
        if egcd(e, phi)[0] == 1:
            break
    d = modinv(e, phi)
    return {"p": p, "q": q, "n": n, "phi": phi, "e": e, "d": d}


def encrypt(m: int, e: int, n: int) -> int:
    return pow(m, e, n)


def decrypt(c: int, d: int, n: int) -> int:
    return pow(c, d, n)


if __name__ == "__main__":
    k = keygen(bits=16)
    msg = 42
    c = encrypt(msg, k["e"], k["n"])
    assert decrypt(c, k["d"], k["n"]) == msg
    print(f"RSA(16-біт множники): n={k['n']}, e={k['e']}, d={k['d']}")
    print(f"шифрування {msg} -> {c} -> {decrypt(c, k['d'], k['n'])}")
    val, steps = fast_pow_mod(7, 13, 100)
    print(f"7^13 mod 100 = {val}; кроків: {len(steps)}")
