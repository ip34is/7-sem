"""Аналіз навчального RSA: факторизація модуля, час генерації простих, кількість множень.

Факторизація потрібна, щоб показати, чому модуль із 28-бітовими множниками непридатний
для захисту: ρ-метод Полларда знаходить множник приблизно за √p кроків.
"""
from __future__ import annotations

import math
import random
import time

from crypto_lab.rsa_edu import fast_pow_mod, gen_prime


def trial_division(n: int) -> int:
    """Повний перебір непарних дільників до √n — O(√n) = O(p) кроків."""
    if n % 2 == 0:
        return 2
    d = 3
    while d * d <= n:
        if n % d == 0:
            return d
        d += 2
    return n


def pollard_rho(n: int, seed: int = 1) -> int:
    """ρ-метод Полларда (варіант Брента): нетривіальний дільник n за ≈ √p ітерацій."""
    if n % 2 == 0:
        return 2
    rng = random.Random(seed)
    while True:
        y, c, m = rng.randrange(1, n), rng.randrange(1, n), 128
        g = r = q = 1
        while g == 1:
            x = y
            for _ in range(r):
                y = (y * y + c) % n
            k = 0
            while k < r and g == 1:
                ys = y
                for _ in range(min(m, r - k)):
                    y = (y * y + c) % n
                    q = q * abs(x - y) % n
                g = math.gcd(q, n)
                k += m
            r *= 2
        if g == n:
            g = 1
            while g == 1:
                ys = (ys * ys + c) % n
                g = math.gcd(abs(x - ys), n)
        if g != n:
            return g


def time_it(fn, *args) -> tuple[object, float]:
    t = time.perf_counter()
    res = fn(*args)
    return res, time.perf_counter() - t


def multiplications(exp: int) -> tuple[int, int]:
    """(квадратів, множень на основу) у fast_pow_mod для показника exp."""
    _, steps = fast_pow_mod(3, exp, 1_000_003)
    return len(steps), bin(exp).count("1")


def factor_table(bits_list=(12, 16, 20, 24, 28, 32, 36), trial_up_to: int = 24):
    """Час генерації пари простих і факторизації n = p·q для заданої розрядності множників."""
    rows = []
    for bits in bits_list:
        (p, t_p) = time_it(gen_prime, bits)
        q = gen_prime(bits)
        while q == p:
            q = gen_prime(bits)
        n = p * q
        f_rho, t_rho = time_it(pollard_rho, n)
        assert f_rho in (p, q)
        t_trial = None
        if bits <= trial_up_to:
            f_tr, t_trial = time_it(trial_division, n)
            assert f_tr == min(p, q)
        rows.append({"bits": bits, "n_bits": n.bit_length(), "t_prime": t_p,
                     "t_trial": t_trial, "t_rho": t_rho})
    return rows
