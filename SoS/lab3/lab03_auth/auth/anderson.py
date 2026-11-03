"""Формула Андерсона (лекція 8) — оцінювання стійкості парольної системи.

Умова: імовірність підбору пароля за час його дії не має перевищувати задану.

    P ≥ (R · T) / G,   звідки   G ≥ (R · T) / P

де P — допустима ймовірність підбору, R — швидкість спроб (за одиницю часу),
T — період дії пароля (у тих самих одиницях), G — розмір простору паролів.
Мінімальна довжина: L = ceil(log(G) / log(A)), A — потужність алфавіту.
"""
from __future__ import annotations

import math


def required_space(rate_per_minute: float, period_days: float,
                   max_probability: float) -> float:
    """Мінімальний розмір простору паролів G за формулою Андерсона."""
    attempts = rate_per_minute * period_days * 24 * 60
    return attempts / max_probability


def min_length(space: float, alphabet_size: int) -> int:
    """Мінімальна довжина пароля L для алфавіту потужності A."""
    if space <= 1:
        return 1
    return math.ceil(math.log(space) / math.log(alphabet_size))


def entropy_bits(alphabet_size: int, length: int) -> float:
    """Ентропія пароля у бітах: H = L · log2(A)."""
    return length * math.log2(alphabet_size)


if __name__ == "__main__":
    # Приклад із лекції 8: R=10/хв, T=90 діб, P=1e-6, алфавіт 95 символів.
    G = required_space(10, 90, 1e-6)
    L = min_length(G, 95)
    print(f"G ≥ {G:.3e}; мінімальна довжина L = {L}; ентропія {entropy_bits(95, L):.1f} біт")
