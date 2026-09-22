"""Завдання 1: генератор x = -ln(ξ)/λ і перевірка на експоненційний закон."""
import math
import random

import numpy as np

from stats_utils import chi2_test, mean_var, plot_hist, report

N = 10_000


def main():
    rng = random.Random(2026)
    for lam in [0.5, 1.0, 2.0, 5.0, 10.0]:
        # 1 - random() ∈ (0;1], тож ln(0) неможливий
        x = np.array([-math.log(1 - rng.random()) / lam for _ in range(N)])
        mu, var = mean_var(x)
        lam_hat = 1 / mu
        print(f"\nλ = {lam}")
        print(f"  μ~ = {mu:.4f} (1/λ = {1 / lam:.4f}),  σ²~ = {var:.4f} (1/λ² = {1 / lam ** 2:.4f})")
        print(f"  σ/μ = {math.sqrt(var) / mu:.3f} ≈ 1 -> гіпотеза: експоненційний закон, λ~ = 1/μ~ = {lam_hat:.4f}")
        edges = np.linspace(0, x.max(), 21)
        report("χ²", *chi2_test(x, lambda t: 1 - np.exp(-lam_hat * t), 1, edges))
        plot_hist(x, edges, lambda t: lam_hat * np.exp(-lam_hat * t),
                  f"Експоненційний генератор, λ = {lam}", f"task1_exp_lambda_{lam}.png")


if __name__ == "__main__":
    main()
