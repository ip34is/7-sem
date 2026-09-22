"""Завдання 2: конгруентний генератор z(i+1) = a·z(i) mod c, x = z/c."""
import matplotlib.pyplot as plt
import numpy as np

from stats_utils import OUT, chi2_test, mean_var, plot_hist, report

N = 10_000
Z0 = 1  # непарне z0 — умова максимального періоду
PARAMS = [(5 ** 13, 2 ** 31), (16807, 2 ** 31 - 1), (65539, 2 ** 31),
          (5 ** 13, 2 ** 12), (5, 2 ** 8), (2 ** 10, 2 ** 31)]


def lcg(a, c, n):
    x, z = np.empty(n), Z0
    for i in range(n):
        z = a * z % c
        x[i] = z / c
    return x


def period(a, c, limit=2_000_000):
    """Запам'ятовуємо значення і рахуємо кроки до його повторення."""
    z = Z0
    for _ in range(64):  # вихід на цикл, якщо послідовність вироджується
        z = a * z % c
    first = z
    for i in range(1, limit + 1):
        z = a * z % c
        if z == first:
            return i
    return None


def plot_pairs(x, a, c, filename):
    fig = plt.figure(figsize=(10, 4.8))
    ax = fig.add_subplot(1, 2, 1)
    ax.scatter(x[:-1], x[1:], s=1, alpha=0.5, color="#5b8def")
    ax.set_title("пари (ζᵢ, ζᵢ₊₁)")
    ax.set_aspect("equal")
    ax = fig.add_subplot(1, 2, 2, projection="3d")
    ax.scatter(x[:-2], x[1:-1], x[2:], s=1, alpha=0.4, color="#e0533d")
    ax.set_title("трійки (ζᵢ, ζᵢ₊₁, ζᵢ₊₂)")
    ax.view_init(elev=20, azim=55 if a == 65539 else -60)
    fig.suptitle(f"a = {a}, c = {c}")
    fig.tight_layout()
    fig.savefig(OUT / filename, dpi=110)
    plt.close(fig)


def main():
    edges = np.linspace(0, 1, 21)
    for k, (a, c) in enumerate(PARAMS, 1):
        x = lcg(a, c, N)
        mu, var = mean_var(x)
        p = period(a, c)
        print(f"\na = {a}, c = {c}")
        print(f"  μ~ = {mu:.4f} (0.5),  σ²~ = {var:.4f} (1/12 = 0.0833),  "
              f"період = {p if p else '> 2·10⁶'}")
        report("χ² U(0;1)", *chi2_test(x, lambda t: np.clip(t, 0, 1), 0, edges))
        plot_hist(x, edges, np.ones_like, f"LCG a = {a}, c = {c}", f"task1_lcg_{k}_hist.png")
        plot_pairs(x, a, c, f"task1_lcg_{k}_pairs.png")


if __name__ == "__main__":
    main()
