"""Завдання 3: затримка сортування 1 000 000 об'єктів — ідентифікація закону та генератор-імітатор."""
import math
import random
import time
from operator import attrgetter

import matplotlib.pyplot as plt
import numpy as np
from scipy import stats

from stats_utils import OUT, chi2_test, mean_var, report

N_OBJECTS, N_RUNS, WARMUP = 1_000_000, 500, 10
CSV = OUT / "sort_times.csv"  # щоб переміряти — видалити файл


class Item:
    __slots__ = ("key", "name")

    def __init__(self, key, name):
        self.key, self.name = key, name


def measure():
    rng = random.Random(1)
    items = [Item(rng.random(), i) for i in range(N_OBJECTS)]
    times = []
    for r in range(WARMUP + N_RUNS):
        rng.shuffle(items)  # перемішування не входить у замір
        t0 = time.perf_counter()
        items.sort(key=attrgetter("key"))
        if r >= WARMUP:
            times.append((time.perf_counter() - t0) * 1000)
        if (r + 1) % 50 == 0:
            print(f"  виміряно {r + 1}/{WARMUP + N_RUNS}")
    return np.array(times)


class Gen:
    """Генератори випадкових величин на основі ζ ~ U(0;1)."""

    def __init__(self, seed):
        self.rng = random.Random(seed)

    def zeta(self):
        return 1 - self.rng.random()

    def normal(self, mu, sigma):  # метод Марсальї–Брея
        while True:
            a1, a2 = 2 * self.zeta() - 1, 2 * self.zeta() - 1
            s = a1 * a1 + a2 * a2
            if 0 < s <= 1:
                return mu + sigma * a1 * math.sqrt(-2 * math.log(s) / s)

    def erlang(self, k, lam):
        # Σ ln ζ замість ln Π ζ: при великих k добуток зникає до 0
        return -sum(math.log(self.zeta()) for _ in range(k)) / lam

    def table(self, xs, fs):  # табличний метод
        z = self.rng.random()
        i = min(max(int(np.searchsorted(fs, z, side="right")), 1), len(xs) - 1)
        return xs[i - 1] + (xs[i] - xs[i - 1]) * (z - fs[i - 1]) / (fs[i] - fs[i - 1])


def candidates(x, mu, var):
    """Гіпотези: закон -> (розподіл, кількість оцінених параметрів, генератор)."""
    sd, mn, mx = math.sqrt(var), x.min(), x.max()
    k = round(mu ** 2 / var)
    s_ln = math.sqrt(math.log(1 + var / mu ** 2))
    m_ln = math.log(mu) - s_ln ** 2 / 2
    s, x0, scale = stats.lognorm.fit(x)  # зсув — методом максимальної правдоподібності
    return {
        "Рівномірний": (stats.uniform(mn, mx - mn), 2, lambda g: mn + (mx - mn) * g.zeta()),
        "Нормальний": (stats.norm(mu, sd), 2, lambda g: g.normal(mu, sd)),
        "Експоненційний": (stats.expon(scale=mu), 1, lambda g: -mu * math.log(g.zeta())),
        "Ерланга": (stats.gamma(k, scale=mu / k), 2, lambda g: g.erlang(k, k / mu)),
        "Логнормальний": (stats.lognorm(s_ln, scale=math.exp(m_ln)), 2,
                          lambda g: math.exp(g.normal(m_ln, s_ln))),
        "Логнормальний зі зсувом": (stats.lognorm(s, x0, scale), 3,
                                    lambda g: x0 + math.exp(g.normal(math.log(scale), s))),
    }


def chi2_homogeneity(x, y):
    """χ²-критерій однорідності двох вибірок на децилях виміряних даних."""
    edges = np.percentile(x, np.linspace(0, 100, 11))
    edges[0], edges[-1] = -np.inf, np.inf
    chi2, p, df, _ = stats.chi2_contingency([np.histogram(x, edges)[0], np.histogram(y, edges)[0]])
    return chi2, stats.chi2.ppf(0.95, df), df, p


def main():
    if CSV.exists():
        x = np.loadtxt(CSV, delimiter=",", skiprows=1, usecols=1)
    else:
        x = measure()
        np.savetxt(CSV, np.column_stack([np.arange(1, len(x) + 1), x]), delimiter=",",
                   header="run,time_ms", comments="", fmt=["%d", "%.6f"])
    mu, var = mean_var(x)
    print(f"n = {len(x)}, min = {x.min():.1f} мс, max = {x.max():.1f} мс")
    print(f"μ~ = {mu:.1f} мс, σ~ = {math.sqrt(var):.1f} мс, σ/μ = {math.sqrt(var) / mu:.3f}, "
          f"асиметрія = {stats.skew(x):.2f}")

    print("\nПеревірка гіпотез за критерієм χ²:")
    laws = candidates(x, mu, var)
    edges = np.linspace(x.min(), x.max(), 21)
    p_values = {}
    for name, (dist, n_params, _) in laws.items():
        result = chi2_test(x, dist.cdf, n_params, edges)
        report(name, *result)
        p_values[name] = result[3]
    best = max(p_values, key=p_values.get)
    print(f"Найкраще наближення: {best}")

    g = Gen(42)
    model = np.array([laws[best][2](g) for _ in range(10_000)])
    xs = np.sort(x)
    xs = np.concatenate([[2 * xs[0] - xs[1]], xs])
    fs = np.linspace(0, 1, len(xs))
    table = np.array([g.table(xs, fs) for _ in range(10_000)])

    print("\nТочність відтворення (по 10000 згенерованих значень):")
    print(f"  {'':<26}{'μ':>8}{'σ':>7}{'P50':>8}{'P95':>8}{'P99':>8}")
    for name, d in [("Виміряно", x), (best, model), ("Табличний", table)]:
        q = np.percentile(d, [50, 95, 99])
        print(f"  {name:<26}{np.mean(d):>8.1f}{np.std(d, ddof=1):>7.1f}" + "".join(f"{v:>8.1f}" for v in q))
    for name, d in [(best, model), ("Табличний", table)]:
        print(f"{name}:")
        report("χ² однорідності", *chi2_homogeneity(x, d))
        print(f"  Колмогоров–Смірнов: p = {stats.ks_2samp(x, d).pvalue:.4f}")

    plt.figure(figsize=(10, 3.5))
    plt.plot(np.arange(1, len(x) + 1), x, lw=0.8)
    plt.xlabel("номер запуску")
    plt.ylabel("час, мс")
    plt.grid(alpha=0.3)
    plt.tight_layout()
    plt.savefig(OUT / "task2_series.png", dpi=110)
    plt.close()

    xs_plot = np.linspace(edges[0], edges[-1], 400)
    plt.figure(figsize=(9, 5))
    plt.hist(x, bins=edges, color="#c9d6f5", edgecolor="white", label="виміряно")
    for name, (dist, _, _) in laws.items():
        if name not in ("Рівномірний", "Експоненційний"):
            plt.plot(xs_plot, len(x) * (edges[1] - edges[0]) * dist.pdf(xs_plot), label=name)
    plt.xlabel("час, мс")
    plt.ylabel("кількість влучень")
    plt.legend()
    plt.grid(alpha=0.3)
    plt.tight_layout()
    plt.savefig(OUT / "task2_all_fits.png", dpi=110)
    plt.close()

    bins = np.linspace(min(x.min(), model.min()), np.percentile(model, 99.9), 31)
    plt.figure(figsize=(9, 5))
    plt.hist(x, bins=bins, density=True, alpha=0.55, label="виміряно")
    plt.hist(model, bins=bins, density=True, histtype="step", lw=2, label=f"генератор «{best}»")
    plt.hist(table, bins=bins, density=True, histtype="step", lw=1.5, ls="--", label="табличний генератор")
    plt.xlabel("час, мс")
    plt.ylabel("щільність")
    plt.legend()
    plt.grid(alpha=0.3)
    plt.tight_layout()
    plt.savefig(OUT / "task2_simulation.png", dpi=110)
    plt.close()


if __name__ == "__main__":
    main()
