"""Спільні функції: оцінки, критерій згоди χ², гістограма частот."""
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
from scipy import stats

OUT = Path(__file__).parent / "output"
OUT.mkdir(exist_ok=True)


def mean_var(x):
    return np.mean(x), np.var(x, ddof=1)


def chi2_test(x, cdf, n_params, edges):
    """Критерій згоди χ²; n_params — кількість параметрів, оцінених за вибіркою."""
    observed = np.histogram(x, edges)[0]
    p = np.diff(cdf(edges))
    p[0] += cdf(edges[0])  # крайні інтервали охоплюють «хвости» закону
    p[-1] += 1 - cdf(edges[-1])
    obs, exp = [], []
    for o, e in zip(observed, len(x) * p):  # об'єднання інтервалів з n·p_i < 5
        if exp and exp[-1] < 5:
            obs[-1] += o
            exp[-1] += e
        else:
            obs.append(o)
            exp.append(e)
    if len(exp) > 1 and exp[-1] < 5:
        o, e = obs.pop(), exp.pop()
        obs[-1] += o
        exp[-1] += e
    obs, exp = np.array(obs, dtype=float), np.array(exp)
    chi2 = ((obs - exp) ** 2 / exp).sum()
    df = max(len(obs) - 1 - n_params, 1)
    return chi2, stats.chi2.ppf(0.95, df), df, stats.chi2.sf(chi2, df)


def report(name, chi2, crit, df, p):
    ok = chi2 < crit
    print(f"  {name}: χ² = {chi2:.2f} {'<' if ok else '>='} χ²кр = {crit:.2f} "
          f"(df = {df}, p = {p:.4f}) -> {'відповідає' if ok else 'не відповідає'}")


def plot_hist(x, edges, pdf, title, filename, xlabel="x"):
    xs = np.linspace(edges[0], edges[-1], 400)
    plt.figure(figsize=(8, 4.5))
    plt.hist(x, bins=edges, color="#5b8def", edgecolor="white", label="спостережувані nᵢ")
    plt.plot(xs, len(x) * (edges[1] - edges[0]) * pdf(xs), "r-", lw=2, label="теоретичні n·f(x)·h")
    plt.title(title)
    plt.xlabel(xlabel)
    plt.ylabel("кількість влучень")
    plt.legend()
    plt.grid(alpha=0.3)
    plt.tight_layout()
    plt.savefig(OUT / filename, dpi=110)
    plt.close()
