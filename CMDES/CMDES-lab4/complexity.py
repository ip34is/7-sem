"""Експериментальна і теоретична оцінка складності алгоритму імітації мережі з N СМО."""
import gc
import math
import statistics
import time as clock
from pathlib import Path

import fun_rand
from networks import ARRIVAL

TIME = 1000  # модельний час, на якому вимірюється час обчислення
NS = (15, 30, 60, 120)  # кожне наступне N удвічі більше
OUT = Path(__file__).parent / "output"


def measure(build, n, budget=0.3):
    """Рядок (N, час обчислення в с, виконано подій, надійшло вимог, V).

    V — середня кількість СМО, які проходить вимога: кожна вимога породжує 1 + V подій.
    Короткі прогони повторюються, доки сумарний час не досягне budget, і береться найменший час.
    """
    best, spent = math.inf, 0.0
    while spent < budget:
        fun_rand.seed(1)
        model, visits = build(n)
        warmup = 10 * n  # за цей час вимоги проходять мережу — у всіх СМО стаціонарний режим
        model.simulate(warmup)
        create = model.elements[0]
        events, arrivals = model.events, create.quantity
        gc.disable()  # збирач сміття не втручається у вимірювання
        start = clock.perf_counter()
        model.simulate(warmup + TIME)
        elapsed = clock.perf_counter() - start
        gc.enable()
        best, spent = min(best, elapsed), spent + elapsed
    return n, best, model.events - events, create.quantity - arrivals, visits


def series(build, ns=NS):
    return [measure(build, n) for n in ns]


def per_event(rows):
    """Час на одну подію як лінійна функція N: a + b·N, мкс (метод найменших квадратів)."""
    fit = statistics.linear_regression([r[0] for r in rows], [r[1] / r[2] * 1e6 for r in rows])
    return fit.intercept, fit.slope


def theory_time(n, visits, a, b):
    """ν·T·k: подій за час T, помножених на час обробки однієї події a + b·N."""
    return TIME / ARRIVAL * (1 + visits) * (a + b * n) / 1e6


def order(ns, values):
    """Показник m у залежності «значення ~ N^m»: нахил прямої в логарифмічному масштабі."""
    return statistics.linear_regression([math.log(n) for n in ns],
                                        [math.log(v) for v in values]).slope


def print_series(name, rows, a, b):
    print(f"\nСтруктура: {name}")
    print("    N | подій у моделі | виконано подій | подій на вимогу | час, с: імітація / теорія "
          "| зріс у | на подію, мкс")
    previous = None
    for n, elapsed, events, arrivals, visits in rows:
        growth = f"{elapsed / previous:6.2f}" if previous else "     —"
        print(f"{n:5} | {n + 1:14} | {events:14} | {events / arrivals:6.2f} / {1 + visits:<6.2f} | "
              f"{elapsed:7.3f} / {theory_time(n, visits, a, b):<7.3f}       | {growth} | "
              f"{elapsed / events * 1e6:8.2f}")
        previous = elapsed
    ns = [r[0] for r in rows]
    print(f"Час обчислення ~ N^{order(ns, [r[1] for r in rows]):.2f} (імітація), "
          f"~ N^{order(ns, [theory_time(r[0], r[4], a, b) for r in rows]):.2f} (теорія)")


def plot(results, a, b, filename, log=False):
    """results — назва структури -> (функція побудови мережі, рядки вимірювань)."""
    import matplotlib.pyplot as plt

    fig, (left, right) = plt.subplots(1, 2, figsize=(11, 4.2))
    dense = range(NS[0], NS[-1] + 1)
    for name, (build, rows) in results.items():
        ns = [r[0] for r in rows]
        line, = left.plot(ns, [r[1] for r in rows], "o", label=f"{name}: імітація")
        left.plot(dense, [theory_time(n, build(n)[1], a, b) for n in dense], "--",
                  color=line.get_color(), label=f"{name}: теорія")
        right.plot(ns, [r[1] / r[2] * 1e6 for r in rows], "o-", label=name)
    right.plot(dense, [a + b * n for n in dense], "k--", label=f"{a:.2f} + {b:.3f}·N")
    if log:  # у логарифмічному масштабі залежність N^m — пряма з нахилом m
        left.set(xscale="log", yscale="log")
        left.set_xticks(NS, labels=[str(n) for n in NS])
        left.minorticks_off()
    left.set(xlabel="N — кількість СМО", ylabel="час обчислення, с",
             title=f"Час імітації на інтервалі T = {TIME}")
    right.set(xlabel="N — кількість СМО", ylabel="час на одну подію, мкс",
              title="Час обробки однієї події")
    for ax in (left, right):
        ax.grid(alpha=0.3)
        ax.legend(fontsize=8)
    fig.tight_layout()
    OUT.mkdir(exist_ok=True)
    fig.savefig(OUT / filename, dpi=110)
    print(f"\nГрафік збережено: output/{filename}")
