"""Завдання 4: складність алгоритму імітації для розгалужених маршрутів."""
from complexity import NS, TIME, order, per_event, plot, print_series, series, theory_time
from networks import ARRIVAL, P_RETURN, STRUCTURES

THEORY = {  # V — середня кількість СМО на маршруті вимоги; асимптотична складність
    "послідовна": ("N", "O(N²)"),
    "дерево": ("≈ log2(N + 1)", "O(N·log N)"),
    "віяло": ("1", "O(N)"),
    "з поверненням": (f"N / (1 − {P_RETURN})", "O(N²)"),
}


def main():
    print(f"Модельний час T = {TIME}, середній інтервал надходження tC = {ARRIVAL}")
    results = {name: series(build) for name, build in STRUCTURES.items()}
    a, b = per_event(sum(results.values(), []))  # алгоритм той самий — оцінка за всіма рядками
    for name, rows in results.items():
        print_series(name, rows, a, b)

    n = NS[-1]
    print(f"\nПідсумок для N = {n} (ν = (1 + V) / tC; час на подію ≈ {a:.2f} + {b:.3f}·N мкс):")
    print("  структура     | V              | подій  | час, с: імітація / теорія | ~N^m  "
          "| складність")
    for name, rows in results.items():
        visits, complexity = THEORY[name]
        _, elapsed, events, _, v = rows[-1]
        m = order(NS, [r[1] for r in rows])
        print(f"  {name:13} | {visits:14} | {events:6} | {elapsed:7.3f} / "
              f"{theory_time(n, v, a, b):<7.3f}         | {m:5.2f} | {complexity}")
    plot({name: (STRUCTURES[name], rows) for name, rows in results.items()}, a, b,
         "task4_branching.png", log=True)


if __name__ == "__main__":
    main()
