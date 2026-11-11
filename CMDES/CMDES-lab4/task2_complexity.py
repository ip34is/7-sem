"""Завдання 2–3: експериментальна і теоретична оцінка складності для послідовної мережі."""
from complexity import TIME, per_event, plot, print_series, series
from networks import ARRIVAL, chain


def main():
    rows = series(chain)
    a, b = per_event(rows)
    print(f"Модельний час T = {TIME}, середній інтервал надходження tC = {ARRIVAL}")
    print_series("послідовна", rows, a, b)

    print("\nТеоретична оцінка: O(ν·T·k)")
    print("  ν = (N + 1) / tC — подій за одиницю часу: надходження + завершення в кожній з N СМО;")
    print("  k — операцій на одну подію: 4 проходи по списку з N + 2 елементів (мінімальний tnext,")
    print("      статистика, розсилання tcurr, перевірка tnext) + обробка самої події;")
    print(f"      виміряно: час на подію ≈ {a:.2f} + {b:.3f}·N мкс — лінійно зростає з N;")
    print("  ν·T·k = T / tC · (N + 1) · (a + b·N)  =>  O(N²): при подвоєнні N час зростає")
    print("      майже вчетверо (до 4 разів при великих N).")
    plot({"послідовна": (chain, rows)}, a, b, "task2_chain.png")


if __name__ == "__main__":
    main()
