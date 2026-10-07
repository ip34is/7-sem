"""Завдання 6: вихід у кілька наступних блоків і повернення у попередній блок.

CREATE -> PROCESS 1 -> PROCESS 2 (0.6) -> DESPOSE
                    -> PROCESS 3 (0.4) -> DESPOSE (0.7)
                                       -> PROCESS 1 (0.3, повернення)
"""
import fun_rand
from create import Create
from dispose import Dispose
from model import Model
from process import Process
from theory import mmck

DELAY_CREATE, TIME = 2.0, 100_000
P_TO_2, P_TO_3, P_RETURN = 0.6, 0.4, 0.3


def run(verbose_events=0):
    fun_rand.seed(1)
    create = Create("CREATE", DELAY_CREATE)
    p1 = Process("PROCESS 1", 0.8)
    p2 = Process("PROCESS 2", 1.5)
    p3 = Process("PROCESS 3", 2.0, channels=2)
    dispose = Dispose("DESPOSE")

    create.set_next(p1)
    p1.add_route(p2, P_TO_2)
    p1.add_route(p3, P_TO_3)
    p2.set_next(dispose)
    p3.add_route(dispose, 1 - P_RETURN)
    p3.add_route(p1, P_RETURN)

    model = Model([create, p1, p2, p3, dispose])
    model.simulate(TIME, verbose_events)
    return model, create, (p1, p2, p3), dispose


def arrival_rates():
    """Рівняння балансу потоків: e1 = λ + 0.3·e3, e2 = 0.6·e1, e3 = 0.4·e1."""
    e1 = (1 / DELAY_CREATE) / (1 - P_TO_3 * P_RETURN)
    return e1, P_TO_2 * e1, P_TO_3 * e1


def main():
    model, create, processes, dispose = run(verbose_events=6)
    p1, p2, p3 = processes
    model.print_result()

    returned = p1.arrived - create.quantity
    print("\nЧастоти переходів (імітація / задана ймовірність):")
    print(f"  PROCESS 1 -> PROCESS 2: {p2.arrived / p1.quantity:.4f} / {P_TO_2}")
    print(f"  PROCESS 1 -> PROCESS 3: {p3.arrived / p1.quantity:.4f} / {P_TO_3}")
    print(f"  PROCESS 3 -> PROCESS 1: {returned / p3.quantity:.4f} / {P_RETURN}")

    print("\nПорівняння з теорією (мережа Джексона), імітація / теорія:")
    print(f"{'елемент':<10} | {'надійшло':>15} | {'завантаження':>15} | {'черга':>15}")
    for p, rate in zip(processes, arrival_rates()):
        _, mean_queue, mean_load = mmck(1 / rate, p.delay_mean, p.channels)
        print(f"{p.name:<10} | {p.arrived:>7}/{rate * TIME:<7.0f} | "
              f"{p.mean_load(TIME):>7.4f}/{mean_load:<7.4f} | {p.mean_queue(TIME):>7.4f}/{mean_queue:<7.4f}")

    in_system = sum(p.queue + p.busy for p in processes)
    print(f"\nБаланс: створено {create.quantity} = вийшло {dispose.quantity} + у системі {in_system}: "
          f"{'так' if create.quantity == dispose.quantity + in_system else 'НІ'}")


if __name__ == "__main__":
    main()
