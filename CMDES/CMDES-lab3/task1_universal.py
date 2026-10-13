"""Завдання 1: універсальний алгоритм — багатоканальність, маршрут за пріоритетом і ймовірністю.

CREATE -> за пріоритетом: PROCESS A (2 пристрої, черга 2) -> DESPOSE
                          PROCESS B (1 пристрій, черга 3) -> за ймовірністю:
                                DESPOSE (0.6) або PROCESS C (0.4) -> DESPOSE
"""
import fun_rand
from create import Create
from dispose import Dispose
from model import Model
from process import Process
from theory import mmck

DELAY_CREATE, DELAY_A, P_TO_C, TIME = 1.0, 1.5, 0.4, 100_000


def run(verbose_events=0):
    fun_rand.seed(1)
    create = Create("CREATE", DELAY_CREATE)
    a = Process("PROCESS A", DELAY_A, channels=2, max_queue=2)
    b = Process("PROCESS B", 1.0, channels=1, max_queue=3)
    c = Process("PROCESS C", 2.0)
    dispose = Dispose("DESPOSE")

    create.set_routes_by_priority([a, b])
    a.set_next(dispose)
    b.set_routes_by_probability([(dispose, 1 - P_TO_C), (c, P_TO_C)])
    c.set_next(dispose)

    model = Model([create, a, b, c, dispose])
    model.simulate(TIME, verbose_events)
    return model, create, (a, b, c), dispose


def main():
    model, create, (a, b, c), dispose = run(verbose_events=6)
    model.print_result()

    # вимоги, які PROCESS A не може прийняти, ідуть в обхід: для нього це M/M/2/4 з втратами
    p_block, mean_queue, mean_load = mmck(DELAY_CREATE, DELAY_A, 2, 2)
    bypassed = (b.arrived + a.failure) / create.quantity
    print("\nМаршрут за пріоритетом, PROCESS A (імітація / теорія M/M/2/4):")
    print(f"  частка вимог, не прийнятих у PROCESS A: {bypassed:.4f} / {p_block:.4f}")
    print(f"  середнє завантаження:                    {a.mean_load(TIME):.4f} / {mean_load:.4f}")
    print(f"  середня довжина черги:                   {a.mean_queue(TIME):.4f} / {mean_queue:.4f}")

    print("\nМаршрут за ймовірністю (імітація / задана ймовірність):")
    print(f"  PROCESS B -> PROCESS C: {c.arrived / b.quantity:.4f} / {P_TO_C}")

    in_system = sum(len(p.queue) + p.busy for p in (a, b, c))
    lost = a.failure + b.failure + c.failure
    balance = create.quantity == dispose.quantity + lost + in_system
    print(f"\nБаланс: створено {create.quantity} = вийшло {dispose.quantity} + втрачено {lost} "
          f"+ у системі {in_system}: {'так' if balance else 'НІ'}")


if __name__ == "__main__":
    main()
