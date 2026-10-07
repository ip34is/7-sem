"""Завдання 3-4: модель CREATE -> PROCESS 1 -> PROCESS 2 -> PROCESS 3 -> DESPOSE та її верифікація."""
import fun_rand
from create import Create
from dispose import Dispose
from model import Model
from process import Process
from theory import mmck

TIME = 100_000

# № прогону: (delay CREATE, delay PROCESS 1..3, max_queue)
RUNS = [
    (2.0, 1.0, 1.0, 1.0, 5),
    (1.0, 1.0, 1.0, 1.0, 5),
    (4.0, 1.0, 1.0, 1.0, 5),
    (2.0, 2.0, 1.0, 1.0, 5),
    (2.0, 1.0, 2.0, 1.0, 5),
    (2.0, 1.0, 1.0, 2.0, 5),
    (2.0, 1.0, 1.0, 1.0, 0),
    (2.0, 1.0, 1.0, 1.0, 20),
    (2.0, 0.5, 0.5, 0.5, 5),
]


def run(delay_create, d1, d2, d3, max_queue, time=TIME, verbose_events=0):
    fun_rand.seed(1)
    create = Create("CREATE", delay_create)
    processes = [Process(f"PROCESS {i}", d, max_queue=max_queue) for i, d in enumerate((d1, d2, d3), 1)]
    dispose = Dispose("DESPOSE")
    chain = [create, *processes, dispose]
    for element, following in zip(chain, chain[1:]):
        element.set_next(following)
    model = Model(chain)
    model.simulate(time, verbose_events)
    return model, create, processes, dispose


def balance_ok(create, processes, dispose):
    """Закон збереження вимог: кожна вимога або обслужена, або відмовлена, або ще в елементі."""
    inputs = [create.quantity] + [p.quantity for p in processes[:-1]]
    return (all(p.arrived == n for p, n in zip(processes, inputs))
            and all(p.arrived == p.quantity + p.failure + p.queue + p.busy for p in processes)
            and dispose.quantity == processes[-1].quantity)


def main():
    model, *_ = run(*RUNS[0], verbose_events=5)
    model.print_result()

    print(f"\nВерифікація моделі (T = {TIME}). Таблиця А — вхідні параметри, кількості, відмови:")
    print(f"{'№':>2} {'tC':>4} {'t1':>4} {'t2':>4} {'t3':>4} {'maxQ':>4} | {'створено':>8} {'вийшло':>7} | "
          f"{'Pвідм1':>7} {'Pвідм2':>7} {'Pвідм3':>7} | баланс")
    results = []
    for number, params in enumerate(RUNS, 1):
        model, create, processes, dispose = run(*params)
        results.append((number, params, processes))
        fails = " ".join(f"{p.failure_probability():>7.4f}" for p in processes)
        print(f"{number:>2} {params[0]:>4} {params[1]:>4} {params[2]:>4} {params[3]:>4} {params[4]:>4} | "
              f"{create.quantity:>8} {dispose.quantity:>7} | {fails} | "
              f"{'так' if balance_ok(create, processes, dispose) else 'НІ'}")

    print("\nТаблиця Б — середнє завантаження пристроїв і середні довжини черг:")
    print(f"{'№':>2} | {'R1':>6} {'R2':>6} {'R3':>6} | {'L1':>7} {'L2':>7} {'L3':>7}")
    for number, _, processes in results:
        loads = " ".join(f"{p.mean_load(TIME):>6.3f}" for p in processes)
        queues = " ".join(f"{p.mean_queue(TIME):>7.3f}" for p in processes)
        print(f"{number:>2} | {loads} | {queues}")

    print("\nТаблиця В — PROCESS 1: імітація / теорія M/M/1/K:")
    print(f"{'№':>2} | {'Pвідм':>15} | {'завантаження':>15} | {'черга':>15}")
    for number, params, processes in results:
        p = processes[0]
        p_fail, mean_queue, mean_load = mmck(params[0], params[1], 1, params[4])
        print(f"{number:>2} | {p.failure_probability():>7.4f}/{p_fail:<7.4f} | "
              f"{p.mean_load(TIME):>7.4f}/{mean_load:<7.4f} | {p.mean_queue(TIME):>7.4f}/{mean_queue:<7.4f}")


if __name__ == "__main__":
    main()
