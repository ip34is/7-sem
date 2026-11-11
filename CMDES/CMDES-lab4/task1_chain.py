"""Завдання 1: модель з N послідовно з'єднаних СМО, N — параметр моделі."""
import fun_rand
from networks import ARRIVAL, SERVICE, chain

N, TIME = 5, 100_000


def main():
    fun_rand.seed(1)
    model, _ = chain(N)
    model.simulate(TIME, verbose_events=3)
    model.print_result()

    create, processes, dispose = model.elements[0], model.elements[1:-1], model.elements[-1]
    rho = SERVICE / ARRIVAL
    in_system = sum(len(p.queue) + p.busy for p in processes)
    balance = create.quantity == dispose.quantity + in_system
    print(f"\nКількість подій у моделі: N + 1 = {N + 1} (надходження і завершення "
          f"обслуговування в кожній з {N} СМО)")
    print(f"Виконано подій: {model.events}, очікується ν·T = (N + 1)·T / tC = "
          f"{(N + 1) * TIME / ARRIVAL:.0f}")
    print(f"Теорія (кожна СМО — M/M/1 з необмеженою чергою): завантаження {rho:.4f}, "
          f"середня черга {rho ** 2 / (1 - rho):.4f}")
    print(f"Баланс: створено {create.quantity} = вийшло {dispose.quantity} "
          f"+ у системі {in_system}: {'так' if balance else 'НІ'}")


if __name__ == "__main__":
    main()
