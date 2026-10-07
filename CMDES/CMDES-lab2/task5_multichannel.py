"""Завдання 5: PROCESS з кількома ідентичними пристроями."""
import fun_rand
from create import Create
from dispose import Dispose
from model import Model
from process import Process
from theory import mmck

DELAY_CREATE, DELAY_PROCESS, MAX_QUEUE, TIME = 1.0, 2.0, 5, 100_000


def run(channels, verbose_events=0):
    fun_rand.seed(1)
    create = Create("CREATE", DELAY_CREATE)
    process = Process("PROCESS", DELAY_PROCESS, channels=channels, max_queue=MAX_QUEUE)
    dispose = Dispose("DESPOSE")
    create.set_next(process)
    process.set_next(dispose)
    model = Model([create, process, dispose])
    model.simulate(TIME, verbose_events)
    return model, create, process, dispose


def main():
    model, *_ = run(channels=3, verbose_events=5)
    model.print_result()

    print(f"\nВплив кількості пристроїв (T = {TIME}), імітація / теорія M/M/c/K:")
    print(f"{'c':>2} | {'обслужено':>9} | {'Pвідм':>15} | {'завантаження':>15} | {'черга':>15} | баланс")
    for channels in (1, 2, 3, 4, 5):
        _, create, p, dispose = run(channels)
        p_fail, mean_queue, mean_load = mmck(DELAY_CREATE, DELAY_PROCESS, channels, MAX_QUEUE)
        balance = (create.quantity == p.arrived == p.quantity + p.failure + p.queue + p.busy
                   and dispose.quantity == p.quantity)
        print(f"{channels:>2} | {p.quantity:>9} | {p.failure_probability():>7.4f}/{p_fail:<7.4f} | "
              f"{p.mean_load(TIME):>7.4f}/{mean_load:<7.4f} | {p.mean_queue(TIME):>7.4f}/{mean_queue:<7.4f} | "
              f"{'так' if balance else 'НІ'}")


if __name__ == "__main__":
    main()
