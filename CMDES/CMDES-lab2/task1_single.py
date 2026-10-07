"""Завдання 1-2: модель обслуговування одним пристроєм, середнє завантаження пристрою."""
import fun_rand
from create import Create
from dispose import Dispose
from model import Model
from process import Process
from theory import mmck

DELAY_CREATE, DELAY_PROCESS, MAX_QUEUE, TIME = 2.0, 1.0, 5, 100_000


def run(verbose_events=0):
    fun_rand.seed(1)
    create = Create("CREATE", DELAY_CREATE)
    process = Process("PROCESS", DELAY_PROCESS, max_queue=MAX_QUEUE)
    dispose = Dispose("DESPOSE")
    create.set_next(process)
    process.set_next(dispose)
    model = Model([create, process, dispose])
    model.simulate(TIME, verbose_events)
    return model, create, process, dispose


def main():
    model, _, process, _ = run(verbose_events=4)
    model.print_result()

    p_fail, mean_queue, mean_load = mmck(DELAY_CREATE, DELAY_PROCESS, 1, MAX_QUEUE)
    print("\nПорівняння з аналітичною моделлю M/M/1/K:")
    print(f"{'':<24}{'імітація':>10}{'теорія':>10}")
    print(f"{'середнє завантаження':<24}{process.mean_load(TIME):>10.4f}{mean_load:>10.4f}")
    print(f"{'середня довжина черги':<24}{process.mean_queue(TIME):>10.4f}{mean_queue:>10.4f}")
    print(f"{'ймовірність відмови':<24}{process.failure_probability():>10.4f}{p_fail:>10.4f}")


if __name__ == "__main__":
    main()
