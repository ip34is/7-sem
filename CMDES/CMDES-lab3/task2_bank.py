"""Завдання 2: банк для автомобілістів — дві каси з окремими смугами, зміна смуги."""
import fun_rand
from create import Create
from dispose import Dispose
from element import Customer
from model import Model
from process import Process
from theory import mmck

ARRIVAL, SERVICE, MAX_QUEUE, TIME, LONG_TIME = 0.5, 0.3, 3, 1000, 100_000


def cars(lane):
    """Кількість автомобілів на смузі: у черзі та біля віконця."""
    return len(lane.queue) + lane.busy


def run(time=TIME, verbose_events=0):
    fun_rand.seed(1)
    create = Create("КЛІЄНТИ", ARRIVAL)
    lanes = [Process(f"КАСА {i}", SERVICE, max_queue=MAX_QUEUE) for i in (1, 2)]
    dispose = Dispose("ВИЇЗД")

    create.set_router(lambda customer: min(lanes, key=cars))  # коротша смуга, при рівності — перша
    create.tnext = 0.1
    for lane in lanes:
        lane.set_next(dispose)
        # початкові умови: касир зайнятий, у черзі два автомобілі
        lane.start_service(Customer(0, 0.0), fun_rand.norm(1.0, 0.3))
        lane.queue += [Customer(0, 0.0), Customer(0, 0.0)]

    changes = [0]

    def change_lane():
        """Останній автомобіль переїжджає на смугу, де щонайменше на два автомобілі менше."""
        for source, target in (lanes, lanes[::-1]):
            while source.queue and cars(source) - cars(target) >= 2:
                target.in_act(source.queue.pop())
                changes[0] += 1

    model = Model([create, *lanes, dispose], after_event=change_lane)
    model.simulate(time, verbose_events)
    return create, lanes, dispose, changes[0]


def in_bank(lanes, time):
    return sum(lane.queue_area + lane.busy_area for lane in lanes) / time


def main():
    create, lanes, dispose, changes = run(verbose_events=5)
    lost = sum(lane.failure for lane in lanes)
    left = sum(cars(lane) for lane in lanes)

    print(f"\n------------- РЕЗУЛЬТАТИ (T = {TIME}) -------------")
    print(f"Прибуло клієнтів: {create.quantity}, обслужено: {dispose.quantity}, втрачено: {lost}")
    for number, lane in enumerate(lanes, 1):
        print(f"1) середнє завантаження касира {number}:        {lane.mean_load(TIME):.4f}")
    print(f"2) середнє число клієнтів у банку:         {in_bank(lanes, TIME):.4f}")
    print(f"3) середній інтервал між від'їздами:       {dispose.mean_interval():.4f}")
    print(f"4) середній час перебування в банку:       {dispose.mean_time():.4f}")
    for number, lane in enumerate(lanes, 1):
        print(f"5) середнє число клієнтів у черзі {number}:      {lane.mean_queue(TIME):.4f}")
    print(f"6) відсоток клієнтів, яким відмовлено:     {100 * lost / create.quantity:.2f} %")
    print(f"7) число змін під'їзних смуг:              {changes}")

    balance = create.quantity + 6 == dispose.quantity + lost + left
    print(f"\nБаланс: прибуло {create.quantity} + 6 початкових = обслужено {dispose.quantity} "
          f"+ втрачено {lost} + у банку {left}: {'так' if balance else 'НІ'}")

    # завдяки зміні смуг касир не простоює, доки хтось чекає, тому банк загалом — система M/M/2/8
    create, lanes, dispose, _ = run(LONG_TIME)
    p_loss, mean_queue, mean_load = mmck(ARRIVAL, SERVICE, 2, 2 * MAX_QUEUE)
    theory_in_bank = mean_queue + 2 * mean_load
    theory_time = theory_in_bank * ARRIVAL / (1 - p_loss)
    total_load = sum(lane.mean_load(LONG_TIME) for lane in lanes)
    mean_in_bank = in_bank(lanes, LONG_TIME)
    print(f"\nПеревірка на тривалому інтервалі (T = {LONG_TIME}), імітація / теорія M/M/2/8:")
    print(f"  середнє число клієнтів у банку:   {mean_in_bank:.4f} / {theory_in_bank:.4f}")
    print(f"  середній час перебування в банку: {dispose.mean_time():.4f} / {theory_time:.4f}")
    print(f"  сумарне завантаження касирів:     {total_load:.4f} / {2 * mean_load:.4f}")


if __name__ == "__main__":
    main()
