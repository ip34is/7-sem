"""Завдання 3: приймальне відділення лікарні — три типи хворих, супровідні, лабораторія."""
import math

import fun_rand
from create import Create
from dispose import Dispose
from model import Model
from process import Process

ARRIVAL, TIME = 15, 100_000
REGISTRATION = {1: 15, 2: 40, 3: 30}  # середній час реєстрації за типом хворого


def patient_kind():
    r = fun_rand.uniform01()
    return 1 if r < 0.5 else 2 if r < 0.6 else 3


def run(verbose_events=0):
    fun_rand.seed(1)
    create = Create("НАДХОДЖЕННЯ", ARRIVAL, kind=patient_kind)
    reception = Process("ПРИЙМАЛЬНЕ ВІДДІЛЕННЯ", channels=2,
                        distribution=lambda patient: fun_rand.exp(REGISTRATION[patient.kind]),
                        queue_key=lambda patient: patient.kind != 1)  # тип 1 обслуговується першим
    escort = Process("СУПРОВІД У ПАЛАТУ", 3, 8, "unif", channels=3)
    to_lab = Process("ШЛЯХ ДО ЛАБОРАТОРІЇ", 2, 5, "unif", channels=math.inf)
    registry = Process("РЕЄСТРАТУРА ЛАБОРАТОРІЇ", 4.5, 3, "erlang")
    analysis = Process("АНАЛІЗИ", 4, 2, "erlang", channels=2)
    to_reception = Process("ШЛЯХ ДО ПРИЙМАЛЬНОГО", 2, 5, "unif", channels=math.inf)
    ward = Dispose("ПАЛАТА")
    exit_ = Dispose("ВИХІД З ЛАБОРАТОРІЇ")

    def after_analysis(patient):
        if patient.origin == 3:
            return exit_
        patient.kind = 1  # хворий типу 2 після аналізів розглядається як хворий типу 1
        return to_reception

    create.set_next(reception)
    reception.set_router(lambda patient: escort if patient.kind == 1 else to_lab)
    escort.set_next(ward)
    to_lab.set_next(registry)
    registry.set_next(analysis)
    analysis.set_router(after_analysis)
    to_reception.set_next(reception)

    processes = [reception, escort, to_lab, registry, analysis, to_reception]
    model = Model([create, *processes, ward, exit_])
    model.simulate(TIME, verbose_events)
    return model, create, processes, ward, exit_


def main():
    model, create, processes, ward, exit_ = run(verbose_events=4)
    reception, _, _, registry, _, _ = processes
    model.print_result()

    total = ward.quantity + exit_.quantity
    overall = (ward.mean_time() * ward.quantity + exit_.mean_time() * exit_.quantity) / total
    lab_interval = registry.mean_interval()
    print("\nСередній час перебування хворого в системі, хв:")
    print(f"  тип 1 (до доставки в палату):     {ward.mean_time(1):.2f}")
    print(f"  тип 2 (до доставки в палату):     {ward.mean_time(2):.2f}")
    print(f"  тип 3 (до виходу з лабораторії):  {exit_.mean_time(3):.2f}")
    print(f"  усі хворі:                        {overall:.2f}")
    print(f"Середній інтервал між прибуттями хворих у лабораторію, хв: {lab_interval:.2f}")

    # робота лікарів на одного хворого: реєстрація за типом і повторна реєстрація хворих типу 2
    work = (0.5 * REGISTRATION[1] + 0.1 * REGISTRATION[2] + 0.4 * REGISTRATION[3]
            + 0.1 * REGISTRATION[1])
    lab_share = registry.arrived / create.quantity
    in_system = sum(len(p.queue) + p.busy for p in processes)
    balance = create.quantity == total + in_system
    print("\nПеревірка (імітація / очікуване значення):")
    print(f"  частка хворих, що потрапили в лабораторію: {lab_share:.4f} / 0.5")
    print(f"  інтервал між прибуттями в лабораторію:     {lab_interval:.2f} / {ARRIVAL / 0.5:.2f}")
    print(f"  завантаження лікарів приймального:         "
          f"{reception.mean_load(TIME):.4f} / {work / ARRIVAL / 2:.4f}")
    print(f"  баланс: надійшло {create.quantity} = у палатах {ward.quantity} "
          f"+ вийшло {exit_.quantity} + у системі {in_system}: {'так' if balance else 'НІ'}")


if __name__ == "__main__":
    main()
