"""Мережі з N СМО: послідовна і розгалужені структури маршруту.

Кожна функція повертає модель і середню кількість СМО, які проходить одна вимога.
"""
from create import Create
from dispose import Dispose
from model import Model
from process import Process

ARRIVAL, SERVICE, P_RETURN = 2.0, 1.0, 0.3


def _elements(n):
    create = Create("CREATE", ARRIVAL)
    processes = [Process(f"P{i}", SERVICE) for i in range(1, n + 1)]
    return create, processes, Dispose("DISPOSE")


def chain(n):
    """CREATE -> P1 -> P2 -> ... -> Pn -> DISPOSE: вимога проходить усі n СМО."""
    create, processes, dispose = _elements(n)
    for source, target in zip([create, *processes], [*processes, dispose]):
        source.set_next(target)
    return Model([create, *processes, dispose]), n


def tree(n):
    """Бінарне дерево: Pi передає вимогу в P2i або P2i+1 з імовірністю 0,5; з листя — DISPOSE."""
    create, processes, dispose = _elements(n)
    create.set_next(processes[0])
    for i, process in enumerate(processes, 1):
        children = [processes[j - 1] if j <= n else dispose for j in (2 * i, 2 * i + 1)]
        process.set_routes_by_probability([(child, 0.5) for child in children])
    visits = sum(0.5 ** (i.bit_length() - 1) for i in range(1, n + 1))  # Pi на глибині log2(i)
    return Model([create, *processes, dispose]), visits


def fan(n):
    """Віяло: CREATE передає вимогу в одну з n паралельних СМО з імовірністю 1/n."""
    create, processes, dispose = _elements(n)
    create.set_routes_by_probability([(process, 1 / n) for process in processes])
    for process in processes:
        process.set_next(dispose)
    return Model([create, *processes, dispose]), 1


def loop(n):
    """Ланцюг із поверненням: після Pn вимога з імовірністю P_RETURN повертається в P1."""
    model, _ = chain(n)
    processes, dispose = model.elements[1:-1], model.elements[-1]
    processes[-1].set_routes_by_probability([(processes[0], P_RETURN),
                                             (dispose, 1 - P_RETURN)])
    return model, n / (1 - P_RETURN)


STRUCTURES = {"послідовна": chain, "дерево": tree, "віяло": fan, "з поверненням": loop}
