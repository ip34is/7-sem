"""Аналітичні характеристики СМО M/M/c/K для перевірки результатів імітації."""


def mmck(arrival_mean, service_mean, channels=1, max_queue=1000):
    """Повертає (ймовірність відмови, середня черга, середнє завантаження пристрою).

    arrival_mean — середній інтервал між вимогами, service_mean — середній час обслуговування.
    Нескінченна черга наближається великим max_queue (при завантаженні < 1).
    """
    a = service_mean / arrival_mean
    weights = [1.0]
    for n in range(1, channels + max_queue + 1):
        weights.append(weights[-1] * a / min(n, channels))
    total = sum(weights)
    p = [w / total for w in weights]
    p_fail = p[-1]
    mean_queue = sum((n - channels) * p[n] for n in range(channels + 1, len(p)))
    mean_load = sum(min(n, channels) * p[n] for n in range(len(p))) / channels
    return p_fail, mean_queue, mean_load
