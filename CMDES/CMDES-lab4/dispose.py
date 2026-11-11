"""DESPOSE: вихід вимог із моделі та час їх перебування в системі."""
from element import Element


class Dispose(Element):
    def __init__(self, name):
        super().__init__(name)
        self.times = {}  # тип вимоги -> [кількість, сумарний час у системі]

    def in_act(self, customer):
        self.mark_arrival()
        self.quantity += 1
        stat = self.times.setdefault(customer.origin, [0, 0.0])
        stat[0] += 1
        stat[1] += self.tcurr - customer.t_start

    def mean_time(self, kind=None):
        """Середній час у системі для вимог типу kind (None — для всіх)."""
        stats = [s for k, s in self.times.items() if kind is None or k == kind]
        count = sum(s[0] for s in stats)
        return sum(s[1] for s in stats) / count if count else 0.0
