"""Model: універсальний алгоритм імітації за принципом найближчої події."""


class Model:
    def __init__(self, elements, after_event=None):
        self.elements = elements
        self.after_event = after_event  # правило конкретної моделі, виконується після кожної події
        self.tcurr = 0.0

    def simulate(self, time, verbose_events=0):
        """verbose_events — скільки перших подій вивести у протокол."""
        step = 0
        while True:
            tnext = min(e.tnext for e in self.elements)
            if tnext > time:  # статистика збирається рівно на інтервалі [0; time]
                tnext = time
            for e in self.elements:
                e.do_statistics(tnext - self.tcurr)
            self.tcurr = tnext
            if self.tcurr >= time:
                break
            for e in self.elements:
                e.tcurr = self.tcurr
            for e in self.elements:
                if e.tnext == self.tcurr:
                    if step < verbose_events:
                        print(f"\nПодія в {e.name}, t = {self.tcurr:.4f}")
                    e.out_act()
            if self.after_event:
                self.after_event()
            if step < verbose_events:
                for e in self.elements:
                    e.print_info()
            step += 1

    def print_result(self):
        print(f"\n------------- РЕЗУЛЬТАТИ (T = {self.tcurr:g}) -------------")
        for e in self.elements:
            e.print_result(self.tcurr)
