"""PROCESS: обслуговування кількома ідентичними пристроями з обмеженою чергою."""
import math

from element import Element


class Process(Element):
    def __init__(self, name, delay_mean, channels=1, max_queue=math.inf,
                 delay_dev=0.0, distribution="exp"):
        super().__init__(name, delay_mean, delay_dev, distribution)
        self.channels = channels
        self.max_queue = max_queue
        self.tnexts = [math.inf] * channels  # момент звільнення кожного пристрою
        self.queue = 0
        self.arrived = 0
        self.failure = 0
        self.queue_area = 0.0
        self.busy_area = 0.0

    @property
    def busy(self):
        return sum(t != math.inf for t in self.tnexts)

    def in_act(self):
        self.arrived += 1
        if self.busy < self.channels:
            self.tnexts[self.tnexts.index(math.inf)] = self.tcurr + self.get_delay()
            self.tnext = min(self.tnexts)
        elif self.queue < self.max_queue:
            self.queue += 1
        else:
            self.failure += 1

    def out_act(self):
        for i, t in enumerate(self.tnexts):
            if t != self.tcurr:
                continue
            super().out_act()
            self.tnexts[i] = math.inf
            if self.queue > 0:
                self.queue -= 1
                self.tnexts[i] = self.tcurr + self.get_delay()
            self.tnext = min(self.tnexts)
            target = self.next_element()
            if target:
                target.in_act()

    def do_statistics(self, delta):
        self.queue_area += self.queue * delta
        self.busy_area += self.busy * delta

    def mean_queue(self, time):
        return self.queue_area / time

    def mean_load(self, time):
        """Середня частка зайнятих пристроїв."""
        return self.busy_area / time / self.channels

    def failure_probability(self):
        return self.failure / self.arrived if self.arrived else 0.0

    def print_info(self):
        print(f"  {self.name}: busy = {self.busy}/{self.channels}, queue = {self.queue}, "
              f"quantity = {self.quantity}, failure = {self.failure}, tnext = {self.tnext:.4f}")

    def print_result(self, time):
        print(f"{self.name}: arrived = {self.arrived}, quantity = {self.quantity}, "
              f"failure = {self.failure}")
        print(f"    mean queue = {self.mean_queue(time):.4f}, mean load = {self.mean_load(time):.4f}, "
              f"failure probability = {self.failure_probability():.4f}")
