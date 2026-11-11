"""PROCESS: багатоканальне обслуговування з обмеженою чергою і пріоритетом у черзі."""
import math

from element import Element


class Process(Element):
    def __init__(self, name, delay_mean=1.0, delay_dev=0.0, distribution="exp",
                 channels=1, max_queue=math.inf, queue_key=None):
        super().__init__(name, delay_mean, delay_dev, distribution)
        self.channels = channels  # math.inf — затримка без обмеження кількості пристроїв
        self.max_queue = max_queue
        self.queue_key = queue_key  # функція(вимога) -> пріоритет у черзі, менше — раніше
        self.in_service = []  # пари (момент завершення, вимога)
        self.queue = []
        self.arrived = 0
        self.failure = 0
        self.queue_area = 0.0
        self.busy_area = 0.0

    @property
    def busy(self):
        return len(self.in_service)

    def can_accept(self):
        return self.busy < self.channels or len(self.queue) < self.max_queue

    def start_service(self, customer, delay=None):
        delay = self.get_delay(customer) if delay is None else delay
        self.in_service.append((self.tcurr + delay, customer))
        self.tnext = min(t for t, _ in self.in_service)

    def in_act(self, customer):
        self.mark_arrival()
        self.arrived += 1
        if self.busy < self.channels:
            self.start_service(customer)
        elif len(self.queue) < self.max_queue:
            self.queue.append(customer)
        else:
            self.failure += 1

    def take_from_queue(self):
        if self.queue_key is None:
            return self.queue.pop(0)
        index = min(range(len(self.queue)), key=lambda i: (self.queue_key(self.queue[i]), i))
        return self.queue.pop(index)

    def out_act(self):
        for item in [x for x in self.in_service if x[0] == self.tcurr]:
            self.in_service.remove(item)
            super().out_act()
            if self.queue:
                self.start_service(self.take_from_queue())
            self.tnext = min((t for t, _ in self.in_service), default=math.inf)
            customer = item[1]
            target = self.next_element(customer)
            if target:
                target.in_act(customer)

    def do_statistics(self, delta):
        self.queue_area += len(self.queue) * delta
        self.busy_area += self.busy * delta

    def mean_queue(self, time):
        return self.queue_area / time

    def mean_load(self, time):
        """Частка зайнятих пристроїв; для необмеженої кількості — середнє число зайнятих."""
        return self.busy_area / time / (1 if self.channels == math.inf else self.channels)

    def failure_probability(self):
        return self.failure / self.arrived if self.arrived else 0.0

    def print_info(self):
        print(f"  {self.name}: busy = {self.busy}/{self.channels}, queue = {len(self.queue)}, "
              f"quantity = {self.quantity}, failure = {self.failure}, tnext = {self.tnext:.4f}")

    def print_result(self, time):
        print(f"{self.name}: arrived = {self.arrived}, quantity = {self.quantity}, "
              f"failure = {self.failure}")
        print(f"    mean queue = {self.mean_queue(time):.4f}, "
              f"mean load = {self.mean_load(time):.4f}, "
              f"failure probability = {self.failure_probability():.4f}")
