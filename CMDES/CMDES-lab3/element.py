"""Вимога та базовий елемент моделі: часова затримка і вибір наступного елемента."""
import math

import fun_rand


class Customer:
    def __init__(self, kind, t_start):
        self.kind = kind  # поточний тип, може змінюватись у моделі
        self.origin = kind  # тип при надходженні
        self.t_start = t_start


class Element:
    def __init__(self, name, delay_mean=1.0, delay_dev=0.0, distribution="exp"):
        self.name = name
        self.delay_mean = delay_mean
        self.delay_dev = delay_dev
        self.distribution = distribution  # назва закону або функція(вимога) -> затримка
        self.tcurr = 0.0
        self.tnext = math.inf
        self.quantity = 0
        self.routes = []
        self.routing = "probability"
        self.last_in = None
        self.gap_sum = 0.0
        self.gaps = 0

    def get_delay(self, customer=None):
        if callable(self.distribution):
            return self.distribution(customer)
        if self.distribution == "exp":
            return fun_rand.exp(self.delay_mean)
        if self.distribution == "norm":
            return fun_rand.norm(self.delay_mean, self.delay_dev)
        if self.distribution == "unif":
            return fun_rand.unif(self.delay_mean, self.delay_dev)
        if self.distribution == "erlang":
            return fun_rand.erlang(self.delay_mean, self.delay_dev)
        return self.delay_mean

    def set_next(self, element):
        self.set_routes_by_probability([(element, 1.0)])

    def set_routes_by_probability(self, routes):
        """routes — список (елемент, ймовірність)."""
        self.routes, self.routing = routes, "probability"

    def set_routes_by_priority(self, elements):
        """elements — елементи в порядку спадання пріоритету."""
        self.routes, self.routing = elements, "priority"

    def set_router(self, function):
        """function(вимога) -> елемент: довільне правило вибору маршруту."""
        self.routing = function

    def next_element(self, customer):
        if callable(self.routing):
            return self.routing(customer)
        if self.routing == "priority":
            for element in self.routes:  # перший за пріоритетом, який може прийняти вимогу
                if element.can_accept():
                    return element
            return self.routes[0] if self.routes else None
        r, cumulative = fun_rand.uniform01(), 0.0
        for element, probability in self.routes:
            cumulative += probability
            if r < cumulative:
                return element
        return None

    def can_accept(self):
        return True

    def mark_arrival(self):
        if self.last_in is not None:
            self.gap_sum += self.tcurr - self.last_in
            self.gaps += 1
        self.last_in = self.tcurr

    def mean_interval(self):
        """Середній інтервал між надходженнями вимог в елемент."""
        return self.gap_sum / self.gaps if self.gaps else 0.0

    def in_act(self, customer):
        pass

    def out_act(self):
        self.quantity += 1

    def do_statistics(self, delta):
        pass

    def print_info(self):
        print(f"  {self.name}: quantity = {self.quantity}, tnext = {self.tnext:.4f}")

    def print_result(self, time):
        print(f"{self.name}: quantity = {self.quantity}")
