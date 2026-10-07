"""Базовий елемент моделі: часова затримка, лічильник і маршрути до наступних елементів."""
import math

import fun_rand


class Element:
    def __init__(self, name, delay_mean=1.0, delay_dev=0.0, distribution="exp"):
        self.name = name
        self.delay_mean = delay_mean
        self.delay_dev = delay_dev
        self.distribution = distribution
        self.tcurr = 0.0
        self.tnext = math.inf
        self.quantity = 0
        self.routes = []

    def get_delay(self):
        if self.distribution == "exp":
            return fun_rand.exp(self.delay_mean)
        if self.distribution == "norm":
            return fun_rand.norm(self.delay_mean, self.delay_dev)
        if self.distribution == "unif":
            return fun_rand.unif(self.delay_mean, self.delay_dev)
        return self.delay_mean

    def set_next(self, element):
        self.routes = [(element, 1.0)]

    def add_route(self, element, probability):
        self.routes.append((element, probability))

    def next_element(self):
        """Вибір наступного елемента за ймовірностями маршрутів."""
        r, cumulative = fun_rand.uniform01(), 0.0
        for element, probability in self.routes:
            cumulative += probability
            if r < cumulative:
                return element
        return None

    def in_act(self):
        pass

    def out_act(self):
        self.quantity += 1

    def do_statistics(self, delta):
        pass

    def print_info(self):
        print(f"  {self.name}: quantity = {self.quantity}, tnext = {self.tnext:.4f}")

    def print_result(self, time):
        print(f"{self.name}: quantity = {self.quantity}")
