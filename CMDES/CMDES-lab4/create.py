"""CREATE: джерело вимог."""
from element import Customer, Element


class Create(Element):
    def __init__(self, name, delay_mean, delay_dev=0.0, distribution="exp", kind=None):
        super().__init__(name, delay_mean, delay_dev, distribution)
        self.tnext = 0.0
        self.kind = kind  # функція, що повертає тип нової вимоги

    def out_act(self):
        super().out_act()
        self.tnext = self.tcurr + self.get_delay()
        customer = Customer(self.kind() if self.kind else 0, self.tcurr)
        target = self.next_element(customer)
        if target:
            target.in_act(customer)
