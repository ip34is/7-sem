"""CREATE: джерело вимог."""
from element import Element


class Create(Element):
    def __init__(self, name, delay_mean, delay_dev=0.0, distribution="exp"):
        super().__init__(name, delay_mean, delay_dev, distribution)
        self.tnext = 0.0  # імітація починається з надходження вимоги

    def out_act(self):
        super().out_act()
        self.tnext = self.tcurr + self.get_delay()
        target = self.next_element()
        if target:
            target.in_act()
