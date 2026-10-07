"""DESPOSE: вихід вимог із моделі."""
from element import Element


class Dispose(Element):
    def in_act(self):
        self.quantity += 1
