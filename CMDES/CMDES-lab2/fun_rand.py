"""Генератори випадкових величин (аналог класу FunRand)."""
import math
import random

_rng = random.Random()


def seed(value):
    _rng.seed(value)


def uniform01():
    return _rng.random()


def exp(mean):
    return -mean * math.log(1 - _rng.random())


def unif(low, high):
    return low + _rng.random() * (high - low)


def norm(mean, dev):
    return mean + dev * _rng.gauss(0, 1)
