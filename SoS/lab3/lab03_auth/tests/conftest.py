import os
import sys

# ТЕСТОВИЙ КЛЮЧ — не використовувати поза стендом
os.environ.setdefault("AUTH_PEPPER", "test-pepper-lab3-not-a-secret")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
