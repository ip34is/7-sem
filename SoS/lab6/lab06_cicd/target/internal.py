"""«Внутрішня» служба стенда — ціль для завдання на SSRF (лабораторна робота 5).

Доступна лише з мережі стенда, назовні порт не публікується.
"""
from flask import Flask

app = Flask(__name__)


@app.route("/")
def root():
    return "Внутрішня службова система. Доступ лише з довіреної мережі.\n"


@app.route("/secret")
def secret():
    # Синтетичний «секрет» — маркер успішної експлуатації SSRF.
    return "SSRF-FLAG: internal-service-reached-2026\n"


@app.route("/metadata")
def metadata():
    return (
        "instance-id: bpz-lab-internal\n"
        "role: document-processor\n"
        "token: SYNTHETIC-TOKEN-DO-NOT-USE\n"
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001)
