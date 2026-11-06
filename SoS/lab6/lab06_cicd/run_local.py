"""Локальний прогін конвеєра .github/workflows/security.yml (ЛР6, варіант 14).

Повторює три задачі конвеєра тими самими командами, що й GitHub Actions, але в Docker
(образ інструментів із Dockerfile та офіційний образ gitleaks):
  sast    — Bandit, Semgrep (rules/ + p/python), quality gate (python gate.py);
  sca     — pip-audit (текст + JSON), SBOM CycloneDX;
  secrets — gitleaks (сканування робочого каталогу).

Запуск з каталогу lab06_cicd:
  python run_local.py              # повний прогін; код завершення = результат конвеєра
  python run_local.py --baseline   # стадія sast + запис baseline.json (окремий коміт)
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
IMAGE = "bpz-lab6-tools"
GITLEAKS = "zricethezav/gitleaks:v8.18.4"
DOCKER_FALLBACK = Path(os.environ.get("LOCALAPPDATA", "")) / "Programs/DockerDesktop/resources/bin/docker.exe"

# Ті самі команди, що в security.yml.
SAST = [
    "bandit -r target -f json -o bandit.json -q || true",
    "semgrep --metrics=off --disable-version-check --config rules/ --config p/python "
    "--json --output semgrep.json target >/dev/null 2>&1 || true",
]
GATE = "python gate.py"
SCA = [
    "pip-audit -r audit_target.txt || true",
    "pip-audit -r audit_target.txt -f json -o pip-audit.json >/dev/null 2>&1 || true",
    "cyclonedx-py requirements audit_target.txt -o sbom.json || true",
]


def docker() -> str:
    found = shutil.which("docker") or (str(DOCKER_FALLBACK) if DOCKER_FALLBACK.exists() else None)
    if not found:
        sys.exit("Docker не знайдено: встановіть і запустіть Docker Desktop")
    return found


def run(args: list[str]) -> int:
    return subprocess.run(args).returncode


def in_tools(cmd: str) -> int:
    """Команда в образі інструментів; каталог lab06_cicd змонтовано як /work."""
    return run([docker(), "run", "--rm", "-v", f"{HERE}:/work", "-w", "/work", IMAGE, "sh", "-c", cmd])


def ensure_image() -> None:
    probe = subprocess.run([docker(), "image", "inspect", IMAGE], capture_output=True)
    if probe.returncode != 0:
        print(f"Збираю образ {IMAGE} …", flush=True)
        if run([docker(), "build", "-q", "-t", IMAGE, str(HERE)]) != 0:
            sys.exit("Не вдалося зібрати образ інструментів")


def stage(title: str) -> None:
    print(f"\n══════ {title} ══════", flush=True)


def job_sast(baseline: bool = False) -> int:
    stage("sast: Bandit + Semgrep (власні правила + p/python)")
    for cmd in SAST:
        in_tools(cmd)
    stage("sast: Quality gate" + (" — запис базової лінії" if baseline else ""))
    return in_tools(GATE + (" --update-baseline" if baseline else ""))


def job_sca() -> int:
    stage("sca: pip-audit + SBOM (CycloneDX)")
    for cmd in SCA:
        in_tools(cmd)
    return 0                      # як у security.yml: стадія лише формує звіти (|| true)


def job_secrets() -> int:
    stage("secrets: gitleaks")
    return run([docker(), "run", "--rm", "-v", f"{HERE}:/repo", GITLEAKS, "detect",
                "--source", "/repo", "--no-git", "--redact", "--no-banner",
                "--report-format", "json", "--report-path", "/repo/gitleaks.json"])


def main() -> int:
    sys.stdout.reconfigure(encoding="utf-8")
    ensure_image()
    if "--baseline" in sys.argv:
        return job_sast(baseline=True)
    results = {"sast": job_sast(), "sca": job_sca(), "secrets": job_secrets()}
    stage("Підсумок конвеєра")
    for job, code in results.items():
        print(f"  {job:8} {'✓ пройдено' if code == 0 else '✗ ПРОВАЛ'} (код {code})")
    failed = any(results.values())
    print(f"Конвеєр: {'ЗАБЛОКОВАНО' if failed else 'ЗЕЛЕНИЙ'} (код завершення {int(failed)})")
    return int(failed)


if __name__ == "__main__":
    sys.exit(main())
