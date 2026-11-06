# Образ інструментів ЛР6 для локального прогону конвеєра (ті самі версії, що в requirements.txt).
# setuptools потрібен semgrep 1.86 (pkg_resources), cyclonedx-bom формує SBOM.
FROM python:3.12-slim
RUN pip install --no-cache-dir setuptools==69.5.1 bandit==1.7.10 semgrep==1.86.0 pip-audit==2.7.3 cyclonedx-bom==4.6.1
WORKDIR /work
