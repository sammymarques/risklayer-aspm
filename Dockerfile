# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026, NOME 1, NOME 2, NOME 3
# RiskLayer ASPM - distribuído sob a licença BSD de 3 cláusulas (veja LICENSE.md).

FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Usuário sem privilégios
RUN useradd --create-home --uid 10001 appuser

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY --chown=appuser:appuser . .
RUN mkdir -p resultados && chown appuser:appuser resultados

USER appuser
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/', timeout=3)" || exit 1

CMD ["python", "-m", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]