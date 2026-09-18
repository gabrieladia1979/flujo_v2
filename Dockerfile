FROM python:3.11-slim AS builder

WORKDIR /build

RUN apt-get update \
    && apt-get install --yes --no-install-recommends build-essential cmake \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN python -m pip install --upgrade pip \
    && python -m pip wheel --wheel-dir /wheels -r requirements.txt

FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN apt-get update \
    && apt-get install --yes --no-install-recommends libgomp1 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 10001 appuser \
    && mkdir -p /app/model \
    && chown -R appuser:appuser /app

COPY --from=builder /wheels /wheels
RUN python -m pip install --no-cache-dir /wheels/* \
    && rm -rf /wheels \
    && python -m spacy download es_core_news_sm

# .dockerignore deliberately excludes model/*.gguf while retaining the small
# model/phisharg_xgboost.pkl classifier shipped with this API version.
COPY --chown=appuser:appuser . .

RUN chmod +x /app/scripts/container-entrypoint.sh

USER appuser

EXPOSE 8080

ENTRYPOINT ["/app/scripts/container-entrypoint.sh"]
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080"]
