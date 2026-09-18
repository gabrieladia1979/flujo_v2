FROM python:3.11-slim AS builder

WORKDIR /build
RUN apt-get update \
    && apt-get install --yes --no-install-recommends build-essential cmake \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt requirements-hybrid.txt ./
RUN python -m pip install --upgrade pip \
    && python -m pip install --index-url https://download.pytorch.org/whl/cpu 'torch>=2.2,<3' \
    && python -m pip wheel --wheel-dir /wheels -r requirements.txt -r requirements-hybrid.txt

FROM python:3.11-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app

RUN apt-get update \
    && apt-get install --yes --no-install-recommends libgomp1 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 10001 appuser \
    && mkdir -p /app/model /app/artifacts/hybrid \
    && chown -R appuser:appuser /app

COPY --from=builder /wheels /wheels
RUN python -m pip install --no-cache-dir /wheels/* \
    && rm -rf /wheels \
    && python -m spacy download es_core_news_sm

# Model weights stay outside Git and the image. ECS downloads a versioned,
# checksum-verified artifact before the service becomes ready.
COPY --chown=appuser:appuser . .
RUN chmod +x /app/scripts/container-entrypoint.sh
USER appuser
EXPOSE 8080
ENTRYPOINT ["/app/scripts/container-entrypoint.sh"]
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080", "--workers", "1"]
