# Multi-stage build for PhishARG Hybrid NLP classifier
FROM python:3.11-slim AS base

WORKDIR /app

# Install hybrid dependencies (includes sentence-transformers + XGBoost)
COPY requirements-hybrid.txt requirements.txt ./
RUN pip install --no-cache-dir -r requirements-hybrid.txt -r requirements.txt

# Copy application code
COPY . .

# The hybrid model artifacts should be mounted or downloaded at runtime
# via PHISHARG_HYBRID_MODEL_DIR environment variable

EXPOSE 8080

# Health check for production readiness
HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:8080/', timeout=5)" || exit 1

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080", "--workers", "1"]
