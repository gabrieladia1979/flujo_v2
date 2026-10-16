#!/usr/bin/env sh
set -eu

# Production ECS tasks set MODEL_BOOTSTRAP_ON_START=true. Keeping this optional
# preserves local development, where the GGUF may already be mounted locally.
python scripts/bootstrap_models.py
if [ "${PRELOAD_HYBRID:-false}" = "true" ]; then
  python -c 'from scripts.bootstrap_hybrid import ensure_hybrid_model_available; ensure_hybrid_model_available()'
fi
exec "$@"
