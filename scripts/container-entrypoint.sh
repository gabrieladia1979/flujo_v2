#!/usr/bin/env sh
set -eu

# Production ECS tasks set MODEL_BOOTSTRAP_ON_START=true. Keeping this optional
# preserves local development, where the GGUF may already be mounted locally.
python scripts/bootstrap_models.py
exec "$@"
