"""Provision the versioned SLM artifact from private S3 onto task-local storage.

The container image deliberately ships the small XGBoost classifier only.  The GGUF
is downloaded by an ECS task role to its ephemeral filesystem, then verified before
llama.cpp can memory-map it.
"""

from __future__ import annotations

import hashlib
import os
import re
from pathlib import Path
from urllib.parse import urlparse

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SLM_PATH = PROJECT_ROOT / "model" / "qwen2.5-3b-instruct-q4_k_m.gguf"
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")


class ModelBootstrapError(RuntimeError):
    """The configured model artifact cannot be safely provisioned."""


def is_truthy(value: str | None) -> bool:
    return (value or "").strip().lower() in {"1", "true", "yes", "on"}


def parse_s3_uri(uri: str) -> tuple[str, str]:
    parsed = urlparse(uri)
    if parsed.scheme != "s3" or not parsed.netloc or not parsed.path.strip("/"):
        raise ModelBootstrapError(f"Expected an s3://bucket/key URI, got {uri!r}")
    return parsed.netloc, parsed.path.lstrip("/")


def configured_s3_location() -> tuple[str, str] | None:
    """Read bucket/key configuration, accepting a URI for local compatibility."""
    bucket = os.getenv("SLM_MODEL_S3_BUCKET", "").strip()
    key = os.getenv("SLM_MODEL_S3_KEY", "").strip()
    uri = os.getenv("SLM_MODEL_S3_URI", "").strip()

    if bucket or key:
        if not bucket or not key:
            raise ModelBootstrapError(
                "SLM_MODEL_S3_BUCKET and SLM_MODEL_S3_KEY must be set together"
            )
        return bucket, key
    if uri:
        return parse_s3_uri(uri)
    return None


def configured_destination() -> Path:
    return Path(os.getenv("SLM_MODEL_LOCAL_PATH", str(DEFAULT_SLM_PATH))).expanduser()


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def validate_expected_sha256(expected_sha256: str) -> str:
    value = expected_sha256.strip().lower()
    if not SHA256_PATTERN.fullmatch(value):
        raise ModelBootstrapError("SLM_MODEL_SHA256 must be a 64-character lowercase SHA-256")
    return value


def _download_file(client: object, bucket: str, key: str, destination: Path, version_id: str) -> None:
    extra_args = {"VersionId": version_id} if version_id else None
    if extra_args:
        client.download_file(bucket, key, str(destination), ExtraArgs=extra_args)
    else:
        client.download_file(bucket, key, str(destination))


def ensure_slm_model_available(*, client: object | None = None) -> Path:
    """Return a verified local GGUF, downloading it atomically if S3 is configured.

    A checksum is mandatory when downloading.  Existing local files are accepted only
    when no S3 location is configured, which preserves the development workflow.
    """
    destination = configured_destination()
    location = configured_s3_location()

    if location is None:
        if destination.exists():
            return destination
        raise ModelBootstrapError(
            "SLM GGUF is absent and no S3 source is configured. Set SLM_MODEL_S3_BUCKET and SLM_MODEL_S3_KEY."
        )

    expected_sha256 = validate_expected_sha256(os.getenv("SLM_MODEL_SHA256", ""))
    version_id = os.getenv("SLM_MODEL_S3_VERSION_ID", "").strip()
    if not version_id:
        raise ModelBootstrapError("SLM_MODEL_S3_VERSION_ID is required for a reproducible S3 deployment")
    if destination.exists() and sha256(destination) == expected_sha256:
        print(f"[bootstrap] Reusing verified {destination.name}")
        return destination

    bucket, key = location
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(f".{destination.name}.part")
    temporary.unlink(missing_ok=True)

    print(f"[bootstrap] Downloading s3://{bucket}/{key} to {destination.name}")
    try:
        if client is None:
            import boto3

            client = boto3.client("s3")
        _download_file(client, bucket, key, temporary, version_id)
        if sha256(temporary) != expected_sha256:
            raise ModelBootstrapError(f"SHA-256 mismatch for {destination.name}")
        os.replace(temporary, destination)
        return destination
    finally:
        temporary.unlink(missing_ok=True)


def main() -> None:
    if is_truthy(os.getenv("MODEL_BOOTSTRAP_ON_START", "false")):
        ensure_slm_model_available()
    else:
        print("[bootstrap] Startup download disabled; the protected warm-up endpoint can provision the SLM.")


if __name__ == "__main__":
    main()
