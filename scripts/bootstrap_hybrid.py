"""Download and verify a versioned hybrid classifier archive for an ECS task."""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import stat
import zipfile
from pathlib import Path, PurePosixPath

from services.hybrid_classifier import validate_manifest


class HybridBootstrapError(RuntimeError):
    pass


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _extract_verified_archive(archive: Path, destination: Path) -> None:
    """Extract only regular files under the expected artifact root."""
    total_bytes = 0
    with zipfile.ZipFile(archive) as bundle:
        members = bundle.infolist()
        if len(members) > 1000:
            raise HybridBootstrapError("Too many files in hybrid artifact")
        for member in members:
            path = PurePosixPath(member.filename)
            mode = (member.external_attr >> 16) & 0xFFFF
            if path.is_absolute() or ".." in path.parts or "\\" in member.filename:
                raise HybridBootstrapError("Unsafe hybrid archive path")
            file_type = stat.S_IFMT(mode)
            if file_type not in (0, stat.S_IFREG, stat.S_IFDIR):
                raise HybridBootstrapError("Unsupported hybrid archive member")
            if file_type == stat.S_IFDIR and not member.is_dir():
                raise HybridBootstrapError("Unsupported hybrid archive member")
            total_bytes += member.file_size
            if total_bytes > 4 * 1024**3:
                raise HybridBootstrapError("Hybrid artifact exceeds 4 GiB unpacked")
            target = destination.joinpath(*path.parts)
            if member.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with bundle.open(member) as source, target.open("xb") as output:
                shutil.copyfileobj(source, output)


def ensure_hybrid_model_available(*, client=None) -> Path:
    directory = Path(os.getenv("PHISHARG_HYBRID_MODEL_DIR", "artifacts/hybrid/cloud-a100")).resolve()
    bucket = os.getenv("HYBRID_MODEL_S3_BUCKET", "").strip()
    key = os.getenv("HYBRID_MODEL_S3_KEY", "").strip()
    version = os.getenv("HYBRID_MODEL_S3_VERSION_ID", "").strip()
    expected = os.getenv("HYBRID_MODEL_SHA256", "").strip().lower()

    if not bucket and not key:
        if directory.is_dir():
            validate_manifest(directory)
            return directory
        raise HybridBootstrapError("Hybrid artifact absent; configure its S3 source or a local directory")
    if not bucket or not key or not version or not re.fullmatch(r"[0-9a-f]{64}", expected):
        raise HybridBootstrapError("Hybrid S3 bucket, key, version ID and ZIP SHA-256 are required")
    if directory.is_dir():
        validate_manifest(directory)
        return directory

    directory.parent.mkdir(parents=True, exist_ok=True)
    archive = directory.with_name(f".{directory.name}.zip.part")
    temporary = directory.with_name(f".{directory.name}.extracting")
    archive.unlink(missing_ok=True)
    if temporary.exists():
        shutil.rmtree(temporary)
    try:
        if client is None:
            import boto3

            client = boto3.client("s3")
        client.download_file(bucket, key, str(archive), ExtraArgs={"VersionId": version})
        if _sha256(archive) != expected:
            raise HybridBootstrapError("Hybrid ZIP SHA-256 mismatch")
        temporary.mkdir()
        _extract_verified_archive(archive, temporary)
        validate_manifest(temporary)
        os.replace(temporary, directory)
        return directory
    finally:
        archive.unlink(missing_ok=True)
        if temporary.exists():
            shutil.rmtree(temporary)
