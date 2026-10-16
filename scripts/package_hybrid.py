"""Validate and package a trained hybrid artifact for private, versioned S3 delivery."""

from __future__ import annotations

import argparse
import hashlib
import json
import zipfile
from pathlib import Path, PurePosixPath

from services.hybrid_classifier import validate_manifest


def package_hybrid(source: Path, output: Path) -> dict:
    source = source.resolve(strict=True)
    output = output.resolve()
    manifest = validate_manifest(source)
    if output.is_relative_to(source):
        raise ValueError("Output ZIP must be outside the model directory")
    expected = {"manifest.json", *manifest["hashes"]}
    if any(PurePosixPath(name).is_absolute() or ".." in PurePosixPath(name).parts or "\\" in name for name in expected):
        raise ValueError("Unsafe artifact path in manifest")
    files = sorted(source / name for name in expected)
    if any(path.is_symlink() or any(parent.is_symlink() for parent in path.parents if parent.is_relative_to(source)) for path in files):
        raise ValueError("Artifact must not contain symlinks")
    if not files or len(files) > 1000:
        raise ValueError("Invalid number of artifact files")
    if sum(path.stat().st_size for path in files) > 4 * 1024**3:
        raise ValueError("Artifact exceeds 4 GiB unpacked")
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, "x", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as bundle:
        for path in files:
            bundle.write(path, path.relative_to(source).as_posix())
    digest = hashlib.sha256()
    with output.open("rb") as archive:
        for chunk in iter(lambda: archive.read(1024 * 1024), b""):
            digest.update(chunk)
    return {"zip": str(output), "bytes": output.stat().st_size, "sha256": digest.hexdigest()}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    arguments = parser.parse_args()
    print(json.dumps(package_hybrid(arguments.model, arguments.output), indent=2))
