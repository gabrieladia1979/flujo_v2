"""Install a checksum-pinned classifier bundle; never deserialize during download."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile
import zipfile

FILES = {"phisharg_xgboost.pkl", "manifest.json", "booster.json"}
MAX_BYTES = 64 * 1024 * 1024


def checksum(data):
    return hashlib.sha256(data).hexdigest()


def required(name):
    value = os.environ.get(name, "").strip()
    if not value or value.startswith("<") or value == "null":
        raise ValueError(f"Missing deployment configuration: {name}")
    return value


def expected_hash(name):
    value = required(name).lower()
    if not re.fullmatch(r"[0-9a-f]{64}", value):
        raise ValueError(f"Invalid SHA-256: {name}")
    return value


def install_bundle(archive_path, destination, bundle_hash, model_hash):
    archive_path, destination = Path(archive_path), Path(destination)
    if archive_path.stat().st_size > MAX_BYTES:
        raise ValueError("Classifier archive too large")
    if checksum(archive_path.read_bytes()) != bundle_hash:
        raise ValueError("Classifier bundle SHA-256 mismatch")
    with zipfile.ZipFile(archive_path) as archive:
        entries = archive.infolist()
        if len(entries) != 3 or {entry.filename for entry in entries} != FILES:
            raise ValueError("Unexpected classifier archive members")
        if sum(entry.file_size for entry in entries) > MAX_BYTES:
            raise ValueError("Expanded classifier too large")
        if any(stat.S_ISLNK(entry.external_attr >> 16) or entry.is_dir() for entry in entries):
            raise ValueError("Classifier archive must contain regular files")
        contents = {entry.filename: archive.read(entry) for entry in entries}
    manifest = json.loads(contents["manifest.json"])
    if (checksum(contents["phisharg_xgboost.pkl"]) != model_hash
            or manifest.get("model_sha256") != model_hash
            or checksum(contents["booster.json"]) != manifest.get("booster_sha256")
            or manifest.get("model_file") != "phisharg_xgboost.pkl"
            or manifest.get("booster_file") != "booster.json"
            or manifest.get("public_phishing_probability_index") != 0
            or manifest.get("features") != 6022):
        raise ValueError("Classifier manifest/integrity/contract mismatch")
    destination.mkdir(parents=True, exist_ok=True)
    # Startup runs before the API imports any classifier. Each file is replaced
    # atomically only after the entire archive has passed validation.
    for name, data in contents.items():
        with tempfile.NamedTemporaryFile(dir=destination, delete=False) as output:
            temp = Path(output.name)
            output.write(data)
        try:
            os.replace(temp, destination / name)
        finally:
            temp.unlink(missing_ok=True)
    return destination / "phisharg_xgboost.pkl"


def ensure_classifier_available(client=None):
    if os.getenv("CLASSIFIER_BOOTSTRAP_ON_START", "").lower() not in {"1", "true", "yes", "on"}:
        return None
    # Immutable source and both digests are mandatory, even on a warm task.
    bucket, key, version = (required("CLASSIFIER_MODEL_S3_" + part) for part in ("BUCKET", "KEY", "VERSION_ID"))
    bundle_hash = expected_hash("CLASSIFIER_BUNDLE_SHA256")
    model_hash = expected_hash("CLASSIFIER_MODEL_SHA256")
    destination = Path(required("PFI_CLASSIFIER_MODEL_PATH")).expanduser().resolve()
    if destination.name != "phisharg_xgboost.pkl":
        raise ValueError("Classifier destination must end in phisharg_xgboost.pkl")
    if client is None:
        import boto3
        from botocore.config import Config
        client = boto3.client("s3", config=Config(connect_timeout=10, read_timeout=60,
                                               retries={"max_attempts": 2}))
    response = client.get_object(Bucket=bucket, Key=key, VersionId=version)
    body = response["Body"]
    try:
        with tempfile.TemporaryDirectory() as temporary:
            archive = Path(temporary) / "classifier.zip"
            size = 0
            with archive.open("wb") as output:
                for chunk in iter(lambda: body.read(1024 * 1024), b""):
                    size += len(chunk)
                    if size > MAX_BYTES:
                        raise ValueError("Classifier download too large")
                    output.write(chunk)
            return install_bundle(archive, destination.parent, bundle_hash, model_hash)
    finally:
        body.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path)
    parser.add_argument("--destination", type=Path)
    args = parser.parse_args()
    if args.archive:
        if args.destination is None:
            parser.error("--destination is required with --archive")
        install_bundle(args.archive, args.destination, expected_hash("CLASSIFIER_BUNDLE_SHA256"),
                       expected_hash("CLASSIFIER_MODEL_SHA256"))
    else:
        ensure_classifier_available()


if __name__ == "__main__":
    main()
