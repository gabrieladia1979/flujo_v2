"""Package the selected audit artifact for a versioned, checksum-pinned S3 upload."""
import argparse
import hashlib
import json
from pathlib import Path
import zipfile

FILES = ("booster.json", "manifest.json", "phisharg_xgboost.pkl")


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def package_model(source, output):
    source, output = Path(source).resolve(), Path(output).resolve()
    manifest = json.loads((source / "manifest.json").read_text(encoding="utf-8"))
    if manifest["model_sha256"] != sha256(source / "phisharg_xgboost.pkl"):
        raise ValueError("Model checksum differs from its manifest")
    if manifest["booster_sha256"] != sha256(source / "booster.json"):
        raise ValueError("Native booster checksum differs from its manifest")
    if manifest["public_phishing_probability_index"] != 0:
        raise ValueError("The audit route requires phishing in column zero")
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, "x", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name in FILES:
            entry = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            entry.compress_type = zipfile.ZIP_DEFLATED
            entry.external_attr = 0o100644 << 16
            archive.writestr(entry, (source / name).read_bytes(), compresslevel=9)
    result = {"bundle_sha256": sha256(output), "model_sha256": manifest["model_sha256"],
              "files": list(FILES), "threshold": manifest["threshold"], "bytes": output.stat().st_size}
    output.with_suffix(".manifest.json").write_text(json.dumps(result, indent=2)+"\n", encoding="utf-8")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(package_model(args.model, args.output)))


if __name__ == "__main__":
    main()
