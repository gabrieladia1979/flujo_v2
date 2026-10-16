"""Check cloud artifact integrity and archive extraction boundaries."""

import hashlib
import shutil
import zipfile

import pytest

from scripts import bootstrap_hybrid


class LocalS3:
    def __init__(self, archive):
        self.archive = archive

    def download_file(self, bucket, key, destination, ExtraArgs):
        assert ExtraArgs == {"VersionId": "version-1"}
        shutil.copyfile(self.archive, destination)


def configure(monkeypatch, tmp_path, archive, digest=None):
    monkeypatch.setenv("PHISHARG_HYBRID_MODEL_DIR", str(tmp_path / "model"))
    monkeypatch.setenv("HYBRID_MODEL_S3_BUCKET", "private-models")
    monkeypatch.setenv("HYBRID_MODEL_S3_KEY", "hybrid/v1/model.zip")
    monkeypatch.setenv("HYBRID_MODEL_S3_VERSION_ID", "version-1")
    monkeypatch.setenv("HYBRID_MODEL_SHA256", digest or hashlib.sha256(archive.read_bytes()).hexdigest())


def test_download_verified_zip(monkeypatch, tmp_path):
    archive = tmp_path / "artifact.zip"
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr("manifest.json", "{}")
        bundle.writestr("encoder/config.json", "{}")
    configure(monkeypatch, tmp_path, archive)
    monkeypatch.setattr(bootstrap_hybrid, "validate_manifest", lambda path: {"ok": True})
    destination = bootstrap_hybrid.ensure_hybrid_model_available(client=LocalS3(archive))
    assert (destination / "encoder/config.json").read_text() == "{}"
    assert not (tmp_path / ".model.zip.part").exists()


@pytest.mark.parametrize("entry", ["../escaped.txt", "encoder/../../escaped.txt", "\\escaped.txt"])
def test_rejects_unsafe_zip_paths(monkeypatch, tmp_path, entry):
    archive = tmp_path / "artifact.zip"
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr(entry, "bad")
    configure(monkeypatch, tmp_path, archive)
    monkeypatch.setattr(bootstrap_hybrid, "validate_manifest", lambda path: {})
    with pytest.raises(bootstrap_hybrid.HybridBootstrapError):
        bootstrap_hybrid.ensure_hybrid_model_available(client=LocalS3(archive))
    assert not (tmp_path / "escaped.txt").exists()
    assert not (tmp_path / "model").exists()


def test_rejects_wrong_sha_before_extraction(monkeypatch, tmp_path):
    archive = tmp_path / "artifact.zip"
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr("manifest.json", "{}")
    configure(monkeypatch, tmp_path, archive, "0" * 64)
    with pytest.raises(bootstrap_hybrid.HybridBootstrapError, match="SHA-256"):
        bootstrap_hybrid.ensure_hybrid_model_available(client=LocalS3(archive))
    assert not (tmp_path / "model").exists()
