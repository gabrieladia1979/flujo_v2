"""Focused unit tests for S3 model provisioning without AWS credentials."""

import hashlib
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.bootstrap_models import (
    ModelBootstrapError,
    configured_s3_location,
    ensure_slm_model_available,
    parse_s3_uri,
)


class FakeS3:
    def __init__(self, payload: bytes):
        self.payload = payload
        self.calls = []

    def download_file(self, bucket, key, destination, **kwargs):
        self.calls.append((bucket, key, kwargs))
        Path(destination).write_bytes(self.payload)


class ModelBootstrapTests(unittest.TestCase):
    def test_uri_requires_bucket_and_key(self):
        self.assertEqual(parse_s3_uri("s3://models/slm/model.gguf"), ("models", "slm/model.gguf"))
        with self.assertRaises(ModelBootstrapError):
            parse_s3_uri("https://models/slm/model.gguf")

    def test_bucket_and_key_are_configured_together(self):
        with patch.dict(os.environ, {"SLM_MODEL_S3_BUCKET": "models"}, clear=True):
            with self.assertRaises(ModelBootstrapError):
                configured_s3_location()

    def test_s3_provisioning_requires_an_object_version(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(
            os.environ,
            {
                "SLM_MODEL_S3_BUCKET": "models",
                "SLM_MODEL_S3_KEY": "slm/v1/model.gguf",
                "SLM_MODEL_SHA256": "0" * 64,
                "SLM_MODEL_LOCAL_PATH": str(Path(directory) / "model.gguf"),
            },
            clear=True,
        ):
            with self.assertRaisesRegex(ModelBootstrapError, "VERSION_ID"):
                ensure_slm_model_available(client=FakeS3(b"not used"))

    def test_download_uses_version_and_verifies_checksum(self):
        payload = b"verified gguf fixture"
        digest = hashlib.sha256(payload).hexdigest()
        with tempfile.TemporaryDirectory() as directory, patch.dict(
            os.environ,
            {
                "SLM_MODEL_S3_BUCKET": "models",
                "SLM_MODEL_S3_KEY": "slm/v1/model.gguf",
                "SLM_MODEL_S3_VERSION_ID": "version-123",
                "SLM_MODEL_SHA256": digest,
                "SLM_MODEL_LOCAL_PATH": str(Path(directory) / "model.gguf"),
            },
            clear=True,
        ):
            client = FakeS3(payload)
            destination = ensure_slm_model_available(client=client)
            self.assertEqual(destination.read_bytes(), payload)
            self.assertEqual(
                client.calls,
                [("models", "slm/v1/model.gguf", {"ExtraArgs": {"VersionId": "version-123"}})],
            )

    def test_download_rejects_bad_checksum_and_does_not_publish_partial_file(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(
            os.environ,
            {
                "SLM_MODEL_S3_BUCKET": "models",
                "SLM_MODEL_S3_KEY": "slm/v1/model.gguf",
                "SLM_MODEL_S3_VERSION_ID": "version-123",
                "SLM_MODEL_SHA256": "0" * 64,
                "SLM_MODEL_LOCAL_PATH": str(Path(directory) / "model.gguf"),
            },
            clear=True,
        ):
            destination = Path(os.environ["SLM_MODEL_LOCAL_PATH"])
            with self.assertRaises(ModelBootstrapError):
                ensure_slm_model_available(client=FakeS3(b"wrong"))
            self.assertFalse(destination.exists())
            self.assertFalse(destination.with_name(".model.gguf.part").exists())


if __name__ == "__main__":
    unittest.main()
