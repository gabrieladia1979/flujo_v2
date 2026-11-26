import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from scripts.bootstrap_classifier import ensure_classifier_available, install_bundle
from scripts.render_audit_task import render


class ClassifierBootstrapTests(unittest.TestCase):
    def bundle(self, root, extra=None, manifest_changes=None):
        model, booster = b"opaque-model-no-pickle-execution", b"native-booster"
        model_hash = hashlib.sha256(model).hexdigest()
        manifest = dict(model_file="phisharg_xgboost.pkl", booster_file="booster.json",
                        model_sha256=model_hash, booster_sha256=hashlib.sha256(booster).hexdigest(),
                        features=6022, public_phishing_probability_index=0)
        manifest.update(manifest_changes or {})
        path = root / "bundle.zip"
        with zipfile.ZipFile(path, "w") as bundle:
            for name, data in {"phisharg_xgboost.pkl": model, "booster.json": booster,
                               "manifest.json": json.dumps(manifest).encode(), **(extra or {})}.items():
                bundle.writestr(name, data)
        return path, hashlib.sha256(path.read_bytes()).hexdigest(), model_hash

    def test_installs_only_verified_bundle(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            archive, bundle_hash, model_hash = self.bundle(root)
            result = install_bundle(archive, root / "installed", bundle_hash, model_hash)
            self.assertEqual(hashlib.sha256(result.read_bytes()).hexdigest(), model_hash)
            self.assertEqual(len(list(result.parent.iterdir())), 3)

    def test_corruption_does_not_replace_existing_model(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            archive, bundle_hash, model_hash = self.bundle(root)
            target = root / "installed"
            target.mkdir()
            (target / "phisharg_xgboost.pkl").write_bytes(b"previous")
            with self.assertRaisesRegex(ValueError, "SHA-256"):
                install_bundle(archive, target, "0" * 64, model_hash)
            self.assertEqual((target / "phisharg_xgboost.pkl").read_bytes(), b"previous")

    def test_rejects_traversal_duplicate_and_extra_entries(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for extra in ({"../outside": b"bad"}, {"unexpected.pkl": b"bad"}):
                archive, bundle_hash, model_hash = self.bundle(root, extra)
                with self.assertRaisesRegex(ValueError, "members"):
                    install_bundle(archive, root / "installed", bundle_hash, model_hash)
            archive, _, model_hash = self.bundle(root)
            with zipfile.ZipFile(archive, "a") as bundle:
                bundle.writestr("manifest.json", b"{}")
            with self.assertRaisesRegex(ValueError, "members"):
                install_bundle(archive, root / "installed", hashlib.sha256(archive.read_bytes()).hexdigest(), model_hash)
            self.assertFalse((root / "installed").exists())

    def test_rejects_wrong_model_hash_manifest_and_class_semantics(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for changes in ({"public_phishing_probability_index": 1}, {"features": 6},
                            {"model_sha256": "0" * 64}, {"booster_sha256": "0" * 64}):
                archive, bundle_hash, model_hash = self.bundle(root, manifest_changes=changes)
                with self.assertRaisesRegex(ValueError, "contract mismatch"):
                    install_bundle(archive, root / "installed", bundle_hash, model_hash)

    def test_download_pins_version_and_closes_body(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            archive, bundle_hash, model_hash = self.bundle(root)
            body = io.BytesIO(archive.read_bytes())
            class FakeS3:
                def get_object(self, **kwargs):
                    self.arguments = kwargs
                    return {"Body": body}
            client = FakeS3()
            env = dict(CLASSIFIER_BOOTSTRAP_ON_START="true", CLASSIFIER_MODEL_S3_BUCKET="models",
                       CLASSIFIER_MODEL_S3_KEY="classifier.zip", CLASSIFIER_MODEL_S3_VERSION_ID="immutable-version",
                       CLASSIFIER_BUNDLE_SHA256=bundle_hash, CLASSIFIER_MODEL_SHA256=model_hash,
                       PFI_CLASSIFIER_MODEL_PATH=str(root / "installed/phisharg_xgboost.pkl"))
            with patch.dict(os.environ, env, clear=True):
                self.assertTrue(ensure_classifier_available(client).is_file())
                self.assertEqual(client.arguments, dict(Bucket="models", Key="classifier.zip", VersionId="immutable-version"))
                self.assertTrue(body.closed)
                os.environ.pop("CLASSIFIER_MODEL_S3_VERSION_ID")
                with self.assertRaisesRegex(ValueError, "VERSION_ID"):
                    ensure_classifier_available(client)

    def test_task_renderer_requires_real_configuration_and_injects_release(self):
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(ValueError, "ECS_EXECUTION_ROLE_ARN"):
                render()
        env = {name: "example" for name in ("ECS_EXECUTION_ROLE_ARN", "ECS_TASK_ROLE_ARN", "IMAGE_URI",
                "PHISHARG_REPLAY_TABLE", "CLASSIFIER_MODEL_S3_BUCKET", "CLASSIFIER_MODEL_S3_VERSION_ID",
                "API_KEY_SECRET_ARN", "TOKEN_KEY_SECRET_ARN")}
        env["PHISHARG_CORS_ORIGINS"] = "https://addin.example"
        with patch.dict(os.environ, env, clear=True):
            task = render()
            container = task["containerDefinitions"][0]
            configuration = {entry["name"]: entry["value"] for entry in container["environment"]}
            self.assertEqual(configuration["PHISHARG_ENV"], "production")
            self.assertEqual(configuration["CLASSIFIER_MODEL_S3_VERSION_ID"], "example")
            self.assertEqual(configuration["CLASSIFIER_MODEL_SHA256"],
                             "d176ffcbede82073a83e39139da8ee00665adeb4a6a60508c6cd51561a191728")
            self.assertEqual({item["name"] for item in container["secrets"]}, {"API_KEY", "PHISHARG_TOKEN_KEY"})
            os.environ["PHISHARG_CORS_ORIGINS"] = "*"
            with self.assertRaisesRegex(ValueError, "CORS"):
                render()
