"""Render the existing Fargate task with explicit release and environment inputs."""
import json
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def required(name):
    value = os.environ.get(name, "").strip()
    if not value or value.startswith("<"):
        raise ValueError(f"Missing deployment variable: {name}")
    return value


def render():
    task = json.loads((ROOT / "deploy/ecs/task-definition.json").read_text())
    release = json.loads((ROOT / "deploy/ecs/classifier-release.json").read_text())
    task["executionRoleArn"] = required("ECS_EXECUTION_ROLE_ARN")
    task["taskRoleArn"] = required("ECS_TASK_ROLE_ARN")
    container = task["containerDefinitions"][0]
    container["image"] = required("IMAGE_URI")
    environment = {entry["name"]: entry["value"] for entry in container["environment"]}
    environment.update({
        "PHISHARG_ENV": "production",
        "PHISHARG_REPLAY_TABLE": required("PHISHARG_REPLAY_TABLE"),
        "PHISHARG_CORS_ORIGINS": required("PHISHARG_CORS_ORIGINS"),
        "CLASSIFIER_BOOTSTRAP_ON_START": "true",
        "PFI_CLASSIFIER_MODEL_PATH": "/app/artifacts/audit-candidate-v2/phisharg_xgboost.pkl",
        "CLASSIFIER_MODEL_S3_BUCKET": required("CLASSIFIER_MODEL_S3_BUCKET"),
        "CLASSIFIER_MODEL_S3_KEY": release["s3_key"],
        "CLASSIFIER_MODEL_S3_VERSION_ID": required("CLASSIFIER_MODEL_S3_VERSION_ID"),
        "CLASSIFIER_BUNDLE_SHA256": release["bundle_sha256"],
        "CLASSIFIER_MODEL_SHA256": release["model_sha256"],
    })
    if "*" in environment["PHISHARG_CORS_ORIGINS"]:
        raise ValueError("Production CORS must use explicit origins")
    container["environment"] = [{"name": key, "value": value} for key, value in environment.items()]
    container["secrets"] = [
        {"name": "API_KEY", "valueFrom": required("API_KEY_SECRET_ARN")},
        {"name": "PHISHARG_TOKEN_KEY", "valueFrom": required("TOKEN_KEY_SECRET_ARN")},
    ]
    return task


if __name__ == "__main__":
    print(json.dumps(render(), indent=2))
