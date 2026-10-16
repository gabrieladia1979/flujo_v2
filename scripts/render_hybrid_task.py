"""Fill deployment-specific ECS values without committing account secrets or IDs."""

import json
import os
from pathlib import Path


def required(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise SystemExit(f"Missing GitHub Actions variable: {name}")
    return value


def main() -> None:
    source = Path("deploy/ecs/task-definition-hybrid.json")
    task = json.loads(source.read_text(encoding="utf-8"))
    container = task["containerDefinitions"][0]
    task["executionRoleArn"] = required("ECS_EXECUTION_ROLE_ARN")
    task["taskRoleArn"] = required("HYBRID_TASK_ROLE_ARN")
    container["secrets"] = [
        {"name": "API_KEY", "valueFrom": required("API_KEY_SECRET_ARN")},
        {"name": "PHISHARG_TOKEN_KEY", "valueFrom": required("TOKEN_KEY_SECRET_ARN")},
    ]
    values = {item["name"]: item for item in container["environment"]}
    values["HYBRID_MODEL_S3_BUCKET"]["value"] = required("HYBRID_MODEL_BUCKET")
    values["HYBRID_MODEL_S3_VERSION_ID"]["value"] = required("HYBRID_MODEL_VERSION_ID")
    values["HYBRID_MODEL_SHA256"]["value"] = required("HYBRID_MODEL_SHA256")
    container["logConfiguration"]["options"]["awslogs-region"] = required("AWS_REGION")
    output = Path("hybrid-task-rendered.json")
    output.write_text(json.dumps(task, indent=2) + "\n", encoding="utf-8")
    print(f"Rendered {output}")


if __name__ == "__main__":
    main()
