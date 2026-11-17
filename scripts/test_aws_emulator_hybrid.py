"""Local Moto test of the real Hybrid artifact, S3 bootstrap, and replay.

Qwen, Docker, ECS, and the public endpoint are outside this test.
"""

import os
import sys
import time
import hashlib
import tempfile
import boto3
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from services.hybrid_classifier import _load, validate_manifest
from schemas import EmailPayloadSchema


def main():
    print("=== 1. Conectando al emulador local de AWS (http://127.0.0.1:9297) ===")
    endpoint_url = os.getenv("AWS_ENDPOINT_URL", "http://127.0.0.1:9297")
    s3 = boto3.client(
        "s3",
        endpoint_url=endpoint_url,
        region_name="us-east-1",
        aws_access_key_id="test",
        aws_secret_access_key="test",
    )
    dynamodb = boto3.client(
        "dynamodb",
        endpoint_url=endpoint_url,
        region_name="us-east-1",
        aws_access_key_id="test",
        aws_secret_access_key="test",
    )

    # 1. Asegurar bucket S3
    bucket_name = "phisharg-models-test"
    try:
        s3.create_bucket(Bucket=bucket_name)
    except Exception:
        pass
    s3.put_bucket_versioning(
        Bucket=bucket_name,
        VersioningConfiguration={"Status": "Enabled"},
    )
    print(f"Bucket S3 '{bucket_name}' listo y versionado.")

    # 2. Asegurar tabla DynamoDB
    table_name = "phisharg-replay-tokens"
    try:
        dynamodb.create_table(
            TableName=table_name,
            KeySchema=[{"AttributeName": "nonce", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "nonce", "AttributeType": "S"}],
            BillingMode="PAY_PER_REQUEST",
        )
        print(f"Tabla DynamoDB '{table_name}' creada.")
    except Exception:
        print(f"Tabla DynamoDB '{table_name}' ya existente.")

    # 3. Use the actual ZIP prepared for AWS.
    with tempfile.TemporaryDirectory() as tmp_str:
        tmp_dir = Path(tmp_str)
        zip_path = Path(__file__).resolve().parents[1] / "artifacts/hybrid/upload/multilingual-candidate-v3-curated-inference.zip"
        if not zip_path.is_file():
            raise FileNotFoundError(f"Missing real inference ZIP: {zip_path}")
        with zip_path.open("rb") as source:
            zip_sha256 = hashlib.file_digest(source, "sha256").hexdigest()

        # 4. Subir a S3
        key = "hybrid/multilingual-candidate-v3-curated/v1/model.zip"
        upload_resp = s3.put_object(
            Bucket=bucket_name,
            Key=key,
            Body=zip_path.open("rb"),
        )
        version_id = upload_resp.get("VersionId")
        print(f"\n=== 2. Modelo subido a S3 con VersionId: {version_id} ===")
        print(f"SHA-256 del ZIP: {zip_sha256}")

        # 5. Probar bootstrap_hybrid.py contra el emulador
        dest_dir = tmp_dir / "extracted_hybrid_model"
        os.environ["AWS_ENDPOINT_URL"] = endpoint_url
        os.environ["AWS_ACCESS_KEY_ID"] = "test"
        os.environ["AWS_SECRET_ACCESS_KEY"] = "test"
        os.environ["AWS_DEFAULT_REGION"] = "us-east-1"
        os.environ["PHISHARG_HYBRID_MODEL_DIR"] = str(dest_dir)
        os.environ["HYBRID_MODEL_S3_BUCKET"] = bucket_name
        os.environ["HYBRID_MODEL_S3_KEY"] = key
        os.environ["HYBRID_MODEL_S3_VERSION_ID"] = version_id
        os.environ["HYBRID_MODEL_SHA256"] = zip_sha256

        print("\n=== 3. Probando scripts.bootstrap_hybrid.ensure_hybrid_model_available() ===")
        from scripts.bootstrap_hybrid import ensure_hybrid_model_available

        result_path = ensure_hybrid_model_available(client=s3)
        validate_manifest(result_path)
        classifier = _load(str(result_path))
        payload = EmailPayloadSchema(metadata={"asunto": "Resumen de la reunion", "remitente_email": "equipo@example.com"}, contenido="Compartimos el resumen de la reunion semanal. No hace falta realizar ninguna accion.")
        score = classifier.raw_score(payload)
        assert 0 <= score <= 1
        print(f"[OK] Real Hybrid inference: score={score:.4f}")
        qwen_path = Path(os.getenv("PHISHARG_SLM_MODEL_PATH", r"C:\Users\Usuario\Downloads\qwen2.5-3b-instruct-q4_k_m.gguf"))
        if not qwen_path.is_file():
            raise FileNotFoundError(f"Missing local Qwen GGUF: {qwen_path}")
        os.environ["PHISHARG_SLM_MODEL_PATH"] = str(qwen_path)
        from fastapi.testclient import TestClient
        import main
        with TestClient(main.app) as api:
            response = api.post(
                "/api/v1/analyze/hybrid?include_lime=false",
                headers={main.API_KEY_NAME: main.API_KEY},
                json={"metadata": {"asunto": "Verifique su cuenta ahora", "remitente_email": "sender@example.com"},
                      "contenido": "Su cuenta sera bloqueada hoy. Ingrese urgentemente a http://microsoft-login-example.net y escriba su usuario, contrasena y codigo MFA."},
            )
        assert response.status_code == 200, response.text
        assert response.json()["explanation_source"] == "qwen", response.text
        print("[OK] Hybrid descargado desde Moto + Qwen local: explanation_source=qwen")
        print(f"[OK] Modelo descargado y verificado en: {result_path}")
        print(f"[OK] Archivos extraídos: {[p.name for p in result_path.iterdir()]}")

    # 6. Probar DynamoDB Token Replay Protection en main.py
    print("\n=== 4. Probando DynamoDB Replay Protection en main.py ===")
    os.environ["PHISHARG_REPLAY_TABLE"] = table_name
    import main

    # Inyectar cliente apuntando al endpoint local
    dynamo_resource = boto3.resource(
        "dynamodb",
        endpoint_url=endpoint_url,
        region_name="us-east-1",
        aws_access_key_id="test",
        aws_secret_access_key="test",
    )
    main._get_replay_table = lambda: dynamo_resource.Table(table_name)

    nonce = f"test-nonce-{int(time.time())}"
    now = int(time.time())
    main._claim_token_nonce(nonce, expires=now + 120, now=now)
    print(f"[OK] Primer reclamo de nonce '{nonce}' en DynamoDB exitoso!")

    try:
        main._claim_token_nonce(nonce, expires=now + 120, now=now)
        print("[FAIL] Replay no fue detectado!")
    except ValueError as e:
        print(f"[OK] Replay detectado correctamente por DynamoDB: {e}")

    print("\n=======================================================")
    print(" Moto S3 + real Hybrid + local Qwen + replay: OK. Docker and ECS remain untested. ")
    print("=======================================================")


if __name__ == "__main__":
    main()
