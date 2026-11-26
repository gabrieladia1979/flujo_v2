# Preparación de Fargate: audit-candidate-v2 (26/11/2026)

Esta rama actualiza la API XGBoost (`/api/v1/analyze`) con el modelo de `audit`,
contexto bancario y autenticación del add-in existente. No agrega la ruta
`/api/v1/analyze/hybrid`: el add-in `hybrid-aws-pilot` debe compilarse con
`PHISHARG_ANALYZER_ENGINE=xgboost`. Qwen continúa como explicador del veredicto.

## Publicación controlada

Los pushes **no ejecutan el workflow**. `Prepare or deploy AWS Fargate` solo se
inicia mediante `workflow_dispatch`. Con `deploy_service=false` (por defecto)
construye, prueba y publica una imagen en ECR; con `true` también actualiza ECS.
Este cambio de código no ha ejecutado ninguna de esas operaciones.

La imagen no contiene pesos ni correos. Antes de importar la API, el entrypoint
descarga el ZIP del clasificador desde una versión explícita de S3, comprueba su
SHA-256, nombres de archivos, manifiesto, contrato y SHA del pickle/booster, y
lo instala bajo `/app/artifacts/audit-candidate-v2`. Luego conserva la descarga
y precarga de Qwen existentes. `/health/ready` requiere clasificador y NLP,
y también Qwen cuando `PRELOAD_SLM=true` (como en esta tarea ECS).

## Artefacto y recursos previos

El paquete local preparado es `flujo_v2/artifacts/upload/audit-candidate-v2-20261126.zip`.
Los hashes y la clave sugerida están en `classifier-release.json`. No subir CSV,
correos, `.env` ni claves al repositorio o a la imagen.

1. Subir ese ZIP a un bucket privado con versionado habilitado, bajo
   `xgboost/audit-candidate-v2/20261126/model.zip`. Registrar el `VersionId`
   devuelto por S3 y verificar que coincide el SHA-256 del ZIP.
2. Configurar una tabla DynamoDB con clave primaria **String `nonce`** y TTL
   **`expires_at`**. Compartirla entre todas las tareas. El backend falla con
   503 si no puede registrar un nonce; nunca ignora ese control en producción.
3. Guardar `API_KEY` y `PHISHARG_TOKEN_KEY` (mínimo 32 caracteres) en Secrets
   Manager. La clave de firma debe coincidir con la del emisor de Vercel.
   Las variables de GitHub siguientes contienen los ARN, nunca las claves.
4. Ajustar la política de rol en `task-role-policy.json` al bucket/tabla reales.
   Mantener lectura del GGUF, agregar `s3:GetObjectVersion` del ZIP y
   `dynamodb:PutItem` de esa tabla. El rol de ejecución necesita acceso a los
   dos secretos y, si corresponde, a sus claves KMS. No se crearon recursos IAM.

## Variables de GitHub Actions

Para construir/probar/publicar ECR manualmente:

- `AWS_DEPLOY_ROLE_ARN`: rol OIDC autorizado para esta rama/repo, lectura de la
  versión del ZIP en S3 y publicación en el ECR existente `phisharg-api`.
- `CLASSIFIER_MODEL_S3_BUCKET` y `CLASSIFIER_MODEL_S3_VERSION_ID`: bucket y
  versión reales del paquete. La clave y hashes vienen del release versionado.

Para seleccionar además `deploy_service=true`:

- `ECS_CLUSTER`, `ECS_SERVICE`, `ECS_EXECUTION_ROLE_ARN`, `ECS_TASK_ROLE_ARN`.
- `API_KEY_SECRET_ARN`, `TOKEN_KEY_SECRET_ARN`: referencias de Secrets Manager
  que devuelvan la cadena de cada clave (o referencias JSON key completas).
- `PHISHARG_REPLAY_TABLE`: nombre de la tabla anterior.
- `PHISHARG_CORS_ORIGINS`: orígenes HTTPS exactos del add-in, separados por coma.

La región sigue siendo `us-east-1`; familia, CPU/memoria, log group y versión
SHA/VersionId de Qwen conservan la configuración existente. Revisar esos recursos
para la cuenta destino antes de desplegar. El JSON de tarea contiene marcadores
intencionales y debe generarse con `scripts/render_audit_task.py`; la validación
falla si faltan variables. El rol OIDC necesita `iam:PassRole` limitado a ambos
roles ECS, registro de task definitions, actualización y lectura del servicio.

## Verificación

El workflow descarga el mismo ZIP/version que usará ECS y lo verifica antes del
build. Monta los pesos en la imagen y ejecuta `scripts/smoke_audit_candidate.py`:
Galicia legítimo, suplantación BBVA y solicitud de secretos autenticada, más 36
contrastes de reglas. Solo después publica la imagen con etiqueta Git SHA.
ECS espera estabilidad usando su health check de readiness. Verificar luego una
sesión real Outlook → Vercel → ALB/ECS antes de activar la distribución del add-in.

Las pruebas locales de bootstrap usan S3 simulado y no credenciales. El contrato
cliente real → emisor real → API real fue probado por loopback con fallback del
explicador. Docker Desktop no tenía daemon activo: no se afirma haber construido
la imagen Linux localmente. El build y smoke dentro de Linux quedan como puerta
obligatoria del workflow manual, antes de cualquier actualización del servicio.

Los resultados de evaluación son de desarrollo, no una garantía de precisión
productiva. Ver `reports/REENTRENAMIENTO_XGBOOST_20261125.md` para las métricas,
la cobertura y las limitaciones del conjunto de correos.
