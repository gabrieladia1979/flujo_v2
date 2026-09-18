# Deploy de PhishARG en AWS ECS/Fargate

La imagen contiene la API y el clasificador XGBoost de 2.6 MB. Nunca contiene el GGUF de 1.8 GB: la task lo descarga desde S3 privado al disco efímero local y llama.cpp lo usa desde allí.

## Camino rápido para la demo

1. Crear un bucket S3 privado con versionado habilitado y subir el GGUF.
2. Calcular SHA-256 del archivo exacto y guardar el bucket, key, version ID y checksum.
3. Crear ECR, publicar la imagen y completar [la task definition](../deploy/ecs/task-definition.json).
4. Adjuntar [la policy mínima de task role](../deploy/ecs/task-role-policy.json), configurar el secret `API_KEY` y crear un ECS Service con `desiredCount=1`.
5. Esperar que `GET /api/v1/health/ready` devuelva 200 antes de usar la demo. Al terminar, bajar el servicio a cero si no debe permanecer encendido.

## Artefactos y configuración

| Artefacto | Ubicación | Motivo |
|---|---|---|
| Código, dependencias y `phisharg_xgboost.pkl` | Imagen ECR | El clasificador es pequeño y queda ligado a la versión de API. |
| `qwen2.5-3b-instruct-q4_k_m.gguf` | S3 privado versionado | Es pesado y se administra fuera de Git y de la imagen. |
| GGUF en ejecución | `/app/model/...gguf` del disco efímero de la task | `llama.cpp` hace memory-map local, sin latencia de EFS/NFS. |

La configuración de producción exige estos valores:

```text
MODEL_BOOTSTRAP_ON_START=true
PRELOAD_SLM=true
SLM_MODEL_S3_BUCKET=<bucket privado>
SLM_MODEL_S3_KEY=slm/qwen2.5-3b-instruct-q4_k_m/v1/model.gguf
SLM_MODEL_S3_VERSION_ID=<version-id de S3>
SLM_MODEL_SHA256=<sha256 de 64 caracteres>
SLM_MODEL_LOCAL_PATH=/app/model/qwen2.5-3b-instruct-q4_k_m.gguf
```

El bootstrap descarga a un archivo temporal, valida el checksum y sólo entonces lo publica en la ruta final. La task role necesita únicamente `s3:GetObject` y `s3:GetObjectVersion` para ese objeto. No requiere credenciales AWS dentro del contenedor.

## Estado, warm-up y escalado

| Endpoint | Significado |
|---|---|
| `GET /api/v1/health` | Liveness. Informa si existe el archivo GGUF y si el SLM ya está inicializado. No descarga ni carga el modelo. |
| `GET /api/v1/health/ready` | Readiness. Devuelve 503 hasta que el clasificador y el SLM inicializado estén listos. |
| `POST /api/v1/internal/warmup` | Requiere `X-API-Key`. Descarga el GGUF si falta y lo inicializa. Útil sólo cuando `MODEL_BOOTSTRAP_ON_START=false`. |

Para la defensa, usar `desiredCount=1`, `MODEL_BOOTSTRAP_ON_START=true` y `PRELOAD_SLM=true`. Eso fuerza la descarga y carga antes de que el target esté healthy. Una vez healthy, el archivo y el modelo en memoria duran mientras esa task exista. Si ECS la reemplaza o escala a cero, ambos se pierden y el siguiente arranque repite el bootstrap.

## Límites operativos

- Cada proceso permite **una** generación SLM a la vez. Si llega otra durante la inferencia, devuelve la explicación determinista existente en vez de poner en riesgo CPU y latencia de la API.
- Punto de partida: 2 vCPU, 8 GB de RAM, `SLM_THREADS=2` y una sola task. Medir startup, memoria pico y p95 antes de reducir recursos o aumentar capacidad.
- Evitar EFS para el GGUF activo. El archivo se descarga una vez a almacenamiento local y llama.cpp lo memory-mapea localmente.
- No crear NAT Gateway para esta primera demo sólo por costumbre. Si la task corre en subred privada, usar un VPC Gateway Endpoint para S3; si no, evaluar la topología de red con las reglas de seguridad del ALB.

## Verificación previa

- [ ] El SHA-256 corresponde al object version ID configurado.
- [ ] La task role tiene sólo acceso de lectura al objeto S3 esperado.
- [ ] `GET /api/v1/health` muestra `model_file_exists: true` y `loaded: true` después del arranque.
- [ ] `GET /api/v1/health/ready` responde 200 antes de abrir la demo.
- [ ] Se creó un AWS Budget con alertas antes de exponer el servicio.
