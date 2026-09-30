# Piloto híbrido v3-curated en AWS Fargate

Esta rama parte de `aws-fargate-deployment` y conserva su formato de imagen, ECS y arranque. El modelo híbrido queda en una task y una ruta experimental separadas. La rama original no se modifica.

## Artefacto disponible y decisión

Los pesos reales de `multilingual-candidate-v3-curated` están extraídos localmente en `artifacts/hybrid/multilingual-candidate-v3-curated/` y pasan `validate_manifest` con los diez hashes del manifiesto. El ZIP original entregado por el equipo es `Modelo Final-20260930T122555Z-1-001.zip` (SHA-256 `54129a7fe21bd637e7e5ba298906f335c8b74d822ee2ecde400a5bf3e1bbd261`). Contiene también archivos de entrenamiento y envoltorios que no requiere la API.

El ZIP de **solo inferencia**, ya generado localmente para S3, es `artifacts/hybrid/upload/multilingual-candidate-v3-curated-inference.zip`: 436.054.043 bytes, SHA-256 `4820cf63e1a00e701814b2c0aa556f6e72b0a846c7973934185a00ca26f6cfa3`. No se agrega a Git ni a la imagen. Para regenerarlo desde los pesos extraídos:

```powershell
python -m scripts.package_hybrid --model artifacts/hybrid/multilingual-candidate-v3-curated --output artifacts/hybrid/upload/multilingual-candidate-v3-curated-inference.zip
```

El ZIP se debe volver a hashear tras cualquier regeneración y actualizar `HYBRID_MODEL_SHA256` en la task definition. No se debe asumir que una nueva compresión conservará el hash anterior.

Elegimos v3-curated para el piloto porque **sus pesos están disponibles**. No hay una comparación pareada que demuestre superioridad respecto del A100 anterior: los corpus y tests difieren. El reporte de entrenamiento de v3 usa 11.073 correos, con particiones agrupadas de 7.792/1.619/1.662. En el test guardado comunica F1 0,9698, 9 falsos positivos y 45 falsos negativos. En la reproducción local con el código actual se observaron 8 falsos positivos y 45 falsos negativos (F1 0,9704): la normalización NFKC añadida después del entrenamiento cambia algunos textos y por tanto los scores. Esa diferencia debe resolverse o fijarse como nueva versión antes de presentar una reproducción exacta o pasar a producción. Las pruebas con casos propios tampoco sustituyen una evaluación independiente de correos reales.

## Subir el artefacto privado

1. Elegir un bucket privado con versionado habilitado, en la región de ECS. Configurar credenciales AWS CLI con permiso de carga. No usar un bucket público.
2. En PowerShell, desde la raíz de este repositorio, verificar el hash, subir el ZIP a la clave nueva y guardar el `VersionId` que devuelve S3:

```powershell
$zip = (Resolve-Path 'artifacts/hybrid/upload/multilingual-candidate-v3-curated-inference.zip').Path
(Get-FileHash -Algorithm SHA256 $zip).Hash.ToLowerInvariant()
aws s3api put-object --bucket <MODEL_BUCKET> --key hybrid/multilingual-candidate-v3-curated/v1/model.zip --body $zip --region <REGION>
```

3. Sustituir `<MODEL_BUCKET>`, `<S3_OBJECT_VERSION_ID>`, `<ACCOUNT_ID>`, `<REGION>` e `<IMAGE_TAG>` en [task-definition-hybrid.json](../deploy/ecs/task-definition-hybrid.json). Aplicar [task-role-policy-hybrid.json](../deploy/ecs/task-role-policy-hybrid.json) al task role. La task lee exactamente esa clave y versión, comprueba el SHA-256 del ZIP y los hashes internos del manifiesto, y falla al arrancar si hay discrepancias.
4. Crear el repositorio ECR del piloto si todavía no existe, iniciar sesión, construir la imagen Linux y subirla:

```powershell
aws ecr get-login-password --region <REGION> | docker login --username AWS --password-stdin <ACCOUNT_ID>.dkr.ecr.<REGION>.amazonaws.com
docker build -t phisharg-hybrid:<IMAGE_TAG> .
docker tag phisharg-hybrid:<IMAGE_TAG> <ACCOUNT_ID>.dkr.ecr.<REGION>.amazonaws.com/phisharg-hybrid:<IMAGE_TAG>
docker push <ACCOUNT_ID>.dkr.ecr.<REGION>.amazonaws.com/phisharg-hybrid:<IMAGE_TAG>
aws ecs register-task-definition --cli-input-json file://deploy/ecs/task-definition-hybrid.json --region <REGION>
```

Estas líneas usan marcadores; reemplazarlos antes de ejecutarlas. El execution role debe poder descargar la imagen, leer `API_KEY` de Secrets Manager y escribir logs; el task role necesita acceso al objeto S3 versionado. La task también requiere ruta de red hacia S3, Secrets Manager y CloudWatch Logs (NAT o VPC endpoints). Registrar una task definition no despliega ni modifica el servicio existente.

## Verificación del piloto

Arrancar una sola task aislada con `PRELOAD_HYBRID=true` y `PRELOAD_SLM=false`. El endpoint `/api/v1/health/ready` debe responder 200 solo después de cargar el clasificador legado y el híbrido; si el ZIP o el modelo fallan, la task no queda lista. Probar `/api/v1/analyze/hybrid` con el `X-API-Key` del piloto y correos legítimos y maliciosos. Medir memoria, tiempo de inicio, latencia p95 y errores en CloudWatch, y verificar HTTPS antes de probar con el Add-in. `/api/v1/analyze` sigue disponible con el modelo legado. La explicación híbrida de este piloto es determinista; no corresponde atribuirla a Qwen ni a LIME/SHAP.

El Dockerfile conserva la base de `aws-fargate-deployment` y añade PyTorch CPU, Sentence Transformers y XGBoost. La construcción Linux y la ejecución en ECS aún deben verificarse; no se afirma que ya esté desplegado.

## Evidencia para las correcciones del 50 %

El dataset v3 y sus reportes sí documentan tamaño, balance, particiones, idioma **inferido por fuente**, procesamiento, características, tokenización, arquitectura, ajuste fino del encoder, umbral y métricas. Son evidencia útil para la entrega actual del 75 %. No existían como versión entregable del 22/08, así que no conviene presentarlos como prueba histórica de aquella entrega.

Todavía falta acreditar la procedencia primaria y licencia de cada colección, auditar etiquetas y lenguas a nivel de mensaje y disponer de IDs de campañas o un holdout independiente que descarte fuga entre fuentes. El reporte advierte expresamente esas limitaciones. El encoder MiniLM sí recibió ajuste fino; no se debe confundir con el SLM Qwen, cuyo ajuste fino no está demostrado por este artefacto. Por estas razones, el criterio de la rúbrica sobre origen, características y pertinencia de datasets está **mejor documentado pero aún no completamente cerrado**.
