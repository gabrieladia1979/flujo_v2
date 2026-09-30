# Preparación del piloto híbrido en AWS

## Decisión de modelo

El candidato de referencia es `multilingual-candidate-a100`. Sus 1.661 predicciones del test original se reprodujeron localmente tras corregir la carga del intercepto XGBoost: F1 0,969325, 13 falsos positivos y 42 falsos negativos. Frente al baseline TF-IDF de la misma corrida, F1 0,961431, 18 falsos positivos y 51 falsos negativos. El intervalo de confianza reportado para la diferencia de F1 incluye cero: la ventaja observada no está demostrada para cualquier población.

La variante `v3-curated` comunica F1 0,9698, 9 falsos positivos y 45 falsos negativos sobre un corpus revisado de 11.073 filas, distinto del corpus A100 original de 11.054 filas. No se puede interpretar la diferencia como una mejora directa sin evaluación pareada sobre un mismo conjunto reservado. En 24 casos contrastivos propios de v3 obtuvo 1 falso positivo y 2 falsos negativos. El A100 original tuvo 4 falsos positivos y 2 falsos negativos en otro conjunto de 16 casos: no es una comparación controlada. Las variantes semilla 7 y 21 reducen o igualan falsas alarmas, pero dejan pasar más ataques en el test original. Por ahora no se promueve una variante nueva.

## Estado de los pesos

`artifacts/hybrid/` está ignorado por Git. Este checkout contiene código y reportes, pero no `manifest.json`, `encoder/` ni `finetuned_embeddings_xgboost.json` del A100. El paquete no se puede construir ni validar con pesos reales hasta recuperarlos del equipo o de Colab. El ZIP debe contener esos archivos en la raíz, sin carpeta envolvente. No publicar pesos en Git ni en la imagen Docker.

## Ruta de despliegue preparada

- La imagen instala PyTorch para CPU y las dependencias del clasificador híbrido. Conserva el endpoint legado y agrega `/api/v1/analyze/hybrid`.
- Al iniciar con `PRELOAD_HYBRID=true`, la API descarga un ZIP versionado desde S3 privado con el task role, comprueba el SHA-256 del ZIP, extrae rutas seguras y verifica los hashes y el contrato del manifiesto antes de cargar el encoder y la cabeza XGBoost.
- `/api/v1/health/ready` responde 503 hasta que el clasificador legado y el híbrido estén cargados. El SLM puede quedar desactivado en este piloto, de modo que las explicaciones híbridas son deterministas; no se presentan como salida de Qwen ni como atribuciones SHAP.
- [task-definition-hybrid.json](../deploy/ecs/task-definition-hybrid.json) y [task-role-policy-hybrid.json](../deploy/ecs/task-role-policy-hybrid.json) son plantillas con marcadores. No registran recursos AWS ni cambian el servicio existente.

## Verificación antes de subir

1. Recuperar el directorio exacto del A100. Validar `manifest.json` y los hashes con `validate_manifest`; repetir el test de artefacto y la reproducción de scores del holdout.
2. Crear el ZIP con `python -m scripts.package_hybrid --model artifacts/hybrid/multilingual-candidate-a100 --output model-a100.zip`. El comando valida el manifiesto, incluye solo los archivos necesarios para inferencia y muestra SHA-256 y tamaño. Subirlo a una clave nueva de un bucket privado versionado; conservar el `VersionId` devuelto por S3.
3. Completar los marcadores de las plantillas. Mantener permisos de lectura restringidos a esa clave y registrar una task nueva, separada del servicio productivo. Comprobar que la imagen se construye en Linux y que caben pesos, ZIP y archivos temporales en disco efímero.
4. Levantar una sola task para piloto. Exigir readiness 200, probar el endpoint híbrido con un correo legítimo y uno malicioso, comparar el contrato JSON y medir memoria, inicio y latencia p95 con el artefacto real.
5. Probar desde el Add-in de forma explícita antes de cambiar su `API_BASE_URL` o su ruta. Conservar `/api/v1/analyze` y el servicio anterior como respaldo. Verificar HTTPS extremo a extremo antes de enviar correos reales.

Los reportes científicos describen entrenamientos y evaluaciones históricas. Esta preparación de infraestructura no prueba que el modelo híbrido esté hoy desplegado ni que supere al modelo anterior en correos reales actuales.

La construcción de la imagen aún requiere un Docker Engine Linux activo; la verificación local de este checkout se limita a compilación de Python y tests. El task necesita acceso de red a S3, Secrets Manager y CloudWatch Logs (NAT o VPC endpoints configurados).
