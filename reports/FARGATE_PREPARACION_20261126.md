# Fargate y add-in: preparación del 26/11/2026

Se incorporó `audit` (761feeb) en la rama existente `aws-fargate-deployment`.
Se resolvieron los conflictos tomando el flujo/clasificador audit probado y
conservando el runtime especializado de Qwen, su descarga S3 y precarga de ECS.

Validación local:

- 276 pruebas del flujo, tokens, integridad del ZIP, renderer de tarea y descarga
  S3 simulada; además 2 pruebas de concurrencia SLM y 5 de readiness: **283 en total**,
  más 6 subpruebas. No se ejecutaron los scripts interactivos de GGUF ni pruebas
  internas de copias locales de llama.cpp, que requieren sus propios entornos.
- Instalación del ZIP real mediante `bootstrap_classifier.py --archive`; hash
  del bundle y modelo coinciden con `deploy/ecs/classifier-release.json`.
- Smoke de tres casos del modelo real y 36 contrastes de seguridad, correcto.
- Probe HTTP del código Fargate contra el cliente y emisor reales del piloto:
  cuatro casos, ocho permisos y ocho análisis; replay rechazado. Reporte
  `addin_fargate_contract_20261126.json` (transporte loopback, fallback Qwen).
- Compilaciones Hybrid/XGBoost del add-in, TypeScript y 19 pruebas Node pasaron
  en `Add_in_PFI_hybrid_pilot` (commit a1d15c4). Entrega permanece intacta.
- YAML verificado: único evento `workflow_dispatch`, sin `push`; deploy ECS
  condicionado a `deploy_service=true`, cuyo valor por defecto es false.

No se construyó la imagen local: el daemon Docker Desktop no estaba activo.
El workflow manual exige construirla y ejecutar el modelo verificado dentro de
Linux antes de publicar en ECR o actualizar ECS. No se ejecutó el workflow,
no se subieron pesos a S3 y no se modificaron recursos AWS/Vercel.

Para desplegar todavía se necesitan el upload del ZIP versionado, la tabla de
nonces, los secretos y variables documentados en `deploy/ecs/README.md`.
La plantilla contiene marcadores para los valores nuevos y falla si faltan.
El add-in debe seleccionar el motor xgboost para apuntar a esta API; la ruta
Hybrid corresponde al otro backend y no se emula.

Los conjuntos de evaluación ya se usaron durante el desarrollo. La mejora
medida (71→9 falsos positivos y 466→63 falsos negativos en 1662 muestras) no
sustituye validación independiente con correo reciente revisado por humanos.
