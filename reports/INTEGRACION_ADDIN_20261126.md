# Integración audit, add-in y entrega AWS — 26/11/2026

El add-in canónico de `entrega` seguía el protocolo Hybrid: ruta
`/api/v1/analyze/hybrid`, XAI obligatorio y tokens de Vercel. El clasificador
reentrenado de `audit` usa `/api/v1/analyze`. Se implementó un modo explícito
XGBoost en la rama ya existente **`hybrid-aws-pilot`**, sin modificar `entrega`.

Antes del traslado se respaldaron los diffs de ambos worktrees en
`artifacts/addin-transfer-20261126/`. El worktree de entrega estaba limpio al
inicio de esta revisión; el piloto tenía una modificación previa del título,
conservada semánticamente en el título dependiente del motor seleccionado.

## Contrato probado

- Desarrollo del piloto: XGBoost por defecto, proxy local hacia puerto 8001.
- Producción: Hybrid se conserva por defecto; XGBoost se selecciona con
  `PHISHARG_ANALYZER_ENGINE=xgboost` o `npm run build:xgboost`.
- El nombre visible y la dirección real del remitente se envían por separado.
- Se conserva HTML y sus destinos ocultos, y se muestra `bank_context` sin
  confundir banco mencionado con identidad autenticada.
- Hybrid sigue exigiendo XAI. XGBoost acepta su propio contrato sin inventar XAI.
- `/api/v1/analyze?quick=true` entrega el mismo veredicto sin esperar SHAP/SLM;
  la segunda fase usa otro permiso y una caché separada para enriquecerlo.
- El backend audit acepta el HMAC de cuerpo exacto del emisor existente de
  Vercel, incluidos expiración y nonce de un solo uso. Producción requiere el
  almacén compartido de nonces, claves de servidor y CORS del add-in.

## Evidencia

Pasaron **265 pruebas Python enfocadas y 6 subpruebas**, **19 pruebas Node**, tipado TypeScript y las
compilaciones de producción Hybrid/XGBoost. El probe ejecutó el cliente
TypeScript real, el emisor JavaScript real y una API Python temporal con el
clasificador `audit-candidate-v2`: cuatro correos sintéticos en dos fases,
ocho permisos, ocho análisis y rechazo de replay. Ver
[`addin_contract_20261126.json`](addin_contract_20261126.json).

También pasó el smoke del artefacto seleccionado: Galicia legítimo, imitación de
BBVA y solicitud de secretos desde dominio autenticado, más 36 contrastes de reglas.

La prueba usó transporte loopback y fallback del explicador. No prueba Outlook
interactivo, certificados TLS/ALB de AWS ni un despliegue real de Vercel.

## Estado de ramas y publicación

Se consultaron las ramas remotas. El add-in `entrega` coincide con su remoto en
`c38cdcf` (17/11); `origin/audit` sigue el baseline `705e840` y la entrega del
backend tiene la revisión `9dce97e` (20/11), que distribuye Qwen fuera de Git.
La rama AWS solicitada existe: **`aws-fargate-deployment`**, inicialmente
`e099c28`. Se actualiza a partir de audit conservando la entrega de Qwen y la
infraestructura especializada de esa rama.

Los pesos reentrenados se empaquetaron para S3 en:

```text
artifacts/upload/audit-candidate-v2-20261126.zip
SHA256: 0a0f9c94cda222cf18a50ae57eb2275caf468ec27c404ff7855cc8a2869c0ff6
Modelo: d176ffcbede82073a83e39139da8ee00665adeb4a6a60508c6cd51561a191728
```

El ZIP contiene solo pickle, booster nativo y manifiesto. No incluye correos,
claves, `.env` ni el GGUF. La subida a S3 y la activación de servicios AWS quedan
como pasos explícitos de despliegue; actualizar la rama no debe desplegar ECS.

## Comparación con entrega del add-in

La comparación de los HEAD `c38cdcf` (entrega) y `092c990` (piloto) mostró
diferencias finales en README, tres documentos, package.json/package-lock.json
y el título HTML. Los servicios del cliente, el emisor de tokens y el panel
tenían el mismo contenido. Se conservaron los commits de entrega; no se
revirtió su integración Hybrid ni se reemplazó esa rama por el piloto.
