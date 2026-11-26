# Proyecto Flujo

Integración actual con Outlook: [modo XGBoost, protocolo y pruebas](reports/INTEGRACION_ADDIN_20261126.md).
El add-in correspondiente se trabaja en la rama existente `hybrid-aws-pilot`.

Este repositorio contiene el código fuente del proyecto Flujo.

## Clasificador y respuesta del backend

Se conserva la columna `0` del modelo. El endpoint `POST /api/v1/analyze` aplica también reglas de contenido para solicitudes de secretos y desvío de pagos acompañado de instrucciones de no verificar. Las señales se reflejan en `is_phishing`, `risk_score`, `reason` e `intent` y se entregan al explicador.

La respuesta incorpora tres campos: `raw_model_score` (score previo a reglas; nulo si el modelo no intervino), `decision_source` y `content_signals` (regla y descripción). El score final puede incluir un piso heurístico de 0.95; no debe interpretarse como probabilidad calibrada del modelo.

Ver [resultados, pruebas y límites](reports/classifier_content_improvements.md). Los cambios se ejecutan al iniciar o recargar este backend. El servicio remoto necesita actualizarse con este código para reflejarlos.

## Auditoría de datos y entorno (25/11/2026)

Ver [inventario, comparación de runtimes y límites con correos históricos](reports/AUDITORIA_DATOS_Y_RUNTIME_20261125.md).
El pickle de esta rama requiere **XGBoost 2.0.3**, fijado en `requirements.txt`.
Con XGBoost 3.2.0 el mismo archivo carga pero cambia sus predicciones; el backend
rechaza versiones no verificadas para evitar resultados silenciosamente distintos.
Esta restricción corresponde al clasificador histórico de `audit`; los modelos
híbridos de otras ramas tienen su propio contrato de carga.

Si falta el clasificador o spaCy, `/api/v1/analyze` responde **503**, sin emitir un
veredicto legítimo. Health informa `status: degraded`. Un correo cuyo asunto y
cuerpo visible superen los 50.000 caracteres responde **413**, sin truncar el texto.
Las reglas críticas que pueden resolver una amenaza sin el modelo siguen activas.

La respuesta añade `bank_context`: banco del dominio remitente, bancos mencionados,
estado de autenticación y dominios imitadores observados. El registro inicial
incluye BBVA, Galicia, Santander, Macro, Nación, Provincia, Ciudad, ICBC, Credicoop,
Supervielle, Patagonia, Comafi e Hipotecario, con fuentes en
[`data/argentine_banks.json`](data/argentine_banks.json). Una mención bancaria no
confirma quién envió el correo. Los dominios de marketing externos desconocidos
no se marcan como fraude por esa sola razón.

La regla `bank_brand_impersonation` requiere una identidad bancaria declarada,
un dominio que imita la marca fuera de sus dominios registrados y un pedido
afirmativo de validar o acceder a una cuenta. Usa el piso heurístico de 0.95 y
expone `intent: suplantacion_bancaria`; no es una probabilidad calibrada.
El contexto bancario también se entrega al explicador y a su fallback.

La [mejora posterior del flujo bancario](reports/MEJORAS_FLUJO_BANCARIO_20261125.md)
unifica la interpretación de remitentes con nombre visible y dominios alternativos
con autenticación, y distingue códigos documentales explícitamente suministrados
de pedidos de secretos personales. Incluye comparaciones antes/después y límites.

## Candidato XGBoost reentrenado (25/11/2026)

Se generó un [candidato separado con menos falsas alarmas](reports/REENTRENAMIENTO_XGBOOST_20261125.md).
La selección del artefacto admite `PFI_CLASSIFIER_MODEL_PATH`; la configuración
local apunta a `artifacts/audit-candidate-v2/phisharg_xgboost.pkl`. El pickle
histórico sigue disponible y permanece como default cuando la variable no está
definida. Es necesario reiniciar un backend ya abierto para cambiar de modelo.
Los pesos y `.env` son locales; no se desplegó ni actualizó un servicio remoto.

## Requisitos Previos

Asegurate de tener Python instalado y luego instala las dependencias:

```bash
pip install -r requirements.txt
```

## Configuración del Modelo (¡Importante!)

El clasificador de esta rama usa `model/phisharg_xgboost.pkl`. Los pesos del SLM
son opcionales para clasificar; si faltan, las explicaciones usan el fallback.

**Pasos para configurar el modelo localmente:**

1.  Pedile a un compañero de equipo el archivo comprimido con la carpeta `model/`.
2.  Descomprimí el archivo.
3.  Colocá la carpeta `model/` en la raíz de este proyecto (al mismo nivel que este archivo `README.md`).

La estructura final debería verse así:
```text
Flujo/
├── model/
│   └── phisharg_xgboost.pkl
├── README.md
├── requirements.txt
└── ... resto de los archivos ...
```

El archivo GGUF del SLM se excluye de Git mediante `.gitignore`.
