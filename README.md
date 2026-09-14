# Proyecto Flujo

## Experimento NLP híbrido

La rama `codex/hybrid-nlp` agrega un encoder multilingüe ajustable y un XGBoost nuevo, con comparación contra TF-IDF y embeddings congelados. El clasificador y endpoint actuales se conservan. Ver [entrenamiento, datasets, evaluación y endpoint experimental](docs/HYBRID_NLP.md).

Este repositorio contiene el código fuente del proyecto Flujo.

## Clasificador y respuesta del backend

Se conserva la columna `0` del modelo. El endpoint `POST /api/v1/analyze` aplica también reglas de contenido para solicitudes de secretos y desvío de pagos acompañado de instrucciones de no verificar. Las señales se reflejan en `is_phishing`, `risk_score`, `reason` e `intent` y se entregan al explicador.

La respuesta incorpora tres campos: `raw_model_score` (score previo a reglas; nulo si el modelo no intervino), `decision_source` y `content_signals` (regla y descripción). El score final puede incluir un piso heurístico de 0.95; no debe interpretarse como probabilidad calibrada del modelo.

Ver [resultados, pruebas y límites](reports/classifier_content_improvements.md). Los cambios se ejecutan al iniciar o recargar este backend. El servicio remoto necesita actualizarse con este código para reflejarlos.

## Requisitos Previos

Asegurate de tener Python instalado y luego instala las dependencias:

```bash
pip install -r requirements.txt
```

## Configuración del Modelo (¡Importante!)

Debido al tamaño de los archivos del modelo (como `model.safetensors`), la carpeta `model/` **no** está incluida en este repositorio para no exceder los límites de tamaño de GitHub.

**Pasos para configurar el modelo localmente:**

1.  Pedile a un compañero de equipo el archivo comprimido con la carpeta `model/`.
2.  Descomprimí el archivo.
3.  Colocá la carpeta `model/` en la raíz de este proyecto (al mismo nivel que este archivo `README.md`).

La estructura final debería verse así:
```text
Flujo/
├── model/
│   └── model.safetensors
├── README.md
├── requirements.txt
└── ... resto de los archivos ...
```

*(Nota: La carpeta `model/` está incluida en el archivo `.gitignore` y no se subirá al repositorio remoto accidentalmente).*
