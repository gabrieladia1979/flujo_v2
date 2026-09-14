# Guía: Entrenamiento del Modelo Híbrido en Google Colab (con GPU)

Esta guía explica paso a paso cómo entrenar el modelo **Híbrido Multilingüe (Transformer + XGBoost)** en **Google Colab** aprovechando una GPU gratuita (T4) para reducir el tiempo de entrenamiento de **40 minutos (CPU) a menos de 3 minutos**.

---

## 1. Crear un Notebook en Google Colab

1. Andá a [Google Colab](https://colab.research.google.com/).
2. Creá un **Nuevo Cuaderno** (`New Notebook`).
3. **Activar la GPU:**
   - En el menú superior: `Entorno de ejecución` (Runtime) > `Cambiar tipo de entorno de ejecución` (Change runtime type).
   - En **Acelerador de hardware**, seleccioná **T4 GPU**.
   - Hacé clic en **Guardar**.

---

## 2. Celdas de Código para Ejecutar

### Celda 1: Clonar el repositorio y cambiar a la rama híbrida
```bash
!git clone https://github.com/gabrieladia1979/flujo_v2.git
%cd flujo_v2
!git checkout codex/hybrid-nlp
```

---

### Celda 2: Instalar dependencias
```bash
!pip install sentence-transformers==5.7.0 xgboost scikit-learn
```

---

### Celda 3: Crear carpetas y subir el dataset
Google Colab no tiene el archivo `multilingual-v1.csv` porque está ignorado en Git para no saturar el repositorio.

Ejecutá esta celda para crear la estructura de carpetas:
```bash
!mkdir -p artifacts/hybrid/corpus
!mkdir -p reports
```

Ahora subí el archivo `multilingual-v1.csv` (19.2 MB):
- **Opción A (Arrastrar y soltar):** En el panel izquierdo de Colab, hacé clic en el ícono de carpeta, navegá a `flujo_v2` > `artifacts` > `hybrid` > `corpus` y arrastrá tu archivo `multilingual-v1.csv` (ubicado en tu PC en `flujo_v2\artifacts\hybrid\corpus\multilingual-v1.csv`).
- **Opción B (Por código):**
```python
from google.colab import files
import shutil

print("Seleccioná el archivo 'multilingual-v1.csv' desde tu disco local:")
uploaded = files.upload()
for filename in uploaded.keys():
    shutil.move(filename, "artifacts/hybrid/corpus/" + filename)
print("¡Archivo subido correctamente!")
```

---

### Celda 4: Entrenar el modelo con GPU (`--device cuda`)
Acá podés aumentar la potencia del modelo a **3 épocas**, **256 tokens** y **4 capas entrenables** (en GPU corre en ~2 minutos):

```bash
!python scripts/train_hybrid.py \
  --dataset artifacts/hybrid/corpus/multilingual-v1.csv \
  --phishing-label 1 \
  --output artifacts/hybrid/multilingual-candidate-colab \
  --report reports/hybrid_multilingual_colab \
  --epochs 3 \
  --batch-size 32 \
  --max-tokens 256 \
  --trainable-layers 4 \
  --device cuda
```

---

### Celda 5: Evaluar el modelo en los 14 casos diagnósticos
Para comprobar que no tenga falsos positivos ni falsos negativos y comparar contra el modelo anterior:

```bash
!python scripts/evaluate_hybrid.py \
  --model artifacts/hybrid/multilingual-candidate-colab \
  --dataset data/classifier_eval_v1.jsonl \
  --output reports/hybrid_eval_colab \
  --compare-legacy
```

---

### Celda 6: Descargar el modelo entrenado a tu PC
Para traer el modelo entrenado y los reportes a tu máquina local:

```python
import shutil
from google.colab import files

# Comprimir la carpeta del modelo entrenado y reportes
shutil.make_archive("multilingual-candidate-colab", "zip", "artifacts/hybrid/multilingual-candidate-colab")
shutil.make_archive("reports_colab", "zip", "reports")

# Descargar automáticamente a tu carpeta de Descargas
files.download("multilingual-candidate-colab.zip")
files.download("reports_colab.zip")
```

---

## 3. Cómo usar el modelo descargado en tu PC

1. Descomprimí `multilingual-candidate-colab.zip` dentro de la carpeta `artifacts/hybrid/multilingual-candidate-colab` en tu repositorio local.
2. En tu terminal de PowerShell, podés probarlo con la variable de entorno:
```powershell
$env:PHISHARG_HYBRID_MODEL_DIR = 'artifacts/hybrid/multilingual-candidate-colab'
.venv-hybrid/Scripts/python.exe -m uvicorn main:app --host 127.0.0.1 --port 8001
```
