# Estructura de flujo_v2

- `main.py`, `schemas.py`, `database.py`: entrada de la API y contratos compartidos.
- `services/`: clasificación, reglas de seguridad, explicaciones y acceso a modelos.
- `scripts/`: entrenamiento, evaluación, empaquetado y pruebas operativas del clasificador Hybrid.
- `scripts/slm/`: preparación, curaduría y entrenamiento experimental de Qwen. Ver `QWEN_SFT_PILOT.md`.
- `notebooks/`: notebooks de Colab; `qwen_hybrid_xai_colab.ipynb` se regenera con `scripts/slm/build_qwen_colab.py`.
- `data/`: corpus y casos de evaluación versionados. Un conjunto de prueba no equivale a evidencia de rendimiento productivo.
- `reports/`: auditorías y resultados reproducibles.
- `docs/`: instrucciones técnicas y límites conocidos.
- `deploy/` y `.github/workflows/`: despliegue y automatización.
- `artifacts/` y `model/`: archivos locales de pesos, modelos y salidas. Los pesos grandes y `artifacts/slm/` están fuera de Git.

Los scripts y el dataset SLM antiguos que siguen en la raíz se conservan por compatibilidad histórica: `qwen25_unsloth_finetuning.py`, `convertidor_dataset.py`, `generar_dataset_slm.py` y `dataset_slm_chatml.jsonl`. No se usan para el ajuste Hybrid nuevo. Las utilidades `patch*.py` y `fix_regex.py` también son históricas; no moverlas ni ejecutarlas sin revisar sus efectos. Las pruebas `test_*.py` permanecen en la raíz para mantener las rutas de `pytest` y los comandos documentados.

Para regenerar la demostración local de Qwen desde la raíz:

```powershell
.\.venv\Scripts\python.exe scripts/slm/build_qwen_review_candidates.py
.\.venv\Scripts\python.exe scripts/slm/curate_qwen_demo.py
.\.venv\Scripts\python.exe scripts/slm/build_qwen_colab.py
```

Estas salidas quedan en `artifacts/slm/`; el notebook se escribe en `notebooks/`.
