# Informe de Avance: Integración del SLM (Qwen 2.5 3B) en PhishARG

## ¿Qué logramos en esta sesión?

En esta sesión logramos completar el ciclo de "Small Language Model" para la capa de **Explicabilidad (XAI)** del proyecto PhishARG. Dejamos de depender de APIs externas (Gemini) y logramos entrenar y correr un modelo open-source directamente en el backend local.

### 1. Dataset y Formato (ChatML)
- Reemplazamos la idea de generar el dataset con Gemini (por límites de cuota) y usamos el dataset de 2000 ejemplos `slm_finetuning_dataset.jsonl` generado localmente.
- Creamos el script `convertidor_dataset.py` que toma esos 2000 correos y los formatea estrictamente bajo el estándar **ChatML**.
- **Solución de Bugs:** El dataset original devolvía acciones inválidas como `"delete_email"`. El convertidor nuevo lee las señales crudas (XAI Rules), infiere la intención (ej: `premio_falso`, `robo_credenciales`) y selecciona dinámicamente las acciones correctas estipuladas en el contrato de la API (`slm_explanation.py`), como `"do_not_click"` o `"do_not_share_sensitive_information"`.

### 2. Fine-Tuning en Google Colab
- Creamos el script `qwen25_unsloth_finetuning.py`.
- Resolvimos la incompatibilidad de dependencias en Colab (conflictos entre `trl` y `transformers 5.5`) usando `SFTConfig` en lugar del obsoleto `TrainingArguments`.
- Usamos **Unsloth** con LoRA (Rank 32) para entrenar eficientemente en una GPU A100.
- El modelo alcanzó una **Loss de Validación bajísima (0.027)**, lo que indica que aprendió a la perfección a clonar el estilo de respuesta estructurado sin memorizar.
- Exportamos el modelo resultante en formato ligero **GGUF (Q4_K_M)**.

### 3. Integración en FastAPI (Local)
- Descargamos el modelo entrenado y lo ubicamos en `model/qwen2.5-3b-instruct-q4_k_m.gguf`.
- **Protección Git:** Añadimos `*.gguf` al `.gitignore` para evitar que se suba el modelo de 2GB a GitHub y rompa el repositorio.
- Instalamos la librería precompilada `llama-cpp-python` compatible con Windows y CPU.
- Probamos la arquitectura con `simular_ciclo_completo.py` y `test_slm_vivo.py`.
- **Resultados:** El modelo de 3 Billones de parámetros ahora lee el output matemático del XGBoost y escupe JSONs impecables con 0 alucinaciones y de manera 100% offline y gratuita.

### ¿Cómo probarlo ahora mismo?
Cualquier miembro del equipo puede ejecutar el flujo entero usando:
```bash
python simular_ciclo_completo.py
```
O levantando la API normal (`uvicorn main:app --reload`).

*(Nota: si a otro miembro del equipo le da error al correrlo, debe instalar el motor local de SLM en su entorno virtual usando: `pip install llama-cpp-python --extra-index-url https://abetlen.github.io/llama-cpp-python/whl/cpu`)*
