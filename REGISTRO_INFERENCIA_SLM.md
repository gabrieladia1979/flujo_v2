# Registro de Inferencia SLM (PhishARG)

Este documento registra la configuración exacta utilizada para la inferencia del SLM en el entorno de producción (o pruebas locales), cumpliendo con el checklist de `MEJORAS_OUTPUT_SLM.md`.

## Versión del Modelo
* **Modelo Base:** Qwen 2.5 3B Instruct
* **Formato:** GGUF
* **Cuantización:** Q4_K_M (Ofrece el mejor equilibrio entre velocidad de inferencia en CPU y retención de conocimiento, ocupando ~2.1GB de RAM).
* **Ruta de Descarga (HuggingFace):** `Qwen/Qwen2.5-3B-Instruct-GGUF`
* **Archivo Específico:** `qwen2.5-3b-instruct-q4_k_m.gguf`

## Configuración de Inferencia (Llama-CPP-Python)
Estos parámetros se encuentran hardcodeados/configurados en `services/slm_client.py`:

* **temperature:** `0.1` (Se mantiene baja para priorizar la estructura JSON estricta y evitar alucinaciones en la explicación).
* **max_tokens:** `300` (Se limita para evitar explicaciones innecesariamente largas que superen el contrato de Pydantic y para reducir el coste de inferencia).
* **n_ctx (Context Window):** `2048` (Suficiente para contener el System Prompt, el User Prompt con las evidencias y la respuesta esperada).
* **response_format:** `{"type": "json_object"}` (Obliga al modelo a estructurar su salida como JSON válido a nivel de gramática del sampler).

## Integración con Fallback
El cliente (`slm_client.py`) implementa un patrón de reintento (1 intento máximo) en caso de que el `json_object` devuelto no pueda ser parseado por `json.loads()`. Si el reintento también falla, o si ocurre un timeout, el sistema delega automáticamente en `render_server_fallback(context)`, asegurando que el veredicto del clasificador XGBoost siempre sea entregado al cliente sin demoras críticas.
