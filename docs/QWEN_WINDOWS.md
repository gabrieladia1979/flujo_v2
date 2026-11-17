# Qwen en Windows: runtime CPU verificado

Verificado el 17 de noviembre de 2026 con Python 3.11 y el GGUF Qwen 2.5 3B Instruct Q4_K_M del servicio audit.

Las ruedas Windows de llama-cpp-python 0.3.35 y 0.3.36 produjeron una access violation incluso al consultar llama_print_system_info(), antes de cargar el modelo. La rueda CPU oficial 0.3.2 resolvió la inicialización y permitió generar una explicación real mediante la API Hybrid. La causa interna de la incompatibilidad de las ruedas nuevas no quedó aislada.

Instalar desde la raíz del servidor:

```powershell
.\.venv\Scripts\python.exe -m pip install --only-binary=:all: --extra-index-url https://abetlen.github.io/llama-cpp-python/whl/cpu llama-cpp-python==0.3.2
$env:PHISHARG_HYBRID_MODEL_DIR = (Resolve-Path artifacts/hybrid/multilingual-candidate-v3-curated).Path
$env:PHISHARG_SLM_MODEL_PATH = 'C:\Users\Usuario\Downloads\qwen2.5-3b-instruct-q4_k_m.gguf'
```

El SHA-256 del GGUF probado es `c3ba6d838a8615e9048c9d37642c5009ed0195fd8783eb04384102ffecd75cc5`.

Una petición con TestClient a `/api/v1/analyze/hybrid?include_lime=false` devolvió HTTP 200 y `explanation_source=qwen`, con resumen, evidencia y acción validados. Tardó 38,22 segundos, incluyendo carga inicial del SLM. Es una comprobación local de un caso, sin LIME; no es un benchmark ni acredita rendimiento en AWS. El pin se aplica sólo a Windows. La imagen Linux sigue pendiente de validación.

Referencia del diagnóstico: https://github.com/abetlen/llama-cpp-python/issues/1581
