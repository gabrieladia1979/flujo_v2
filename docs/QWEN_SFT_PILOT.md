# Ajuste experimental de Qwen para explicaciones

Para Google Colab, abrí `notebooks/qwen_hybrid_xai_colab.ipynb` y ejecutá las celdas en orden. El notebook incluye el contrato y ambos scripts, por lo que solo pide subir el JSONL de casos revisados. `scripts/slm/build_qwen_colab.py` lo regenera si cambia el contrato o los scripts. Exige al menos 20 ejemplos de entrenamiento y 10 de evaluación, con phishing y legítimos en ambos grupos.

Para un ensayo de la mecánica en Colab, `scripts/slm/curate_qwen_demo.py` genera `artifacts/slm/colab_demo_reviewed.jsonl` a partir de 48 casos sintéticos inspeccionados del repositorio. La separación actual tiene 35 casos de entrenamiento y 13 de evaluación, ambas clases presentes, sin contextos idénticos entre particiones y agrupados por hash del cuerpo. Muchos casos legítimos solo tienen evidencia insuficiente. Esta muestra verifica el flujo de entrenamiento, no la calidad del modelo en correos argentinos nuevos. No reemplazar el GGUF del piloto con el adaptador resultante sin evaluación independiente.

El Qwen 2.5 3B Instruct que usa el piloto sigue siendo el GGUF base. Estos scripts preparan un candidato LoRA separado; no cambian el servicio ni suben pesos a AWS.

## Datos aceptados

Cada línea JSONL debe tener `case_id`, `source_id`, `reviewed: true`, `context` y `explanation`. Una persona debe contrastar el correo original, la salida del clasificador Hybrid y cada señal antes de marcar `reviewed`. El script valida el contrato de `services/slm_explanation.py`, pero no puede certificar que la evidencia sea verdadera.

Para Argentina, incluir casos reales o autorizados de suplantación y mensajes legítimos de comercio electrónico, billeteras y bancos. Mercado Libre, Mercado Pago y las entidades bancarias pueden aparecer en el correo como marcas alegadas; la marca por sí sola no prueba autenticidad ni phishing. Registrar las señales observadas, por ejemplo presión temporal, solicitud de credenciales, enlace discordante o ausencia de esas señales. No copiar URL completas ni datos personales al dataset. Conservar `source_id` estable entre variantes del mismo correo para evitar fuga entre entrenamiento y evaluación.

El viejo `dataset_slm_chatml.jsonl` no se incorpora automáticamente: contiene referencias a TF-IDF/LogReg y ejemplos cuya puntuación o intención no coincide con el contexto actual. Requiere revisión individual y reconstrucción de evidencias desde el pipeline vigente.

## Candidatos locales para revisión

`scripts/slm/build_qwen_review_candidates.py` genera `artifacts/slm/review_candidates.jsonl` desde los casos de diagnóstico y contraste. En la corrida del 17/11/2026 se obtuvieron 75 candidatos y se separaron 5 desacuerdos entre etiqueta e inferencia. De los candidatos, 45 quedaron solo con `evidence.insufficient`.

`scripts/slm/build_qwen_regional_candidates.py` toma una muestra balanceada de mensajes con marcas y entidades argentinas del corpus `SpaPhish_Master_Final_v5.csv` y genera `artifacts/slm/regional_review_candidates.jsonl`. En la corrida local se obtuvieron 120 candidatos y se separaron 4 desacuerdos. Los 120 quedaron con `evidence.insufficient` porque el corpus no aporta cabeceras verificadas y el analizador actual no extrajo señales utilizables de esos textos. Estos pares **no sirven aún** para enseñar explicaciones contextuales ricas. Ambos archivos tienen `reviewed: false` por diseño y permanecen fuera de Git; pueden contener texto de correos.

Para crear un JSONL apto para Colab, revisar cada correo y su etiqueta, ejecutar Hybrid con metadatos de seguridad auténticos cuando existan, comprobar que las evidencias describan señales observadas, excluir desacuerdos y casos sin evidencia útil, y recién entonces marcar `reviewed: true`. La validación automática del contrato no sustituye esa revisión.

## Uso

```powershell
.\.venv\Scripts\python.exe scripts/slm/prepare_qwen_sft.py ruta\casos_revisados.jsonl artifacts/slm/sft
```

Revisar `artifacts/slm/sft/audit.json` y ambos archivos JSONL. Con suficientes casos de ambas clases y evaluación separada, ejecutar en una máquina CUDA con versiones compatibles de `torch`, `transformers`, `datasets`, `peft`, `trl` y `bitsandbytes`:

```powershell
python scripts/slm/train_qwen_sft.py artifacts/slm/sft --output artifacts/slm/qwen-lora
```

El script guarda un adaptador LoRA. Antes de usarlo en el piloto: probar salidas contra `validate_slm_output`, medir la tasa de respaldo, evaluar correos argentinos no vistos y comparar con el GGUF base. La conversión a GGUF y el despliegue son pasos posteriores.
