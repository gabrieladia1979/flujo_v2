# Adaptador Qwen de la entrega

[Descargar el ZIP del adaptador de Colab](qwen-hybrid-lora-20261117-152453.zip).

- **Corrida:** `qwen-hybrid-lora-20261117-152453`.
- **Base:** `Qwen/Qwen2.5-3B-Instruct`.
- **Adaptador PEFT LoRA:** rango 16, alfa 32. El ZIP contiene los pesos `adapter_model.safetensors`, la configuración, el tokenizador y `data_audit.json`.
- **Datos registrados:** 48 casos sintéticos revisados, con 38 de entrenamiento y 10 de evaluación, según el archivo de auditoría exportado por Colab.
- **Integridad:** 57.683.887 bytes. SHA-256 `1f8d51339cff7e1f62f70d8f2f59b0caaf321c5cfcf6138a8af68e585a13cd6a`.

El [notebook de Colab](../../notebooks/qwen_hybrid_xai_colab.ipynb) y el [script de ajuste](../../scripts/slm/train_qwen_sft.py) documentan el procedimiento experimental. La auditoría conserva los recuentos de la corrida. El ZIP se puede extraer para cargar el adaptador con PEFT sobre la base indicada en `adapter_config.json`.

## Relación con la tesis

El capítulo 4 describe un procedimiento anterior sobre la misma familia Qwen, con QLoRA de 4 bits, rango 32 y 2.000 ejemplos ChatML. El [script histórico](../../qwen25_unsloth_finetuning.py) documenta esa configuración. Este ZIP corresponde a la corrida posterior de 48 ejemplos.

## Resultado y uso

En ocho contextos sintéticos de alerta, con el mismo Qwen base, prompt, esquema JSON y validador, la base obtuvo 7 respuestas válidas y el adaptador obtuvo 6. La acción esperada apareció en 3 y 2 respuestas válidas respectivamente. Se conserva Qwen base para la inferencia del piloto. El adaptador se entrega como evidencia experimental. El ZIP está excluido de la imagen Docker por `.dockerignore`.
