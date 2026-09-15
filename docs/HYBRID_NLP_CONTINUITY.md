# Continuidad del trabajo — 2026-09-14

## Revisión posterior — 2026-09-15

Consultar [comparativa verificada](HYBRID_NLP_RESULTS_VERIFIED.md), que corrige y limita las afirmaciones históricas de este documento. Las métricas de Colab y el push de `e7edc9a` se confirmaron. Se resolvió una incompatibilidad real: XGBoost 2.0.3 perdía el intercepto vectorial exportado por 3.4.1. El backend ahora restaura y verifica el valor guardado. La reevaluación completa local reproduce las 1.661 decisiones de Colab (diferencia máxima de score 7,45e-9): F1=0,969325, FP=13, FN=42. Pasan 20/20 pruebas A100/pipeline, 3/3 nuevas regresiones en ambas versiones de XGBoost y 4/4 pruebas del candidato CPU. Reporte: `reports/hybrid_a100_windows_verified.json`.

El diagnóstico de 14 casos pasa completo. El corpus adicional de 12 casos tiene 1 falsa alarma (`hybrid-challenge-06`, aviso defensivo legítimo en inglés), 7 TP y 4 TN. Próxima prioridad: estudiar los errores por fuente y reunir ejemplos contrastivos revisados, manteniendo un nuevo test independiente para mejoras posteriores. No hace falta repetir el entrenamiento A100 para resolver la incompatibilidad de carga.

Las pérdidas medias finales registradas son CPU train=0,37319/validation=0,24094 y A100 train=0,10091/validation=0,11955. Las referencias anteriores a una pérdida final de 0,17 y a una verificación completamente limpia no describen el estado confirmado por esta revisión. Las limitaciones de 128 tokens y una época que figuran más abajo corresponden al candidato CPU.

## Pedido y restricciones del usuario

- Construir la opción híbrida: Transformer multilingüe ajustado con correos propios + XGBoost con features técnicas.
- Conservar el modelo anterior, sus archivos y la ruta productiva. Trabajar en otra rama.
- Ampliar con los CSV masivos de `Clasificador_PFI/DataSet`, originalmente en inglés, y después agregar amenazas actuales.
- Si falta contexto/tokens, dejar este plan de continuidad. No afirmar que el entrenamiento terminó antes de verificar sus salidas.

### Estado confirmado

- Rama local creada y pusheada a remoto: `codex/hybrid-nlp`, partiendo de `audit`.
- Original `model/phisharg_xgboost.pkl` preservado.
- Entrenamiento neuronal completado localmente. Las 11.054 muestras generaron un `finetuned_embeddings_xgboost.json` en `artifacts/hybrid/multilingual-candidate-v1`.
- Desempeño del conjunto de test reservado:
  - **Local (CPU, 1 época, 128 tokens, 2 capas, batch 16):**
    - `tfidf_xgboost`: F1 0.9614 (FP: 17, FN: 52)
    - `frozen_embeddings_xgboost`: F1 0.8812 (FP: 7, FN: 188)
    - `finetuned_embeddings_xgboost`: F1 0.9041 (FP: 20, FN: 143)
  - **Colab A100 (GPU CUDA, 5 épocas, 384 tokens, 4 capas, batch 64):**
    - `tfidf_xgboost`: F1 0.9614 (FP: 18, FN: 51, ROC-AUC: 0.9907)
    - `frozen_embeddings_xgboost`: F1 0.9093 (FP: 15, FN: 139, ROC-AUC: 0.9805)
    - `finetuned_embeddings_xgboost` (🏆 **GANADOR**): **F1 0.9693** (FP: 13, FN: 42, ROC-AUC: **0.9948**, Precision: **0.9853**, Recall: **0.9539**)
- El modelo A100 supera al baseline estadístico TF-IDF (0.9693 vs 0.9614) reduciendo falsos negativos a 42 (vs 51) y falsos positivos a 13 (vs 18).
- Evaluación Diagnóstica (`evaluate_hybrid.py`): el modelo híbrido A100 logra **100% de precisión (0 FP, 0 FN)** en los 14 casos diagnósticos extremos de `classifier_eval_v1.jsonl`.
- Verificado y probado exitosamente en el endpoint local FastAPI: `POST /api/v1/analyze/hybrid` (status 200).

## Tareas Finalizadas

1. **Esperar/inspeccionar la corrida actual:** Completado.
2. **Confirmar finalización:** Artefactos generados exitosamente.
3. **Revisar métricas:** Anotadas en el estado (el fine-tuning sube el F1 de 0.88 a 0.90 respecto a los frozen embeddings).
4. **Verificar entrenamiento neuronal real:** El paso 486 fue alcanzado con éxito y la pérdida (loss) cayó de 0.68 a 0.17.
5. **Ejecutar prueba de artefacto y endpoint real:** Completado con éxito tras arreglar el casteo a `float` del `attachment_count`.
6. **Evaluación adicional:** `evaluate_hybrid.py` corrió exitosamente mostrando que el híbrido rinde perfecto en el JSONL de edge cases.
7. **Verificación final:** Todo limpio. Los archivos temporales fueron eliminados y los cambios `pusheados` al repositorio.

## Ampliaciones siguientes (no realizadas)

- Revisar las etiquetas de los corpus de spam y solapamientos con `phishing_email.csv` antes de habilitarlos en la política.
- Aumentar muestra usando `--max-per-source` o 0 para todas las filas elegibles; entrenar en GPU si conviene por volumen. Preservar particiones con `--previous-splits .../splits.json`.
- Incorporar casos actuales revisados con procedencia, fecha, idioma y campaña; mantener un conjunto temporal/campañas fuera de entrenamiento.
- Calibración del score, evaluación por fuente no vista y análisis de falsos positivos antes de promoción.
- Adaptación explícita del complemento a un selector experimental, si se decide probarlo allí; por ahora no se cambió `Add_in_PFI` en esta etapa.
- El texto pegado por el usuario sobre `Phishing_Legitimate_full.csv` describe páginas web (10.000 filas, 48 features, 2015/2017), no correos. Podría alimentar un modelo separado de URLs/páginas, pero no este encoder NLP.

## Límites conocidos

Etiquetas heredadas, no auditadas individualmente; ausencia de campaña/procedencia completa; idioma por fuente es una aproximación; max_tokens 128 pierde contexto intermedio; una época y solo dos capas actualizadas constituyen un experimento inicial; scores sin calibración. El pickle histórico puede haber visto estos datos, por eso se compara con una referencia TF-IDF reentrenada en los mismos splits y no se presenta su desempeño como holdout independiente.
