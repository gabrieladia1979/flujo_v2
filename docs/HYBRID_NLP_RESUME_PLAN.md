# Plan de continuidad tras recibir los seis experimentos de Colab

Fecha: 2026-09-15. Pedido del usuario: dejar un plan para continuar sin perder contexto.

## Estado confirmado

- Repositorio: `C:/Users/gabri/OneDrive/Documentos/GitHub/flujo_v2`.
- Rama: `codex/hybrid-nlp`. No reemplazar el modelo histórico ni la rama `audit`.
- Commits locales previos: `4f49564` corrige carga del intercepto XGBoost; `659a4d0` agrega auditoría y experimentos.
- Recibido: `C:/Users/gabri/Downloads/flujo_experiment_reports_v2.zip` (313751 bytes). Contiene los seis reportes JSON y Markdown, no pesos de modelos.
- Los 12 archivos se importaron a `reports/hybrid_experiments_v2_*.json` y `.md`. Se comprobaron los hashes de los datasets locales y las cantidades de scores de test.
- Las seis corridas GPU que figuraban pendientes en documentos anteriores ya tienen reportes completos. Todavía no se reprodujeron sus pesos en Windows.
- El A100 original está instalado en `artifacts/hybrid/multilingual-candidate-a100`. La carga corregida reproduce sus 1661 predicciones de Colab; pruebas previas aprobadas.

## Resultados recibidos: NLP ajustado + XGBoost

| Variante | Test | F1 | FP | FN |
| --- | ---: | ---: | ---: | ---: |
| A100 original, semilla 42 | 1661 | 0,969325 | 13 | 42 |
| Semilla 7 | 1661 | 0,967923 | 6 | 51 |
| Semilla 21 | 1661 | 0,965129 | 9 | 53 |
| Contexto 128 tokens | 1661 | 0,963626 | 15 | 50 |
| Dos capas ajustadas | 1661 | 0,954160 | 13 | 68 |
| Una época | 1661 | 0,925668 | 14 | 114 |
| Dataset ampliado | 2176 | 0,966902 | 27 | 34 |

Los cinco experimentos del corpus original declaran el mismo dataset y la misma partición previa. Verificar la alineación de scores con los IDs antes de hacer comparaciones pareadas. El ampliado usa otro test: **no comparar directamente su F1/FP/FN con las cifras de 1661 correos**. Su baseline TF-IDF sobre 2176 correos da F1=0,956474, FP=22, FN=57: el híbrido detecta más positivos a costa de más falsas alarmas.

Recomendación provisional: mantener el A100 original corregido como candidato principal. La semilla 7 merece evaluación adicional por sus 6 falsas alarmas, pero omite 9 ataques más que el original. No elegir una semilla solamente por haber obtenido buen test; el test ya se ha usado para inspección de alternativas. No promover `expanded` por ser el último entrenamiento.

## Próxima acción: conservar pesos de Colab

El ZIP recibido contiene solamente reportes. Si la sesión de Colab sigue activa, descargar **seed7** y **expanded**, como mínimo, antes de cerrarla. Para conservar las comparaciones reproducibles, es preferible descargar los seis candidatos. En el notebook `notebooks/PhishARG_Next_Experiments_Colab.ipynb`, la última celda permite elegir `model_to_export` y exportar cada candidato. Los directorios son `artifacts/hybrid/experiments-v2/<id>`.

Ejemplo para descargar los dos candidatos prioritarios desde Colab:

```python
import shutil
from google.colab import files
for name in ['seed7', 'expanded']:
    path = shutil.make_archive('/content/flujo_model_' + name, 'zip',
                               'artifacts/hybrid/experiments-v2/' + name)
    files.download(path)
```

No sustituir los pesos del A100 original. Si la sesión terminó y se perdieron los pesos, los reportes no permiten reconstruirlos: habrá que repetir las corridas necesarias.

## Trabajo siguiente, en orden

1. **Completar comparativa científica sin reentrenar:** calcular media y dispersión de las tres semillas (42/7/21), comparar cada híbrido contra su baseline de la misma semilla, y registrar las ablaciones. El runner cambia la semilla neuronal y la del XGBoost juntas: no atribuir la variación exclusivamente al Transformer. Mantener la limitación del bootstrap anterior: el IC de la diferencia A100 original menos TF-IDF incluía cero.
2. **Comparar ampliado sobre los mismos ejemplos:** reconstruir el orden de test con `artifacts/hybrid/expansion-v2/splits.json` y su `training.csv`; alinear con los 1661 ejemplos originales usando identidad del contenido y metadata, no IDs de fila entre CSV diferentes. Si no hay correspondencia exacta, reportar cobertura y evaluar ambos pesos sobre un mismo corpus; no inventar emparejamientos por posición.
3. **Importar pesos descargados de forma conservadora:** inspeccionar ZIP, rechazar rutas que salgan del destino, extraer a carpetas nuevas. Validar manifiestos/hashes. Usar `load_hybrid_head` de `services/hybrid_classifier.py`: XGBoost 2.0.3 perdía el `base_score` vectorial de 3.4.1 y ya fue corregido. No degradar los tests ni modificar hashes sin una transformación documentada.
4. **Reproducir nuevos artefactos en Windows:** ejecutar `scripts/verify_hybrid_holdout.py` para cada candidato con su reporte/dataset correcto. Verificar primero scores, umbral y decisiones, luego endpoint. El test `test_hybrid_artifact.py` acepta `HYBRID_TEST_ARTIFACT` y `HYBRID_TEST_REPORT`; algunos datos esperados de diagnóstico podrían variar entre candidatos, por lo que un fallo debe investigarse, no silenciarse.
5. **Evaluar fuera del test usado para elegir modelos:** correr A100 original, seed7 y expanded sobre `artifacts/hybrid/expansion-v2/external_eval.jsonl`, `data/hybrid_challenge_v1.jsonl`, `data/hybrid_contrastive_v2.jsonl` y `data/classifier_eval_v1.jsonl`, guardando reportes con nombres nuevos. Estos corpus ya fueron observados: sirven para diagnóstico/comparación, no como evaluación final intacta de futuros ajustes.
6. **Revisar calidad de etiquetas:** `reports/hybrid_a100_audit_v2.json` enumera los 55 errores originales. Hay casos sospechosos que requieren cuerpo completo, enlaces, adjuntos y procedencia (`row-126`, `row-5653`, `row-5814`, entre otros). No cambiar una etiqueta solamente porque el modelo discrepa. Preparar datos contrastivos nuevos para entrenamiento, separados por familia/campaña de una nueva reserva final.
7. **Cerrar recomendación:** comparar recall, falsas alarmas, resultados por idioma/fuente y latencia. Elegir para piloto con evidencia. Mantener respaldo del modelo anterior. Solo después considerar integración del selector en el complemento; no se ha modificado `Add_in_PFI` en esta etapa.

## Evidencia adicional ya disponible

- A100 original en 475 ejemplos de grupos nuevos: 172 TP, 298 TN, 2 FP, 3 FN. Ling aporta solamente ham de una fuente no vista; no mide recall de esa fuente.
- En 16 pares contrastivos: 6 TP, 4 TN, 4 FP, 2 FN. Confunde algunos consejos defensivos y solicitudes maliciosas. Evitar excepciones textuales ajustadas a estos tests.
- Calibración Platt ajustada únicamente en validación: mejora Brier, pero log-loss externo empeora ligeramente. No fue activada en el backend.
- Corpus ampliado preparado: 28496 filas (24533 train/1787 validation/2176 test); 2959 filas de grupos nuevos reservadas fuera de ese corpus. La ampliación conserva pertenencia de grupos antiguos, pero añade filas de esos grupos a validation/test.
- No hay todavía un conjunto de correos reales recientes con fechas/campañas/etiquetas verificadas. Los ejemplos de amenazas modernas son sintéticos y están identificados como tales.

## Precauciones de continuidad

- Hay cambios anteriores ajenos a esta revisión en reportes `classifier_*` y una eliminación preexistente de `test_pkl_load.py`; no restaurarlos ni incluirlos accidentalmente en commits.
- Los modelos, corpus y paquete Colab están ignorados por Git bajo `artifacts/hybrid/`; guardar reportes/código no respalda los pesos.
- No afirmar que se instaló un modelo nuevo por haber recibido su reporte.
- Esta PC reportó CUDA no disponible. La comparación GPU ya fue ejecutada por el usuario; continuar con sus resultados, no repetir entrenamiento sin necesidad.
