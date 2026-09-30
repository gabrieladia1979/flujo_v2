# Comparativa verificada del NLP híbrido

Revisión del 15 de septiembre de 2026 a partir de `reports/hybrid_multilingual_v1.json` y `reports/hybrid_multilingual_a100.json`. Los archivos `splits.json` de ambos artefactos son iguales. El test contiene 1.661 correos: 911 positivos y 750 negativos.

El sistema entrena un Transformer multilingüe con etiquetas de correos y utiliza sus embeddings junto con características técnicas en XGBoost. Es un clasificador NLP híbrido con ajuste neuronal supervisado.

| Métrica | Híbrido CPU | Híbrido A100 | TF-IDF de la corrida A100 |
| --- | ---: | ---: | ---: |
| F1 phishing | 0,9041 | 0,9693 | 0,9614 |
| Precision phishing | 97,46% | 98,53% | 97,95% |
| Recall phishing | 84,30% | 95,39% | 94,40% |
| Falsos positivos | 20 | 13 | 18 |
| Falsos negativos | 143 | 42 | 51 |
| ROC-AUC | 0,9867 | 0,9948 | 0,9907 |

El híbrido A100 mejora el F1 observado en 0,00789 (0,79 puntos porcentuales) frente al TF-IDF de su corrida: evita 5 falsas alarmas y detecta 9 positivos adicionales. Frente al híbrido CPU reduce los FP un 35% y los FN un 70,6%. Estas dos comparaciones tienen referencias distintas.

| Configuración | CPU | A100 |
| --- | ---: | ---: |
| Épocas | 1 | 5 |
| Máximo de tokens | 128 | 384 |
| Capas ajustadas | 2 | 4 |
| Batch | 16 | 64 |
| Tiempo de fine-tuning registrado | 881,10 s | 129,51 s |
| Train loss media de la última época | 0,37319 | 0,10091 |
| Validation loss de la última época | 0,24094 | 0,11955 |

## Interpretación y límites

- Los valores de loss 0,175 y 0,079 del mensaje original no corresponden a las medias finales guardadas en estos reportes. Una pérdida de un minibatch, si existiera en un log, debe identificarse como tal.
- La corrida A100 tardó 6,80 veces menos en el tramo medido, pero cambió épocas, contexto, capas y batch. No es una medición controlada de aceleración del hardware ni permite aislar qué cambio causó la mejora.
- Los baselines TF-IDF CPU y A100 redondean ambos a F1 0,9614, pero sus predicciones difieren: CPU FP=17/FN=52; A100 FP=18/FN=51.
- El diagnóstico de 14 casos contiene 6 positivos y 8 negativos. Su resultado final incluye reglas de seguridad y no representa una tasa de acierto garantizada en correos nuevos.
- Un raw_model_score de 0,9997 es una puntuación del modelo sin calibración demostrada; no debe presentarse como certeza del 99,97%. El risk_score también puede incorporar reglas.
- Son resultados de un split y una semilla. La superioridad observada requiere intervalos de confianza y evaluación adicional para establecer su estabilidad. ROC-AUC 0,9948 no elimina los 42 falsos negativos presentes al umbral elegido.

## Próximos pasos

1. Revisar los 13 FP y 42 FN por fuente, longitud, idioma y tipo de engaño; usar los fallos del test para auditoría y reservar un nuevo test independiente antes de seguir ajustando con esa información.
2. Evaluar campañas y fuentes no vistas, con correos actuales revisados y procedencia documentada.
3. Ampliar los datos elegibles después de auditar etiquetas y duplicados, preservando grupos y particiones.
4. Medir variación entre semillas e intervalos de confianza de la diferencia frente al baseline.
5. Calibrar puntuaciones con validación y evaluar su calibración en test independiente antes de expresarlas como probabilidades.
6. Comparar configuraciones controladas de contexto, capas y épocas para identificar qué aporta cada cambio.

## Verificación local del artefacto importado

El 15 de septiembre se ejecutaron `test_hybrid_artifact.py` y `test_hybrid_pipeline.py` con el artefacto A100: **19 pruebas aprobadas y 1 fallida**. Pasaron la llamada HTTP al endpoint híbrido, las comprobaciones de pesos modificados y las pruebas del pipeline.

La prueba `test_saved_artifact_reproduces_heldout_raw_score` encontró inicialmente 0,5114362836 al servir el primer correo de test frente a 0,5665662289 guardado en el reporte Colab. Cambiar el límite entre 128, 256, 384 y 512 tokens no alteró la puntuación de este correo.

### Causa resuelta y evaluación completa

La causa fue XGBoost: Colab 3.4.1 guardó `base_score` como `[5.552983E-1]`; Windows 2.0.3 cargaba silenciosamente 0,5. El modelo y tokenizador originales, ejecutados con Transformers 5.16.1 pero XGBoost 2.0.3, también reproducían el fallo. Usar XGBoost 3.4.1 resolvió la prueba. El backend ahora aplica explícitamente el intercepto guardado mediante la API pública y comprueba que se conservó, sin modificar el artefacto ni cambiar el entorno productivo.

La evaluación usa la misma función `raw_score` del backend, correo por correo, sin reglas ni ajuste del umbral:

| Ejecución local | F1 | FP | FN | Decisiones diferentes de Colab |
| --- | ---: | ---: | ---: | ---: |
| Antes de corregir la carga | 0,966443 | 13 | 47 | 5 |
| Después de corregir la carga | 0,969325 | 13 | 42 | 0 |

Los 1.661 scores coinciden con Colab dentro de 1e-6; diferencia máxima 7,45e-9. Los reportes están en `reports/hybrid_a100_windows_transformers4.json` (antes) y `reports/hybrid_a100_windows_verified.json` (después). Incluyen IDs de errores y métricas por fuente sin copiar cuerpos de correos. La tabla de Colab ya está reproducida localmente.

Validación adicional: 20/20 pruebas del artefacto A100 y pipeline, 3/3 regresiones de intercepto con XGBoost 2.0.3 y 3.4.1, y 4/4 pruebas del candidato CPU. El endpoint HTTP está cubierto con el modelo real. El diagnóstico original vuelve a dar 6 TP/8 TN/0 FP/0 FN.

En `hybrid_challenge_v1.jsonl`, 12 casos adicionales, el resultado es 7 TP/4 TN/1 FP/0 FN. La falsa alarma `hybrid-challenge-06` es un aviso legítimo en inglés que aconseja denegar un inicio de sesión desconocido y contactar al soporte habitual. El score 0,98286 proviene del modelo, sin reglas. Es un caso para mejorar la distinción entre consejo defensivo y solicitud maliciosa con datos revisados y un nuevo test reservado; no se agregó una excepción textual ni se entrenó con el test.

Para reproducir en el entorno híbrido:

```powershell
.venv-hybrid/Scripts/python.exe scripts/verify_hybrid_holdout.py --model artifacts/hybrid/multilingual-candidate-a100 --report reports/hybrid_multilingual_a100.json --dataset artifacts/hybrid/corpus/multilingual-v1.csv --output reports/hybrid_a100_windows_verified.json
```

Se verificó mediante `git ls-remote` que el commit `e7edc9a` estaba en la rama remota `codex/hybrid-nlp`; `audit` apuntaba a `58d3954`, igual que la referencia local. Esta corrección se guarda en la rama local; no se realiza un push en esta revisión.

El desarrollo continúa en `codex/hybrid-nlp`, con endpoint experimental `/api/v1/analyze/hybrid`.
