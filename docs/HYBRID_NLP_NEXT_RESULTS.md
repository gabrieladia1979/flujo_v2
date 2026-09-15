# Siguientes pasos ejecutados — 2026-09-15

## Modelo recomendado

El candidato principal sigue siendo **multilingual-candidate-a100**, con la corrección de carga de XGBoost. Es el mejor resultado observado en el test original: F1=0,969325 frente a 0,961431 del TF-IDF. Recomendarlo para evaluación asistida/piloto no implica que su ventaja esté demostrada en todas las poblaciones. Mantener el modelo anterior disponible y no bloquear automáticamente correos basándose únicamente en este resultado.

## Resultados nuevos

| Evaluación | Muestras | TP | TN | FP | FN |
| --- | ---: | ---: | ---: | ---: | ---: |
| Test original reproducido en Windows | 1661 | 869 | 737 | 13 | 42 |
| Grupos nuevos de corpus locales | 475 | 172 | 298 | 2 | 3 |
| Pares contrastivos bilingües sintéticos | 16 | 6 | 4 | 4 | 2 |

La evaluación de 475 correos excluye los grupos normalizados de todo el corpus anterior. Incluye Enron=100, Nazario=75, Nigerian_Fraud=100, SpamAssasin=100 y Ling=100. Ling es una fuente no usada en entrenamiento, pero aquí solamente contiene correos ham: prueba falsas alarmas, no recall de phishing. Las etiquetas son heredadas y no se dispone de fechas verificadas ni IDs de campaña reales. No presentar esta prueba como un holdout temporal de ataques actuales. F1=0,985673 en esta mezcla concreta.

Los 16 casos nuevos prueban la diferencia entre consejos defensivos y solicitudes maliciosas sobre MFA, códigos de dispositivo, pagos y recuperación. Son textos escritos para diagnóstico; no se incorporaron al entrenamiento. Los temas se apoyan en [Microsoft, campaña de phishing con códigos de dispositivo de abril de 2026](https://www.microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026/) y [CISA, MFA resistente al phishing](https://www.cisa.gov/sites/default/files/2023-01/fact-sheet-implementing-phishing-resistant-mfa-508c.pdf). No son correos reales extraídos de esas publicaciones.

## Incertidumbre y calibración

Se ejecutaron 2000 remuestreos pareados por grupo normalizado, semilla 42. Intervalo percentil del 95% para la diferencia de F1 A100 menos TF-IDF: **[-0,001979; 0,017390]**. Incluye cero: la ventaja puntual es favorable pero no concluyente. Este cálculo mide incertidumbre de muestreo; no sustituye reentrenar con distintas semillas.

Se ajustó una calibración Platt exclusivamente con los 1617 registros de validación. En el test original, Brier bajó de 0,026194 a 0,025688 y log-loss de 0,096283 a 0,092452. En los 475 casos externos, Brier bajó de 0,012816 a 0,012171, pero log-loss subió de 0,044440 a 0,045354. **No se activó en el backend:** el efecto es mixto y no justifica presentar los scores como certezas. El umbral y las decisiones del A100 se mantienen.

## Auditoría de errores y datos

`reports/hybrid_a100_audit_v2.json` enumera los 55 errores originales por ID, fuente, idioma aproximado, longitud y señales observables. De ellos, 45 pertenecen a SpaPhish (11 FP/34 FN), 2 a Enron (FP), 6 a Nazario (FN) y 2 a Nigerian_Fraud (FN).

La lectura de extractos identificó familias para revisión: notificaciones de marcas y facturas, comunicaciones operativas, falsos premios, documentos compartidos y correos reenviados. Hay etiquetas que requieren revisar el correo completo y su procedencia: por ejemplo `row-126`/`row-5653` parecen avisos operativos en el extracto pero tienen etiqueta positiva; `row-5814` contiene una solicitud de validar datos pero tiene etiqueta negativa. Estas observaciones no prueban que las etiquetas estén equivocadas: podrían depender del enlace, remitente o adjunto. No se cambiaron etiquetas basándose en predicciones o extractos.

Se inventariaron **31874 filas** de las fuentes habilitadas y quedaron **31455 utilizables** después de limpieza. Se reservaron **2959 filas / 2908 grupos nuevos** fuera del corpus preparado para entrenamiento; la muestra evaluada toma como máximo 100 grupos por fuente. Ling también queda completamente fuera del entrenamiento. Como estas pruebas ya fueron consultadas, cualquier ajuste dirigido a sus fallos necesita una nueva reserva intacta para evaluación final.

El corpus ampliado tiene **28496 filas**, con 24533 de entrenamiento, 1787 de validación y 2176 de test. Se preserva la pertenencia de los 8573 grupos antiguos; los tamaños de validación/test crecen porque nuevas filas pertenecen a esos mismos grupos. Las comparaciones controladas usan el corpus original y sus splits originales, para evitar confundir ampliación de datos con cambios de arquitectura. El experimento ampliado se reporta por separado.

## Entrenamientos preparados, aún no ejecutados

Esta PC informó `torch.cuda.is_available() == False`. Se prepararon seis corridas CUDA: dos semillas adicionales (7 y 21), contexto 128, dos capas ajustadas, una época y corpus ampliado. Las tres ablaciones cambian un solo parámetro respecto al A100 original; el resto conserva cinco épocas, 384 tokens, cuatro capas y batch 64. Semillas distintas reutilizan exactamente la misma partición.

- Notebook: `notebooks/PhishARG_Next_Experiments_Colab.ipynb`.
- Paquete local de código y corpus: `artifacts/hybrid/colab-next-steps-v2.zip` (~23 MB).
- Configuración: `data/hybrid_experiments_v2.json`.
- Runner: `scripts/run_hybrid_experiments.py`; sin `--run` solo muestra comandos; requiere CUDA para ejecutar.

Abrir el notebook en Colab con GPU, ejecutar la celda de carga seleccionando el ZIP y luego las celdas de entrenamiento. Descargar reportes y candidatos antes de cerrar la sesión. No hay selección ni promoción automática del último modelo: hay que comparar calidad, falsas alarmas y errores antes de reemplazar al A100.

## Qué falta para cerrar los seis pasos

1. Revisar procedencia/enlaces/adjuntos de las etiquetas sospechosas antes de corregirlas; el listado y la inspección inicial están hechos.
2. Obtener correos reales recientes con fecha, campaña y etiqueta revisada. Ya hay una prueba por grupos nuevos y otra sintética informada por fuentes actuales; ninguna sustituye ese conjunto temporal.
3. Ejecutar y evaluar el entrenamiento ampliado; el corpus y las reservas están preparados.
4. Ejecutar las semillas adicionales; el intervalo por grupos ya está calculado.
5. Calibración experimental realizada, sin promoción por resultados mixtos.
6. Ejecutar las tres ablaciones en GPU y comparar sus reportes. El notebook y los comandos están preparados.

El siguiente modelo recomendado puede cambiar con esos resultados. Hoy la elección fundamentada es el A100 corregido, no cualquier modelo que se entrene después.
