# Auditoría de datos, runtime e identidad bancaria — 25/11/2026

Trabajo local en `flujo_v2`, rama `audit`, sobre el clasificador XGBoost histórico.
Se mantuvieron los pesos, la columna 0 y el umbral 0.8. No se reentrenó ni se
desplegó un servicio. Las variantes híbridas de otros directorios se inspeccionaron
como contexto, sin modificarlas.

## Resultado práctico

Se reprodujo una incompatibilidad de inferencia del pickle entre XGBoost 3.2.0
y 2.0.3. Se fijó 2.0.3 en las dependencias y se actualizó el `.venv` local.
El cargador ahora rechaza runtimes distintos: cargar el archivo sin excepciones
no alcanzaba para asegurar las mismas predicciones. Esta es una restricción
verificada para el pickle histórico; una migración futura necesita pruebas de
paridad, no una sustitución automática de versiones.

El backend dejó de convertir un modelo no disponible en un resultado legítimo
con riesgo cero: responde HTTP 503. Health informa estado degradado cuando falta
el clasificador, vectorizador, spaCy o matcher. Los mensajes con más de 50.000
caracteres visibles, contando el asunto, responden 413 sin truncamiento silencioso.
Las amenazas críticas que pueden resolverse sin el modelo siguen funcionando.

Se incorporó contexto de **13 bancos argentinos** con fuentes públicas:
BBVA, Galicia, Santander, Macro, Nación, Provincia, Ciudad, ICBC, Credicoop,
Supervielle, Patagonia, Comafi e Hipotecario. El registro está en
[`argentine_banks.json`](../data/argentine_banks.json).

La API devuelve `bank_context` y entrega sus observaciones al explicador/fallback:

- Banco correspondiente al dominio del remitente, separado de bancos mencionados.
- Dominio reconocido sin verificación suficiente, con fallo de DMARC, o con
  autenticación alineada informada por las cabeceras recibidas.
- Dominios que incluyen una marca bancaria fuera de las raíces registradas.

Para BBVA se contemplan `bbva.com` y `bbva.com.ar`, de acuerdo con su página de
[correos falsos](https://www.bbva.com.ar/economia-para-tu-dia-a-dia/ciberseguridad/phising.html).
Galicia conserva `bancogalicia.com.ar` y reconoce `galicia.ar`; el propio banco
publica su [correo de contacto](https://www.galicia.ar/personas/educacion-financiera/Todas-las-formas-de-contactarte-con-Galicia).
Las demás entradas incluyen su fuente en el registro. Las raíces web identifican
la entidad; el registro no afirma enumerar todos sus proveedores de correo.

La nueva regla `bank_brand_impersonation` requiere tres señales combinadas:
identidad bancaria declarada en remitente/asunto o dominio imitador del remitente,
un dominio que imita esa marca fuera de las raíces reconocidas y un pedido
afirmativo de validar o acceder a una cuenta. Usa el piso heurístico existente de
0.95 e intención `suplantacion_bancaria`. No representa una probabilidad calibrada.
Una mención de BBVA, un aviso de descuentos o un proveedor de marketing
desconocido por sí solos no activan esa regla. Se prueban negaciones y citas.
La autenticación positiva no desactiva solicitudes de secretos ni otras reglas.

## Dónde están los datos

Se buscaron CSV, archivos de correo y modelos en Documents, Downloads y Desktop,
excluyendo repositorios internos de Git, entornos virtuales y dependencias.
No aparecieron `.eml` ni `.mbox` en esa búsqueda. Eso no descarta archivos en otras
ubicaciones o correos accesibles solo desde Outlook.

| Ubicación | Contenido confirmado |
|---|---|
| `C:/Users/Usuario/Documents/GitHub/Clasificador_PFI/` | Seis versiones de CSV SpaPhish y scripts de entrenamiento/aumento |
| `Clasificador_PFI/DataSet_Kaggle_Original.zip` | Siete CSV, **164.972 filas** sumadas; no son 164.972 correos únicos ni todos phishing |
| `C:/Users/Usuario/Documents/PhishARG - Datasets respaldo PFI/01_Hybrid_XAI/` | `training.csv` de 11.114 filas; `corpus_curado_11073.csv`; splits y auditoría |
| `C:/Users/Usuario/Downloads/PFI MODELOS/` | Copia de entrenamiento, manifiesto, splits y candidato multilingüe con encoder |
| `flujo_v2/artifacts/hybrid/multilingual-candidate-v3-curated/` | Otro candidato, distinto del pickle que sirve esta rama |
| `flujo_v2_hybrid_cleanup/` | Código y evaluaciones históricas de la variante híbrida; rama `entrega` |

El complemento del directorio `Add_in_PFI` llama `/api/v1/analyze/hybrid`, mientras
que `flujo_v2` en `audit` expone `/api/v1/analyze`. Hay variantes estables y piloto;
esa diferencia local no prueba que la instalación publicada esté mal. La nueva
funcionalidad se verificó en la API local de `audit`, sin sesión real de Outlook.

## Calidad y solapamiento

El [inventario reproducible](local_datasets_audit_20261125.json) no exporta cuerpos
ni asuntos. Normaliza mayúsculas y espacios, sin deduplicación semántica.

| Dataset | Filas | Repeticiones exactas normalizadas de asunto+cuerpo |
|---|---:|---:|
| SpaPhish Extendido Argentina | 5.395 | 2.259 |
| Master Final | 8.401 | 2.261 |
| V2 | 13.401 | 7.150 |
| V3 | 14.401 | 7.518 |
| V4 | 14.781 | **7.688** |
| V5 | 7.095 | 1 |
| training.csv de respaldo | 11.114 | 11 |
| corpus curado | 11.073 | 0 |

En V4, los cuerpos sin considerar el asunto tienen 9.032 repeticiones. En el corpus
curado quedan 1.358 repeticiones de cuerpo, agrupadas dentro de una partición:
no se observaron mensajes/cuerpos exactos ni grupos declarados compartidos entre
train, validation y test. Eso reduce una clase de fuga, sin demostrar independencia
entre campañas reales. Los scripts de aumento generan/adaptan mensajes: la
presencia de un CSV no demuestra que cada fila sea un correo real revisado.

La partición curada tiene train=7.792, validation=1.619 y test=1.662. **1.036 de los
1.662 mensajes de test coinciden exactamente con V4** bajo normalización de asunto
y cuerpo. El pickle no documenta su conjunto original: este test no se puede
presentar como holdout independiente del modelo histórico.

El entrenamiento `phisharg_obra_maestra_v4.py` ajusta TF-IDF y escaladores antes de
`train_test_split`. Tampoco separa campañas. No debe reutilizarse tal cual para
probar una mejora: las transformaciones aprendidas deben ajustarse solo en train.

El ZIP incluye CEAS=39.154, Enron=29.767, Ling=2.859, Nazario=1.565,
Nigerian Fraud=3.332, phishing_email=82.486 y SpamAssasin=5.809 filas. Una etiqueta
de spam no debe convertirse automáticamente en phishing. La política de la
variante híbrida usa solo ham de Enron/SpamAssasin y deja otras mezclas pendientes
de revisión. Tampoco debe sumarse `phishing_email.csv` como fuente independiente
sin revisar sus solapamientos y transformaciones.

## Cobertura bancaria del corpus

La [inspección de menciones](bank_dataset_coverage_20261125.json) cuenta textos,
no identidades autenticadas. En el corpus curado:

| Banco mencionado | Etiqueta legítima | Etiqueta phishing |
|---|---:|---:|
| BBVA | 71 | 61 |
| Galicia | 76 | 140 |
| Santander | 56 | 63 |
| Macro | 63 | 54 |
| Nación | 53 | 54 |
| Provincia | 59 | 51 |
| Ciudad | 56 | 46 |
| ICBC | 69 | 42 |

No se encontraron menciones con los patrones usados de Credicoop, Supervielle,
Comafi o Banco Hipotecario; Banco Patagonia aparece en un positivo. El registro
de dominios permite reconocer esas entidades, pero no crea entrenamiento que
falta. Las cifras incluyen etiquetas heredadas y pueden contar plantillas.

## Mediciones

El archivo del modelo tiene SHA256
`fa7cf7c1fbe8d217a7199f824413305bfcb0e61cacb800451382925c0b5cf2a8`.
Las copias locales de `audit`, `flujo_v2_hybrid_cleanup` y `flujo_v2 Entrega`
coinciden. El cambio observado no se explica por archivos distintos.

| Diagnóstico de 14 casos | TP | TN | FP | FN |
|---|---:|---:|---:|---:|
| XGBoost 3.2.0, columna 0 | 4 | 3 | 5 | 2 |
| XGBoost 2.0.3, columna 0 | 6 | 8 | 0 | 0 |

Esto reproduce la diferencia de versiones, sin demostrar su mecanismo interno.
No se invirtieron columnas para forzar resultados. La comparación de 2.0.3 está
en [el reporte específico](xgboost_203_diagnostic_20261125.json).

Antes de agregar el contexto bancario, la misma muestra histórica de 246 casos
(semilla 42, hasta 40 por fuente/etiqueta) produjo:

| Runtime | TP | TN | FP | FN |
|---|---:|---:|---:|---:|
| 3.2.0 | 77 | 16 | 106 | 47 |
| 2.0.3 | 40 | 108 | 14 | 84 |

Restaurar el runtime histórico reduce fuertemente las falsas alarmas de esta
muestra, pero empeora el recall agregado. **No es una mejora global de F1** ni
soluciona la generalización al phishing inglés. Ver [antes](xgboost_historical_diagnostic_20261125.json)
y [compatible](xgboost_compatible_diagnostic_20261125.json).

La evaluación completa con 2.0.3, antes de las reglas bancarias, puntuó los 1.662
casos sin errores de procesamiento: TP=447, TN=677, FP=72, FN=466; F1=0.6243 y
recall=0.4896. Son resultados contra etiquetas heredadas, con solapamiento de
entrenamiento desconocido y sin remitente/cabeceras reales. La debilidad observada
impide afirmar que el modelo está listo para cualquier correo real.

El reporte [del pipeline final con contexto bancario](xgboost_banks_fulltest_20261125.json)
registra hashes del código y del registro además de los scores por ID. Los reportes
no copian asuntos, cuerpos ni direcciones personales.

La reevaluación final completó los 1.662 casos sin errores y conservó exactamente
los mismos scores y decisiones de esa partición. Las reglas bancarias nuevas no
se activaron en esos casos: no se les atribuye una mejora de precisión real sobre
ese corpus. Su comportamiento se verifica con contrastes sintéticos separados.

Tres [ejemplos HTTP sintéticos](bank_identity_examples_20261125.json) verificaron:
un resumen BBVA con cabeceras positivas como legítimo; un remitente que imita BBVA
y pide validar la cuenta como phishing bancario; y un remitente del dominio BBVA
con cabeceras positivas que pide contraseña/SMS como phishing por solicitud de
credenciales. Son ejemplos de comportamiento, no evidencia de precisión productiva.

## Validación y límites

Pasaron **225 pruebas** de clasificación, identidad bancaria, API, regresiones,
reglas, fallos de disponibilidad y contrato del explicador. El GGUF se aisló con
fallback durante la suite. Persisten advertencias de serialización XGBoost y de
versión de scikit-learn (pickle 1.9.0, runtime 1.9.1); no se ocultaron.

Las pruebas bancarias son sintéticas: cubren raíces/subdominios de las 13 entidades,
direcciones BBVA globales y locales, sufijos engañosos, cabeceras ausentes o DMARC
fallido, negaciones, citas, proveedores desconocidos y solicitudes de secretos
incluso desde un dominio autenticado. No se midió lectura de logos/imágenes,
reputación de URLs, adjuntos cifrados ni detección general de homógrafos.

## Siguiente entrenamiento sustentable

1. Conservar este modelo como referencia y comparar un candidato separado.
2. Revisar manualmente correos completos de bancos: remitente, fecha, cabeceras,
   enlaces y adjuntos; conservar ejemplos legítimos difíciles y phishing por banco.
3. Mantener procedencia y separar campañas/plantillas antes de cualquier ajuste de
   TF-IDF, selección de parámetros, calibración o entrenamiento.
4. Tratar los conjuntos ya inspeccionados como desarrollo; reservar un test nuevo
   por campaña/fecha para medir el candidato, sin corregir etiquetas por lo que
   predice el propio modelo.
5. Comparar XGBoost y el pipeline completo por banco, idioma, FP y FN; elegir el
   umbral con validación y revisar el deterioro de recall antes de promoverlo.
6. Exportar modelo, esquema de features, semántica de clases, versiones y hashes
   juntos; probar paridad de scores y decisiones en el entorno de despliegue.

No hace falta reemplazar XGBoost por un LLM para reconocer bancos. Hace falta
combinar identidad explícita, evidencia del correo y entrenamiento/evaluación
con datos revisados. Lo implementado aquí mejora el flujo y su trazabilidad;
el reentrenamiento y la validación con correos recientes siguen pendientes.

## Reproducción de la evaluación final

Desde la raíz de `flujo_v2`:

```powershell
.\.venv\Scripts\python.exe scripts/evaluate_local_csv.py --dataset 'C:\Users\Usuario\Documents\PhishARG - Datasets respaldo PFI\01_Hybrid_XAI\corpus_curado_11073.csv' --max-per-source-label 0 --output reports/xgboost_banks_fulltest_20261125.json
```

El inventario se reproduce con `scripts/audit_local_datasets.py`, pasando los CSV
y el ZIP como argumentos y `--output` para el JSON. No extrae ni modifica fuentes.
