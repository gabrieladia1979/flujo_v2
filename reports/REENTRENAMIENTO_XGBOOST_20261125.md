# Reducción de falsas alarmas con XGBoost reentrenado — 25/11/2026

Se entrenó y comparó un nuevo clasificador XGBoost, separado del pickle histórico.
El candidato elegido es `artifacts/audit-candidate-v2/phisharg_xgboost.pkl`.
El original `model/phisharg_xgboost.pkl` permanece intacto. No se añadieron
excepciones por frases de Galicia ni se declararon legítimos mensajes por mostrar
un enlace de un banco.

## Resultados del flujo completo

Evaluación sobre los mismos 1.662 mensajes de desarrollo previamente inspeccionados,
con etiquetas heredadas: 749 negativos y 913 positivos. No constituye un nuevo
holdout independiente ni una medición de precisión en una bandeja actual.

| Configuración | Falsas alarmas | Ataques omitidos | TP | TN | F1 phishing |
|---|---:|---:|---:|---:|---:|
| Flujo histórico, después de las mejoras previas | 71 | 466 | 447 | 678 | 0.6247 |
| Candidato v1, umbral 0.685 | 31 | 34 | 879 | 718 | 0.9643 |
| Candidato v2 seleccionado, umbral 0.89 | **9** | **63** | **850** | **740** | **0.9594** |

El v2 prioriza menos falsas alarmas: frente al v1 elimina 22 FP, a cambio de
omitir 29 positivos adicionales de este conjunto. Frente al flujo histórico
reduce tanto FP como FN. Esta elección no elimina todos los ataques omitidos.
La tasa de falsas alarmas observada del v2 es 9/749 (1.20%), no una garantía de
mantenerse por debajo del presupuesto de validación en datos nuevos.

Referencias: [baseline](flow_refinements_fulltest_20261125.json),
[v1](candidate_v1_fulltest_20261125.json) y
[v2 final](candidate_v2_final_fulltest_20261125.json).

## Correos bancarios

Se probó el endpoint local con el modelo real y fallback offline para el explicador:

| Conjunto | Casos | Falsas alarmas antes | Falsas alarmas v2 | Ataques omitidos antes/v2 |
|---|---:|---:|---:|---:|
| Mensajes del dataset que mencionan bancos | 158 | 16 | **0** | 0 / 0 |
| Escenarios sintéticos de 13 bancos | 65 | 0 | 0 | 0 / 0 |
| Variantes sintéticas de dominios y remitentes | 30 | 0 | 0 | No contiene ataques |

En el subconjunto bancario se mantienen detectados los **106 positivos** y se
aceptan los **52 negativos** según sus etiquetas heredadas. Se resuelven las 16
variantes de la plantilla de transferencia acreditada que menciona Galicia.
No se inventaron remitentes ni cabeceras para los registros del CSV.
Son variantes de desarrollo ya conocidas, no 16 campañas independientes nuevas.

Ver [prueba bancaria final](bank_candidate_v2_final_20261125.md) y
[scores, entidades y respuestas por ID](bank_candidate_v2_final_20261125.json).

## Cómo se entrenó

Se usó `corpus_curado_11073.csv`, del respaldo local. El entrenador verifica que
un grupo declarado no cruce particiones y exige IDs únicos. Los grupos y las
particiones del corpus se conservaron; no se movieron los errores del test a train.

- **Train:** 7.790 mensajes; 4.326 positivos y 3.464 negativos.
- **Validación:** 1.619; 893 positivos y 726 negativos.
- **Comparación de test:** 1.662; 913 positivos y 749 negativos.
- Se excluyeron dos registros de train que superan el límite de texto visible:
  `row-7202` y `row-10883`. No se truncaron silenciosamente.

La extracción de características ahora se comparte entre entrenamiento e inferencia
mediante `extract_model_inputs`. TF-IDF de palabras y bigramas (6.000 columnas) y
los escaladores se ajustan exclusivamente con train. Se mantienen las 22 columnas
técnicas existentes y el formato total de 6.022 entradas. Se sustituyó el vocabulario
histórico por uno aprendido en el train multilingüe; no se descargó otro modelo.

El booster usa objetivo binario, semilla 42, profundidad 5, tasa 0.08, hasta 350
árboles y cuatro hilos. La validación controla early stopping, calibración sigmoide
y elección del umbral. Estas decisiones comparten validación; su calidad necesita
evaluación posterior independiente para afirmaciones de calibración.

El primer punto de operación admitía hasta 2% de falsas alarmas en validación y
eligió 0.685. Para priorizar el pedido de reducir alertas, el segundo impone 1% y
elige 0.89 usando únicamente los scores de validación: 7 FP/726 negativos y 89 FN/893
positivos. No cambia los árboles, vocabulario ni escaladores del primer candidato.
El cambio de presupuesto se decidió después de inspeccionar resultados de desarrollo;
por eso toda la comparación posterior se identifica como desarrollo.

El booster nativo aprende `1 = phishing`; el adaptador conserva el contrato público
de esta rama: clases `[0, 1]` con **columna 0 = phishing**. La semántica y versiones
se exportan en los metadatos del artefacto. Se verificó la coincidencia exacta de
los 1.662 scores crudos entre la matriz de entrenamiento/evaluación y el backend
servido, diferencia máxima **0.0**.

El [reporte de entrenamiento](audit_candidate_v1_training_20261125.json) registra
conteos, registros excluidos, scores por ID, versiones y hashes; la
[selección de operación](audit_candidate_v2_selection_20261125.json) registra los
scores de validación, el presupuesto y el hash del modelo padre.

## Integración y comprobaciones

El backend admite `PFI_CLASSIFIER_MODEL_PATH`, resolviendo rutas relativas desde
la raíz del proyecto. Cambiar de modelo limpia la caché para evitar reutilizar
veredictos del artefacto anterior. Los evaluadores aceptan `--model` y reportan
el hash del artefacto realmente cargado. Health añade `artifact_group`.

Se endureció una combinación contradictoria: un dominio bancario con indicadores
`pass` pero `has_headers: false` no recibe descuentos de autenticación basados en
esos `pass`. Se conservan las señales negativas. Esto cierra una regresión detectada
al probar el nuevo umbral, sin debilitar el test.

Pasaron **260 pruebas** con el candidato seleccionado: API, reglas, identidad de
los 13 bancos, cabeceras ausentes, secretos incluso con autenticación positiva,
caché, columna de probabilidad, serialización y rechazo de grupos compartidos
entre train y test. Se aisló el GGUF; no se midió su generación ni una sesión de Outlook.

## Activación local y rollback

La configuración local usa:

```dotenv
PFI_CLASSIFIER_MODEL_PATH=artifacts/audit-candidate-v2/phisharg_xgboost.pkl
```

El `.env` y los pesos bajo `artifacts/` están excluidos de Git. La activación es
local: un backend ya iniciado necesita recargarse o reiniciarse; ningún servicio
remoto se desplegó. Para volver al original, usar
`PFI_CLASSIFIER_MODEL_PATH=model/phisharg_xgboost.pkl` y reiniciar el backend.
El código y la configuración de ejemplo pueden versionarse; distribuir los pesos
y activar la variable en un servidor es un paso de despliegue separado.

## Reproducción

```powershell
# Entrenar un candidato nuevo, sin sobrescribir otro existente.
.\.venv\Scripts\python.exe scripts/train_audit_candidate.py --dataset 'C:\Users\Usuario\Documents\PhishARG - Datasets respaldo PFI\01_Hybrid_XAI\corpus_curado_11073.csv' --output artifacts/audit-reproduction/phisharg_xgboost.pkl --report reports/audit_reproduction.json --max-fpr 0.01

# Probar el artefacto ya generado.
.\.venv\Scripts\python.exe scripts/probe_bank_emails.py --dataset 'C:\Users\Usuario\Documents\PhishARG - Datasets respaldo PFI\01_Hybrid_XAI\corpus_curado_11073.csv' --include-flow-contrasts --model artifacts/audit-candidate-v2/phisharg_xgboost.pkl --output reports/bank_candidate_v2_final_20261125
```

Los próximos resultados de promoción deben medirse con correos completos, recientes,
revisados por humanos y separados por campaña/fecha. No se modificaron etiquetas
para coincidir con el modelo ni se presenta el 0/158 de desarrollo como precisión
productiva garantizada.
