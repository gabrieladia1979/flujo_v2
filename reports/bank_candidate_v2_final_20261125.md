# Prueba de correos bancarios por HTTP

Local FastAPI TestClient, real model and rules, offline SLM fallback; no messages sent

Resultados contra escenarios sintéticos y etiquetas heredadas; no son precisión productiva.

| Conjunto | Casos | Aciertos | Falsas alarmas | Ataques omitidos |
|---|---:|---:|---:|---:|
| historical_inherited_labels | 158 | 158 | 0 | 0 |
| synthetic | 65 | 65 | 0 | 0 |
| synthetic_flow | 30 | 30 | 0 | 0 |

## Dataset por banco mencionado

Un mensaje puede mencionar varios bancos; las filas de esta tabla se solapan.

| Banco | Casos | Aciertos | Falsas alarmas | Ataques omitidos |
|---|---:|---:|---:|---:|
| BBVA | 44 | 44 | 0 | 0 |
| Banco Ciudad | 17 | 17 | 0 | 0 |
| Banco Galicia | 56 | 56 | 0 | 0 |
| Banco Macro | 40 | 40 | 0 | 0 |
| Banco Nación | 18 | 18 | 0 | 0 |
| Banco Provincia | 44 | 44 | 0 | 0 |
| ICBC | 36 | 36 | 0 | 0 |
| Santander | 23 | 23 | 0 | 0 |

## Fallos observados

| ID | Conjunto | Bancos | Esperado | Obtenido | Score |
|---|---|---|---|---|---:|

## Límites

- Synthetic bank mail is authored diagnostics, not production accuracy.
- Corpus labels and authenticity are inherited, not individually verified.
- Historical CSV has no sender/header evidence; none was invented.
- Training overlap is unknown; these are not independent holdout estimates.
- SLM generation and a real Outlook session were not tested.
