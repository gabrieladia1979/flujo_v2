# Prueba de correos bancarios por HTTP

Local FastAPI TestClient, real model and rules, offline SLM fallback; no messages sent

Resultados contra escenarios sintéticos y etiquetas heredadas; no son precisión productiva.

| Conjunto | Casos | Aciertos | Falsas alarmas | Ataques omitidos |
|---|---:|---:|---:|---:|
| historical_inherited_labels | 158 | 141 | 17 | 0 |
| synthetic | 65 | 65 | 0 | 0 |

## Fallos observados

| ID | Conjunto | Bancos | Esperado | Obtenido | Score |
|---|---|---|---|---|---:|
| row-253 | historical_inherited_labels | Banco Galicia | legítimo | phishing | 0.9831 |
| row-484 | historical_inherited_labels | Banco Galicia | legítimo | phishing | 0.9831 |
| row-1560 | historical_inherited_labels | Banco Galicia | legítimo | phishing | 0.9831 |
| row-2729 | historical_inherited_labels | Banco Galicia | legítimo | phishing | 0.9831 |
| row-2730 | historical_inherited_labels | BBVA | legítimo | phishing | 0.9500 |
| row-3214 | historical_inherited_labels | Banco Galicia | legítimo | phishing | 0.9831 |
| row-3778 | historical_inherited_labels | Banco Galicia | legítimo | phishing | 0.9831 |
| row-4342 | historical_inherited_labels | Banco Galicia | legítimo | phishing | 0.9831 |
| row-4641 | historical_inherited_labels | Banco Galicia | legítimo | phishing | 0.9831 |
| row-4700 | historical_inherited_labels | Banco Galicia | legítimo | phishing | 0.9831 |
| row-5142 | historical_inherited_labels | Banco Galicia | legítimo | phishing | 0.9831 |
| row-5610 | historical_inherited_labels | Banco Galicia | legítimo | phishing | 0.9831 |
| row-6122 | historical_inherited_labels | Banco Galicia | legítimo | phishing | 0.9831 |
| row-6272 | historical_inherited_labels | Banco Galicia | legítimo | phishing | 0.9831 |
| row-6416 | historical_inherited_labels | Banco Galicia | legítimo | phishing | 0.9831 |
| row-6497 | historical_inherited_labels | Banco Galicia | legítimo | phishing | 0.9831 |
| row-6644 | historical_inherited_labels | Banco Galicia | legítimo | phishing | 0.9831 |

## Límites

- Synthetic bank mail is authored diagnostics, not production accuracy.
- Corpus labels and authenticity are inherited, not individually verified.
- Historical CSV has no sender/header evidence; none was invented.
- Training overlap is unknown; these are not independent holdout estimates.
- SLM generation and a real Outlook session were not tested.

## Revisión de los errores observados

- Los 17 desacuerdos con las etiquetas del dataset se concentran en dos familias: 16 variantes de un aviso de transferencia acreditada de Galicia y un mensaje de firma documental que menciona BBVA/DocuSign.
- En las 16 variantes Galicia, la alerta proviene del modelo (score crudo aproximado 0.9831), sin regla de contenido activada. Cambia principalmente el importe; no son 16 escenarios independientes.
- En el mensaje BBVA/DocuSign, el modelo original puntúa aproximadamente 0.0162 y la regla de solicitud de credenciales eleva el resultado a 0.95. El texto incluye instrucciones de acceso a un documento mediante código: requiere distinguir este flujo de la entrega de secretos bancarios.
- Estos CSV no incluyen remitente ni cabeceras verificables. No se completaron esos campos a partir del nombre del banco. Las etiquetas se conservaron y no se modificó el clasificador para hacer pasar estos ejemplos.

## Dataset por banco mencionado

Las filas se solapan cuando un mensaje menciona más de un banco.

| Banco | Casos | Aciertos | Falsas alarmas | Ataques omitidos |
|---|---:|---:|---:|---:|
| BBVA | 44 | 43 | 1 | 0 |
| Banco Ciudad | 17 | 17 | 0 | 0 |
| Banco Galicia | 56 | 40 | 16 | 0 |
| Banco Macro | 40 | 40 | 0 | 0 |
| Banco Nación | 18 | 18 | 0 | 0 |
| Banco Provincia | 44 | 44 | 0 | 0 |
| ICBC | 36 | 36 | 0 | 0 |
| Santander | 23 | 23 | 0 | 0 |
