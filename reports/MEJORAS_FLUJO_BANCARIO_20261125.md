# Mejora del flujo bancario — 25/11/2026

Cambios locales en la rama `audit`, sin reentrenamiento ni despliegue. Se conserva
el mismo pickle, la columna 0, el umbral 0.8 y el contrato público de respuesta.

## Cambios

1. La evaluación de confianza usa el dominio ya interpretado por `bank_identity`,
   que admite remitentes como `Banco <avisos@dominio>`. Se elimina la separación
   manual por `@`, que dejaba el carácter `>` dentro del dominio y perdía la identidad.
2. Los descuentos por dominio bancario usan el registro de las 13 entidades,
   incluidos los dominios alternativos. Requieren cabeceras presentes y autenticación
   alineada; la regla positiva existente exige SPF, DKIM y DMARC correctos y ausencia
   de discrepancias de remitente/Reply-To/Return-Path. Un nombre bancario o un enlace
   oficial dentro del cuerpo no obtienen ese descuento por sí solos.
3. La regla de secretos distingue una instrucción de ingresar un código documental
   alfanumérico explícitamente proporcionado en el propio texto de un pedido de
   entregar secretos personales. La distinción es local a esa instrucción: no exime
   una marca, un servicio ni todo el correo. Los pedidos de enviar códigos, ingresar
   un código recibido por SMS o agregar una contraseña siguen evaluándose. Las
   reglas de enlaces engañosos y demás amenazas continúan activas.
4. Se agregan las formas `envíeme`, `envíenme` y `mándeme` a la detección de pedidos
   de secretos, conservando las exclusiones locales de negaciones.

## Comparación HTTP con el modelo real

Se ejecutó `/api/v1/analyze` con FastAPI TestClient, sin simular el clasificador.
Solo la generación del GGUF se reemplazó por el fallback offline. No se enviaron
correos ni se visitaron enlaces. Se conservaron las mismas 253 entradas antes y
después; los reportes registran hashes de código y modelo.

| Conjunto | Casos | Falsas alarmas antes | Falsas alarmas después | Ataques omitidos antes/después |
|---|---:|---:|---:|---:|
| Dataset: mensajes que mencionan bancos | 158 | 17 | 16 | 0 / 0 |
| Escenarios sintéticos de las 13 entidades | 65 | 0 | 0 | 0 / 0 |
| Variantes sintéticas de dominio y formato del remitente | 30 | 8 | 0 | No contiene ataques |

En el dataset se mantienen los 106 positivos detectados. Se corrige `row-2730`,
un mensaje etiquetado legítimo que menciona BBVA/DocuSign: la regla de secretos
había elevado el score de aproximadamente 0.0162 a 0.95 por una instrucción de uso
de un código documental suministrado. Ahora conserva el score del modelo.

Los ocho cambios favorables de formato/dominio corresponden a Galicia (tres),
Provincia, Credicoop, Supervielle, Patagonia e Hipotecario. Los 30 casos son
variantes de desarrollo de avisos autenticados; no son 30 correos reales independientes.

Ver reportes [antes](bank_flow_before_20261125.json) y
[después](bank_flow_after_20261125.json), y la [tabla final por banco](bank_flow_after_20261125.md).

También se repitió la [evaluación completa de 1.662 mensajes](flow_refinements_fulltest_20261125.json).
Los scores crudos del modelo coinciden exactamente con la ejecución anterior.
Solo cambia una decisión: `row-2730` pasa de falsa alarma a legítimo. Las falsas
alarmas globales bajan de 72 a 71; se mantienen TP=447 y FN=466. El F1 pasa de
0.62430 a 0.62474. El conjunto completo, que incluye inglés, sigue mostrando
limitaciones importantes: estos cambios no son una mejora grande de detección general.

## Pruebas

Pasaron **258 pruebas**: regresiones del clasificador, bancos, API, reglas de
seguridad y contenido, explicador e indisponibilidad. Las pruebas nuevas incluyen
contrastes de códigos documentales y personales, secretos después de una frase
inocua, enlaces engañosos, dominios alternativos, remitentes con nombre visible,
cabeceras ausentes, DMARC fallido y Reply-To diferente. También se verifica que
un banco autenticado que pida secretos continúe marcado como phishing.

## Qué sigue pendiente

Persisten las 16 variantes de transferencia acreditada de Galicia sin remitente
ni cabeceras verificables. La alerta proviene del modelo, no de una regla. Son
variantes de una plantilla con importes distintos. No se añadió una excepción
por frase, por banco o por URL para declararlas legítimas: ese mecanismo también
podría aceptar una imitación. Resolverlas requiere evidencia completa del correo
o reentrenar y validar un candidato separado.

Las etiquetas del corpus son heredadas, la independencia respecto al entrenamiento
del pickle es desconocida y los conjuntos ya fueron inspeccionados. Las mediciones
son regresiones de desarrollo, no estimaciones de precisión en una bandeja real.
La mejora acota falsas alarmas del flujo; no resuelve las limitaciones generales
del modelo, especialmente con phishing en inglés.

## Reproducción

```powershell
.\.venv\Scripts\python.exe scripts/probe_bank_emails.py --dataset 'C:\Users\Usuario\Documents\PhishARG - Datasets respaldo PFI\01_Hybrid_XAI\corpus_curado_11073.csv' --include-flow-contrasts --output reports/bank_flow_after_20261125
```
