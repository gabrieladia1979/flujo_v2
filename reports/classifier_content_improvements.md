# Segunda etapa: contenido, backend y Outlook

Se conserva el modelo, la columna **0** y su umbral **0.8**. Se agregan reglas de contenido acotadas que complementan el clasificador, sin reentrenarlo.

## Detección

- `credential_disclosure_request`: petición directa de enviar o compartir contraseñas, claves fiscales, PIN, token o códigos de autenticación. Funciona sin enlaces y con variantes de acentuación/HTML.
- `payment_redirection_no_verification`: pedido de pagar a una cuenta nueva, otro CBU o alias, combinado con instrucciones cercanas de no verificarlo con el proveedor, banco o titular. Una cuenta nueva por sí sola no activa esta regla.

Se excluyen negaciones locales, citas y ejemplos, pedidos de instrucciones de recuperación y cambios de cuenta que requieren verificación previa. Las excepciones no convierten todo un mensaje en confiable: una petición maliciosa en otra oración sigue analizándose.

Si se activa una regla, el score final tiene un piso de **0.95**, aplicado después de los descuentos por cabeceras. Es una política heurística, no una probabilidad calibrada. El score original se conserva para diagnóstico. Autenticar un remitente no garantiza que el contenido sea legítimo.

## Resultados

El corpus v3 contiene los 24 casos anteriores y 32 variantes de desarrollo/contraste. No es un holdout independiente; varias variantes corresponden al mismo escenario.

| Configuración con índice 0 | Aciertos | Falsos positivos | Falsos negativos |
|---|---:|---:|---:|
| Misma implementación con reglas de contenido deshabilitadas | 41/56 | 0 | 15 |
| Reglas de contenido habilitadas | 56/56 | 0 | 0 |

Los dos fallos de la primera etapa ahora se clasifican como phishing:

| Caso original | Score anterior | Score final | Motivo |
|---|---:|---:|---|
| challenge-014 | 0.0154 | 0.9500 | Cuenta nueva y bloqueo de verificación |
| challenge-015 | 0.0129 | 0.9500 | Solicitud de contraseña/código por respuesta |

Ver [evaluación por caso](classifier_content_v3.md), [JSON con reglas, scores y procedencia](classifier_content_v3.json) y [comparación sin reglas](classifier_content_v3_without_rules.json). Las métricas muestran regresiones controladas de desarrollo, no precisión productiva.

## Integración

El endpoint real `/api/v1/analyze` devuelve los campos anteriores más:

```json
{
  "raw_model_score": 0.0129,
  "decision_source": "content_security_rule",
  "content_signals": [
    {
      "rule": "credential_disclosure_request",
      "description": "El mensaje pide enviar o compartir contraseñas, claves o códigos de autenticación."
    }
  ]
}
```

El ejemplo es ilustrativo; los campos son aditivos. `reason` incorpora el motivo, `intent` distingue solicitud de credenciales de desvío de pago y la evidencia se entrega al SLM y a su fallback.

En el repositorio hermano `Add_in_PFI`, el panel muestra directamente estas señales aunque falte JSON del SLM. Se corrigió una inconsistencia anterior: etiquetas, colores e iconos ahora siguen `is_phishing`, en lugar de volver a decidir usando un umbral local de 50%. El score sigue mostrándose como indicador de riesgo.

El complemento toma `API_BASE_URL` de la configuración de compilación, con destino local por defecto. Para reflejarlo en una instalación publicada se necesita actualizar el backend, compilar el complemento con su URL HTTPS y publicar los cambios. Esta tarea modifica y verifica ambos repositorios localmente; no se desplegó ningún servicio remoto ni se verificó una sesión real de Outlook.

## Validación

- 116 pruebas Python pasaron, incluyendo llamadas HTTP autenticadas al endpoint con el clasificador real, cabeceras positivas, respuesta pública y evidencia entregada al explicador.
- 3 pruebas Node pasaron: veredicto legítimo con score superior a 50%, propagación de señales de phishing y conexión configurable sin depender del JSON del SLM.
- Compilación de producción del complemento completada.
- `git diff --check` sin errores de whitespace en ambos repositorios.

Se aisló el SLM con su fallback durante la suite Python. No se midió la generación del GGUF. Persisten advertencias de compatibilidad del pickle XGBoost y deprecaciones del runtime, sin fallos de pruebas.

## Límites y siguiente trabajo

Estas reglas cubren construcciones explícitas en español. Pueden omitir paráfrasis, órdenes separadas por varias oraciones, inglés, ataques escritos enteramente entre comillas, texto contenido solo en imágenes y cambios bancarios fraudulentos que no desalientan la verificación. También pueden señalar solicitudes reales pero inseguras de compartir secretos. No demuestran por sí solas la identidad o intención del remitente.

El siguiente paso para ampliar cobertura sin acumular excepciones es reunir correos etiquetados con revisión humana, separar campañas y remitentes entre desarrollo y validación, y comparar el clasificador híbrido con un modelo reentrenado. No debe ajustarse el umbral usando estos 56 ejemplos como si fueran validación independiente.

## Reproducción

```powershell
python scripts/compare_classifier.py --dataset data/classifier_diagnostic_v3.jsonl --output reports/classifier_content_v3
python scripts/compare_classifier.py --dataset data/classifier_diagnostic_v3.jsonl --output reports/classifier_content_v3_without_rules --disable-content-rules
```

La desactivación es solo una opción del proceso de evaluación; no modifica la configuración del servidor.
