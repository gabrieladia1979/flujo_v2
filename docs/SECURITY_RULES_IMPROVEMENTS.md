# Mejoras de reglas y enlaces — 21/10/2026

Implementadas localmente en las ramas `audit` y `codex/hybrid-xai-aws`. No se ejecutó despliegue. Se preservaron los pesos, el umbral y la extracción de features de cada modelo. Los 42 scores brutos de cada sistema coinciden exactamente con los guardados antes del cambio.

## Cambios

- Reglas bilingües equivalentes en ambas ramas: credenciales, MFA, permisos de aplicaciones, códigos de dispositivo, tarifas de entrega y QR descritos en texto.
- Más variantes de solicitudes de contraseñas y códigos, sin convertir los códigos de pedido en secretos. Se conserva la distinción entre pedidos, negaciones y ejemplos citados.
- Desvío de pagos a cuentas nuevas combinado con instrucciones de evitar confirmación.
- Tarjetas de regalo: combinación de compra, pedido de códigos/fotos y secreto o rechazo de verificación. Comprar una tarjeta por sí solo no dispara la regla.
- Enlaces HTML: compara el host de una URL explícitamente visible con el destino href. Detecta diferencias, respeta destinos iguales/subdominios y desenvuelve Microsoft Safe Links de hosts verificados. No abre enlaces ni consulta reputación.
- Las señales llegan al veredicto, al motivo y al explicador; las gift cards tienen intención de desvío de pago.

## Resultados sobre ejemplos ya conocidos

| Tanda | audit antes | audit después | Hybrid antes | Hybrid después |
|---|---:|---:|---:|---:|
| Primera, 14 etiquetados | 11 | 13 | 9 | 12 |
| Segunda, 24 etiquetados | 18 | 23 | 19 | 23 |
| Total, 38 etiquetados | 29 | 36 | 28 | 35 |

Los cuatro casos restantes se usan como diagnóstico sin etiqueta. Ambos sistemas ahora alertan sobre el enlace HTML que muestra Microsoft pero apunta a otro dominio. Estos casos guiaron las mejoras: los resultados NO estiman precisión en producción.

## Límites pendientes

- audit sigue omitiendo el premio falso y el primer ataque en inglés que solo solicita verificar la cuenta.
- Hybrid conserva falsas alarmas del modelo ante el aviso legítimo en inglés y los dos avisos legítimos sobre verificar cambios de cuenta. Las reglas no rebajan automáticamente un veredicto del modelo por contener frases tranquilizadoras.
- Los enlaces de marketing o redirecciones legítimas que muestran explícitamente una URL distinta pueden activar el control de destino. Solo se desenvuelven los hosts Safe Links reconocidos; no se afirma reputación. Botones y nombres de marcas sin una URL visible no activan esta regla.
- Texto sobre QR no equivale a leer imágenes QR o adjuntos.

## Pares para el futuro entrenamiento

`data/security_contrastive_development.jsonl` contiene 36 ejemplos, 18 pares malicioso/legítimo con `family_id`, fuente sintética, estado de revisión pendiente y uso exclusivo de desarrollo. Se utilizan en regresiones. No se agregaron a los pesos ni al corpus productivo.

No se reentrenó con estas 36 filas: son ejemplos generados durante el diagnóstico y no permiten demostrar que un modelo nuevo mejore. Para una próxima corrida: revisar etiquetas, ampliar con correos de procedencia conocida, mantener cada familia en una sola partición, conservar las reservas anteriores y preparar una reserva nueva de campañas no observadas. El cargador Hybrid actual agrupa por texto normalizado y no utiliza `family_id`; antes de incorporar estos pares hay que preservar explícitamente la familia para impedir que sus contrapartes crucen particiones. El modelo legacy requiere además comprobar procedencia y contrato de clases antes de sustituir su pickle.

## Reproducción

```powershell
.venv-hybrid/Scripts/python.exe -m pytest test_security_contrasts.py test_content_rules.py test_classifier_regressions.py test_security_rules.py -q
```

Hybrid agrega `test_hybrid_pipeline.py test_hybrid_xai_integration.py`. Las pruebas HTTP cubren credenciales, gift cards, enlaces y evidencia visible en explicaciones.

Última ejecución focalizada: audit **131 pruebas aprobadas**, Hybrid **152 pruebas aprobadas**. Además, las seis pruebas de integración del explicador de audit pasaron en la ejecución previa. Se conservan advertencias existentes de dependencias, incluida la de compatibilidad del pickle XGBoost. `git diff --check` sin errores en ambas ramas.
