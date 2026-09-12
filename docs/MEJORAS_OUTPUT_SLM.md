# Checklist para mejorar el output del SLM de PhishARG

Este documento organiza los pasos recomendados para convertir la respuesta libre del SLM en una explicación segura, consistente, medible e integrable con el servidor de PhishARG.

## Alcance implementado en este incremento

Este incremento incorpora el contrato estricto, el prompt versionado y la validación determinística en el servidor. El analizador todavía no invoca un proveedor SLM: entrega el fallback seguro del servidor dentro del campo `slm_explanation` existente. El clasificador conserva la autoridad sobre `is_phishing`, `risk_score` e `intent`.

No se implementaron reintentos, integración cloud, métricas, conjunto de evaluación, ajuste de inferencia ni fine-tuning. El servidor puede construir los mensajes y el contexto estructurado, pero el analizador no invoca `build_slm_prompt_messages` ni transmite datos a un proveedor.

## Estado inicial

- [x] Ejecutar localmente el modelo Llama 3 8B Instruct en formato GGUF.
- [x] Confirmar que el modelo puede sintetizar una explicación a partir de señales de phishing.
- [x] Detectar ambigüedades en las recomendaciones generadas.
- [ ] Registrar la versión exacta del modelo, la cuantización y la configuración de inferencia usada en cada prueba.

## 1. Definir el contrato de salida

- [x] Establecer que el clasificador principal es la autoridad sobre el veredicto y el nivel de riesgo.
- [x] Impedir que el SLM modifique campos como `is_phishing`, `risk_score` o `intent`.
- [x] Definir una salida JSON con campos obligatorios y tipos conocidos.
- [x] Limitar la longitud de la explicación y la cantidad de razones y recomendaciones.
- [x] Definir una lista cerrada de acciones seguras permitidas.
- [x] Prohibir recomendaciones ambiguas, como responder, redactar o reenviar el correo sospechoso.
- [x] Definir una respuesta segura de respaldo para salida ausente o JSON inválido.
- [ ] Conectar la respuesta de respaldo a los errores y timeouts del futuro proveedor.

### Contrato implementado

```json
{
  "summary": "El clasificador determinó que el correo es phishing.",
  "reasons": [
    {
      "evidence_id": "slot.urgencia",
      "text": "Se detectó presión temporal o urgencia en el mensaje."
    }
  ],
  "recommended_actions": [
    {
      "code": "do_not_click",
      "text": "No abras enlaces ni adjuntos del correo."
    }
  ]
}
```

El servidor fija `summary`, valida entre 1 y 5 razones y acepta entre 1 y 3 acciones. El texto de cada razón debe coincidir exactamente con la evidencia identificada y el texto de cada acción debe coincidir con su valor cerrado. Cualquier campo adicional, URL, carácter de control, evidencia desconocida o modificación de la tupla del clasificador activa el fallback seguro.

## 2. Fortalecer el prompt

- [x] Crear un mensaje de sistema específico para ciberseguridad y phishing.
- [x] Indicar explícitamente que el SLM explica un resultado ya calculado y no reclasifica el correo.
- [x] Incluir instrucciones para usar únicamente la evidencia recibida.
- [x] Prohibir que el modelo invente URLs, organismos, fallos técnicos o intenciones.
- [x] Especificar que debe responder exclusivamente con JSON válido.
- [x] Incluir dos o tres ejemplos de respuestas correctas.
- [x] Incluir al menos un ejemplo de correo legítimo.
- [x] Incluir casos con evidencia insuficiente para evitar afirmaciones exageradas.
- [x] Versionar el prompt, por ejemplo como `slm-explainer-v1`.
- [x] Mantener el prompt en el servidor y no duplicarlo en el cliente.

## 3. Preparar los datos enviados al SLM

- [ ] Enviar el resultado estructurado del clasificador en lugar de una descripción improvisada.
- [ ] Incluir el veredicto, puntaje de riesgo, intención y señales detectadas.
- [ ] Incluir solamente fragmentos del correo que sean necesarios para explicar el resultado.
- [ ] Eliminar o enmascarar credenciales, tokens, datos personales y contenido sensible.
- [x] Diferenciar señales observadas de inferencias realizadas por el clasificador.
- [x] Construir evidencia sólo desde slots detectados y ajustes de seguridad que respaldan el veredicto final.
- [x] Limitar a 20 las evidencias aceptadas por el constructor de contexto.
- [ ] Aplicar un límite total al contexto efectivamente enviado al proveedor.

## 4. Validar la respuesta en el servidor

- [x] Parsear la respuesta con un esquema formal, por ejemplo Pydantic.
- [x] Rechazar respuestas que no sean JSON válido.
- [x] Rechazar campos adicionales no contemplados por el contrato.
- [x] Verificar que todas las recomendaciones pertenezcan a la lista permitida.
- [x] Comprobar que las razones puedan vincularse con señales recibidas.
- [x] Limitar cantidad de elementos, longitud de cadenas y caracteres inesperados.
- [x] Rechazar la respuesta antes del parseo cuando supera 16.384 bytes.
- [ ] Aplicar como máximo un reintento con una instrucción de corrección de formato.
- [ ] Usar la respuesta segura de respaldo si el reintento falla.
- [x] Registrar el error sin almacenar contenido sensible del correo.
- [x] Enviar al cliente solamente una respuesta validada por el servidor.

## 5. Crear un conjunto de evaluación

- [ ] Seleccionar casos representativos de phishing y correos legítimos.
- [ ] Incluir urgencia, suplantación, fraude financiero, robo de credenciales y malware.
- [ ] Incluir correos difíciles, ambiguos y con pocas señales.
- [ ] Redactar manualmente la respuesta esperada para cada caso.
- [ ] Revisar las respuestas esperadas con criterios de seguridad consistentes.
- [ ] Separar los casos usados para diseñar el prompt de los usados para evaluarlo.
- [ ] Mantener un conjunto de regresión que no cambie entre versiones.

## 6. Medir la calidad

- [ ] Medir el porcentaje de respuestas con JSON válido.
- [ ] Medir el porcentaje de recomendaciones pertenecientes a la lista segura.
- [ ] Medir afirmaciones sin evidencia o señales inventadas.
- [ ] Medir contradicciones con el veredicto del clasificador.
- [ ] Medir claridad, concisión y utilidad para una persona no técnica.
- [ ] Medir latencia, consumo de memoria y costo por inferencia.
- [ ] Definir umbrales mínimos de aceptación antes de integrar el SLM.
- [ ] Comparar cada cambio de prompt o modelo contra la misma evaluación.

## 7. Ajustar la inferencia

- [ ] Probar una temperatura baja, inicialmente entre `0.1` y `0.3`.
- [ ] Limitar `max_tokens` al tamaño necesario para la respuesta estructurada.
- [ ] Mantener fijos los parámetros durante las comparaciones.
- [ ] Evaluar varias semillas si el runtime permite configurarlas.
- [ ] Evitar optimizar velocidad antes de estabilizar el formato y la seguridad.
- [ ] Registrar parámetros y resultados para que las pruebas sean reproducibles.

## 8. Integrar el SLM en la nube

- [ ] Crear un componente del servidor dedicado a generar explicaciones.
- [ ] Desacoplar la clasificación de la generación de lenguaje.
- [ ] Desplegar el clasificador y el SLM como servicios separados o como módulos claramente aislados.
- [ ] Definir timeouts, límites de concurrencia y manejo de errores.
- [ ] Evitar que un fallo del SLM impida devolver el veredicto del clasificador.
- [ ] Agregar métricas de latencia, errores de formato y uso del fallback.
- [ ] Versionar conjuntamente modelo, prompt, contrato y política de validación.
- [ ] Proteger los endpoints y los datos enviados entre servicios.
- [ ] Confirmar que el cliente nunca invoque directamente los modelos de producción.

## 9. Evaluar fine-tuning

- [ ] No iniciar fine-tuning hasta medir las limitaciones del prompt y la validación.
- [ ] Reunir ejemplos reales o sintéticos revisados manualmente.
- [ ] Eliminar datos personales y secretos del conjunto de entrenamiento.
- [ ] Mantener ejemplos balanceados entre phishing, legítimos y casos inciertos.
- [ ] Definir una guía de etiquetado para evitar respuestas contradictorias.
- [ ] Reservar un conjunto de evaluación que no participe del entrenamiento.
- [ ] Probar primero LoRA o QLoRA en lugar de entrenar el modelo completo.
- [ ] Comparar el modelo ajustado contra el modelo base con las mismas métricas.
- [ ] Adoptar el fine-tuning únicamente si demuestra una mejora consistente y medible.

## Criterios de finalización

- [ ] Al menos el 99 % de las respuestas cumple el esquema JSON.
- [x] Ninguna prueba recomienda responder, hacer clic o compartir información.
- [x] Ninguna respuesta cambia el veredicto establecido por el clasificador.
- [x] Las explicaciones se basan únicamente en señales verificadas.
- [x] Las salidas ausentes o inválidas activan una respuesta segura de respaldo.
- [ ] Los errores y timeouts del futuro proveedor activan la respuesta segura de respaldo en el flujo integrado.
- [ ] La latencia y el costo cumplen los límites definidos para producción.
- [ ] El flujo completo fue probado desde el cliente hasta la respuesta final.
- [ ] Las versiones del clasificador, SLM, prompt y contrato quedan registradas.
