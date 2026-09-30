# Auditoría de Calidad de Etiquetas y Errores (A100)

- **Total de casos de error analizados en test:** 55
- **Oportunidades contrastivas (Defensivo vs Ataque):** 1
- **Sospecha de etiqueta dudosa (Falsos Positivos / Textos cortos):** 3
- **Ataques no detectados (Falsos Negativos):** 0
- **Errores de generalización del modelo (para reentrenar):** 51

## Casos destacados para Curaduría

| ID | Tipo | Fuente | Score | Asunto | Motivo |
|---|---|---|---:|---|---|
| row-8139 | Falso Negativo | Nazario.csv | 0.8483 | Your Smarsh Email Encryption Activation Information | Contiene advertencia o lenguaje defensivo ('No comparta', 'Desestime', etc.) |
| row-220 | Falso Positivo | SpaPhish_Master_Final_v5.csv | 0.9497 | Organización del asado | Texto muy corto sin enlaces ni pedidos sensibles; el modelo sobre-reaccionó a palabras aisladas |
| row-562 | Falso Positivo | SpaPhish_Master_Final_v5.csv | 0.9134 | Regalo para Fede | Texto muy corto sin enlaces ni pedidos sensibles; el modelo sobre-reaccionó a palabras aisladas |
| row-7710 | Falso Positivo | Enron.csv | 0.9961 | usgt letter | Texto muy corto sin enlaces ni pedidos sensibles; el modelo sobre-reaccionó a palabras aisladas |
| row-115 | Falso Negativo | SpaPhish_Master_Final_v5.csv | 0.0685 | ¿cómo fue su experiencia de compra? | Caso desafiante legítimo para el entrenamiento regular |
| row-126 | Falso Negativo | SpaPhish_Master_Final_v5.csv | 0.0671 | 🛠️ Nuevo Horario Mantenimiento Sistemas: Domingos 2:00-6:00 AM | Caso desafiante legítimo para el entrenamiento regular |
| row-190 | Falso Negativo | SpaPhish_Master_Final_v5.csv | 0.0104 | Importante: Cambios en el código de vestimenta | Caso desafiante legítimo para el entrenamiento regular |
| row-342 | Falso Negativo | SpaPhish_Master_Final_v5.csv | 0.6254 | Actualización fiscal Banco Base📒 | Caso desafiante legítimo para el entrenamiento regular |
| row-558 | Falso Negativo | SpaPhish_Master_Final_v5.csv | 0.6918 | Te damos la bienvenida a YouTube Premium | Caso desafiante legítimo para el entrenamiento regular |