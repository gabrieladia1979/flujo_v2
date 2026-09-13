# Comparación local del clasificador

Corpus de diagnóstico incompleto; no mide calidad productiva ni es un holdout verificado.

Modelo SHA256: `fa7cf7c1fbe8d217a7199f824413305bfcb0e61cacb800451382925c0b5cf2a8`. Umbral: `0.8`.

| Índice | Aciertos | Falsos positivos | Falsos negativos |
|---|---:|---:|---:|
| 0 | 56/56 | 0 | 0 |
| 1 | 21/56 | 29 | 6 |

| Caso | Categoría | Esperado | Score 0 | Resultado 0 | Score 1 | Resultado 1 |
|---|---|---|---:|---|---:|---|
| phisharg-eval-0001 | internal_communication | legitimate | 0.0128 | legitimate | 0.9872 | phishing |
| phisharg-eval-0002 | tax_impersonation | phishing | 0.9868 | phishing | 0.0132 | legitimate |
| phisharg-eval-0003 | bank_impersonation | phishing | 1.0000 | phishing | 0.3672 | legitimate |
| phisharg-eval-0004 | internal_communication | legitimate | 0.0000 | legitimate | 0.7373 | legitimate |
| phisharg-eval-0005 | technical_email | legitimate | 0.0128 | legitimate | 0.9872 | phishing |
| phisharg-eval-0006 | internal_communication | legitimate | 0.0128 | legitimate | 0.9872 | phishing |
| challenge-001 | newsletter | legitimate | 0.0643 | legitimate | 1.0000 | phishing |
| challenge-002 | legitimate_invoice | legitimate | 0.0148 | legitimate | 0.9852 | phishing |
| challenge-003 | bank_notification | legitimate | 0.0127 | legitimate | 0.9873 | phishing |
| challenge-004 | password_recovery | legitimate | 0.3652 | legitimate | 0.6348 | legitimate |
| challenge-005 | technical_email | legitimate | 0.0199 | legitimate | 0.9801 | phishing |
| challenge-006 | forwarded_email | legitimate | 0.2128 | legitimate | 1.0000 | phishing |
| challenge-007 | other_legitimate | legitimate | 0.0156 | legitimate | 0.9844 | phishing |
| challenge-008 | marketplace_notification | legitimate | 0.0363 | legitimate | 0.9637 | phishing |
| challenge-009 | credential_theft | phishing | 0.9844 | phishing | 0.0156 | legitimate |
| challenge-010 | tax_impersonation | phishing | 0.9869 | phishing | 0.0131 | legitimate |
| challenge-011 | bank_impersonation | phishing | 0.8368 | phishing | 0.0000 | legitimate |
| challenge-012 | fake_prize | phishing | 0.9709 | phishing | 0.9500 | phishing |
| challenge-013 | fake_delivery | phishing | 0.9866 | phishing | 0.0134 | legitimate |
| challenge-014 | fake_invoice | phishing | 0.9500 | phishing | 0.9846 | phishing |
| challenge-015 | credential_theft | phishing | 0.9500 | phishing | 0.9871 | phishing |
| challenge-016 | malware | phishing | 1.0000 | phishing | 1.0000 | phishing |
| challenge-017 | other_phishing | phishing | 1.0000 | phishing | 1.0000 | phishing |
| challenge-018 | technical_email | legitimate | 0.3521 | legitimate | 0.6479 | legitimate |
| contrast-credential_theft-01 | credential_theft | phishing | 0.9500 | phishing | 0.9864 | phishing |
| contrast-credential_theft-02 | credential_theft | phishing | 0.9500 | phishing | 0.9869 | phishing |
| contrast-credential_theft-03 | credential_theft | phishing | 0.9500 | phishing | 0.9869 | phishing |
| contrast-credential_theft-04 | credential_theft | phishing | 0.9500 | phishing | 0.9873 | phishing |
| contrast-credential_theft-05 | credential_theft | phishing | 0.9500 | phishing | 0.9500 | phishing |
| contrast-credential_theft-06 | credential_theft | phishing | 0.9500 | phishing | 0.9870 | phishing |
| contrast-credential_theft-07 | credential_theft | phishing | 0.9500 | phishing | 0.9867 | phishing |
| contrast-credential_theft-08 | credential_theft | phishing | 0.9500 | phishing | 0.9872 | phishing |
| contrast-credential_theft-09 | credential_theft | phishing | 0.9500 | phishing | 0.9500 | phishing |
| contrast-fake_invoice-01 | fake_invoice | phishing | 0.9500 | phishing | 0.9846 | phishing |
| contrast-fake_invoice-02 | fake_invoice | phishing | 0.9500 | phishing | 0.9870 | phishing |
| contrast-fake_invoice-03 | fake_invoice | phishing | 0.9500 | phishing | 0.9870 | phishing |
| contrast-fake_invoice-04 | fake_invoice | phishing | 0.9500 | phishing | 0.9869 | phishing |
| contrast-other_legitimate-01 | other_legitimate | legitimate | 0.0128 | legitimate | 0.9872 | phishing |
| contrast-other_legitimate-02 | other_legitimate | legitimate | 0.0129 | legitimate | 0.9871 | phishing |
| contrast-other_legitimate-03 | other_legitimate | legitimate | 0.0128 | legitimate | 0.9872 | phishing |
| contrast-other_legitimate-04 | other_legitimate | legitimate | 0.0129 | legitimate | 0.9871 | phishing |
| contrast-other_legitimate-05 | other_legitimate | legitimate | 0.0250 | legitimate | 0.9750 | phishing |
| contrast-other_legitimate-06 | other_legitimate | legitimate | 0.0335 | legitimate | 0.9665 | phishing |
| contrast-other_legitimate-07 | other_legitimate | legitimate | 0.0130 | legitimate | 0.9870 | phishing |
| contrast-other_legitimate-08 | other_legitimate | legitimate | 0.0128 | legitimate | 0.9872 | phishing |
| contrast-other_legitimate-09 | other_legitimate | legitimate | 0.0136 | legitimate | 0.9864 | phishing |
| contrast-other_legitimate-10 | other_legitimate | legitimate | 0.0188 | legitimate | 0.9812 | phishing |
| contrast-other_legitimate-11 | other_legitimate | legitimate | 0.0130 | legitimate | 0.9870 | phishing |
| contrast-other_legitimate-12 | other_legitimate | legitimate | 0.0129 | legitimate | 0.9871 | phishing |
| contrast-other_legitimate-13 | other_legitimate | legitimate | 0.0129 | legitimate | 0.9871 | phishing |
| contrast-other_legitimate-14 | other_legitimate | legitimate | 0.0135 | legitimate | 0.9865 | phishing |
| contrast-other_legitimate-15 | other_legitimate | legitimate | 0.0129 | legitimate | 0.9871 | phishing |
| contrast-other_legitimate-16 | other_legitimate | legitimate | 0.0128 | legitimate | 0.9872 | phishing |
| contrast-other_legitimate-17 | other_legitimate | legitimate | 0.0131 | legitimate | 0.9869 | phishing |
| contrast-other_legitimate-18 | other_legitimate | legitimate | 0.0135 | legitimate | 0.9865 | phishing |
| contrast-other_legitimate-19 | other_legitimate | legitimate | 0.0128 | legitimate | 0.9872 | phishing |
