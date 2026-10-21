"""Deployment smoke gate for shared content rules and final attack verdicts.

These fixed synthetic regressions do not estimate production accuracy.
Benign cases check rule false alarms; model false positives are evaluated
separately and are not silently overridden by a safe-looking phrase.
"""
from schemas import EmailPayloadSchema
from services.content_rules import detect_content_signals


CASES = [('credential_en-phishing',
  'Send your current password and one-time authentication code to our technician.',
  'credential_disclosure_request'),
 ('credential_en-legitimate',
  'Never send your current password or one-time authentication code to anyone.',
  None),
 ('credential_mixed-phishing',
  'Hola equipo, reply with your password and MFA code para conservar el acceso.',
  'credential_disclosure_request'),
 ('credential_mixed-legitimate',
  'Hola equipo, never share your password or MFA code. No action is required.',
  None),
 ('credential_es-phishing',
  'Envianos tu clave de acceso y el código de un solo uso que llegó a tu teléfono.',
  'credential_disclosure_request'),
 ('credential_es-legitimate',
  'No envíes tu clave de acceso ni el código de un solo uso que llegó a tu teléfono.',
  None),
 ('credential_support-phishing',
  'Para migrar tu cuenta necesitamos que nos mandes la contraseña que usás para entrar.',
  'credential_disclosure_request'),
 ('credential_support-legitimate',
  'Para migrar tu cuenta no necesitamos que nos mandes la contraseña que usás para entrar.',
  None),
 ('credential_url-phishing',
  'Ingrese a https://validacion.example y escriba su contraseña y código MFA.',
  'credential_disclosure_request'),
 ('credential_url-legitimate',
  'Nunca ingrese su contraseña ni su código MFA en un sitio recibido por correo.',
  None),
 ('credential_quote-phishing',
  'Enviame "tu contraseña" y el código de verificación.',
  'credential_disclosure_request'),
 ('credential_quote-legitimate',
  'Ejemplo: "Enviame tu contraseña y el código de verificación". Reportá este mensaje.',
  None),
 ('payment_es-phishing',
  'Transferí a esta nueva cuenta hoy. No llames para verificar el cambio.',
  'payment_redirection_no_verification'),
 ('payment_es-legitimate',
  'No transfieras a esta nueva cuenta hoy. Llamá para verificar el cambio.',
  None),
 ('payment_en-phishing',
  'Pay the invoice to our new bank account. Do not call our office to confirm the change.',
  'payment_redirection_no_verification'),
 ('payment_en-legitimate',
  'Pay the invoice to our new bank account only after calling the supplier to verify the change.',
  None),
 ('gift_es-phishing',
  'Comprá tarjetas de regalo. Mandame fotos de los códigos y mantenelo en secreto.',
  'gift_card_code_request'),
 ('gift_es-legitimate',
  'No compres tarjetas de regalo. Nunca mandes fotos de los códigos y reportá cualquier pedido '
  'secreto.',
  None),
 ('gift_en-phishing',
  'Buy five gift cards now. Email me photos of the redemption codes. Keep this between us.',
  'gift_card_code_request'),
 ('gift_en-legitimate',
  'Do not buy gift cards on behalf of an unknown sender. Never email photos of redemption codes. '
  'Keep this policy available.',
  None),
 ('mfa_es-phishing',
  'Aprobá todas las notificaciones de acceso que lleguen al celular, aunque no hayas iniciado '
  'sesión.',
  'mfa_push_coercion'),
 ('mfa_es-legitimate',
  'No apruebes notificaciones de acceso que lleguen al celular si no iniciaste sesión.',
  None),
 ('mfa_en-phishing',
  'Approve the login notification even if you did not sign in on your phone.',
  'mfa_push_coercion'),
 ('mfa_en-legitimate',
  'Do not approve the login notification if you did not sign in on your phone.',
  None),
 ('oauth-phishing',
  'Grant the application permissions. Ignore the unverified publisher warning.',
  'unverified_app_consent_coercion'),
 ('oauth-legitimate',
  'Do not grant the application permissions. Never ignore the unverified publisher warning.',
  None),
 ('device-phishing',
  'Ingrese a microsoft.com/devicelogin. Autorice el equipo aunque no sea suyo.',
  'device_code_coercion'),
 ('device-legitimate',
  'No autorice el equipo aunque aparezca un código de dispositivo que no pidió.',
  None),
 ('qr-phishing',
  'Escanea el código QR e ingresa tus datos o tu cuenta quedará bloqueada.',
  'qr_phishing'),
 ('qr-legitimate',
  'No escanees el código QR ni ingreses tus datos ante una amenaza de cuenta bloqueada.',
  None),
 ('html_url-phishing',
  '<a href="http://microsoft.validacion.example/login">https://www.microsoft.com/</a>',
  'displayed_url_destination_mismatch'),
 ('html_url-legitimate',
  '<a href="https://login.microsoft.com/">https://www.microsoft.com/</a>',
  None),
 ('html_nested-phishing',
  '<a href="//evil.example"><strong>https://bank.example</strong></a>',
  'displayed_url_destination_mismatch'),
 ('html_nested-legitimate',
  '<a href="https://bank.example/help"><strong>https://bank.example</strong></a>',
  None),
 ('html_ip-phishing',
  '<a href="https://192.0.2.10/">https://bank.example</a>',
  'displayed_url_destination_mismatch'),
 ('html_ip-legitimate', '<a href="https://192.0.2.10/">https://192.0.2.10/</a>', None)]


def verify_security_rules(classify):
    for name, body, expected_rule in CASES:
        signals = {signal.rule for signal in detect_content_signals(body)}
        if expected_rule is None:
            if signals:
                raise SystemExit(f'Unexpected content rule for {name}: {sorted(signals)}')
        else:
            if expected_rule not in signals:
                raise SystemExit(f'Missing content rule for {name}: {expected_rule}')
            payload = EmailPayloadSchema(metadata={'asunto': 'Smoke regression'}, contenido=body)
            result = classify(payload)
            if not result['is_phishing'] or result['risk_score'] < 0.95:
                raise SystemExit(f'Final security verdict failed for {name}')
        print(f'security regression: {name}: passed')
    print(f'Security smoke gate: {len(CASES)} cases passed')
