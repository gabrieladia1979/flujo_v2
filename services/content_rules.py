"""Conservative Spanish content rules complementing the unchanged ML model.

These are observable combinations, not calibrated probabilities or proof of
fraud. Quoted examples and negated requests are excluded locally, never by
allowlisting an entire message because it mentions training or security.
"""

import re
import unicodedata
from html.parser import HTMLParser

from schemas import ContentSignal


class _VisibleText(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts = []
        self.ignored = []

    def handle_starttag(self, tag, attrs):
        if tag in {'blockquote', 'script', 'style'}:
            self.ignored.append(tag)
        elif not self.ignored and tag in {'p', 'div', 'br', 'li'}:
            self.parts.append('\n')

    def handle_endtag(self, tag):
        if self.ignored and tag == self.ignored[-1]:
            self.ignored.pop()
        elif not self.ignored and tag in {'p', 'div', 'li'}:
            self.parts.append('\n')

    def handle_data(self, data):
        if not self.ignored:
            self.parts.append(data)


def _clauses(text):
    parser = _VisibleText()
    parser.feed(text)
    visible = ''.join(parser.parts)
    visible = re.sub(r'(?m)^\s*>[^\n]*', '', visible)
    visible = re.sub(r'"[^"\n]*"|“[^”\n]*”|«[^»\n]*»', '', visible)
    normalized = ''.join(c for c in unicodedata.normalize('NFKD', visible.lower())
                         if not unicodedata.combining(c))
    return [re.sub(r'\s+', ' ', s).strip() for s in re.split(r'[.!?;\n]+', normalized) if s.strip()]


_SEND = re.compile(
    r'\b(?:responda|responde|respondeme|respondanos|envie|envia|enviame|envienos|mande|manda|mandame|'
    r'comparta|comparti|compartime|facilite|facilita|ingrese|ingresa|ingresando|actualice|actualiza|actualizando|'
    r'confirme|confirma|confirmar|'
    r'reply|replying|send|sending|provide|providing|share|sharing|enter|entering|input|inputting|submit|submitting|verify|verifying|confirm|confirming|updating)\b'
)

_SECRET = re.compile(
    r'\b(?:contrasenas?|passwords?|claves? (?:fiscal(?:es)?|bancarias?|de acceso)|tokens?|cvv|pin|'
    r'codigos? (?:sms|de (?:seguridad|verificacion|autenticacion))|'
    r'credentials?|authentication codes?|verification codes?|security codes?|recovery codes?|(?:six|6)[ -]digit|otp)\b'
)

_PAY = re.compile(
    r'\b(?:transfiera|transferi|transfieran|pague|paga|paguen|deposite|deposita|realice (?:el pago|la transferencia)|'
    r'transfer|wire|pay|deposit|remit|make (?:the )?payment)\b'
)

_NEW_ACCOUNT = re.compile(
    r'\b(?:(?:nueva|otra) cuenta|cuenta (?:nueva|actualizada)|nuevo (?:cbu|alias)|(?:cbu|alias) (?:nuevo|actualizado)|'
    r'(?:new|updated|different)(?: [a-z]+)? (?:bank account|account)|(?:bank account|account) (?:new|updated))\b'
)

_NO_VERIFY = re.compile(
    r'\b(?:no (?:llame|llames|llamen|contacte|contactes|contacten|verifique|verifiques|consulte|consultes|siga)|'
    r'sin (?:llamar|contactar|verificar|consultar|seguir)|'
    r'(?:do not|dont|never) (?:call|contact|verify|check|reach out|follow)|without (?:calling|contacting|verifying|following))\b'
)

_VERIFY_TARGET = re.compile(
    r'\b(?:proveedor|banco|titular|beneficiario|contacto|contactos|telefono|telefonicamente|interna|procedimiento|'
    r'supplier|vendor|bank|beneficiary|payee|phone|telephone|help desk|support|contact|verify|internal|procedure|records)\b'
)

_INDIRECT_REQUEST = re.compile(
    r'\b(?:si|sin|no|nunca|jamas|instrucciones|consejos|informacion|enlaces?|recordatorio|aviso|ejemplo|politica|sobre|acerca|'
    r'cambiar|restablecer|recuperar|olvidaste|olvido|necesitas|dudas|problemas|estado|'
    r'if|without|never|instructions|tips|advice|information|links?|reminder|notice|example|policy|about|'
    r'change|reset|recover|forgot|need|questions|issues|status|protect|guidelines|guidance|guideline)\b'
)

_PRIOR_VERIFICATION = re.compile(
    r'\b(?:despues de|tras|previa|solo si|una vez|before|prior to|after|only if|once)\b.{0,70}'
    r'\b(?:verificar|verificacion|confirmar|confirmado|validar|validado|verify|verification|confirm|confirmed|validate|calling)\b'
)

# Amenazas 2026: MFA Push fatigue & Coerción de Notificaciones
_MFA_APPROVE = re.compile(
    r'\b(?:approve|apruebe|aprueba|aprobe|acepta|acepte)\b.{0,50}'
    r'\b(?:notification|prompt|request|notificacion|solicitud|acceso|sign-in|login)\b'
)
_MFA_CONTEXT = re.compile(
    r'\b(?:sign-in|login|inicio de sesion|autenticacion|mfa|push|acceso|dispositivo|telefono|phone)\b'
)
_MFA_COERCE = re.compile(
    r'\b(?:even if you did not|aunque no|sin haber|do not contact|no contacte|no llame|dont contact|do not reject|no la rechace|quedara suspendida|will be suspended|on your behalf|en su nombre)\b'
)

# Amenazas 2026: Consent Phishing / Abuso de Permisos de Aplicaciones no verificadas
_APP_PERM = re.compile(
    r'\b(?:acepta|acepte|aceptar|concede|conceder|autoriza|autorizar|approve|grant|authorize|accept)\b.{0,40}'
    r'\b(?:permisos|acceso|access|permissions)\b'
)
_UNVERIFIED_APP = re.compile(
    r'\b(?:ignora|ignore|ignorar|bypassear)\b.{0,60}'
    r'\b(?:no verificado|unverified|advertencia|warning)\b'
)

# Amenazas 2026: Device Code Login Coercion (microsoft.com/devicelogin abuse)
_DEVICE_CODE = re.compile(
    r'\b(?:devicelogin|codigo de dispositivo|device code)\b'
)
_DEVICE_COERCE = re.compile(
    r'\b(?:autorice|autoriza|authorize)\b.{0,40}\b(?:equipo|device|cuenta|account)\b.{0,50}\b(?:aunque|even if)\b'
)

# Amenazas 2026: Fraude de tarifas de entrega / paquetería
_DELIVERY_CONTEXT = re.compile(
    r'\b(?:delivery|paquete|envio|shipping|package|parcel|postal|fedx|ups|dhl|correo|andreani)\b'
)
_DELIVERY_FEE = re.compile(
    r'\b(?:redelivery fee|delivery fee|customs fee|fee|tarifa|tasa|costo de (?:re)?envio)\b'
)
_DELIVERY_ACTION = re.compile(
    r'\b(?:pay|pague|paga|pagar|abonar|abone|abona)\b'
)


def _affirmative_match(pattern, clause):
    for match in pattern.finditer(clause):
        prefix = clause[:match.start()]
        # Limit negation/context to this request; a later sentence remains inspected.
        if re.search(r'\b(?:no|nunca|jamas|evite|evita|never|do not|dont|avoid)\b(?:\W+\w+){0,4}\W*$', prefix):
            continue
        if re.search(r'\b(?:ejemplo|frase|dice|decia|dicen|solicitud|mensaje sospechoso|example|quote|warning)\s*:\s*$', prefix):
            continue
        yield match


def detect_content_signals(body: str) -> list[ContentSignal]:
    clauses = _clauses(body)
    signals = []

    # 1. Petición directa de credenciales / contraseñas / códigos (Español e Inglés)
    for clause in clauses:
        requested = False
        for request in _affirmative_match(_SEND, clause):
            window = clause[max(0, request.start() - 50):request.end() + 140]
            secret = _SECRET.search(window)
            if secret and not _INDIRECT_REQUEST.search(window[:secret.start()]):
                requested = True
                break
        if requested:
            signals.append(ContentSignal(rule='credential_disclosure_request', description=
                'El mensaje pide enviar o compartir contraseñas, claves o códigos de autenticación.'))
            break

    # 2. Desvío de pagos a cuenta nueva sin verificación (Español e Inglés)
    for index, clause in enumerate(clauses):
        if not any(_affirmative_match(_PAY, clause)) or not _NEW_ACCOUNT.search(clause):
            continue
        if _PRIOR_VERIFICATION.search(clause):
            continue
        nearby = clauses[max(0, index - 1):index + 2]
        if any(_NO_VERIFY.search(s) and _VERIFY_TARGET.search(s) for s in nearby):
            signals.append(ContentSignal(rule='payment_redirection_no_verification', description=
                'El mensaje pide pagar a una cuenta nueva y desalienta verificarlo con el proveedor, banco o titular.'))
            break

    # 3. Coerción de aprobación MFA Push
    for index, clause in enumerate(clauses):
        nearby = clauses[max(0, index - 1):index + 2]
        if any(_MFA_APPROVE.search(s) for s in nearby) and any(_MFA_CONTEXT.search(s) for s in nearby) and any(_MFA_COERCE.search(s) for s in nearby):
            signals.append(ContentSignal(rule='mfa_push_coercion', description=
                'El mensaje solicita aprobar una notificación de inicio de sesión o MFA no solicitada e insta a no contactar al soporte.'))
            break

    # 4. Abuso de permisos / OAuth Consent Phishing
    for index, clause in enumerate(clauses):
        nearby = clauses[max(0, index - 1):index + 2]
        if any(_APP_PERM.search(s) for s in nearby) and any(_UNVERIFIED_APP.search(s) for s in nearby):
            signals.append(ContentSignal(rule='unverified_app_consent_coercion', description=
                'El mensaje solicita autorizar permisos excesivos de aplicación ignorando advertencias de editor no verificado.'))
            break

    # 5. Coerción de código de dispositivo (Device Code Phishing)
    for index, clause in enumerate(clauses):
        nearby = clauses[max(0, index - 1):index + 2]
        if any(_DEVICE_CODE.search(s) for s in nearby) and any(_DEVICE_COERCE.search(s) for s in nearby):
            signals.append(ContentSignal(rule='device_code_coercion', description=
                'El mensaje solicita autorizar un dispositivo desconocido mediante un código de inicio de sesión.'))
            break

    # 6. Fraude de tarifas de entrega / paquetería
    for index, clause in enumerate(clauses):
        nearby = clauses[max(0, index - 1):index + 2]
        if any(_DELIVERY_CONTEXT.search(s) for s in nearby) and any(_DELIVERY_FEE.search(s) for s in nearby) and any(_DELIVERY_ACTION.search(s) for s in nearby):
            signals.append(ContentSignal(rule='delivery_fee_fraud', description=
                'El mensaje solicita el pago de tarifas de entrega o reenvío de paquetes no solicitados.'))
            break

    return signals
