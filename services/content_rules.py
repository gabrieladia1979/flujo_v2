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
        if tag in {'script', 'style'}:
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
    # Remove quoted text ONLY if preceded by educational/reporting cues
    visible = re.sub(r'(?i)\b(?:ejemplo|frase|dice|decía|decia|dicen|solicitud|mensaje sospechoso)\s*(?::\s*)?(?:"[^"\n]*"|“[^”\n]*”|«[^»\n]*»)', '', visible)
    normalized = ''.join(c for c in unicodedata.normalize('NFKD', visible.lower())
                         if not unicodedata.combining(c))
    return [re.sub(r'\s+', ' ', s).strip() for s in re.split(r'[.!?;\n]+', normalized) if s.strip()]


_SEND = re.compile(r'\b(?:responda|responde|respondeme|respondanos|envie|envia|enviame|envienos|mande|manda|mandame|comparta|comparti|compartime|facilite|facilita|ingrese|ingresa|ingresando|actualice|actualiza|actualizando|confirme|confirma|confirmar)\b')
_SECRET = re.compile(r'\b(?:contrasenas?|passwords?|claves? (?:fiscal(?:es)?|bancarias?|de acceso)|tokens?|cvv|pin|codigos? (?:sms|de (?:seguridad|verificacion|autenticacion)))\b')
_PAY = re.compile(r'\b(?:transfiera|transferi|transfieran|pague|paga|paguen|deposite|deposita|realice (?:el pago|la transferencia))\b')
_NEW_ACCOUNT = re.compile(r'\b(?:(?:nueva|otra) cuenta|cuenta (?:nueva|actualizada)|nuevo (?:cbu|alias)|(?:cbu|alias) (?:nuevo|actualizado))\b')
_NO_VERIFY = re.compile(r'\b(?:no (?:llame|llames|llamen|contacte|contactes|contacten|verifique|verifiques|consulte|consultes)|sin (?:llamar|contactar|verificar|consultar))\b')
_VERIFY_TARGET = re.compile(r'\b(?:proveedor|banco|titular|beneficiario|telefono|telefonicamente)\b')
_INDIRECT_REQUEST = re.compile(r'\b(?:sin|no|nunca|jamas|instrucciones|consejos|informacion|enlaces?|recordatorio|aviso|ejemplo|politica|sobre|acerca|cambiar|restablecer|recuperar|olvidaste|olvido|necesitas|dudas|problemas|estado)\b')
_PRIOR_VERIFICATION = re.compile(r'\b(?:despues de|tras|previa|solo si|una vez)\b.{0,70}\b(?:verificar|verificacion|confirmar|confirmado|validar|validado)\b')

# --- MFA Push Fatigue patterns ---
_MFA_APPROVE = re.compile(r'\b(?:apruebe|aprueba|acepte|acepta|autorice|autoriza|authorize|approve|accept)\b')
_MFA_CONTEXT = re.compile(r'\b(?:notificacion|solicitud de (?:acceso|inicio)|sign.?in|authenticator|segundo factor|mfa|2fa|sesion|login)\b')
_MFA_COERCION = re.compile(r'\b(?:suspendida|bloqueada|desactivar[ae]?|cancelar[ae]?|perdida de acceso|quedara? (?:sin acceso|suspendid[ao]))\b')

# --- QR Code Phishing (Quishing) patterns ---
_QR_SCAN = re.compile(r'\b(?:escanee|escanea|escane[ae] (?:el|este|la)|scan|abra (?:la camara|su camara)|codigo qr|qr code)\b')
_QR_ACTION = re.compile(r'\b(?:ingrese|ingresa|acceda|valide|configure|reconfigure|vincule|vincular|registre)\b')
_QR_THREAT = re.compile(r'\b(?:expir[oa]|caduc[oa]|venci[oa]|suspendid[ao]|bloqueada?|desactivad[ao]|perder[ae]? acceso)\b')


def _affirmative_match(pattern, clause):
    for match in pattern.finditer(clause):
        prefix = clause[:match.start()]
        # Limit negation/context to this request; a later sentence remains inspected.
        if re.search(r'\b(?:no|nunca|jamas|evite|evita)\b(?:\W+\w+){0,4}\W*$', prefix):
            continue
        if re.search(r'\b(?:ejemplo|frase|dice|decia|dicen|solicitud|mensaje sospechoso)\s*:\s*$', prefix):
            continue
        yield match


def detect_content_signals(body: str, subject: str = '') -> list[ContentSignal]:
    full_text = f'{subject}\n{body}' if subject else body
    clauses = _clauses(full_text)
    signals = []
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

    # --- MFA Push Fatigue Detection ---
    if not signals:
        for clause in clauses:
            if _MFA_APPROVE.search(clause) and _MFA_CONTEXT.search(clause):
                nearby_text = ' '.join(clauses)
                if _MFA_COERCION.search(nearby_text):
                    signals.append(ContentSignal(rule='mfa_push_fatigue', description=
                        'El mensaje pide aprobar una solicitud de acceso no iniciada por el usuario y amenaza con suspensión.'))
                    break

    # --- QR Code Phishing (Quishing) Detection ---
    if not signals:
        for clause in clauses:
            if _QR_SCAN.search(clause):
                nearby_text = ' '.join(clauses)
                if (_QR_ACTION.search(nearby_text) and _QR_THREAT.search(nearby_text)):
                    signals.append(ContentSignal(rule='qr_phishing', description=
                        'El mensaje solicita escanear un código QR para evitar la suspensión o bloqueo de la cuenta.'))
                    break

    return signals

