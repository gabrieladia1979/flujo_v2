"""Bank identity evidence, kept separate from an assertion that mail is safe.

No URLs are fetched. Recognized roots require exact or dot-boundary subdomains.
An unknown marketing provider is not automatically treated as phishing.
"""
import json
from email.utils import parseaddr
from pathlib import Path
import re
import unicodedata
from urllib.parse import urlsplit

from schemas import BankContext, ContentSignal


BANKS = json.loads((Path(__file__).resolve().parents[1] / "data" / "argentine_banks.json").read_text(encoding="utf-8"))["banks"]


def normalized(value):
    return "".join(c for c in unicodedata.normalize("NFKD", value.casefold()) if not unicodedata.combining(c))


def bank_for_domain(domain):
    domain = domain.lower().rstrip(".")
    return next((bank for bank in BANKS if any(domain == root or domain.endswith("." + root) for root in bank["domains"])), None)


def _mentions(text, bank):
    text = normalized(text)
    return any(re.search(r"(?<!\w)" + re.escape(alias) + r"(?!\w)", text) for alias in bank["aliases"])


def _lookalike(domain, bank):
    if not domain or bank_for_domain(domain):
        return False
    # Only distinctive brand names; generic words like ciudad and macro require
    # a bank prefix. No fuzzy reputation or arbitrary public-suffix assumptions.
    brands = [root.split(".")[0] for root in bank["domains"]]
    for brand in brands:
        if brand in {"macro", "hipotecario"}:
            brand = "banco" + brand
        if any(label == brand or label.startswith(brand + "-") or label.endswith("-" + brand)
               for label in domain.lower().split(".")):
            return True
    return False


def _url_host(value):
    try:
        if value.startswith("//"):
            value = "https:" + value
        elif value.lower().startswith("www."):
            value = "https://" + value
        return (urlsplit(value).hostname or "").lower().rstrip(".")
    except ValueError:
        return ""


def analyze_bank_identity(payload, urls):
    # Reuse content-rule parsing to exclude quoted examples, scripts and styles.
    from services.content_rules import _clauses, _affirmative_match, _VisibleText
    from services.link_rules import _destination, _Anchors

    display_name, address = parseaddr(payload.metadata.remitente_email or "")
    sender_domain = address.rsplit("@", 1)[-1].lower().rstrip(".") if "@" in address else ""
    sender_bank = bank_for_domain(sender_domain)
    security = payload.security_features
    status = "unrecognized_domain" if sender_domain else "missing"
    if sender_bank:
        status = "known_domain_unverified"
        if security and security.has_headers:
            if security.dmarc_result.lower() == "fail":
                status = "known_domain_auth_failed"
            elif (security.dmarc_result.lower() == "pass" and
                  (security.spf_result.lower() == "pass" or security.dkim_result.lower() == "pass")):
                status = "known_domain_authenticated"

    subject = payload.metadata.asunto or ""
    sender_name = payload.metadata.remitente_nombre or display_name
    clauses = _clauses(payload.contenido or "")
    visible = " ".join(clauses)
    mentioned = [b for b in BANKS if b is sender_bank or _lookalike(sender_domain, b)
                 or _mentions(f"{sender_name} {subject} {visible}", b)]
    hosts = {sender_domain} if sender_domain else set()
    text_parser, anchors = _VisibleText(), _Anchors()
    text_parser.feed(payload.contenido or "")
    anchors.feed(payload.contenido or "")
    active_text = "".join(text_parser.parts)
    active_hrefs = {href for href, _ in anchors.anchors}
    for url in urls:
        if url not in active_text and url not in active_hrefs and url.removeprefix("https:") not in active_hrefs:
            continue
        host = _url_host(url)
        if host:
            hosts.add(host)
            # Resolve only the embedded URL of recognized Safe Links locally.
            if host.endswith(".safelinks.protection.outlook.com"):
                hosts.add(_destination(url))
    lookalikes = sorted(host for host in hosts if any(_lookalike(host, b) for b in mentioned))
    observations = []
    if sender_bank:
        wording = {
            "known_domain_authenticated": "El dominio del remitente corresponde a {name} y las cabeceras informan autenticación alineada. Esto no garantiza que el contenido sea seguro.",
            "known_domain_auth_failed": "El remitente usa un dominio de {name}, pero las cabeceras informan un fallo de DMARC.",
            "known_domain_unverified": "El remitente usa un dominio registrado para {name}; falta autenticación alineada suficiente para confirmar su identidad.",
        }
        observations.append(wording[status].format(name=sender_bank["name"]))
    elif mentioned:
        observations.append("El mensaje menciona " + ", ".join(b["name"] for b in mentioned[:3]) + "; el dominio del remitente no está reconocido como bancario en el registro local.")
    if lookalikes:
        observations.append("Hay dominios que incluyen el nombre de un banco fuera de los dominios registrados; requieren verificación independiente.")

    # A brand-shaped domain alone is not proof of fraud. Require an identity
    # claim in the sender/subject AND an affirmative account-validation request.
    action = re.compile(r"\b(?:verifica|verifique|valida|valide|confirma|confirme|actualiza|actualice|reactiva|reactive|ingresa|ingrese|accede|acceda|verify|validate|confirm|sign in|log in)\b")
    account = re.compile(r"\b(?:cuenta|acceso|sesion|home ?banking|online banking|account|login|access)\b")
    asks_for_access = any(account.search(clause) and any(_affirmative_match(action, clause)) for clause in clauses)
    signals = []
    for bank in mentioned:
        claims_identity = _mentions(f"{sender_name} {subject}", bank) or _lookalike(sender_domain, bank)
        if claims_identity and asks_for_access and any(_lookalike(host, bank) for host in hosts):
            signals.append(ContentSignal(rule="bank_brand_impersonation", description=
                f"El mensaje se presenta como {bank['name']}, pide validar o ingresar a una cuenta y usa un dominio que imita al banco fuera de sus dominios registrados."))
            break
    return BankContext(sender_bank=sender_bank["name"] if sender_bank else None,
                       sender_domain=sender_domain, sender_status=status,
                       mentioned_banks=[b["name"] for b in mentioned],
                       lookalike_domains=lookalikes[:50], observations=observations), signals
