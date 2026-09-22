"""Versioned preprocessing shared by hybrid training and inference.

Only observable features are used. CSV psychological annotations and legacy
precomputed URL features are deliberately excluded to avoid train/serve skew.
"""

import ipaddress
import re
import unicodedata
from html import unescape
from html.parser import HTMLParser
from urllib.parse import urlsplit

FEATURE_VERSION = 'hybrid-features-v1'
FEATURE_NAMES = [
    'url_count', 'http_count', 'ip_host_count', 'brand_external_count',
    'punycode_count', 'max_host_length', 'max_host_dots', 'attachment_count',
    'received_hop_count', 'urgency_count', 'secret_count', 'payment_count',
    'threat_count', 'action_count', 'text_length_log', 'exclamation_count',
]
BRAND_DOMAINS = {
    'arca': ('arca.gob.ar',), 'afip': ('afip.gob.ar',),
    'anses': ('anses.gob.ar',), 'galicia': ('bancogalicia.com.ar', 'galicia.ar'),
    'mercadopago': ('mercadopago.com', 'mercadopago.com.ar'),
    'netflix': ('netflix.com',), 'santander': ('santander.com.ar',),
}
URL_PATTERN = re.compile(r'(?:https?://|hxxps?://|www\.)[^\s<>"\'\)\]]+', re.I)


class EmailParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.text = []
        self.urls = []
        self.hidden = []

    def handle_starttag(self, tag, attrs):
        if tag in ('script', 'style'):
            self.hidden.append(tag)
        if not self.hidden:
            if tag in ('br', 'p', 'div', 'li', 'tr'):
                self.text.append(' ')
            key = {'a': 'href', 'area': 'href', 'form': 'action'}.get(tag)
            for name, value in attrs:
                if key and name == key and value:
                    value = unescape(value.strip())
                    if value.startswith('//'):
                        value = 'https:' + value
                    if URL_PATTERN.match(value):
                        self.urls.append(value)

    def handle_endtag(self, tag):
        if self.hidden and self.hidden[-1] == tag:
            self.hidden.pop()
        elif not self.hidden and tag in ('p', 'div', 'li', 'tr'):
            self.text.append(' ')

    def handle_data(self, data):
        if not self.hidden:
            self.text.append(data)


def normalized(text):
    return ''.join(c for c in unicodedata.normalize('NFKD', text.lower())
                   if not unicodedata.combining(c))


def prepare_email(subject, body):
    # Anonymization tokens are text, not HTML tags.
    body = re.sub(r'<([A-Z_]{2,})>', r' \1 ', body or '')
    parser = EmailParser()
    parser.feed(body)
    visible = re.sub(r'\s+', ' ', unescape(''.join(parser.text))).strip()
    text = re.sub(r'\s+', ' ', f'{subject or ""} {visible}').strip()
    text = unicodedata.normalize('NFKC', text)
    urls = list(dict.fromkeys(URL_PATTERN.findall(text) + parser.urls))
    return text, urls


def encoder_text(subject, body, char_budget=4000):
    text, _ = prepare_email(subject, body)
    # Head + tail keeps a late call to action, bounded identically at serving.
    if len(text) > char_budget:
        return text[:char_budget // 2] + ' [...] ' + text[-char_budget // 2:]
    return text


def technical_features(subject, body, attachment_count=0, received_hop_count=0):
    import math
    text, urls = prepare_email(subject, body)
    hosts = []
    http = ip = brand_external = punycode = 0
    for url in urls:
        url = re.sub(r'^hxxp', 'http', url, flags=re.I)
        if url.lower().startswith('www.'):
            url = 'https://' + url
        try:
            parts = urlsplit(url)
            host = (parts.hostname or '').lower().rstrip('.')
        except ValueError:
            continue
        hosts.append(host)
        http += parts.scheme.lower() == 'http'
        punycode += 'xn--' in host
        try:
            ipaddress.ip_address(host)
            ip += 1
        except ValueError:
            pass
        brand_external += any(brand in host and not any(
            host == official or host.endswith('.' + official) for official in domains
        ) for brand, domains in BRAND_DOMAINS.items())
    plain = normalized(text)
    patterns = [
        r'\b(?:urgente|inmediatamente|ahora|ultimo aviso|24 horas|48 horas)\b',
        r'\b(?:contrasena|clave|token|cvv|pin|codigo de seguridad)\b',
        r'\b(?:transferencia|pago|pague|pagar|cbu|alias|deuda|factura)\b',
        r'\b(?:bloqueo|bloqueada|suspension|suspendida|embargo|sancion)\b',
        r'\b(?:ingrese|ingresa|acceda|verifique|actualice|envie|responda|clic)\b',
    ]
    return [len(urls), http, ip, brand_external, punycode,
            max(map(len, hosts), default=0), max((h.count('.') for h in hosts), default=0),
            max(0, min(int(attachment_count), 100)), max(0, min(int(received_hop_count), 100)),
            *[len(re.findall(pattern, plain)) for pattern in patterns],
            math.log1p(len(text)), text.count('!')]
