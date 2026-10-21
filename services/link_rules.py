"""Offline checks for URL-shaped anchor labels that conceal another host.

Does not fetch URLs or assert reputation. Known Microsoft Safe Links wrappers
are decoded locally; only an embedded destination matching the label is safe.
"""
import ipaddress
import re
from html.parser import HTMLParser
from urllib.parse import parse_qs, urlsplit

from schemas import ContentSignal


_URL = re.compile(r'^(?:https?://|www\.)[^\s<>]+$', re.I)


def _host(value):
    value = value.strip()
    if value.startswith('//'):
        value = 'https:' + value
    if value.lower().startswith('www.'):
        value = 'https://' + value
    try:
        host = (urlsplit(value).hostname or '').lower().rstrip('.')
        return host.encode('idna').decode('ascii').removeprefix('www.')
    except (ValueError, UnicodeError):
        return ''


def _same_site(left, right):
    # Exact or destination subdomain only; never guess the public suffix.
    # Do not treat arbitrary IP address suffixes as domain relationships.
    try:
        ipaddress.ip_address(left)
        return left == right
    except ValueError:
        return left == right or right.endswith('.' + left)


def _destination(value):
    host = _host(value)
    if host.endswith('.safelinks.protection.outlook.com'):
        values = parse_qs(urlsplit(value).query).get('url', [])
        if len(values) == 1 and values[0].lower().startswith(('https://', 'http://')):
            return _host(values[0])
    return host


class _Anchors(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.hidden = []
        self.current = None
        self.anchors = []

    def handle_starttag(self, tag, attrs):
        if tag in {'script', 'style', 'blockquote'}:
            self.hidden.append(tag)
        if self.hidden:
            return
        if tag == 'a':
            self.current = ((dict(attrs).get('href') or '').strip(), [])
        elif tag == 'br' and self.current:
            self.current[1].append(' ')

    def handle_data(self, data):
        if self.current and not self.hidden:
            self.current[1].append(data)

    def handle_endtag(self, tag):
        if self.hidden and self.hidden[-1] == tag:
            self.hidden.pop()
        elif tag == 'a' and self.current:
            self.anchors.append((self.current[0], ''.join(self.current[1]).strip()))
            self.current = None


def detect_link_signals(body):
    parser = _Anchors()
    parser.feed(body or '')
    for href, label in parser.anchors:
        # Brand labels or buttons alone make no claim about a URL destination.
        if not _URL.fullmatch(label) or not href.lower().startswith(('https://', 'http://', '//')):
            continue
        shown, actual = _host(label), _destination(href)
        if shown and actual and not _same_site(shown, actual):
            return [ContentSignal(rule='displayed_url_destination_mismatch', description=
                'Un enlace muestra una dirección web pero apunta a un dominio diferente; verifique el destino por un canal independiente.')]
    return []
