"""Regression checks for lossless, URL-preserving positional fragments."""
from scripts.probe_lime_fragments import fragment_spans


def test_fragments_preserve_original_text_and_complete_urls():
    url = 'https://login.example.test/auth?token=a-b_c&next=/cuenta'
    body = '  Hola,\nrevisá tu cuenta: ' + url + ' hoy.\nGracias por leer este correo completo.  '
    spans = fragment_spans(body)
    fragments = [body[start:end] for start, end in spans]
    assert len(fragments) == 8
    assert ''.join(fragments) == body
    containing_url = [text for text in fragments if url in text]
    assert len(containing_url) == 1
    for start, end in spans:
        if start:
            assert body[start - 1].isspace()
        if end < len(body):
            assert body[end - 1].isspace()


def test_short_or_empty_text_has_no_empty_fragments():
    assert fragment_spans(' \n ') == []
    body = 'hola hola'
    spans = fragment_spans(body)
    assert len(spans) == 2
    assert [body[start:end].strip() for start, end in spans] == ['hola', 'hola']
