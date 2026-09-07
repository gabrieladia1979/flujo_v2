"""Focused analyzer regressions runnable without the ML runtime dependencies.

The test replaces only external ML dependencies. It executes the production
``analyze_email`` function, security rules, final authority composition, and
the SLM fallback renderer.

Run with:
    python -m unittest -v test_analyzer_slm_integration.py
"""

import contextlib
import importlib
import io
import sys
import types
import unittest
from contextlib import contextmanager
from unittest.mock import patch

import numpy as np


class _BootstrapMatcher:
    def __init__(self, vocab):
        self.vocab = vocab

    def add(self, name, patterns):
        return None

    def __call__(self, doc):
        return []


class _Vocab:
    def __init__(self):
        self.strings = {1: "FINANCIERO"}


class _Span:
    text = "actualizar datos"


class _Doc:
    def __getitem__(self, key):
        return _Span()


class _NLP:
    def __init__(self):
        self.vocab = _Vocab()
        self.max_length = 0

    def __call__(self, text):
        return _Doc()


from schemas import EmailPayloadSchema, MetadataSchema, SecurityFeaturesSchema
from services.slm_explanation import LEGITIMATE_SUMMARY, PHISHING_SUMMARY


_MISSING = object()


@contextmanager
def _isolated_analyzer_import():
    """Import analyzer with ML stubs, then restore every import side effect."""

    import __main__
    import services

    module_names = ("spacy", "spacy.matcher", "services.analyzer")
    previous_modules = {name: sys.modules.get(name, _MISSING) for name in module_names}
    previous_package_attribute = getattr(services, "analyzer", _MISSING)
    previous_main_lemma = getattr(__main__, "lematizador_spacy", _MISSING)

    spacy_stub = types.ModuleType("spacy")
    spacy_stub.load = lambda name: _NLP()
    matcher_stub = types.ModuleType("spacy.matcher")
    matcher_stub.Matcher = _BootstrapMatcher

    try:
        sys.modules.pop("services.analyzer", None)
        if hasattr(services, "analyzer"):
            delattr(services, "analyzer")
        sys.modules["spacy"] = spacy_stub
        sys.modules["spacy.matcher"] = matcher_stub

        with patch("pickle.load", side_effect=RuntimeError("model disabled for focused test")):
            with contextlib.redirect_stdout(io.StringIO()):
                analyzer = importlib.import_module("services.analyzer")
        yield analyzer
    finally:
        for name in module_names:
            previous = previous_modules[name]
            if previous is _MISSING:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = previous

        if previous_package_attribute is _MISSING:
            if hasattr(services, "analyzer"):
                delattr(services, "analyzer")
        else:
            services.analyzer = previous_package_attribute

        if previous_main_lemma is _MISSING:
            if hasattr(__main__, "lematizador_spacy"):
                delattr(__main__, "lematizador_spacy")
        else:
            __main__.lematizador_spacy = previous_main_lemma


class _ArrayResult:
    def __init__(self, value):
        self.value = value

    def toarray(self):
        return np.array([[self.value]])


class _Vectorizer:
    def transform(self, values):
        return _ArrayResult(0.0)


class _Scaler:
    def transform(self, values):
        return np.asarray(values, dtype=float)


class _Classifier:
    def __init__(self, phishing_score):
        self.phishing_score = phishing_score

    def predict_proba(self, values):
        # Production V4 reads index zero as the phishing probability.
        return np.array([[self.phishing_score, 1.0 - self.phishing_score]])


class _FinancialMatcher:
    def __call__(self, doc):
        return [(1, 0, 1)]


class AnalyzerSLMIntegrationTests(unittest.TestCase):
    def setUp(self):
        self._analyzer_scope = _isolated_analyzer_import()
        self.analyzer = self._analyzer_scope.__enter__()
        self.addCleanup(self._analyzer_scope.__exit__, None, None, None)

        names = (
            "nlp",
            "matcher_global",
            "tfidf",
            "scaler_meta",
            "scaler_slots",
            "scaler_legibilidad",
            "calibrated_model",
            "UMBRAL_CRITICO",
            "DOMINIOS_OFICIALES",
        )
        original_globals = {name: getattr(self.analyzer, name) for name in names}
        original_cache = dict(self.analyzer._ANALYSIS_CACHE)

        def restore_analyzer_globals():
            for name, value in original_globals.items():
                setattr(self.analyzer, name, value)
            self.analyzer._ANALYSIS_CACHE.clear()
            self.analyzer._ANALYSIS_CACHE.update(original_cache)

        self.addCleanup(restore_analyzer_globals)
        self.analyzer._ANALYSIS_CACHE.clear()
        self.analyzer.nlp = _NLP()
        self.analyzer.matcher_global = _FinancialMatcher()
        self.analyzer.tfidf = _Vectorizer()
        self.analyzer.scaler_meta = _Scaler()
        self.analyzer.scaler_slots = _Scaler()
        self.analyzer.scaler_legibilidad = None
        self.analyzer.UMBRAL_CRITICO = 0.91
        self.analyzer.DOMINIOS_OFICIALES = []

    def _payload(self, subject, security_features):
        return EmailPayloadSchema(
            metadata=MetadataSchema(
                asunto=subject,
                remitente_email="sender@example.test",
            ),
            contenido="Mensaje de prueba con una solicitud financiera.",
            security_features=security_features,
        )

    def test_final_authority_and_fallback_follow_post_adjustment_verdict(self):
        self.analyzer.calibrated_model = _Classifier(0.80)
        escalated = self.analyzer.analyze_email(
            self._payload(
                "Escalated verdict",
                SecurityFeaturesSchema(spf_result="fail"),
            )
        )
        self.assertTrue(escalated.is_phishing)
        self.assertEqual(0.95, escalated.risk_score)
        self.assertEqual("coaccionar_pago", escalated.intent)
        self.assertIn(PHISHING_SUMMARY, escalated.slm_explanation)
        self.assertIn("No abras enlaces ni adjuntos", escalated.slm_explanation)
        self.assertNotIn("Borrador del SLM", escalated.slm_explanation)

        self.analyzer.calibrated_model = _Classifier(0.95)
        lowered_payload = self._payload(
            "Lowered verdict",
            SecurityFeaturesSchema(
                spf_result="pass",
                dkim_result="pass",
                dmarc_result="pass",
            ),
        )
        lowered = self.analyzer.analyze_email(lowered_payload)
        self.assertFalse(lowered.is_phishing)
        self.assertEqual(0.9, lowered.risk_score)
        self.assertEqual("comunicacion_operativa", lowered.intent)
        self.assertIn(LEGITIMATE_SUMMARY, lowered.slm_explanation)
        self.assertIn("No se requiere una acción adicional", lowered.slm_explanation)

        self.analyzer._ANALYSIS_CACHE.clear()
        repeated = self.analyzer.analyze_email(lowered_payload)
        self.assertEqual(lowered.model_dump(), repeated.model_dump())

    def test_critical_threat_path_returns_server_owned_safe_fallback(self):
        self.analyzer.calibrated_model = _Classifier(0.01)
        critical_payload = self._payload(
            "Critical threat",
            SecurityFeaturesSchema(dmarc_result="fail"),
        )
        result = self.analyzer.analyze_email(critical_payload)

        self.assertTrue(result.is_phishing)
        self.assertEqual(1.0, result.risk_score)
        self.assertEqual("suplantacion_o_malware", result.intent)
        self.assertIn(PHISHING_SUMMARY, result.slm_explanation)
        self.assertIn("Una regla crítica de seguridad", result.slm_explanation)
        self.assertIn("No abras enlaces ni adjuntos", result.slm_explanation)
        self.assertNotIn("Borrador del SLM", result.slm_explanation)


class ZZAnalyzerIntegrationIsolationTests(unittest.TestCase):
    def test_absent_and_preloaded_analyzer_states_are_restored_exactly(self):
        import services

        original_module = sys.modules.get("services.analyzer", _MISSING)
        original_package_attribute = getattr(services, "analyzer", _MISSING)

        def restore_original_state():
            if original_module is _MISSING:
                sys.modules.pop("services.analyzer", None)
            else:
                sys.modules["services.analyzer"] = original_module

            if original_package_attribute is _MISSING:
                if hasattr(services, "analyzer"):
                    delattr(services, "analyzer")
            else:
                services.analyzer = original_package_attribute

        self.addCleanup(restore_original_state)

        # Scenario 1: no analyzer was loaded before the focused import.
        sys.modules.pop("services.analyzer", None)
        if hasattr(services, "analyzer"):
            delattr(services, "analyzer")
        with _isolated_analyzer_import() as focused_analyzer:
            self.assertIs(focused_analyzer, sys.modules["services.analyzer"])
        self.assertNotIn("services.analyzer", sys.modules)
        self.assertFalse(hasattr(services, "analyzer"))

        real_import = __import__
        spacy_import_attempted = []

        def reject_real_spacy(name, globals=None, locals=None, fromlist=(), level=0):
            if name == "spacy" or name.startswith("spacy."):
                spacy_import_attempted.append(name)
                error = ModuleNotFoundError("No module named 'spacy'")
                error.name = "spacy"
                raise error
            return real_import(name, globals, locals, fromlist, level)

        with patch("builtins.__import__", side_effect=reject_real_spacy):
            with self.assertRaises(ModuleNotFoundError) as raised:
                importlib.import_module("services.analyzer")
        self.assertEqual("spacy", raised.exception.name)
        self.assertEqual(["spacy"], spacy_import_attempted)
        self.assertNotIn("services.analyzer", sys.modules)

        # Scenario 2: a legitimate preloaded module must survive by identity.
        sentinel_module = types.ModuleType("services.analyzer")
        sentinel_module.preloaded_state = object()
        sys.modules["services.analyzer"] = sentinel_module
        services.analyzer = sentinel_module
        with _isolated_analyzer_import() as focused_analyzer:
            self.assertIsNot(focused_analyzer, sentinel_module)
            self.assertIs(focused_analyzer, sys.modules["services.analyzer"])
        self.assertIs(sentinel_module, sys.modules["services.analyzer"])
        self.assertIs(sentinel_module, services.analyzer)

        # Restore and verify the state that existed before this regression ran.
        restore_original_state()
        if original_module is _MISSING:
            self.assertNotIn("services.analyzer", sys.modules)
        else:
            self.assertIs(original_module, sys.modules["services.analyzer"])
        if original_package_attribute is _MISSING:
            self.assertFalse(hasattr(services, "analyzer"))
        else:
            self.assertIs(original_package_attribute, services.analyzer)


if __name__ == "__main__":
    unittest.main(verbosity=2)
