"""
Tests de validación para el motor de reglas heurísticas de security_features.
Ejecutar con: python test_security_rules.py
"""

import sys
import dataclasses

from schemas import SecurityFeaturesSchema, SecurityAdjustment
from services.security_rules import apply_security_rules


def test_all_defaults_no_adjustments():
    """Features con valores por defecto no deben generar ajustes."""
    features = SecurityFeaturesSchema()
    adjustments = apply_security_rules(features)
    assert len(adjustments) == 0, (
        f"Expected 0 adjustments for default features, got {len(adjustments)}: "
        f"{[a.rule for a in adjustments]}"
    )
    print("[PASS] test_all_defaults_no_adjustments")


def test_spf_fail():
    """SPF fail debe generar ajuste +0.15."""
    features = SecurityFeaturesSchema(spf_result="fail")
    adjustments = apply_security_rules(features)
    spf_adj = [a for a in adjustments if a.rule == "spf_fail"]
    assert len(spf_adj) == 1, f"Expected 1 SPF adjustment, got {len(spf_adj)}"
    assert spf_adj[0].delta == 0.15, f"Expected delta 0.15, got {spf_adj[0].delta}"
    print("[PASS] test_spf_fail")


def test_spf_softfail():
    """SPF softfail debe generar ajuste +0.05."""
    features = SecurityFeaturesSchema(spf_result="softfail")
    adjustments = apply_security_rules(features)
    spf_adj = [a for a in adjustments if a.rule == "spf_softfail"]
    assert len(spf_adj) == 1
    assert spf_adj[0].delta == 0.05
    print("[PASS] test_spf_softfail")


def test_dkim_fail():
    """DKIM fail debe generar ajuste +0.10."""
    features = SecurityFeaturesSchema(dkim_result="fail")
    adjustments = apply_security_rules(features)
    dkim_adj = [a for a in adjustments if a.rule == "dkim_fail"]
    assert len(dkim_adj) == 1
    assert dkim_adj[0].delta == 0.10
    print("[PASS] test_dkim_fail")


def test_dmarc_fail():
    """DMARC fail debe generar ajuste +0.15."""
    features = SecurityFeaturesSchema(dmarc_result="fail")
    adjustments = apply_security_rules(features)
    dmarc_adj = [a for a in adjustments if a.rule == "dmarc_fail"]
    assert len(dmarc_adj) == 1
    assert dmarc_adj[0].delta == 0.15
    print("[PASS] test_dmarc_fail")


def test_compauth_fail():
    """CompAuth fail debe generar ajuste +0.10."""
    features = SecurityFeaturesSchema(compauth_result="fail")
    adjustments = apply_security_rules(features)
    ca_adj = [a for a in adjustments if a.rule == "compauth_fail"]
    assert len(ca_adj) == 1
    assert ca_adj[0].delta == 0.10
    print("[PASS] test_compauth_fail")


def test_return_path_mismatch():
    """Return-Path mismatch debe generar ajuste +0.10."""
    features = SecurityFeaturesSchema(from_return_path_match=False)
    adjustments = apply_security_rules(features)
    rp_adj = [a for a in adjustments if a.rule == "return_path_mismatch"]
    assert len(rp_adj) == 1
    assert rp_adj[0].delta == 0.10
    print("[PASS] test_return_path_mismatch")


def test_reply_to_mismatch():
    """Reply-To mismatch debe generar ajuste +0.05."""
    features = SecurityFeaturesSchema(from_reply_to_match=False)
    adjustments = apply_security_rules(features)
    rt_adj = [a for a in adjustments if a.rule == "reply_to_mismatch"]
    assert len(rt_adj) == 1
    assert rt_adj[0].delta == 0.05
    print("[PASS] test_reply_to_mismatch")


def test_sender_from_mismatch():
    """Sender/From mismatch debe generar ajuste +0.08."""
    features = SecurityFeaturesSchema(sender_vs_from_match=False)
    adjustments = apply_security_rules(features)
    sf_adj = [a for a in adjustments if a.rule == "sender_from_mismatch"]
    assert len(sf_adj) == 1
    assert sf_adj[0].delta == 0.08
    print("[PASS] test_sender_from_mismatch")


def test_scl_medium():
    """SCL 5-8 debe generar ajuste +0.12."""
    features = SecurityFeaturesSchema(scl=6)
    adjustments = apply_security_rules(features)
    scl_adj = [a for a in adjustments if a.rule == "scl_medium"]
    assert len(scl_adj) == 1
    assert scl_adj[0].delta == 0.12
    print("[PASS] test_scl_medium")


def test_scl_high():
    """SCL >= 9 debe generar ajuste +0.20 (no +0.12)."""
    features = SecurityFeaturesSchema(scl=9)
    adjustments = apply_security_rules(features)
    scl_high = [a for a in adjustments if a.rule == "scl_high"]
    scl_medium = [a for a in adjustments if a.rule == "scl_medium"]
    assert len(scl_high) == 1
    assert scl_high[0].delta == 0.20
    assert len(scl_medium) == 0, "SCL>=9 should not also trigger scl_medium"
    print("[PASS] test_scl_high")


def test_bcl_high():
    """BCL >= 5 debe generar ajuste +0.05."""
    features = SecurityFeaturesSchema(bcl=7)
    adjustments = apply_security_rules(features)
    bcl_adj = [a for a in adjustments if a.rule == "bcl_high"]
    assert len(bcl_adj) == 1
    assert bcl_adj[0].delta == 0.05
    print("[PASS] test_bcl_high")


def test_executable_attachment():
    """Adjunto ejecutable debe generar ajuste +0.15."""
    features = SecurityFeaturesSchema(has_executable_attachment=True)
    adjustments = apply_security_rules(features)
    exe_adj = [a for a in adjustments if a.rule == "executable_attachment"]
    assert len(exe_adj) == 1
    assert exe_adj[0].delta == 0.15
    print("[PASS] test_executable_attachment")


def test_internal_auth():
    """Auth interna debe generar ajuste -0.10."""
    features = SecurityFeaturesSchema(auth_as="Internal")
    adjustments = apply_security_rules(features)
    int_adj = [a for a in adjustments if a.rule == "internal_auth"]
    assert len(int_adj) == 1
    assert int_adj[0].delta == -0.10
    print("[PASS] test_internal_auth")


def test_all_checks_pass():
    """Todo OK (SPF+DKIM+DMARC pass, sin spoofing) debe generar ajuste -0.05."""
    features = SecurityFeaturesSchema(
        spf_result="pass",
        dkim_result="pass",
        dmarc_result="pass",
        from_return_path_match=True,
        from_reply_to_match=True,
        sender_vs_from_match=True,
    )
    adjustments = apply_security_rules(features)
    ok_adj = [a for a in adjustments if a.rule == "all_checks_pass"]
    assert len(ok_adj) == 1
    assert ok_adj[0].delta == -0.15
    print("[PASS] test_all_checks_pass")


def test_worst_case_scenario():
    """El peor caso: todas las reglas negativas activas simultáneamente."""
    features = SecurityFeaturesSchema(
        spf_result="fail",
        dkim_result="fail",
        dmarc_result="fail",
        compauth_result="fail",
        from_return_path_match=False,
        from_reply_to_match=False,
        sender_vs_from_match=False,
        scl=9,
        bcl=8,
        has_executable_attachment=True,
    )
    adjustments = apply_security_rules(features)
    total_delta = sum(a.delta for a in adjustments)
    
    # Debe ser positivo (incrementa riesgo significativamente)
    assert total_delta > 0.5, f"Expected total delta > 0.5, got {total_delta}"
    
    # No debe haber reglas positivas (all_checks_pass) activadas
    positive_rules = [a for a in adjustments if a.delta < 0]
    assert len(positive_rules) == 0, (
        f"Worst case should have no positive rules, got: {[a.rule for a in positive_rules]}"
    )
    
    print(f"[PASS] test_worst_case_scenario (total delta: +{total_delta:.2f}, "
          f"{len(adjustments)} reglas)")


def test_best_case_internal():
    """Mejor caso: email interno con todo OK."""
    features = SecurityFeaturesSchema(
        spf_result="pass",
        dkim_result="pass",
        dmarc_result="pass",
        compauth_result="pass",
        from_return_path_match=True,
        from_reply_to_match=True,
        sender_vs_from_match=True,
        scl=0,
        bcl=0,
        has_executable_attachment=False,
        auth_as="Internal",
    )
    adjustments = apply_security_rules(features)
    total_delta = sum(a.delta for a in adjustments)
    
    # Debe ser negativo (reduce riesgo)
    assert total_delta < 0, f"Expected negative total delta, got {total_delta}"
    assert abs(total_delta - (-0.25)) < 1e-9, f"Expected -0.25, got {total_delta}"
    
    print(f"[PASS] test_best_case_internal (total delta: {total_delta:.2f})")


def test_score_clamping():
    """Simula el clamping del score ajustado a [0.0, 1.0]."""
    # Score bajo con ajustes negativos no debe ir por debajo de 0
    base_score = 0.05
    delta = -0.15
    adjusted = max(0.0, min(1.0, base_score + delta))
    assert adjusted == 0.0, f"Expected 0.0, got {adjusted}"

    # Score alto con ajustes positivos no debe superar 1.0
    base_score = 0.95
    delta = 0.50
    adjusted = max(0.0, min(1.0, base_score + delta))
    assert adjusted == 1.0, f"Expected 1.0, got {adjusted}"
    
    print("[PASS] test_score_clamping")


def test_spf_pass_no_penalty():
    """SPF pass no debe generar penalización."""
    features = SecurityFeaturesSchema(spf_result="pass")
    adjustments = apply_security_rules(features)
    spf_adj = [a for a in adjustments if "spf" in a.rule]
    assert len(spf_adj) == 0, f"SPF pass should not penalize, got: {[a.rule for a in spf_adj]}"
    print("[PASS] test_spf_pass_no_penalty")


if __name__ == "__main__":
    tests = [
        test_all_defaults_no_adjustments,
        test_spf_fail,
        test_spf_softfail,
        test_dkim_fail,
        test_dmarc_fail,
        test_compauth_fail,
        test_return_path_mismatch,
        test_reply_to_mismatch,
        test_sender_from_mismatch,
        test_scl_medium,
        test_scl_high,
        test_bcl_high,
        test_executable_attachment,
        test_internal_auth,
        test_all_checks_pass,
        test_worst_case_scenario,
        test_best_case_internal,
        test_score_clamping,
        test_spf_pass_no_penalty,
    ]
    
    passed = 0
    failed = 0
    
    for test_fn in tests:
        try:
            test_fn()
            passed += 1
        except AssertionError as e:
            print(f"[FAIL] {test_fn.__name__}: {e}")
            failed += 1
        except Exception as e:
            print(f"[FAIL] {test_fn.__name__}: UNEXPECTED ERROR: {e}")
            failed += 1
    
    print(f"\n{'='*50}")
    print(f"Results: {passed} passed, {failed} failed, {len(tests)} total")
    print(f"{'='*50}")
    
    sys.exit(0 if failed == 0 else 1)
