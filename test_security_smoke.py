"""Ensure the deployment gate fails on rule and final-verdict regressions."""
import pytest
from scripts import security_smoke


def test_deploy_gate_rejects_missing_rule(monkeypatch):
    monkeypatch.setattr(security_smoke, 'detect_content_signals', lambda body: [])
    with pytest.raises(SystemExit, match='Missing content rule'):
        security_smoke.verify_security_rules(lambda payload: {'is_phishing': True, 'risk_score': 0.95})


def test_deploy_gate_rejects_lost_final_verdict():
    with pytest.raises(SystemExit, match='Final security verdict failed'):
        security_smoke.verify_security_rules(lambda payload: {'is_phishing': False, 'risk_score': 0.01})


def test_deploy_gate_rejects_false_alarm_in_benign_rule_case(monkeypatch):
    from schemas import ContentSignal
    monkeypatch.setattr(security_smoke, 'CASES', [('benign', 'Meeting', None)])
    monkeypatch.setattr(security_smoke, 'detect_content_signals', lambda body: [
        ContentSignal(rule='bad_rule', description='Unexpected signal')])
    with pytest.raises(SystemExit, match='Unexpected content rule'):
        security_smoke.verify_security_rules(lambda payload: {})
