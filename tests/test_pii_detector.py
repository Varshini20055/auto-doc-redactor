"""
Basic tests for the PII detection module.
Run with: pytest tests/ (from the project root, with backend on PYTHONPATH —
see tests/conftest.py).
"""
from app.services.pii_detector import detect_with_presidio


def test_detects_email():
    text = "Please contact John Smith at john.smith@example.com for more details."
    findings = detect_with_presidio(text)
    entity_types = {f.entity_type for f in findings}
    assert "EMAIL_ADDRESS" in entity_types


def test_detects_phone_number():
    text = "Call us at 415-555-2671 to schedule an appointment."
    findings = detect_with_presidio(text)
    entity_types = {f.entity_type for f in findings}
    assert "PHONE_NUMBER" in entity_types


def test_detects_credit_card():
    text = "Card number: 4111 1111 1111 1111 expires 12/27."
    findings = detect_with_presidio(text)
    entity_types = {f.entity_type for f in findings}
    assert "CREDIT_CARD" in entity_types


def test_detects_realistic_ssn():
    # Presidio deliberately ignores canonical example SSNs like 123-45-6789
    # (denylisted as a known placeholder) — use a realistic one here.
    text = "SSN on file: 294-81-5563"
    findings = detect_with_presidio(text)
    entity_types = {f.entity_type for f in findings}
    assert "US_SSN" in entity_types


def test_no_findings_on_empty_text():
    assert detect_with_presidio("") == []


def test_score_threshold_is_configurable():
    text = "Contact via 415-555-2671"
    strict = detect_with_presidio(text, score_threshold=0.9)
    lenient = detect_with_presidio(text, score_threshold=0.1)
    assert len(lenient) >= len(strict)
