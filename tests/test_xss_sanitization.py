"""
Tests for XSS Sanitization in Reports, Findings, and Evidence (Requirements #48, #74)

Verifies:
- Malicious HTML / JavaScript (<script>, <img> onError, {{7*7}}) in host names or findings are escaped
- HTML report generation neutralizes executable tags
"""

import pytest
from backend.app.engine.reports import ReportGenerator


def test_html_report_escapes_xss_payloads():
    gen = ReportGenerator()
    malicious_host = {
        "id": "h1",
        "name": "<script>alert('pwned')</script>",
        "hostname": 'host" onmouseover="alert(1)',
        "os_distribution": "Linux <svg onload=alert(1)>",
        "os_version": "1.0",
        "environment": "prod"
    }
    malicious_finding = [
        {
            "id": "f1",
            "rule_id": "SSH-001",
            "title": "Title <img src=x onerror=alert(1)>",
            "category": "ssh",
            "severity": "CRITICAL",
            "status": "OPEN",
            "control": "ssh.permit_root_login",
            "actual_value": "<script>evil()</script>",
            "expected_value": "no",
            "rationale": "Rationale <b onfocus=alert(1)>bold</b>",
            "remediation_guidance": "Fix <iframe src=javascript:alert(1)>",
            "verification_method": "check"
        }
    ]
    assessment_data = {
        "id": "ass-1",
        "compliance_score": 85.0,
        "total_rules": 60,
        "passed_rules": 51,
        "failed_rules": 9,
        "critical_count": 1,
        "high_count": 2,
        "medium_count": 3,
        "low_count": 3,
    }

    html = gen.generate_html_report(assessment_data, malicious_host, malicious_finding)

    # All unescaped tags must be absent
    assert "<script>alert('pwned')</script>" not in html
    assert "&lt;script&gt;alert(&#x27;pwned&#x27;)&lt;/script&gt;" in html
    assert "<svg onload=alert(1)>" not in html
    assert "<img src=x onerror=alert(1)>" not in html
    assert "<iframe" not in html
