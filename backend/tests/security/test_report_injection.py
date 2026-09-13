from __future__ import annotations

import pytest

from webguard.domain.models import Evidence
from webguard.reporting import HtmlReportRenderer, ReportBuilder


@pytest.mark.security
def test_html_report_escapes_all_target_controlled_markup(make_scan_result) -> None:  # type: ignore[no-untyped-def]
    base = make_scan_result()
    finding = base.findings[0].model_copy(
        update={
            "title": '<img src=x onerror="alert(1)">',
            "category": '<svg onload="alert(2)">',
            "description": "</style><script>alert(3)</script>",
            "recommendation": '<a href="javascript:alert(4)">click</a>',
            "evidence": (
                Evidence(label="Server", value='<script src="https://evil.invalid/x.js"></script>'),
                Evidence(label="Cookie name", value='session"><img src=x onerror=alert(5)>'),
                Evidence(label="Redirect", value='" autofocus onfocus="alert(6)'),
                Evidence(label="Header", value='<iframe srcdoc="<script>alert(7)</script>">'),
            ),
            "references": ("javascript:alert(8)",),
        }
    )
    result = make_scan_result(finding=finding)
    malicious_target = result.target.model_copy(
        update={"display_url": "https://example.com/<script>alert(9)</script>"}
    )
    result = result.model_copy(update={"target": malicious_target})
    html = HtmlReportRenderer().render(ReportBuilder().build(result))

    assert "<script" not in html.lower()
    assert "<img" not in html.lower()
    assert "<svg" not in html.lower()
    assert "<iframe" not in html.lower()
    assert 'href="javascript:' not in html.lower()
    assert "&lt;script&gt;" in html
    assert "&lt;img" in html
    assert "script-src &#x27;none&#x27;" in html


@pytest.mark.security
def test_json_escapes_html_delimiters_without_ceasing_to_be_valid_json(make_scan_result) -> None:  # type: ignore[no-untyped-def]
    import json

    from webguard.reporting import JsonReportRenderer

    base = make_scan_result()
    finding = base.findings[0].model_copy(update={"description": "<script>alert(1)</script>"})
    payload = JsonReportRenderer().render(ReportBuilder().build(make_scan_result(finding=finding)))
    parsed = json.loads(payload)
    assert parsed["findings"][0]["description"] == "<script>alert(1)</script>"
    assert "<script" not in payload.lower()
    assert "\\u003cscript\\u003e" in payload.lower()
