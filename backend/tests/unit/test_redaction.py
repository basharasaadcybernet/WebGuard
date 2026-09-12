from webguard.security.redaction import redact_header, redact_mapping, redact_url, sanitize_text


def test_redacts_url_credentials_query_and_fragment() -> None:
    redacted = redact_url("https://user:password@example.com/path?token=secret#fragment")
    assert redacted == "https://example.com/path?[redacted]"
    assert "password" not in redacted
    assert "secret" not in redacted


def test_redacts_sensitive_headers_and_cookie_value() -> None:
    assert redact_header("Authorization", "Bearer secret") == "[redacted]"
    assert redact_header("Set-Cookie", "session=secret; Secure") == ("session=[redacted]; Secure")
    assert redact_header("Set-Cookie", "malformed-secret") == "cookie=[redacted]"
    assert redact_header("Server", "example\r\nInjected") == "example Injected"


def test_redacts_structured_log_context() -> None:
    context = redact_mapping(
        {
            "target_url": "https://example.com/?secret=value",
            "authorization": "Bearer secret",
            "status": 200,
        }
    )
    assert context["target_url"] == "https://example.com/?[redacted]"
    assert context["authorization"] == "[redacted]"
    assert context["status"] == 200


def test_sanitize_text_is_bounded() -> None:
    assert sanitize_text("abcdef", maximum=4) == "abc…"


def test_sanitize_text_rejects_invalid_bound() -> None:
    import pytest

    with pytest.raises(ValueError, match="positive"):
        sanitize_text("value", maximum=0)
