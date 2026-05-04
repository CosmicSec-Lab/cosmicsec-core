"""Tests for request transformation and security middleware."""

from services.common.request_transform import (
    _sanitize_value,
    _sanitize_query_params,
    redact_pii_from_response,
)


class TestSanitizeValue:
    def test_removes_script_tag(self):
        result = _sanitize_value("<script>alert('xss')</script>hello")
        assert "<script>" not in result

    def test_removes_javascript_protocol(self):
        result = _sanitize_value("javascript:alert(1)")
        assert "javascript:" not in result

    def test_removes_onclick(self):
        result = _sanitize_value('<img onclick="alert(1)">')
        assert "onclick=" not in result

    def test_preserves_safe_content(self):
        result = _sanitize_value("Hello World")
        assert result == "Hello World"


class TestSanitizeQueryParams:
    def test_sanitizes_xss_in_param(self):
        result = _sanitize_query_params("name=<script>alert(1)</script>&age=25")
        assert "<script>" not in result

    def test_preserves_safe_params(self):
        result = _sanitize_query_params("name=hello&age=25")
        assert result == "name=hello&age=25"

    def test_empty_string(self):
        assert _sanitize_query_params("") == ""

    def test_multiple_params_with_one_malicious(self):
        result = _sanitize_query_params("safe=1&malicious=<script>x</script>&also=2")
        assert "<script>" not in result
        assert "safe=1" in result


class TestRedactPII:
    def test_redacts_password_in_json(self):
        body = '{"username": "test", "password": "secret123"}'
        result = redact_pii_from_response(body)
        assert "secret123" not in result
        assert "***REDACTED***" in result

    def test_redacts_credit_card(self):
        body = '{"card": "4111-1111-1111-1111"}'
        result = redact_pii_from_response(body)
        assert "4111" not in result

    def test_redacts_ssn(self):
        body = '{"ssn": "123-45-6789"}'
        result = redact_pii_from_response(body)
        assert "123-45-6789" not in result
        assert "***SSN***" in result

    def test_preserves_safe_json(self):
        body = '{"name": "John", "age": 30}'
        result = redact_pii_from_response(body)
        assert result == body
