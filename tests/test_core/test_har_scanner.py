"""Unit tests for pure-Python HAR 1.2 capture reader and API surface extractor."""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from reforge.core.scanners.har_scanner import (
    ApiSurfaceResult,
    HarCapture,
    HarParseError,
    HarScanner,
)


def _build_har(
    entries: list[dict[str, Any]],
    version: str = "1.2",
    creator: dict[str, str] | None = None,
) -> dict[str, Any]:
    return {
        "log": {
            "version": version,
            "creator": creator or {"name": "ReforgeTest", "version": "1.0"},
            "entries": entries,
        }
    }


def _build_entry(
    url: str,
    method: str = "GET",
    status: int = 200,
    mime_type: str = "application/json",
    headers: list[dict[str, str]] | None = None,
    response_text: str | None = None,
    response_encoding: str | None = None,
    post_text: str | None = None,
    server_ip: str | None = None,
) -> dict[str, Any]:
    req_headers = headers or []
    entry: dict[str, Any] = {
        "startedDateTime": "2026-10-14T20:00:00.000Z",
        "time": 42.0,
        "request": {
            "method": method,
            "url": url,
            "httpVersion": "HTTP/1.1",
            "headers": req_headers,
            "cookies": [],
            "queryString": [],
            "headersSize": 100,
            "bodySize": len(post_text.encode("utf-8")) if post_text else 0,
        },
        "response": {
            "status": status,
            "statusText": "OK" if status == 200 else "Error",
            "httpVersion": "HTTP/1.1",
            "headers": [{"name": "Content-Type", "value": mime_type}],
            "cookies": [],
            "content": {
                "size": len(response_text.encode("utf-8")) if response_text else 0,
                "mimeType": mime_type,
                "text": response_text,
                "encoding": response_encoding,
            },
            "redirectURL": "",
            "headersSize": 80,
            "bodySize": 0,
        },
    }
    if post_text is not None:
        entry["request"]["postData"] = {
            "mimeType": "application/json",
            "text": post_text,
        }
    if server_ip is not None:
        entry["serverIPAddress"] = server_ip
    return entry


class TestHarValidationAndProfiles:
    """Tests for HAR format validation, schema profile, and producer quirks."""

    def test_valid_har_12_parsing(self) -> None:
        data = _build_har([
            _build_entry("https://api.example.com/v1/health"),
        ])
        capture = HarScanner.parse_dict(data)
        assert isinstance(capture, HarCapture)
        assert capture.version == "1.2"
        assert capture.creator_name == "ReforgeTest"
        assert capture.total_records == 1
        assert len(capture.records) == 1
        record = capture.records[0]
        assert record.ordinal == 0
        assert record.request is not None
        assert record.request.method == "GET"
        assert record.request.url == "https://api.example.com/v1/health"
        assert record.response is not None
        assert record.response.status == 200

    def test_invalid_json_raises_har_parse_error(self) -> None:
        with pytest.raises(HarParseError, match="Malformed JSON in HAR"):
            HarScanner.parse_text("{invalid_json: 123")

    def test_missing_log_object(self) -> None:
        with pytest.raises(HarParseError, match="HAR must contain log object"):
            HarScanner.parse_dict({"not_log": {}})

    def test_unsupported_version_rejected(self) -> None:
        data = _build_har([], version="1.1")
        with pytest.raises(HarParseError, match="Only the pinned HAR 1.2 schema profile is supported"):
            HarScanner.parse_dict(data)

    def test_missing_entries_array(self) -> None:
        with pytest.raises(HarParseError, match="HAR log must contain entries array"):
            HarScanner.parse_dict({"log": {"version": "1.2"}})

    def test_mitmproxy_savehar_null_postdata_text_accepted(self) -> None:
        entry = _build_entry("https://api.example.com/upload", method="POST")
        entry["request"]["postData"] = {"mimeType": "application/json", "text": None}
        data = _build_har([entry])
        capture = HarScanner.parse_dict(data)
        assert capture.total_records == 1
        assert capture.records[0].request is not None
        assert capture.records[0].request.post_data is not None
        assert capture.records[0].request.post_data.text is None

    def test_playwright_bracketed_ipv6_server_ip_address(self) -> None:
        entry = _build_entry("https://api.example.com/status", server_ip="[::1]")
        data = _build_har([entry])
        capture = HarScanner.parse_dict(data)
        record = capture.records[0]
        assert record.server_ip_address == "[::1]"
        assert any("bracketed IPv6" in lim for lim in record.limitations)


class TestHarRedactionAndCredentials:
    """Tests for authentication header, cookie, transport URL, and sensitive value redaction."""

    def test_auth_headers_redacted(self) -> None:
        headers = [
            {"name": "Authorization", "value": "Bearer secret_jwt_token_12345"},
            {"name": "Proxy-Authorization", "value": "Basic dXNlcjpwYXNz"},
            {"name": "Cookie", "value": "session_id=abcdef123456"},
            {"name": "X-Custom-Header", "value": "normal_value"},
        ]
        entry = _build_entry("https://api.example.com/v1/profile", headers=headers)
        data = _build_har([entry])
        capture = HarScanner.parse_dict(data)
        record = capture.records[0]
        assert record.request is not None

        headers_by_name = {h.name.lower(): h.value for h in record.request.headers}
        assert headers_by_name["authorization"] == "[REDACTED]"
        assert headers_by_name["proxy-authorization"] == "[REDACTED]"
        assert headers_by_name["cookie"] == "[REDACTED]"
        assert headers_by_name["x-custom-header"] == "normal_value"

        redaction_reasons = {r.reason for r in record.redactions}
        assert "transport-credential" in redaction_reasons

    def test_transport_url_userinfo_stripped(self) -> None:
        raw_url = "https://user:mypassword@api.example.com:8443/v1/resource?query=1"
        entry = _build_entry(raw_url)
        data = _build_har([entry])
        capture = HarScanner.parse_dict(data)
        record = capture.records[0]
        assert record.request is not None
        assert "user:mypassword" not in record.request.url
        assert record.request.url == "https://api.example.com:8443/v1/resource?query=1"
        assert any(r.reason == "transport-credential" and r.pointer == "/request/url" for r in record.redactions)

    def test_explicit_sensitive_values_redacted(self) -> None:
        entry = _build_entry(
            "https://api.example.com/v1/data?token=CLASSIFIED_KEY_999",
            headers=[{"name": "X-Token", "value": "my_CLASSIFIED_KEY_999_here"}],
            post_text='{"secret": "CLASSIFIED_KEY_999"}',
            response_text="Found CLASSIFIED_KEY_999 in response",
        )
        data = _build_har([entry])
        capture = HarScanner.parse_dict(data, sensitive_values=["CLASSIFIED_KEY_999"])
        record = capture.records[0]

        assert record.request is not None
        assert "CLASSIFIED_KEY_999" not in record.request.url
        assert "[REDACTED]" in record.request.url

        assert record.request.headers[0].value == "[REDACTED]"
        assert record.request.post_data is not None
        assert record.request.post_data.text == "[REDACTED]"

        assert record.response is not None
        assert record.response.content_text == "[REDACTED]"
        assert any(r.reason == "explicit-sensitive-value" for r in record.redactions)


class TestBase64ResponseContentInspection:
    """Tests for base64 response content decoding and binary field reporting."""

    def test_valid_base64_retained(self) -> None:
        payload = b"Hello, Reforge Security Analysis!"
        b64_payload = base64.b64encode(payload).decode("ascii")
        expected_sha = hashlib.sha256(payload).hexdigest()

        entry = _build_entry(
            "https://api.example.com/binary",
            response_text=b64_payload,
            response_encoding="base64",
        )
        data = _build_har([entry])
        capture = HarScanner.parse_dict(data)
        record = capture.records[0]

        assert len(record.binary_fields) == 1
        bin_field = record.binary_fields[0]
        assert bin_field.state == "retained"
        assert bin_field.bytes_length == len(payload)
        assert bin_field.sha256 == expected_sha
        assert bin_field.content_base64 == b64_payload

    def test_base64_with_sensitive_value_redacted(self) -> None:
        payload = b"Top secret data: SUPER_CONFIDENTIAL_PASSWD"
        b64_payload = base64.b64encode(payload).decode("ascii")

        entry = _build_entry(
            "https://api.example.com/confidential",
            response_text=b64_payload,
            response_encoding="base64",
        )
        data = _build_har([entry])
        capture = HarScanner.parse_dict(data, sensitive_values=["SUPER_CONFIDENTIAL_PASSWD"])
        record = capture.records[0]

        assert len(record.binary_fields) == 1
        bin_field = record.binary_fields[0]
        assert bin_field.state == "redacted"
        assert bin_field.bytes_length is None
        assert bin_field.sha256 is None
        assert bin_field.content_base64 is None
        assert record.response is not None
        assert record.response.content_text is None


class TestApiSurfacePathTemplating:
    """Tests for path templating rules (numeric, uuid, hex, iso-date, literals)."""

    def test_path_templating_rules(self) -> None:
        urls = [
            "https://api.test/api/CreateDocument",
            "https://api.test/api/ListDocuments",
            "https://api.test/api/Report2",
            "https://api.test/api/v1/users",
            "https://api.test/api/v2/users",
            "https://api.test/dates/2023-02-29",  # Invalid calendar leap year: literal
            "https://api.test/dates/2024-02-29",  # Valid leap year: iso-date
            "https://api.test/ids/abc123",  # < 32 hex chars: literal
            "https://api.test/ids/0123456789abcdef0123456789abcdef",  # >= 32 hex chars: hex
            "https://api.test/ids/550e8400-e29b-41d4-a716-446655440000",  # UUID
            "https://api.test/users/8812",  # Numeric
            "https://api.test/users/9031",  # Numeric
        ]
        entries = [_build_entry(u) for u in urls]
        capture = HarScanner.parse_dict(_build_har(entries))
        surface = capture.extract_api_surface()

        templates = [g.path_template for g in surface.groups]
        assert "/api/CreateDocument" in templates
        assert "/api/ListDocuments" in templates
        assert "/api/Report2" in templates
        assert "/api/v1/users" in templates
        assert "/api/v2/users" in templates
        assert "/dates/2023-02-29" in templates
        assert "/dates/{iso-date}" in templates
        assert "/ids/abc123" in templates
        assert "/ids/{hex}" in templates
        assert "/ids/{uuid}" in templates
        assert "/users/{numeric}" in templates

        # Check /users/{numeric} merged 8812 and 9031
        users_group = next(g for g in surface.groups if g.path_template == "/users/{numeric}")
        assert users_group.record_ordinals == [10, 11]
        assert len(users_group.templated_segments) == 1
        seg = users_group.templated_segments[0]
        assert seg.segment_index == 1
        assert seg.rule == "numeric"
        assert seg.observed_values == ["8812", "9031"]

    def test_encoded_dot_segments_preserved(self) -> None:
        url = "https://api.test/a/%2e%2e/admin"
        capture = HarScanner.parse_dict(_build_har([_build_entry(url)]))
        surface = capture.extract_api_surface()
        assert surface.groups[0].path_template == "/a/%2e%2e/admin"


class TestApiSurfaceGroupingAndMetadata:
    """Tests for endpoint grouping, response status and MIME tracking, flags, and auth detection."""

    def test_grouping_merges_statuses_and_mimes(self) -> None:
        entries = [
            _build_entry("https://api.test/items/1", status=200, mime_type="application/json; charset=utf-8"),
            _build_entry("https://api.test/items/2", status=404, mime_type="text/plain"),
        ]
        capture = HarScanner.parse_dict(_build_har(entries))
        surface = capture.extract_api_surface()
        assert len(surface.groups) == 1
        grp = surface.groups[0]
        assert grp.path_template == "/items/{numeric}"
        assert grp.statuses == [200, 404]
        assert grp.content_types == ["application/json", "text/plain"]
        assert "mixed-statuses" in grp.flags
        assert "mixed-content-types" in grp.flags
        assert "single-sample" not in grp.flags

    def test_single_sample_flag(self) -> None:
        entry = _build_entry("https://api.test/unique")
        capture = HarScanner.parse_dict(_build_har([entry]))
        surface = capture.extract_api_surface()
        assert "single-sample" in surface.groups[0].flags

    def test_auth_scheme_detection(self) -> None:
        entries = [
            _build_entry(
                "https://api.test/secure/1",
                headers=[{"name": "Authorization", "value": "Bearer token123"}],
            ),
            _build_entry(
                "https://api.test/secure/2",
                headers=[{"name": "X-API-Key", "value": "keyabc"}],
            ),
        ]
        capture = HarScanner.parse_dict(_build_har(entries))
        surface = capture.extract_api_surface()
        assert len(surface.groups) == 1
        grp = surface.groups[0]
        assert "bearer" in grp.auth_types
        assert "api_key" in grp.auth_types


class TestQueryParameterExtraction:
    """Tests for WHATWG query parameter decoding and ordinal tracking."""

    def test_query_parameter_decoding_and_ordinals(self) -> None:
        entries = [
            _build_entry(
                "https://api.test/products?b=1&a+b=2&a%2Bb=3&=4&%E9%9B%AA=5&b=6&&%FF=7&__proto__=8#ignored=9"
            ),
            _build_entry("https://api.test/products?b=10"),
            _build_entry("https://api.test/health"),
        ]
        capture = HarScanner.parse_dict(_build_har(entries))
        surface = capture.extract_api_surface(include_query_params=True)

        prod_group = next(g for g in surface.groups if g.path_template == "/products")
        names_map = {q.name: q.record_ordinals for q in prod_group.query_parameter_names}

        assert "" in names_map
        assert names_map[""] == [0]
        assert "__proto__" in names_map
        assert names_map["__proto__"] == [0]
        assert "a b" in names_map
        assert names_map["a b"] == [0]
        assert "a+b" in names_map
        assert names_map["a+b"] == [0]
        assert "b" in names_map
        assert names_map["b"] == [0, 1]  # Observed across records 0 and 1
        assert "雪" in names_map
        assert "\ufffd" in names_map

        # Health endpoint should have empty query params
        health_group = next(g for g in surface.groups if g.path_template == "/health")
        assert health_group.query_parameter_names == []


class TestExcludedRecordsAndPagination:
    """Tests for excluded record reporting and surface pagination."""

    def test_excluded_records_categorization(self) -> None:
        entries = [
            _build_entry("https://api.test/valid"),
            {"startedDateTime": "2026-10-14T00:00:00Z", "time": 10},  # request-unavailable
            _build_entry("https://api.test/empty_method", method=""),  # method-unavailable
            _build_entry(""),  # url-redacted
            _build_entry("/relative/path/no/host"),  # url-unparseable
            _build_entry("https://bad\nhost.com/test"),  # url-unparseable (newline in host)
        ]
        capture = HarScanner.parse_dict(_build_har(entries))
        surface = capture.extract_api_surface()

        assert len(surface.groups) == 1
        assert surface.groups[0].path_template == "/valid"
        assert len(surface.excluded_records) == 5

        reasons = {e.reason for e in surface.excluded_records}
        assert "request-unavailable" in reasons
        assert "method-unavailable" in reasons
        assert "url-redacted" in reasons
        assert "url-unparseable" in reasons

    def test_pagination_coverage(self) -> None:
        urls = [f"https://api.test/route{i}" for i in range(15)]
        entries = [_build_entry(u) for u in urls]
        capture = HarScanner.parse_dict(_build_har(entries))

        page1 = capture.extract_api_surface(offset=0, limit=5)
        assert len(page1.groups) == 5
        assert page1.coverage["offset"] == 0
        assert page1.coverage["limit"] == 5
        assert page1.coverage["examined"] == 5
        assert page1.coverage["total"] == 15
        assert page1.coverage["exhausted"] is False
        assert page1.coverage["next_offset"] == 5

        page3 = capture.extract_api_surface(offset=10, limit=5)
        assert len(page3.groups) == 5
        assert page3.coverage["exhausted"] is True
        assert page3.coverage["next_offset"] is None


class TestFileIoAndSerialization:
    """Tests for file-based scanning and dictionary serialization."""

    def test_scan_file_and_to_dict(self, tmp_path: Path) -> None:
        har_data = _build_har([
            _build_entry("https://api.test/v1/users/42"),
            _build_entry("https://api.test/v1/users/99"),
        ])
        har_file = tmp_path / "test_session.har"
        har_file.write_text(json.dumps(har_data), encoding="utf-8")

        result = HarScanner.scan_file(har_file)
        assert isinstance(result, ApiSurfaceResult)
        assert len(result.groups) == 1
        assert result.groups[0].path_template == "/v1/users/{numeric}"

        as_dict = result.to_dict()
        assert "groups" in as_dict
        assert as_dict["templated_groups_count"] == 1
        assert as_dict["records"]["total"] == 2
        assert as_dict["records"]["examined"] == 2
        assert as_dict["records"]["excluded"] == 0
