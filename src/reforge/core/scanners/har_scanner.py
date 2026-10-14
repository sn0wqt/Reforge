"""Pure-Python HTTP Archive (HAR 1.2) capture reader and API surface extractor.

Ported and adapted for Reforge from REA's historical capture and analysis views.
Provides offline parsing, credential and sensitive-value redaction, base64 payload
inspection, and deterministic API surface extraction (methods, origins, path templating,
query parameters, authentication schemes, response statuses, and MIME essences).
"""

from __future__ import annotations

import base64
import datetime
import hashlib
import json
import re
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

CREDENTIAL_HEADERS: frozenset[str] = frozenset(
    {
        "authorization",
        "proxy-authorization",
        "cookie",
        "set-cookie",
    }
)

API_KEY_HEADERS: frozenset[str] = frozenset(
    {
        "x-api-key",
        "api-key",
        "apikey",
        "x-auth-token",
        "x-access-token",
        "x-token",
    }
)

MEDIA_TYPE_ESSENCE_RE = re.compile(r"^[A-Za-z0-9!#$%&'*+.^_`|~-]+/[A-Za-z0-9!#$%&'*+.^_`|~-]+$")
UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
HEX_RE = re.compile(r"^[0-9a-fA-F]{32,}$")
NUMERIC_RE = re.compile(r"^[0-9]+$")
DATE_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$")


class HarParseError(Exception):
    """Raised when HAR input violates the required structure or schema."""

    def __init__(self, message: str, pointer: str = "") -> None:
        super().__init__(message)
        self.pointer = pointer


@dataclass(frozen=True)
class HarHeader:
    """HTTP header name-value pair."""

    name: str
    value: str
    comment: str | None = None

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {"name": self.name, "value": self.value}
        if self.comment is not None:
            result["comment"] = self.comment
        return result


@dataclass(frozen=True)
class HarCookie:
    """HTTP cookie."""

    name: str
    value: str
    path: str | None = None
    domain: str | None = None
    expires: str | None = None
    http_only: bool = False
    secure: bool = False
    comment: str | None = None

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {"name": self.name, "value": self.value}
        if self.path is not None:
            result["path"] = self.path
        if self.domain is not None:
            result["domain"] = self.domain
        if self.expires is not None:
            result["expires"] = self.expires
        if self.http_only:
            result["httpOnly"] = self.http_only
        if self.secure:
            result["secure"] = self.secure
        if self.comment is not None:
            result["comment"] = self.comment
        return result


@dataclass(frozen=True)
class HarPostParam:
    """POST data parameter."""

    name: str
    value: str | None = None
    file_name: str | None = None
    content_type: str | None = None
    comment: str | None = None

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {"name": self.name}
        if self.value is not None:
            result["value"] = self.value
        if self.file_name is not None:
            result["fileName"] = self.file_name
        if self.content_type is not None:
            result["contentType"] = self.content_type
        if self.comment is not None:
            result["comment"] = self.comment
        return result


@dataclass(frozen=True)
class HarPostData:
    """POST data container."""

    mime_type: str
    text: str | None = None
    params: list[HarPostParam] = field(default_factory=list)
    comment: str | None = None

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {"mimeType": self.mime_type, "text": self.text}
        if self.params:
            result["params"] = [p.to_dict() for p in self.params]
        if self.comment is not None:
            result["comment"] = self.comment
        return result


@dataclass(frozen=True)
class HarRequest:
    """Parsed HTTP request from a HAR entry."""

    method: str
    url: str
    http_version: str
    headers: list[HarHeader] = field(default_factory=list)
    cookies: list[HarCookie] = field(default_factory=list)
    query_string: list[dict[str, str]] = field(default_factory=list)
    post_data: HarPostData | None = None
    headers_size: int = -1
    body_size: int = -1
    auth_types: tuple[str, ...] = field(default_factory=tuple)
    comment: str | None = None

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "method": self.method,
            "url": self.url,
            "httpVersion": self.http_version,
            "headers": [h.to_dict() for h in self.headers],
            "cookies": [c.to_dict() for c in self.cookies],
            "queryString": self.query_string,
            "headersSize": self.headers_size,
            "bodySize": self.body_size,
        }
        if self.auth_types:
            result["authTypes"] = list(self.auth_types)
        if self.post_data is not None:
            result["postData"] = self.post_data.to_dict()
        if self.comment is not None:
            result["comment"] = self.comment
        return result


@dataclass(frozen=True)
class HarResponse:
    """Parsed HTTP response from a HAR entry."""

    status: int
    status_text: str
    http_version: str
    headers: list[HarHeader] = field(default_factory=list)
    cookies: list[HarCookie] = field(default_factory=list)
    content_mime_type: str = ""
    content_size: int = -1
    content_text: str | None = None
    content_encoding: str | None = None
    redirect_url: str = ""
    headers_size: int = -1
    body_size: int = -1
    comment: str | None = None

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "status": self.status,
            "statusText": self.status_text,
            "httpVersion": self.http_version,
            "headers": [h.to_dict() for h in self.headers],
            "cookies": [c.to_dict() for c in self.cookies],
            "content": {
                "size": self.content_size,
                "mimeType": self.content_mime_type,
                "text": self.content_text,
                "encoding": self.content_encoding,
            },
            "redirectURL": self.redirect_url,
            "headersSize": self.headers_size,
            "bodySize": self.body_size,
        }
        if self.comment is not None:
            result["comment"] = self.comment
        return result


@dataclass(frozen=True)
class HarBinaryField:
    """Binary field extracted from base64 response content."""

    pointer: str
    representation: str
    state: str
    content_base64: str | None
    bytes_length: int | None
    sha256: str | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "pointer": self.pointer,
            "representation": self.representation,
            "state": self.state,
            "content_base64": self.content_base64,
            "bytes": self.bytes_length,
            "sha256": self.sha256,
        }


@dataclass(frozen=True)
class HarRedaction:
    """Record of a sensitive value or credential redaction."""

    pointer: str
    reason: str
    scope: str | None = None

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {"pointer": self.pointer, "reason": self.reason}
        if self.scope is not None:
            result["scope"] = self.scope
        return result


@dataclass(frozen=True)
class HarRecord:
    """Complete parsed and sanitized HAR entry record."""

    ordinal: int
    request: HarRequest | None
    response: HarResponse | None
    started_date_time: str | None = None
    time_ms: float = 0.0
    server_ip_address: str | None = None
    connection: str | None = None
    binary_fields: list[HarBinaryField] = field(default_factory=list)
    redactions: list[HarRedaction] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ordinal": self.ordinal,
            "startedDateTime": self.started_date_time,
            "time": self.time_ms,
            "request": self.request.to_dict() if self.request is not None else None,
            "response": self.response.to_dict() if self.response is not None else None,
            "serverIPAddress": self.server_ip_address,
            "connection": self.connection,
            "binary_fields": [b.to_dict() for b in self.binary_fields],
            "redactions": [r.to_dict() for r in self.redactions],
            "limitations": self.limitations,
        }


@dataclass(frozen=True)
class HarCapture:
    """Parsed HAR capture file contents."""

    version: str
    creator_name: str
    creator_version: str
    total_records: int
    records: list[HarRecord]
    limitations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "creator": {"name": self.creator_name, "version": self.creator_version},
            "total_records": self.total_records,
            "records": [r.to_dict() for r in self.records],
            "limitations": self.limitations,
        }

    def extract_api_surface(
        self,
        include_query_params: bool = True,
        offset: int = 0,
        limit: int = 50,
    ) -> ApiSurfaceResult:
        """Derive the API surface view from this capture's records."""
        return HarScanner.extract_api_surface(
            self.records,
            include_query_params=include_query_params,
            offset=offset,
            limit=limit,
        )


@dataclass(frozen=True)
class TemplatedSegment:
    """Information about a templated URI path segment."""

    segment_index: int
    rule: str  # "numeric" | "uuid" | "hex" | "iso-date"
    basis: str = "inferred"
    observed_values: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "segment_index": self.segment_index,
            "rule": self.rule,
            "basis": self.basis,
            "observed_values": self.observed_values,
        }


@dataclass(frozen=True)
class QueryParamInfo:
    """Distinct query parameter name observed on an endpoint."""

    name: str
    record_ordinals: list[int]

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "record_ordinals": self.record_ordinals,
        }


@dataclass(frozen=True)
class ApiEndpointGroup:
    """Distinct grouped API surface endpoint."""

    method: str
    origin: str
    path_template: str
    templated_segments: list[TemplatedSegment]
    record_ordinals: list[int]
    statuses: list[int]
    content_types: list[str]
    query_parameter_names: list[QueryParamInfo] = field(default_factory=list)
    auth_types: list[str] = field(default_factory=list)
    flags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "method": self.method,
            "origin": self.origin,
            "path_template": self.path_template,
            "templated_segments": [s.to_dict() for s in self.templated_segments],
            "record_ordinals": self.record_ordinals,
            "statuses": self.statuses,
            "content_types": self.content_types,
            "flags": self.flags,
        }
        if self.query_parameter_names:
            result["query_parameter_names"] = [q.to_dict() for q in self.query_parameter_names]
        if self.auth_types:
            result["auth_types"] = self.auth_types
        return result


@dataclass(frozen=True)
class ExcludedRecord:
    """Record excluded from the API surface and the reason why."""

    ordinal: int
    reason: str  # "url-redacted" | "url-unparseable" | "request-unavailable" | "method-unavailable"

    def to_dict(self) -> dict[str, Any]:
        return {"ordinal": self.ordinal, "reason": self.reason}


@dataclass(frozen=True)
class ApiSurfaceResult:
    """Result of API surface extraction."""

    groups: list[ApiEndpointGroup]
    templated_groups_count: int
    total_records: int
    examined_records: int
    excluded_records: list[ExcludedRecord]
    limitations: list[str]
    coverage: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "groups": [g.to_dict() for g in self.groups],
            "templated_groups_count": self.templated_groups_count,
            "records": {
                "examined": self.examined_records,
                "total": self.total_records,
                "excluded": len(self.excluded_records),
            },
            "excluded_records": [e.to_dict() for e in self.excluded_records],
            "limitations": self.limitations,
            "coverage": self.coverage,
        }


def _detect_segment_rule(val: str) -> str | None:
    """Apply path templating rules in REA priority order: numeric -> uuid -> hex -> iso-date."""
    if NUMERIC_RE.match(val):
        return "numeric"
    if UUID_RE.match(val):
        return "uuid"
    if HEX_RE.match(val):
        return "hex"
    if DATE_RE.match(val):
        try:
            d = datetime.date.fromisoformat(val)
            if d.strftime("%Y-%m-%d") == val:
                return "iso-date"
        except ValueError:
            pass
    return None


def _extract_media_type_essence(raw: str | None) -> str | None:
    """Extract lowercase media-type essence (type/subtype) without parameters."""
    if not raw:
        return None
    part = raw.split(";", 1)[0].strip(" \t")
    if MEDIA_TYPE_ESSENCE_RE.match(part):
        return part.lower()
    return None


def _decode_query_param_names(query: str) -> list[str]:
    """WHATWG form-query parameter name decoding: preserve order, empty names, UTF-8 percent-decoding."""
    names: list[str] = []
    for pair in query.split("&"):
        if not pair:
            continue
        raw_name = pair.split("=", 1)[0]
        # Form-query decoding: literal '+' becomes space before percent-decoding
        name_with_spaces = raw_name.replace("+", " ")
        decoded = urllib.parse.unquote(name_with_spaces, errors="replace")
        names.append(decoded)
    return names


class HarScanner:
    """Zero-dependency pure-Python HAR 1.2 capture reader and API surface extractor."""

    @classmethod
    def parse_file(
        cls,
        path: str | Path,
        sensitive_values: list[str] | None = None,
    ) -> HarCapture:
        """Parse a HAR JSON file from disk."""
        content = Path(path).read_text(encoding="utf-8")
        return cls.parse_text(content, sensitive_values=sensitive_values)

    @classmethod
    def parse_text(
        cls,
        text: str,
        sensitive_values: list[str] | None = None,
    ) -> HarCapture:
        """Parse a HAR JSON string."""
        try:
            data = json.loads(text)
        except Exception as err:
            raise HarParseError(f"Malformed JSON in HAR: {err}") from err
        if not isinstance(data, dict):
            raise HarParseError("HAR root must be a JSON object.")
        return cls.parse_dict(data, sensitive_values=sensitive_values)

    @classmethod
    def parse_dict(
        cls,
        data: dict[str, Any],
        sensitive_values: list[str] | None = None,
    ) -> HarCapture:
        """Parse and validate a HAR dictionary."""
        sensitives = sensitive_values or []

        log = data.get("log")
        if not isinstance(log, dict):
            raise HarParseError("HAR must contain log object.", pointer="/log")

        version = log.get("version")
        if version != "1.2":
            raise HarParseError(
                f"Only the pinned HAR 1.2 schema profile is supported (observed {version!r}).",
                pointer="/log/version",
            )

        entries = log.get("entries")
        if not isinstance(entries, list):
            raise HarParseError("HAR log must contain entries array.", pointer="/log/entries")

        creator = log.get("creator", {})
        creator_name = creator.get("name", "unknown") if isinstance(creator, dict) else "unknown"
        creator_version = creator.get("version", "unknown") if isinstance(creator, dict) else "unknown"

        records: list[HarRecord] = []
        limitations: list[str] = [
            "HAR text is producer-decoded Unicode. Original body bytes remain unknown unless "
            "content explicitly uses valid base64; declared sizes are preserved independently of retained bytes.",
        ]

        for ordinal, entry in enumerate(entries):
            records.append(cls._parse_entry(ordinal, entry, sensitives, creator_name))

        return HarCapture(
            version="1.2",
            creator_name=creator_name,
            creator_version=creator_version,
            total_records=len(records),
            records=records,
            limitations=limitations,
        )

    @classmethod
    def _parse_entry(
        cls,
        ordinal: int,
        entry: Any,
        sensitive_values: list[str],
        creator_name: str,
    ) -> HarRecord:
        """Parse a single HAR log entry with redaction and binary field tracking."""
        redactions: list[HarRedaction] = []
        binary_fields: list[HarBinaryField] = []
        record_limitations: list[str] = []

        if not isinstance(entry, dict):
            redactions.append(HarRedaction(pointer=f"/log/entries/{ordinal}", reason="malformed-entry"))
            return HarRecord(
                ordinal=ordinal,
                request=None,
                response=None,
                redactions=redactions,
            )

        started_date_time = entry.get("startedDateTime")
        time_ms = float(entry.get("time", 0.0))
        server_ip = entry.get("serverIPAddress")
        connection = entry.get("connection")

        # Playwright 1.58.2 quirk: IPv6 bracketed serverIPAddress
        if server_ip and isinstance(server_ip, str) and server_ip.startswith("[") and server_ip.endswith("]"):
            record_limitations.append(
                "Observed bracketed IPv6 serverIPAddress; brackets were normalized for address inspection."
            )

        # 1. Parse Request
        raw_req = entry.get("request")
        parsed_request: HarRequest | None = None
        if isinstance(raw_req, dict):
            raw_url = raw_req.get("url")
            req_url = str(raw_url) if raw_url is not None else ""
            req_method = str(raw_req.get("method", ""))
            http_version = str(raw_req.get("httpVersion", "HTTP/1.1"))

            # Transport URL userinfo credential sanitization
            if req_url:
                parsed_split = urllib.parse.urlsplit(req_url)
                if "@" in parsed_split.netloc:
                    clean_netloc = parsed_split.netloc.rsplit("@", 1)[-1]
                    req_url = urllib.parse.urlunsplit(
                        (
                            parsed_split.scheme,
                            clean_netloc,
                            parsed_split.path,
                            parsed_split.query,
                            parsed_split.fragment,
                        )
                    )
                    redactions.append(HarRedaction(pointer="/request/url", reason="transport-credential"))

            # Redact explicit sensitive values from URL
            for s in sensitive_values:
                if s in req_url:
                    req_url = req_url.replace(s, "[REDACTED]")
                    redactions.append(HarRedaction(pointer="/request/url", reason="explicit-sensitive-value"))

            # Request Headers
            headers: list[HarHeader] = []
            auth_schemes: list[str] = []
            for h_idx, h in enumerate(raw_req.get("headers", [])):
                if not isinstance(h, dict):
                    continue
                h_name = str(h.get("name", ""))
                h_val = str(h.get("value", ""))
                ptr = f"/request/headers/{h_idx}/value"
                lower_name = h_name.lower()

                if lower_name == "authorization":
                    val_strip = h_val.strip()
                    prefix = val_strip.split(" ", 1)[0].lower() if " " in val_strip else val_strip.lower()
                    if prefix in {"bearer", "basic", "digest", "negotiate", "ntlm", "aws4-hmac-sha256"}:
                        auth_schemes.append(prefix)
                    else:
                        auth_schemes.append("authorization")
                elif lower_name in API_KEY_HEADERS:
                    auth_schemes.append("api_key")
                elif lower_name == "cookie":
                    auth_schemes.append("cookie")

                if lower_name in CREDENTIAL_HEADERS:
                    h_val = "[REDACTED]"
                    redactions.append(HarRedaction(pointer=ptr, reason="transport-credential"))
                else:
                    for s in sensitive_values:
                        if s in h_val:
                            h_val = "[REDACTED]"
                            redactions.append(HarRedaction(pointer=ptr, reason="explicit-sensitive-value"))
                            break
                headers.append(HarHeader(name=h_name, value=h_val, comment=h.get("comment")))

            # Request Cookies
            cookies: list[HarCookie] = []
            for c_idx, c in enumerate(raw_req.get("cookies", [])):
                if not isinstance(c, dict):
                    continue
                c_name = str(c.get("name", ""))
                redactions.append(
                    HarRedaction(pointer=f"/request/cookies/{c_idx}/value", reason="transport-credential")
                )
                cookies.append(
                    HarCookie(
                        name=c_name,
                        value="[REDACTED]",
                        path=c.get("path"),
                        domain=c.get("domain"),
                        expires=c.get("expires"),
                        http_only=bool(c.get("httpOnly", False)),
                        secure=bool(c.get("secure", False)),
                        comment=c.get("comment"),
                    )
                )

            # Request PostData (with Mitmproxy SaveHar text: null quirk tolerance)
            post_data: HarPostData | None = None
            raw_post = raw_req.get("postData")
            if isinstance(raw_post, dict):
                pd_text = raw_post.get("text")
                if pd_text is not None:
                    pd_text = str(pd_text)
                    for s in sensitive_values:
                        if s in pd_text:
                            pd_text = "[REDACTED]"
                            redactions.append(
                                HarRedaction(pointer="/request/postData/text", reason="explicit-sensitive-value")
                            )
                            break
                params: list[HarPostParam] = []
                for p in raw_post.get("params", []):
                    if isinstance(p, dict):
                        params.append(
                            HarPostParam(
                                name=str(p.get("name", "")),
                                value=p.get("value"),
                                file_name=p.get("fileName"),
                                content_type=p.get("contentType"),
                                comment=p.get("comment"),
                            )
                        )
                post_data = HarPostData(
                    mime_type=str(raw_post.get("mimeType", "")),
                    text=pd_text,
                    params=params,
                    comment=raw_post.get("comment"),
                )

            parsed_request = HarRequest(
                method=req_method,
                url=req_url,
                http_version=http_version,
                headers=headers,
                cookies=cookies,
                query_string=raw_req.get("queryString", []),
                post_data=post_data,
                headers_size=int(raw_req.get("headersSize", -1)),
                body_size=int(raw_req.get("bodySize", -1)),
                auth_types=tuple(sorted(set(auth_schemes))),
                comment=raw_req.get("comment"),
            )

        # 2. Parse Response
        raw_resp = entry.get("response")
        parsed_response: HarResponse | None = None
        if isinstance(raw_resp, dict):
            status = int(raw_resp.get("status", 0))
            status_text = str(raw_resp.get("statusText", ""))
            resp_http = str(raw_resp.get("httpVersion", "HTTP/1.1"))
            redirect_url = str(raw_resp.get("redirectURL", ""))

            # Response Headers
            resp_headers: list[HarHeader] = []
            for h_idx, h in enumerate(raw_resp.get("headers", [])):
                if not isinstance(h, dict):
                    continue
                h_name = str(h.get("name", ""))
                h_val = str(h.get("value", ""))
                ptr = f"/response/headers/{h_idx}/value"
                if h_name.lower() in CREDENTIAL_HEADERS:
                    h_val = "[REDACTED]"
                    redactions.append(HarRedaction(pointer=ptr, reason="transport-credential"))
                else:
                    for s in sensitive_values:
                        if s in h_val:
                            h_val = "[REDACTED]"
                            redactions.append(HarRedaction(pointer=ptr, reason="explicit-sensitive-value"))
                            break
                resp_headers.append(HarHeader(name=h_name, value=h_val, comment=h.get("comment")))

            # Response Cookies
            resp_cookies: list[HarCookie] = []
            for c_idx, c in enumerate(raw_resp.get("cookies", [])):
                if not isinstance(c, dict):
                    continue
                c_name = str(c.get("name", ""))
                redactions.append(
                    HarRedaction(pointer=f"/response/cookies/{c_idx}/value", reason="transport-credential")
                )
                resp_cookies.append(
                    HarCookie(
                        name=c_name,
                        value="[REDACTED]",
                        path=c.get("path"),
                        domain=c.get("domain"),
                        expires=c.get("expires"),
                        http_only=bool(c.get("httpOnly", False)),
                        secure=bool(c.get("secure", False)),
                        comment=c.get("comment"),
                    )
                )

            # Response Content
            raw_content = raw_resp.get("content", {})
            content_mime = ""
            content_size = -1
            content_text: str | None = None
            content_encoding: str | None = None
            if isinstance(raw_content, dict):
                content_mime = str(raw_content.get("mimeType", ""))
                content_size = int(raw_content.get("size", -1))
                content_text = raw_content.get("text")
                content_encoding = raw_content.get("encoding")

                # Base64 response payload inspection
                if content_encoding == "base64" and content_text is not None:
                    try:
                        clean_b64 = re.sub(r"[\t\n\r ]", "", content_text)
                        decoded_bytes = base64.b64decode(clean_b64, validate=True)
                        sha = hashlib.sha256(decoded_bytes).hexdigest()
                        is_sensitive = any(
                            s.encode("utf-8") in decoded_bytes or s in clean_b64 or s in sha for s in sensitive_values
                        )
                        if is_sensitive:
                            redactions.append(
                                HarRedaction(pointer="/response/content/text", reason="explicit-sensitive-value")
                            )
                            binary_fields.append(
                                HarBinaryField(
                                    pointer="/response/content/text",
                                    representation="har-base64-content",
                                    state="redacted",
                                    content_base64=None,
                                    bytes_length=None,
                                    sha256=None,
                                )
                            )
                            content_text = None
                        else:
                            binary_fields.append(
                                HarBinaryField(
                                    pointer="/response/content/text",
                                    representation="har-base64-content",
                                    state="retained",
                                    content_base64=clean_b64,
                                    bytes_length=len(decoded_bytes),
                                    sha256=sha,
                                )
                            )
                    except Exception:
                        record_limitations.append("Response content declared base64 but payload could not be decoded.")
                elif content_text is not None:
                    for s in sensitive_values:
                        if s in content_text:
                            content_text = "[REDACTED]"
                            redactions.append(
                                HarRedaction(pointer="/response/content/text", reason="explicit-sensitive-value")
                            )
                            break

            parsed_response = HarResponse(
                status=status,
                status_text=status_text,
                http_version=resp_http,
                headers=resp_headers,
                cookies=resp_cookies,
                content_mime_type=content_mime,
                content_size=content_size,
                content_text=content_text,
                content_encoding=content_encoding,
                redirect_url=redirect_url,
                headers_size=int(raw_resp.get("headersSize", -1)),
                body_size=int(raw_resp.get("bodySize", -1)),
                comment=raw_resp.get("comment"),
            )

        return HarRecord(
            ordinal=ordinal,
            request=parsed_request,
            response=parsed_response,
            started_date_time=started_date_time,
            time_ms=time_ms,
            server_ip_address=server_ip,
            connection=connection,
            binary_fields=binary_fields,
            redactions=redactions,
            limitations=record_limitations,
        )

    @classmethod
    def extract_api_surface(
        cls,
        records: list[HarRecord],
        include_query_params: bool = True,
        offset: int = 0,
        limit: int = 50,
    ) -> ApiSurfaceResult:
        """Derive distinct API endpoints, path templates, and metadata from HAR records."""
        # Buckets: key -> _GroupAccumulator
        groups_map: dict[tuple[str, str, str, str], _GroupAccumulator] = {}
        excluded: list[ExcludedRecord] = []
        has_unavailable_response = False

        for rec in records:
            if rec.request is None:
                excluded.append(ExcludedRecord(rec.ordinal, "request-unavailable"))
                continue

            req = rec.request
            if not req.method:
                excluded.append(ExcludedRecord(rec.ordinal, "method-unavailable"))
                continue

            if not req.url:
                excluded.append(ExcludedRecord(rec.ordinal, "url-redacted"))
                continue

            # Parse transport URL without dot-segment normalization
            url = req.url
            if "\t" in url or "\n" in url or "\r" in url:
                excluded.append(ExcludedRecord(rec.ordinal, "url-unparseable"))
                continue

            split = urllib.parse.urlsplit(url)

            # Check for unparseable authority or missing scheme/host
            if not split.scheme or not split.netloc:
                excluded.append(ExcludedRecord(rec.ordinal, "url-unparseable"))
                continue

            clean_netloc = split.netloc.rsplit("@", 1)[-1] if "@" in split.netloc else split.netloc
            origin = f"{split.scheme}://{clean_netloc}"
            raw_path = split.path if split.path else "/"
            if not raw_path.startswith("/"):
                raw_path = "/" + raw_path

            # Path Templating
            template, rules_sig, templated_segs = cls._template_path(raw_path)

            bucket_key = (req.method.upper(), origin, template, rules_sig)
            if bucket_key not in groups_map:
                groups_map[bucket_key] = _GroupAccumulator(
                    method=req.method.upper(),
                    origin=origin,
                    path_template=template,
                    templated_segments=templated_segs,
                )
            accum = groups_map[bucket_key]
            accum.record_ordinals.append(rec.ordinal)

            # Track segment observed values
            for seg in templated_segs:
                if seg.segment_index in accum.segment_values:
                    accum.segment_values[seg.segment_index].update(seg.observed_values)
                else:
                    accum.segment_values[seg.segment_index] = set(seg.observed_values)

            # Response Status & MIME essence
            if rec.response is not None:
                if rec.response.status > 0:
                    accum.statuses.add(rec.response.status)
                else:
                    has_unavailable_response = True
                essence = _extract_media_type_essence(rec.response.content_mime_type)
                if essence:
                    accum.content_types.add(essence)
                elif rec.response.content_mime_type:
                    has_unavailable_response = True
            else:
                has_unavailable_response = True

            # Query Parameter Names
            if include_query_params:
                observed_query_names = set(_decode_query_param_names(split.query))
                for qname in observed_query_names:
                    if qname not in accum.query_names:
                        accum.query_names[qname] = []
                    accum.query_names[qname].append(rec.ordinal)

            # Auth Scheme Detection
            accum.auth_types.update(req.auth_types)

        # Materialize groups
        all_groups: list[ApiEndpointGroup] = []
        for accum in groups_map.values():
            # Build finalized templated segments
            final_segs: list[TemplatedSegment] = []
            for seg in accum.templated_segments:
                observed = sorted(accum.segment_values.get(seg.segment_index, set()))
                final_segs.append(
                    TemplatedSegment(
                        segment_index=seg.segment_index,
                        rule=seg.rule,
                        basis="inferred",
                        observed_values=observed,
                    )
                )

            flags: list[str] = []
            if len(accum.record_ordinals) == 1:
                flags.append("single-sample")
            if len(accum.statuses) > 1:
                flags.append("mixed-statuses")
            if len(accum.content_types) > 1:
                flags.append("mixed-content-types")

            # Finalize query param names sorted by Unicode code point
            query_params: list[QueryParamInfo] = []
            if include_query_params:
                for qname in sorted(accum.query_names.keys()):
                    query_params.append(
                        QueryParamInfo(
                            name=qname,
                            record_ordinals=sorted(accum.query_names[qname]),
                        )
                    )

            all_groups.append(
                ApiEndpointGroup(
                    method=accum.method,
                    origin=accum.origin,
                    path_template=accum.path_template,
                    templated_segments=final_segs,
                    record_ordinals=sorted(accum.record_ordinals),
                    statuses=sorted(accum.statuses),
                    content_types=sorted(accum.content_types),
                    query_parameter_names=query_params,
                    auth_types=sorted(accum.auth_types),
                    flags=flags,
                )
            )

        # Sort all groups by origin -> path_template -> method
        all_groups.sort(key=lambda g: (g.origin, g.path_template, g.method))

        templated_count = sum(1 for g in all_groups if g.templated_segments)
        paged_groups = all_groups[offset : offset + limit]

        limitations: list[str] = [
            "Grouping does not establish handler identity, URL-space schemas or causality.",
        ]
        if include_query_params:
            limitations.append(
                "Observed query parameter names do not establish required parameters, "
                "value types or a complete API schema."
            )
        if has_unavailable_response:
            limitations.append("Some retained records have unavailable status or content type values.")

        coverage = {
            "offset": offset,
            "limit": limit,
            "examined": len(paged_groups),
            "total": len(all_groups),
            "exhausted": offset + len(paged_groups) >= len(all_groups),
            "next_offset": (offset + len(paged_groups)) if (offset + len(paged_groups) < len(all_groups)) else None,
        }

        return ApiSurfaceResult(
            groups=paged_groups,
            templated_groups_count=templated_count,
            total_records=len(records),
            examined_records=len(records) - len(excluded),
            excluded_records=excluded,
            limitations=limitations,
            coverage=coverage,
        )

    @classmethod
    def _template_path(cls, path: str) -> tuple[str, str, list[TemplatedSegment]]:
        """Template path segments and produce rules signature.

        Segment index starts at 0 after the leading slash.
        """
        if path == "/" or not path:
            return "/", "", []

        # Split on '/' ignoring leading slash
        raw_parts = path.lstrip("/").split("/")
        templated_parts: list[str] = []
        rules_sig_parts: list[str] = []
        segments: list[TemplatedSegment] = []

        for idx, part in enumerate(raw_parts):
            rule = _detect_segment_rule(part)
            if rule is not None:
                placeholder = f"{{{rule}}}"
                templated_parts.append(placeholder)
                rules_sig_parts.append(f"{idx}:{rule};")
                segments.append(
                    TemplatedSegment(
                        segment_index=idx,
                        rule=rule,
                        basis="inferred",
                        observed_values=[part],
                    )
                )
            else:
                templated_parts.append(part)

        template_path = "/" + "/".join(templated_parts)
        rules_sig = "".join(rules_sig_parts)
        return template_path, rules_sig, segments

    @classmethod
    def scan_file(
        cls,
        path: str | Path,
        include_query_params: bool = True,
        offset: int = 0,
        limit: int = 50,
        sensitive_values: list[str] | None = None,
    ) -> ApiSurfaceResult:
        """Scan a HAR file directly from disk and return its API surface."""
        capture = cls.parse_file(path, sensitive_values=sensitive_values)
        return cls.extract_api_surface(
            capture.records,
            include_query_params=include_query_params,
            offset=offset,
            limit=limit,
        )


@dataclass
class _GroupAccumulator:
    """Internal mutable accumulator for building an endpoint group."""

    method: str
    origin: str
    path_template: str
    templated_segments: list[TemplatedSegment]
    record_ordinals: list[int] = field(default_factory=list)
    statuses: set[int] = field(default_factory=set)
    content_types: set[str] = field(default_factory=set)
    query_names: dict[str, list[int]] = field(default_factory=dict)
    auth_types: set[str] = field(default_factory=set)
    segment_values: dict[int, set[str]] = field(default_factory=dict)
