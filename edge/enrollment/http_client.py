#!/usr/bin/env python3
"""Bounded server-authenticated HTTPS transport for outbound Edge enrollment."""

from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Mapping, Sequence

from .core import (
    AGENT_VERSION,
    MAX_SAFE_INTEGER,
    EnrollmentError,
    canonical_json_bytes,
    normalize_controller_url,
    validate_enrollment_grant,
)

MAX_REQUEST_BYTES = 64 * 1024
MAX_RESPONSE_BYTES = 64 * 1024


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        return None


def _duplicate_rejecting_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise EnrollmentError("controller response contains a duplicate JSON member")
        result[key] = value
    return result


def _forbid_float(value: str) -> float:
    raise EnrollmentError("controller response contains a floating-point value")


def _forbid_constant(value: str) -> None:
    raise EnrollmentError("controller response contains a non-finite number")


def parse_response_json(content: bytes) -> dict[str, Any]:
    try:
        decoded = content.decode("utf-8")
        value = json.loads(
            decoded,
            object_pairs_hook=_duplicate_rejecting_object,
            parse_float=_forbid_float,
            parse_constant=_forbid_constant,
        )
    except UnicodeError as exc:
        raise EnrollmentError("controller response is not valid UTF-8 JSON") from exc
    except json.JSONDecodeError as exc:
        raise EnrollmentError("controller response is not valid UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise EnrollmentError("controller response must be one JSON object")

    def inspect(item: Any) -> None:
        if isinstance(item, bool) or item is None or isinstance(item, str):
            return
        if isinstance(item, int):
            if abs(item) > MAX_SAFE_INTEGER:
                raise EnrollmentError("controller response integer exceeds the v1 limit")
            return
        if isinstance(item, list):
            for member in item:
                inspect(member)
            return
        if isinstance(item, dict):
            for key, member in item.items():
                try:
                    key.encode("ascii")
                except UnicodeEncodeError as exc:
                    raise EnrollmentError(
                        "controller response member names must be ASCII"
                    ) from exc
                inspect(member)
            return
        raise EnrollmentError("controller response contains an unsupported JSON value")

    inspect(value)
    return value


class HTTPSJSONTransport:
    """POST exact canonical JSON over TLS without redirects or env proxies."""

    def __init__(
        self,
        controller_url: str,
        *,
        ca_file: Path | None = None,
        timeout_seconds: int = 15,
        opener: Any | None = None,
    ) -> None:
        self.controller_url = normalize_controller_url(controller_url)
        if isinstance(timeout_seconds, bool) or not 1 <= timeout_seconds <= 60:
            raise EnrollmentError("HTTPS timeout must be between 1 and 60 seconds")
        self.timeout_seconds = timeout_seconds
        if opener is None:
            context = ssl.create_default_context(cafile=str(ca_file) if ca_file else None)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            opener = urllib.request.build_opener(
                urllib.request.ProxyHandler({}),
                _NoRedirect(),
                urllib.request.HTTPSHandler(context=context),
            )
        self._opener = opener

    def post(
        self,
        path: str,
        body: Mapping[str, Any],
        *,
        expected_statuses: Sequence[int] = (200,),
        enrollment_grant: str | None = None,
    ) -> tuple[int, dict[str, Any]]:
        if not path.startswith("/api/edge/v1/") or "?" in path or "#" in path:
            raise EnrollmentError("HTTPS path is outside the Edge v1 API")
        content = canonical_json_bytes(body)
        if len(content) > MAX_REQUEST_BYTES:
            raise EnrollmentError("controller request exceeds the v1 size limit")
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": "vivolution-edge/{}".format(AGENT_VERSION),
        }
        if enrollment_grant is not None:
            # The grant is accepted only by this explicit argument; callers
            # cannot smuggle it into a URL, environment-derived proxy, or log.
            headers["Authorization"] = (
                "Vivolution-Enrollment "
                + validate_enrollment_grant(enrollment_grant)
            )
        request = urllib.request.Request(
            self.controller_url + path,
            data=content,
            headers=headers,
            method="POST",
        )
        try:
            response = self._opener.open(request, timeout=self.timeout_seconds)
            with response:
                status = int(response.status)
                if status not in expected_statuses:
                    raise EnrollmentError(
                        "controller returned unexpected HTTP status {}".format(status)
                    )
                content_type = response.headers.get_content_type()
                if content_type != "application/json":
                    raise EnrollmentError("controller response is not application/json")
                raw = response.read(MAX_RESPONSE_BYTES + 1)
                if len(raw) > MAX_RESPONSE_BYTES:
                    raise EnrollmentError("controller response exceeds the v1 size limit")
        except urllib.error.HTTPError as exc:
            # Never consume or include the untrusted response body: a server or
            # proxy could reflect the Authorization grant into it.
            raise EnrollmentError(
                "controller rejected the request with HTTP status {}".format(exc.code)
            ) from None
        except urllib.error.URLError:
            raise EnrollmentError("controller HTTPS request failed") from None
        except (OSError, TimeoutError):
            raise EnrollmentError("controller HTTPS request failed") from None
        return status, parse_response_json(raw)
