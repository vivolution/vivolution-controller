"""Exercise the CP1 administrator session through an explicitly selected TLS socket.

All configuration and credentials arrive as JSON on stdin. Output is restricted to
controlled status/reason values so passwords, CSRF tokens, and session cookies never
appear in argv or qualification logs.
"""

from __future__ import annotations

import http.client
import ipaddress
import json
import re
import socket
import ssl
import sys
from html.parser import HTMLParser
from http.cookies import CookieError, SimpleCookie
from pathlib import Path
from urllib.parse import urlencode, urlsplit

MAX_INPUT_BYTES = 64 * 1024
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
HOSTNAME_RE = re.compile(
    r"(?=^.{1,253}$)^(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)"
    r"(?:\.(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?))*$"
)


class AcceptanceError(Exception):
    """A controlled failure whose code is safe to include in evidence."""


class CsrfTokenParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.token: str | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() != "input" or self.token is not None:
            return
        attributes = dict(attrs)
        if attributes.get("name") == "csrfmiddlewaretoken" and attributes.get("value"):
            self.token = attributes["value"]


class AddressHTTPSConnection(http.client.HTTPSConnection):
    """Connect to one pinned address while preserving Host, SNI, and TLS verification."""

    def __init__(
        self,
        server_name: str,
        connect_address: str,
        port: int,
        *,
        context: ssl.SSLContext,
        timeout: float,
    ) -> None:
        super().__init__(server_name, port, context=context, timeout=timeout)
        self.connect_address = connect_address

    def connect(self) -> None:
        raw_socket = socket.create_connection(
            (self.connect_address, self.port),
            self.timeout,
            self.source_address,
        )
        try:
            self.sock = self._context.wrap_socket(raw_socket, server_hostname=self.host)
        except Exception:
            raw_socket.close()
            raise


def controlled_configuration() -> dict[str, object]:
    raw = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
    if len(raw) > MAX_INPUT_BYTES:
        raise AcceptanceError("input_too_large")
    try:
        configuration = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise AcceptanceError("invalid_input") from None
    if not isinstance(configuration, dict):
        raise AcceptanceError("invalid_input")

    server_name = configuration.get("server_name")
    username = configuration.get("username")
    password = configuration.get("password")
    port = configuration.get("port")
    ca_path_value = configuration.get("ca_path")
    connect_address_value = configuration.get("connect_address")
    if not isinstance(server_name, str) or not HOSTNAME_RE.fullmatch(server_name):
        raise AcceptanceError("invalid_server_name")
    if not isinstance(username, str) or not 1 <= len(username) <= 150:
        raise AcceptanceError("invalid_username")
    if not isinstance(password, str) or not 1 <= len(password) <= 1024:
        raise AcceptanceError("invalid_password")
    if not isinstance(port, int) or not 1 <= port <= 65535:
        raise AcceptanceError("invalid_port")
    if not isinstance(ca_path_value, str) or not ca_path_value.startswith("/"):
        raise AcceptanceError("invalid_ca_path")
    if not isinstance(connect_address_value, str):
        raise AcceptanceError("invalid_connect_address")
    try:
        connect_address = ipaddress.ip_address(connect_address_value)
    except ValueError:
        raise AcceptanceError("invalid_connect_address") from None
    if connect_address.is_unspecified or connect_address.is_multicast:
        raise AcceptanceError("invalid_connect_address")
    try:
        ca_path = Path(ca_path_value).resolve(strict=True)
    except (OSError, RuntimeError):
        raise AcceptanceError("ca_unavailable") from None
    if not ca_path.is_file():
        raise AcceptanceError("ca_unavailable")

    return {
        "server_name": server_name,
        "username": username,
        "password": password,
        "port": port,
        "ca_path": ca_path,
        "connect_address": connect_address.compressed,
    }


class AdminSession:
    def __init__(
        self,
        *,
        server_name: str,
        connect_address: str,
        port: int,
        ca_path: Path,
    ) -> None:
        self.server_name = server_name
        self.connect_address = connect_address
        self.port = port
        self.cookies: dict[str, str] = {}
        self.context = ssl.create_default_context(cafile=str(ca_path))
        self.context.minimum_version = ssl.TLSVersion.TLSv1_2

    @property
    def origin(self) -> str:
        if self.port == 443:
            return f"https://{self.server_name}"
        return f"https://{self.server_name}:{self.port}"

    def cookie_header(self) -> str:
        return "; ".join(f"{name}={value}" for name, value in sorted(self.cookies.items()))

    def absorb_cookies(self, headers: list[tuple[str, str]]) -> None:
        for header_name, header_value in headers:
            if header_name.lower() != "set-cookie":
                continue
            parsed = SimpleCookie()
            try:
                parsed.load(header_value)
            except CookieError:
                raise AcceptanceError("invalid_cookie_response") from None
            for name, morsel in parsed.items():
                if not morsel.value or morsel["max-age"] == "0":
                    self.cookies.pop(name, None)
                else:
                    self.cookies[name] = morsel.value

    def request(
        self,
        method: str,
        path: str,
        *,
        body: bytes | None = None,
        cookie_header: str | None = None,
        referer: str | None = None,
    ) -> tuple[int, list[tuple[str, str]], bytes]:
        headers = {
            "Accept": "text/html,application/xhtml+xml",
            "User-Agent": "Vivolution-CP1-Qualification/1",
        }
        selected_cookie_header = self.cookie_header() if cookie_header is None else cookie_header
        if selected_cookie_header:
            headers["Cookie"] = selected_cookie_header
        if referer:
            headers["Referer"] = referer
        if body is not None:
            headers["Content-Type"] = "application/x-www-form-urlencoded"
            headers["Content-Length"] = str(len(body))

        connection = AddressHTTPSConnection(
            self.server_name,
            self.connect_address,
            self.port,
            context=self.context,
            timeout=5.0,
        )
        try:
            connection.request(method, path, body=body, headers=headers)
            response = connection.getresponse()
            response_body = response.read(MAX_RESPONSE_BYTES + 1)
            if len(response_body) > MAX_RESPONSE_BYTES:
                raise AcceptanceError("response_too_large")
            response_headers = response.getheaders()
            return response.status, response_headers, response_body
        finally:
            connection.close()


def header_value(headers: list[tuple[str, str]], name: str) -> str:
    expected = name.lower()
    for header_name, value in headers:
        if header_name.lower() == expected:
            return value
    return ""


def redirect_path(headers: list[tuple[str, str]]) -> str:
    location = header_value(headers, "Location")
    return urlsplit(location).path if location else ""


def csrf_token(document: bytes) -> str:
    parser = CsrfTokenParser()
    try:
        parser.feed(document.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise AcceptanceError("invalid_html_response") from None
    if parser.token is None or not 32 <= len(parser.token) <= 256:
        raise AcceptanceError("csrf_form_token_missing")
    return parser.token


def qualify(configuration: dict[str, object]) -> None:
    server_name = str(configuration["server_name"])
    username = str(configuration["username"])
    password = str(configuration["password"])
    port = int(configuration["port"])
    connect_address = str(configuration["connect_address"])
    ca_path = configuration["ca_path"]
    if not isinstance(ca_path, Path):
        raise AcceptanceError("invalid_ca_path")

    session = AdminSession(
        server_name=server_name,
        connect_address=connect_address,
        port=port,
        ca_path=ca_path,
    )
    login_path = "/admin/login/?next=/admin/"

    status, headers, login_document = session.request("GET", login_path)
    if status != 200:
        raise AcceptanceError("login_form_unavailable")
    session.absorb_cookies(headers)
    if len(session.cookies.get("csrftoken", "")) < 32:
        raise AcceptanceError("csrf_cookie_missing")
    login_csrf = csrf_token(login_document)

    login_body = urlencode(
        {
            "username": username,
            "password": password,
            "csrfmiddlewaretoken": login_csrf,
            "next": "/admin/",
        }
    ).encode("utf-8")
    status, headers, _ = session.request(
        "POST",
        login_path,
        body=login_body,
        referer=f"{session.origin}{login_path}",
    )
    if status != 302 or redirect_path(headers) != "/admin/":
        raise AcceptanceError("authentication_failed")
    session.absorb_cookies(headers)
    if not session.cookies.get("sessionid") or len(session.cookies.get("csrftoken", "")) < 32:
        raise AcceptanceError("authenticated_session_missing")

    authenticated_cookie_header = session.cookie_header()
    status, _, admin_document = session.request("GET", "/admin/")
    if status != 200:
        raise AcceptanceError("admin_index_unavailable")
    admin_text = admin_document.decode("utf-8", errors="replace")
    if "/admin/logout/" not in admin_text or "Log out" not in admin_text:
        raise AcceptanceError("admin_index_invalid")
    logout_csrf = csrf_token(admin_document)

    logout_body = urlencode({"csrfmiddlewaretoken": logout_csrf}).encode("utf-8")
    status, headers, _ = session.request(
        "POST",
        "/admin/logout/",
        body=logout_body,
        referer=f"{session.origin}/admin/",
    )
    if status not in (200, 302):
        raise AcceptanceError("logout_failed")
    session.absorb_cookies(headers)

    status, headers, _ = session.request(
        "GET",
        "/admin/",
        cookie_header=authenticated_cookie_header,
    )
    if status != 302 or redirect_path(headers) != "/admin/login/":
        raise AcceptanceError("session_not_invalidated")


def emit(status: str, reason: str) -> None:
    print(json.dumps({"reason": reason, "status": status}, sort_keys=True, separators=(",", ":")))


def main() -> int:
    try:
        qualify(controlled_configuration())
    except AcceptanceError as error:
        emit("failed", str(error))
        return 1
    except ssl.SSLError:
        emit("failed", "tls_verification_failed")
        return 2
    except (ConnectionError, OSError, http.client.HTTPException):
        emit("failed", "connection_failed")
        return 2
    except Exception:  # noqa: BLE001 - uncontrolled details must never reach evidence.
        emit("failed", "runtime_error")
        return 2
    emit("passed", "authenticated_session_closed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
