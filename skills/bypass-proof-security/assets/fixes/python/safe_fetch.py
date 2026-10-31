"""safe_fetch.py: SSRF-safe outbound HTTP for Python 3.9+.

Why: "resolve the hostname, check the IP, then requests.get(url)" has a time-of-check /
time-of-use gap. The HTTP library resolves DNS again, and a short-TTL record can answer
public for the check and 127.0.0.1 for the connection (DNS rebinding). Redirects are a
second gap: the check only ran on the first URL.

This module checks the IP *inside the connect call*: the address that's validated is the
address that's dialed. TLS still verifies the certificate against the original hostname,
and every redirect hop opens a new, re-checked connection.

Two clients:
  * guarded_httpx_client(): an httpx.Client (pip install httpx). Recommended.
  * safe_get(): stdlib only (urllib), for scripts without dependencies.

    from safe_fetch import guarded_httpx_client, SSRFBlocked
    with guarded_httpx_client(timeout=10) as client:
        r = client.get(user_url)            # raises SSRFBlocked on any blocked hop

Also note: `ipaddress.ip_address(x).is_global` alone is NOT enough. It returns True for
NAT64 addresses embedding 127.0.0.1 (64:ff9b::7f00:1), and before Python 3.12.4 also for
6to4 (2002:7f00:1::). Use is_public_address() below.

Requests users: requests/urllib3 has no supported per-connection DNS hook. Either switch the
call site to the httpx client below, or send traffic through an egress proxy that enforces
the same policy (e.g. Stripe's smokescreen). Don't use a "validate first" wrapper around
requests.get: it has the rebinding gap described above.
"""

from __future__ import annotations

import http.client
import ipaddress
import re
import socket
import ssl
import urllib.error
import urllib.request
from typing import Callable, Iterable, Optional, Sequence, Tuple
from urllib.parse import urljoin, urlsplit

__all__ = [
    "SSRFBlocked",
    "is_public_address",
    "resolve_checked",
    "validate_url",
    "guarded_httpx_client",
    "safe_get",
]


class SSRFBlocked(Exception):
    """Raised when a URL, hostname, port, or resolved address is not allowed."""

    code = "ERR_SSRF_BLOCKED"


_V4_BLOCKED = [
    ipaddress.ip_network(n)
    for n in (
        "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
        "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16",
        "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
    )
]
_V6_GLOBAL_UNICAST = ipaddress.ip_network("2000::/3")
_V6_NAT64 = ipaddress.ip_network("64:ff9b::/96")
_V6_BLOCKED = [ipaddress.ip_network(n) for n in ("2001::/23", "2001:db8::/32", "3fff::/20")]

AddressPolicy = Callable[[str], bool]


def is_public_address(ip: str) -> bool:
    """True only for globally routable unicast addresses.

    IPv6 forms that embed IPv4 (IPv4-mapped, NAT64, 6to4) are judged by the embedded address.
    """
    try:
        addr = ipaddress.ip_address(str(ip).strip("[]").split("%")[0])
    except ValueError:
        return False
    if addr.version == 4:
        return not any(addr in net for net in _V4_BLOCKED)
    if addr.ipv4_mapped is not None:
        return is_public_address(str(addr.ipv4_mapped))
    if addr in _V6_NAT64:
        return is_public_address(str(ipaddress.IPv4Address(int(addr) & 0xFFFFFFFF)))
    if addr.sixtofour is not None:
        return is_public_address(str(addr.sixtofour))
    if addr not in _V6_GLOBAL_UNICAST:
        return False
    return not any(addr in net for net in _V6_BLOCKED)


_BLOCKED_SUFFIXES = (".localhost", ".local", ".internal", ".home.arpa")
_BLOCKED_NAMES = {"localhost", "metadata", "metadata.google.internal", "instance-data"}


# Numeric hosts that aren't canonical dotted quads ("0177.0.0.1", "2130706433", "0x7f.1",
# "127.000.000.001") are read differently by different resolvers: glibc and browsers say
# 127.0.0.1, macOS getaddrinfo says 177.0.0.1. Refuse them instead of guessing.
_NUMERIC_HOST = re.compile(r"^(0x[0-9a-f]*|[0-9]+)(\.(0x[0-9a-f]*|[0-9]+)){0,3}\.?$", re.IGNORECASE | re.ASCII)


def _check_hostname(host: str) -> None:
    h = host.lower().rstrip(".")
    if h in _BLOCKED_NAMES or h.endswith(_BLOCKED_SUFFIXES):
        raise SSRFBlocked(f"hostname {host} is blocked")
    if _NUMERIC_HOST.match(h):
        try:
            if str(ipaddress.IPv4Address(h)) == h:
                return
        except ValueError:
            pass
        raise SSRFBlocked(f"ambiguous numeric host {host}")


def resolve_checked(host: str, port: int, is_allowed: AddressPolicy = is_public_address) -> str:
    """Resolve host and return one address to connect to. Every resolved address must be
    allowed; a name pointing at both public and private space is refused outright."""
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError) as exc:
        raise SSRFBlocked(f"cannot resolve {host}: {exc}") from None
    addresses = [info[4][0] for info in infos]
    bad = [a for a in addresses if not is_allowed(a)]
    if bad or not addresses:
        raise SSRFBlocked(f"{host} resolves to a blocked address ({bad[0] if bad else 'none'})")
    return addresses[0]


def validate_url(
    url: str,
    *,
    allowed_ports: Optional[Sequence[int]] = (80, 443),
    is_allowed: AddressPolicy = is_public_address,
    resolve: bool = True,
) -> Tuple[str, str, int]:
    """Early validation (e.g. when a user saves a webhook URL). Returns (scheme, host, port).

    NOT a substitute for the guarded clients at request time: DNS can change between this
    check and the request.
    """
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError as exc:
        raise SSRFBlocked(f"invalid URL: {exc}") from None
    if parts.scheme not in ("http", "https"):
        raise SSRFBlocked(f"scheme {parts.scheme!r} is not allowed")
    if parts.username is not None or parts.password is not None:
        raise SSRFBlocked("credentials in URL are not allowed")
    if "\\" in parts.netloc:
        raise SSRFBlocked("backslash in authority")  # parsers disagree about where the host ends
    host = parts.hostname
    if not host:
        raise SSRFBlocked("missing host")
    port = port or (443 if parts.scheme == "https" else 80)
    if allowed_ports is not None and port not in allowed_ports:
        raise SSRFBlocked(f"port {port} is not allowed")
    _check_hostname(host)
    if resolve:
        resolve_checked(host, port, is_allowed)
    return parts.scheme, host, port


# ---------------------------------------------------------------------------
# httpx: the check runs inside httpcore's connect_tcp, for every new connection
# (every redirect hop, every pool refill). TLS uses the original hostname (SNI + cert check).
# ---------------------------------------------------------------------------


def guarded_httpx_client(
    *,
    is_allowed: AddressPolicy = is_public_address,
    allowed_ports: Optional[Iterable[int]] = (80, 443),
    max_redirects: int = 5,
    **client_kwargs,
):
    """Return an httpx.Client that refuses non-public destinations on every hop.

    trust_env is forced off: an HTTP(S)_PROXY from the environment would otherwise make the
    proxy do the connecting and bypass this check. Pass `proxy=` only for an egress proxy
    that enforces the same policy.
    """
    import httpcore
    import httpx

    ports = None if allowed_ports is None else frozenset(allowed_ports)

    class _GuardedBackend(httpcore.NetworkBackend):
        def __init__(self) -> None:
            self._inner = httpcore.SyncBackend()

        def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
            if ports is not None and port not in ports:
                raise SSRFBlocked(f"port {port} is not allowed")
            _check_hostname(host)
            ip = resolve_checked(host, port, is_allowed)
            return self._inner.connect_tcp(ip, port, timeout=timeout, local_address=local_address, socket_options=socket_options)

        def connect_unix_socket(self, path, timeout=None, socket_options=None):
            raise SSRFBlocked("unix sockets are not allowed")

        def sleep(self, seconds):
            self._inner.sleep(seconds)

    class _GuardedTransport(httpx.HTTPTransport):
        def __init__(self, verify=True, http2=False, limits=httpx.Limits(), retries=0):
            super().__init__(verify=verify, http2=http2, limits=limits, retries=retries)
            ssl_context = verify if isinstance(verify, ssl.SSLContext) else httpx.create_ssl_context(verify=verify)
            # httpx doesn't expose network_backend, so replace its pool with an equivalent
            # one that uses the guarded backend. Verified on httpx 0.28 / httpcore 1.0.
            self._pool = httpcore.ConnectionPool(
                ssl_context=ssl_context,
                max_connections=limits.max_connections,
                max_keepalive_connections=limits.max_keepalive_connections,
                keepalive_expiry=limits.keepalive_expiry,
                http1=True,
                http2=http2,
                retries=retries,
                network_backend=_GuardedBackend(),
            )

    verify = client_kwargs.pop("verify", True)
    http2 = client_kwargs.pop("http2", False)
    client_kwargs.pop("trust_env", None)
    client_kwargs.setdefault("follow_redirects", True)
    return httpx.Client(
        transport=_GuardedTransport(verify=verify, http2=http2),
        trust_env=False,
        max_redirects=max_redirects,
        **client_kwargs,
    )


# ---------------------------------------------------------------------------
# stdlib: urllib with connection classes whose socket creation is guarded.
# Only http/https handlers are installed (no file:, ftp:, data:), and no proxy handler.
# ---------------------------------------------------------------------------


def _guarded_create_connection(is_allowed: AddressPolicy, ports):
    def create_connection(address, timeout=socket._GLOBAL_DEFAULT_TIMEOUT, source_address=None, *args, **kwargs):
        host, port = address
        if ports is not None and port not in ports:
            raise SSRFBlocked(f"port {port} is not allowed")
        _check_hostname(host)
        ip = resolve_checked(host, port, is_allowed)
        return socket.create_connection((ip, port), timeout, source_address)

    return create_connection


def safe_get(
    url: str,
    *,
    timeout: float = 10.0,
    max_bytes: int = 5 * 1024 * 1024,
    max_redirects: int = 5,
    headers: Optional[dict] = None,
    is_allowed: AddressPolicy = is_public_address,
    allowed_ports: Optional[Iterable[int]] = (80, 443),
    truncate: bool = False,
) -> Tuple[int, dict, bytes]:
    """Stdlib GET with the same guarantees. Returns (status, headers, body).
    truncate=True returns the first max_bytes instead of raising (link previews)."""
    ports = None if allowed_ports is None else frozenset(allowed_ports)
    validate_url(url, allowed_ports=ports, is_allowed=is_allowed, resolve=False)
    guard = _guarded_create_connection(is_allowed, ports)

    class _HTTPConnection(http.client.HTTPConnection):
        def __init__(self, *a, **kw):
            super().__init__(*a, **kw)
            self._create_connection = guard

    class _HTTPSConnection(http.client.HTTPSConnection):
        def __init__(self, *a, **kw):
            super().__init__(*a, **kw)
            self._create_connection = guard  # TLS wraps the socket afterwards with server_hostname=self.host

    class _HTTPHandler(urllib.request.HTTPHandler):
        def http_open(self, req):
            return self.do_open(_HTTPConnection, req)

    class _HTTPSHandler(urllib.request.HTTPSHandler):
        def https_open(self, req):
            return self.do_open(_HTTPSConnection, req, context=ssl.create_default_context())

    class _Redirect(urllib.request.HTTPRedirectHandler):
        max_redirections = max_redirects

        def http_error_302(self, req, fp, code, msg, headers):
            location = headers.get("location") or headers.get("uri")
            if location:  # check before urllib's own handling, so every blocked hop raises SSRFBlocked
                validate_url(urljoin(req.full_url, location), allowed_ports=ports, is_allowed=is_allowed, resolve=False)
            return super().http_error_302(req, fp, code, msg, headers)

        http_error_301 = http_error_303 = http_error_307 = http_error_308 = http_error_302

    opener = urllib.request.OpenerDirector()
    for handler in (_HTTPHandler(), _HTTPSHandler(), _Redirect(), urllib.request.HTTPErrorProcessor(), urllib.request.HTTPDefaultErrorHandler()):
        opener.add_handler(handler)
    request = urllib.request.Request(url, headers=headers or {})
    try:
        resp = opener.open(request, timeout=timeout)
    except urllib.error.HTTPError as err:
        resp = err
    except urllib.error.URLError as err:
        if isinstance(err.reason, SSRFBlocked):
            raise err.reason from None
        raise
    with resp:
        body = resp.read(max_bytes + 1)
        if len(body) > max_bytes:
            if truncate:
                return resp.status, dict(resp.headers.items()), body[:max_bytes]
            raise SSRFBlocked(f"response exceeded {max_bytes} bytes")
        return resp.status, dict(resp.headers.items()), body
