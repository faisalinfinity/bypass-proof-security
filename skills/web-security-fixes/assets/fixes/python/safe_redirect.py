"""safe_redirect.py: open-redirect-proof handling of ?next= / ?return_to= values. Python 3.9+.

urllib.parse doesn't parse URLs the way browsers do, and every gap is a bypass:
  urlparse("https://evil.com\\@trusted.com").hostname == "trusted.com"   (browser: evil.com)
  urlparse(" //evil.com").netloc == ""                                   (browser strips the space)
  urlparse("/\\evil.com").netloc == ""                                    (browser: //evil.com)
So "no netloc means relative" and "hostname == ours" are both fixes that don't hold.

The fix that holds: apply the browser's normalization first (strip C0 controls and spaces,
drop tab/CR/LF, treat backslash as slash), then decide, and emit the normalized string so
the browser and this check see the same URL.

Django: use django.utils.http.url_has_allowed_host_and_scheme(url, allowed_hosts={...},
require_https=True). It handles these cases. This module is for Flask, FastAPI, and others.

    from safe_redirect import safe_redirect_target
    return RedirectResponse(safe_redirect_target(request.query_params.get("next"),
                                                 allowed_origins={"https://app.example.com"}), 303)
"""

from __future__ import annotations

from typing import Iterable, Optional
from urllib.parse import urlsplit

__all__ = ["safe_redirect_target", "is_safe_redirect", "is_registered_redirect_uri"]

_C0_AND_SPACE = "".join(chr(c) for c in range(0x21))
_DEFAULT_PORTS = {"http": 80, "https": 443}


def _normalize(value: str) -> str:
    v = value.strip(_C0_AND_SPACE)  # browsers strip leading/trailing C0 controls and spaces
    for ch in ("\t", "\n", "\r"):
        v = v.replace(ch, "")  # ...and remove tab/newline anywhere in the URL
    return v.replace("\\", "/")  # ...and treat backslash as slash in http(s) URLs


def _origin(scheme: str, host: str, port: Optional[int]) -> str:
    host = f"[{host}]" if ":" in host else host
    if port is None or port == _DEFAULT_PORTS.get(scheme):
        return f"{scheme}://{host}"
    return f"{scheme}://{host}:{port}"


def safe_redirect_target(
    value: object,
    allowed_origins: Iterable[str] = (),
    fallback: Optional[str] = "/",
    max_length: int = 2048,
) -> Optional[str]:
    """Return a value safe for a Location header: a same-origin path ("/x?y#z") or an absolute
    URL on an exactly-matching allowed origin (e.g. "https://app.example.com"). Else fallback."""
    if not isinstance(value, str) or not value or len(value) > max_length:
        return fallback
    v = _normalize(value)
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in v):
        return fallback
    try:
        parts = urlsplit(v)
        port = parts.port
    except ValueError:
        return fallback

    if not parts.scheme and not parts.netloc:
        # Relative: must be an absolute path on this origin. "//x" is protocol-relative.
        if v.startswith("/") and not v.startswith("//"):
            return v
        return fallback

    scheme = parts.scheme.lower()
    if scheme in ("http", "https") and parts.hostname and parts.username is None and parts.password is None:
        if _origin(scheme, parts.hostname, port) in set(allowed_origins):
            return v
    return fallback


def is_safe_redirect(value: object, allowed_origins: Iterable[str] = ()) -> bool:
    return safe_redirect_target(value, allowed_origins, fallback=None) is not None


def is_registered_redirect_uri(redirect_uri: object, registered: Iterable[str]) -> bool:
    """OAuth/OIDC redirect_uri: exact string match against pre-registered URIs (RFC 9700)."""
    return isinstance(redirect_uri, str) and redirect_uri in set(registered)
