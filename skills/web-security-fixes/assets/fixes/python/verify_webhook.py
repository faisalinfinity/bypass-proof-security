"""verify_webhook.py: inbound webhook signature verification. Python 3.9+, stdlib only.

Fixes that don't hold:
  hmac over json.dumps(request.json)   re-serialization changes bytes, so sign-check the RAW body
  sig == expected                      timing leak, so use hmac.compare_digest
  no timestamp check                   captured events replay forever
Get the raw body: Flask request.get_data(); FastAPI/Starlette `await request.body()`;
Django request.body. Read it BEFORE anything parses it.
After verifying, dedupe on the event id (processed-ids table with a TTL).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import time
from typing import Iterable, Optional, Union

__all__ = ["verify_hmac", "verify_github", "verify_stripe", "verify_slack", "verify_standard_webhook"]

Secret = Union[str, bytes]


def _b(v: Union[str, bytes]) -> bytes:
    return v if isinstance(v, bytes) else v.encode("utf-8")


def _secrets(secrets: Union[Secret, Iterable[Secret]]) -> list:
    if isinstance(secrets, (str, bytes)):
        return [_b(secrets)]
    return [_b(s) for s in secrets]


def _fresh(timestamp: object, tolerance: int, now: Optional[float]) -> bool:
    ts = str(timestamp or "")
    if not ts.isdigit() or len(ts) > 12:
        return False
    return abs((time.time() if now is None else now) - int(ts)) <= tolerance


def verify_hmac(payload: bytes, signature: str, secrets, digest=hashlib.sha256, encoding: str = "hex") -> bool:
    """Generic check. Several secrets may be given during rotation; any match passes."""
    if not isinstance(signature, str) or not signature:
        return False
    try:
        given = bytes.fromhex(signature) if encoding == "hex" else base64.b64decode(signature, validate=True)
    except ValueError:
        return False
    return any(hmac.compare_digest(given, hmac.new(s, _b(payload), digest).digest()) for s in _secrets(secrets))


def verify_github(raw_body: bytes, signature_header: Optional[str], secrets) -> bool:
    """X-Hub-Signature-256: sha256=<hex>. No timestamp: dedupe on X-GitHub-Delivery."""
    if not signature_header or not signature_header.startswith("sha256="):
        return False
    return verify_hmac(raw_body, signature_header[7:], secrets)


def verify_stripe(raw_body: bytes, signature_header: Optional[str], secrets, tolerance: int = 300, now: Optional[float] = None) -> bool:
    """Stripe-Signature: t=<unix>,v1=<hex>[,v1=...]; signed payload b"<t>." + raw_body."""
    if not signature_header:
        return False
    t, v1 = None, []
    for part in signature_header.split(","):
        k, _, v = part.strip().partition("=")
        if k == "t":
            t = v
        elif k == "v1":
            v1.append(v)
    if not t or not v1 or not _fresh(t, tolerance, now):
        return False
    payload = f"{t}.".encode() + _b(raw_body)
    return any(verify_hmac(payload, sig, secrets) for sig in v1)


def verify_slack(raw_body: bytes, signature_header: Optional[str], timestamp_header: Optional[str], secrets, tolerance: int = 300, now: Optional[float] = None) -> bool:
    """X-Slack-Signature: v0=<hex>; basestring b"v0:<ts>:" + raw_body."""
    if not signature_header or not signature_header.startswith("v0=") or not _fresh(timestamp_header, tolerance, now):
        return False
    payload = f"v0:{timestamp_header}:".encode() + _b(raw_body)
    return verify_hmac(payload, signature_header[3:], secrets)


def verify_standard_webhook(raw_body: bytes, msg_id: Optional[str], timestamp: Optional[str], signature_header: Optional[str], secrets, tolerance: int = 300, now: Optional[float] = None) -> bool:
    """Standard Webhooks (Svix, Clerk, Resend, ...): headers webhook-id, webhook-timestamp,
    webhook-signature ("v1,<b64> v1,<b64>"); key = base64 of the secret after "whsec_"."""
    if not msg_id or not signature_header or not _fresh(timestamp, tolerance, now):
        return False
    keys = []
    for s in _secrets(secrets):
        raw = s.decode()
        keys.append(base64.b64decode(raw[6:] if raw.startswith("whsec_") else raw))
    payload = f"{msg_id}.{timestamp}.".encode() + _b(raw_body)
    sigs = [p[3:] for p in signature_header.split(" ") if p.startswith("v1,")]
    return any(verify_hmac(payload, sig, keys, encoding="base64") for sig in sigs)
