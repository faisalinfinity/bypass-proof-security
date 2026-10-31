"""Security regression tests built from the web-security-fixes corpus (pytest).

How to use:
  1. Copy this file into tests/security/ and copy ../corpus/*.json to tests/security/corpus/
     (or set WEBSEC_CORPUS to the skill's assets/corpus directory).
  2. Point each `ADAPT` import at your real function or client, and delete sections you don't need.
  3. Run it against the VULNERABLE code first and watch it fail. Then fix, re-run, keep it in CI.
Conventions: a function "rejects" by raising or returning False/None. True means "use the input
as-is". A string means "use this value".
"""
import concurrent.futures
import hashlib
import hmac
import json
import os
import time
from pathlib import Path

import pytest

CORPUS = Path(os.environ.get("WEBSEC_CORPUS", Path(__file__).with_name("corpus")))


def load(name):
    return json.loads((CORPUS / f"{name}.json").read_text(encoding="utf-8"))


def outcome(fn, *args):
    try:
        value = fn(*args)
    except Exception:
        return True, None
    return (value is False or value is None), value


# ------------------------------------------------------------------ open redirect
from myapp.security import safe_next  # ADAPT: (value) -> safe Location | None

REDIRECT = load("redirect")
_C0 = "".join(chr(c) for c in range(0x21))


def lands_on_allowed_origin(location: str) -> bool:
    """Conservative stand-in for browser parsing (exact check: feed outputs to Node's URL in CI).
    Same-origin path: one leading '/', no backslash, no tab/CR/LF/control chars.
    Absolute: must start with an allowed origin followed by '/', '?', '#' or end."""
    loc = location.strip(_C0)
    if any(ord(ch) < 0x20 or ch == "\\" for ch in loc):
        return False
    if loc.startswith("/"):
        return not loc.startswith("//")
    return any(loc == o or loc.startswith((o + "/", o + "?", o + "#")) for o in REDIRECT["assumptions"]["allowed_origins"])


@pytest.mark.parametrize("case", REDIRECT["attacks"], ids=lambda c: repr(c["input"])[:40])
def test_redirect_attack_stays_on_site(case):
    rejected, value = outcome(safe_next, case["input"])
    if not rejected:
        assert lands_on_allowed_origin(case["input"] if value is True else value), case["why"]


@pytest.mark.parametrize("case", REDIRECT["legit"], ids=lambda c: c["input"])
def test_redirect_legit_still_works(case):
    rejected, _ = outcome(safe_next, case["input"])
    assert not rejected


# ------------------------------------------------------------------ SSRF (save-time validator)
from myapp.security import validate_webhook_url  # ADAPT: (url) -> ok | raises

SSRF = load("ssrf")
OFFLINE = os.environ.get("CI_OFFLINE") == "1"


@pytest.mark.parametrize("case", [c for c in SSRF["attacks"] if not (OFFLINE and c.get("needs_dns"))], ids=lambda c: c["input"][:40])
def test_ssrf_attack_blocked(case):
    assert outcome(validate_webhook_url, case["input"])[0], case["why"]


@pytest.mark.parametrize("case", [c for c in SSRF["legit"] if not (OFFLINE and c.get("needs_dns"))], ids=lambda c: c["input"])
def test_ssrf_legit_allowed(case):
    assert not outcome(validate_webhook_url, case["input"])[0]


# ------------------------------------------------------------------ SSRF: DNS rebinding against the code that actually fetches
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from myapp.http import fetch_untrusted  # ADAPT: (url) -> performs the request; in tests allow non-standard ports


def test_ssrf_dns_rebinding_never_reaches_internal(monkeypatch):
    hits = []

    class Internal(BaseHTTPRequestHandler):
        def do_GET(self):
            hits.append(self.path)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"internal-only")

        def log_message(self, *a):
            pass

    srv = ThreadingHTTPServer(("127.0.0.1", 0), Internal)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    port, real, calls = srv.server_address[1], socket.getaddrinfo, {"n": 0}

    def fake(host, p, *a, **kw):  # public answer for the check, loopback for the connection
        if host == "rebind.websec-probe.test":
            calls["n"] += 1
            ip = "1.1.1.1" if calls["n"] == 1 else "127.0.0.1"
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, p))]
        return real(host, p, *a, **kw)

    monkeypatch.setattr(socket, "getaddrinfo", fake)
    try:
        fetch_untrusted(f"http://rebind.websec-probe.test:{port}/")
    except Exception:
        pass
    finally:
        srv.shutdown()
    assert hits == []


# ------------------------------------------------------------------ path traversal
from myapp.files import resolve_user_file  # ADAPT: (base, name) -> Path | raises

PATHS = load("path")


@pytest.fixture
def base_dir(tmp_path):
    d = tmp_path / "uploads"
    d.mkdir()
    return d


@pytest.mark.parametrize("case", [c for c in PATHS["attacks"] if c.get("severity") != "warn"], ids=lambda c: repr(c["input"])[:40])
def test_path_attack_contained(case, base_dir):
    rejected, value = outcome(resolve_user_file, base_dir, case["input"])
    if case.get("severity") == "strict":
        assert rejected, case["why"]
    elif not rejected:
        resolved = (base_dir / (case["input"] if value is True else str(value))).resolve()
        assert resolved != base_dir.resolve() and resolved.is_relative_to(base_dir.resolve()), case["why"]


@pytest.mark.parametrize("case", PATHS["legit"], ids=lambda c: c["input"])
def test_path_legit_works(case, base_dir):
    assert not outcome(resolve_user_file, base_dir, case["input"])[0]


# ------------------------------------------------------------------ webhook signature (route level)
from myapp.main import app  # ADAPT
from fastapi.testclient import TestClient  # ADAPT: Flask: app.test_client(); Django: django.test.Client()

client = TestClient(app)
SECRET = os.environ.get("TEST_WEBHOOK_SECRET", "whsec_test")  # ADAPT
BODY = json.dumps({"id": "evt_test_1", "type": "payment.succeeded"})


def stripe_sig(body: str, t: int) -> str:  # ADAPT: your provider's format
    return f"t={t},v1=" + hmac.new(SECRET.encode(), f"{t}.{body}".encode(), hashlib.sha256).hexdigest()


def post_hook(body, sig=""):
    return client.post("/webhooks/stripe", content=body, headers={"content-type": "application/json", "stripe-signature": sig})


def test_webhook_valid():
    assert post_hook(BODY, stripe_sig(BODY, int(time.time()))).status_code < 300


def test_webhook_tampered():
    assert post_hook(BODY.replace("succeeded", "succeedeD"), stripe_sig(BODY, int(time.time()))).status_code == 400


def test_webhook_reserialized_body():
    assert post_hook(json.dumps(json.loads(BODY), indent=1), stripe_sig(BODY, int(time.time()))).status_code == 400


def test_webhook_replay_window():
    t = int(time.time()) - 600
    assert post_hook(BODY, stripe_sig(BODY, t)).status_code == 400


# ------------------------------------------------------------------ race condition (real DB; Django: transaction=True)
def test_coupon_single_use_under_concurrency():
    def redeem(_):
        return TestClient(app).post("/api/coupons/redeem", json={"code": "TEST-ONCE"}, headers={"authorization": "Bearer test"}).status_code  # ADAPT

    with concurrent.futures.ThreadPoolExecutor(20) as pool:
        codes = list(pool.map(redeem, range(20)))
    assert codes.count(200) == 1


# ------------------------------------------------------------------ authorization: the two-user test
def test_other_user_cannot_touch_my_project():
    alice, bob = {"authorization": "Bearer alice"}, {"authorization": "Bearer bob"}  # ADAPT
    pid = client.post("/api/projects", json={"name": "secret"}, headers=alice).json()["id"]
    for method in ("get", "patch", "delete"):
        r = getattr(client, method)(f"/api/projects/{pid}", headers=bob, **({"json": {"name": "pwned"}} if method == "patch" else {}))
        assert r.status_code in (403, 404)
