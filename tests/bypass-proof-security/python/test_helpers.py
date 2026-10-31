"""Tests for the shipped Python helpers. Run:
  uv run --python 3.9  --with pytest --with httpx pytest tests/bypass-proof-security/python -q
  uv run --python 3.13 --with pytest --with httpx pytest tests/bypass-proof-security/python -q
"""
import base64
import hashlib
import hmac
import json
import os
import socket
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs

import pytest

ROOT = Path(__file__).resolve().parents[3]
SKILL = ROOT / "skills" / "bypass-proof-security"
sys.path.insert(0, str(SKILL / "assets" / "fixes" / "python"))

from safe_fetch import SSRFBlocked, guarded_httpx_client, is_public_address, safe_get, validate_url  # noqa: E402
from safe_path import PathTraversal, resolve_inside, safe_filename  # noqa: E402
from safe_redirect import safe_redirect_target  # noqa: E402
import verify_webhook as vw  # noqa: E402


def corpus(name):
    return json.loads((SKILL / "assets" / "corpus" / f"{name}.json").read_text(encoding="utf-8"))


# ---------------------------------------------------------------- redirect
def browser_oracle(rows):
    out = subprocess.run(["node", str(Path(__file__).with_name("redirect_oracle.mjs"))], input=json.dumps(rows), capture_output=True, text=True, check=True)
    return json.loads(out.stdout)


def run_redirect(fn):
    c = corpus("redirect")
    rows = [{"kind": "attack", "input": e["input"], "output": fn(e["input"])} for e in c["attacks"]]
    rows += [{"kind": "legit", "input": e["input"], "output": fn(e["input"]), "expect": e["expect"]} for e in c["legit"]]
    return browser_oracle(rows)


def test_safe_redirect_passes_corpus_under_browser_parsing():
    allowed = corpus("redirect")["assumptions"]["allowed_origins"]
    assert run_redirect(lambda v: safe_redirect_target(v, allowed_origins=allowed, fallback=None)) == []


def test_naive_python_redirect_checks_fail():
    def netloc_empty(v):
        return v if not urlparse(v).netloc and not urlparse(v).scheme else None

    def hostname_match(v):
        p = urlparse(v)
        return v if (not p.netloc and v.startswith("/")) or p.hostname == "trusted.example" else None

    assert any(f["input"] in (" //evil.example", "/\\evil.example") for f in run_redirect(netloc_empty))
    assert any(f["input"] == "https://evil.example\\@trusted.example" for f in run_redirect(hostname_match))


# ---------------------------------------------------------------- path
def test_resolve_inside_passes_path_corpus(tmp_path):
    base = (tmp_path / "uploads")
    base.mkdir()
    c = corpus("path")
    for e in c["attacks"]:
        try:
            got = resolve_inside(base, e["input"])
        except PathTraversal:
            continue
        assert e.get("severity") is None, f"{e['input']!r} must be rejected"
        assert got != base.resolve() and got.is_relative_to(base.resolve()), e["input"]
    for e in c["legit"]:
        assert resolve_inside(base, e["input"]) == (base / e["input"]).resolve(), e["input"]


def test_startswith_check_is_bypassed_by_sibling_prefix(tmp_path):
    base = tmp_path / "uploads"
    base.mkdir()
    naive = (base / "../uploads_evil/secret.txt").resolve()
    assert str(naive).startswith(str(base.resolve()))  # the naive check passes...
    with pytest.raises(PathTraversal):  # ...the component-wise check does not
        resolve_inside(base, "../uploads_evil/secret.txt")


def test_symlink_escape_is_caught(tmp_path):
    base = tmp_path / "uploads"
    base.mkdir()
    (base / "link").symlink_to(tmp_path)  # inside base, points outside
    with pytest.raises(PathTraversal):
        resolve_inside(base, "link/secret.txt")


def test_safe_filename():
    assert safe_filename("../../etc/passwd") == "passwd"
    assert safe_filename("..\\..\\boot.ini") == "boot.ini"
    assert safe_filename("CON.txt") == "_CON.txt"
    assert safe_filename("...") == "file"


# ---------------------------------------------------------------- ssrf: address policy + static corpus
@pytest.mark.parametrize("ip", ["127.0.0.1", "0.0.0.0", "10.0.0.1", "100.100.100.200", "169.254.169.254", "::1", "::ffff:127.0.0.1",
                                "64:ff9b::7f00:1", "2002:7f00:1::", "fd00:ec2::254", "fe80::1%en0", "2001:db8::1", "3fff::1", "ff02::1"])
def test_blocked_addresses(ip):
    assert not is_public_address(ip)


@pytest.mark.parametrize("ip", ["1.1.1.1", "8.8.8.8", "2606:4700:4700::1111", "::ffff:8.8.8.8", "64:ff9b::808:808"])
def test_public_addresses(ip):
    assert is_public_address(ip)


def test_is_global_alone_is_not_enough():
    import ipaddress
    assert ipaddress.ip_address("64:ff9b::7f00:1").is_global  # stdlib says global...
    assert not is_public_address("64:ff9b::7f00:1")  # ...but it's NAT64 for 127.0.0.1


def test_validate_url_ssrf_corpus():
    c = corpus("ssrf")
    for e in c["attacks"]:
        with pytest.raises(SSRFBlocked):
            validate_url(e["input"])
    for e in c["legit"]:
        validate_url(e["input"])


# ---------------------------------------------------------------- ssrf: live clients
class _Handler(BaseHTTPRequestHandler):
    hits = []

    def do_GET(self):
        _Handler.hits.append(self.path)
        q = parse_qs(urlparse(self.path).query)
        if self.path.startswith("/redirect"):
            self.send_response(302)
            self.send_header("Location", q["to"][0])
            self.end_headers()
            return
        body = b"internal-only"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


@pytest.fixture(scope="module")
def server():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}", srv.server_address[1]
    srv.shutdown()


LOOPBACK_ONLY = dict(is_allowed=lambda ip: ip == "127.0.0.1", allowed_ports=None)
REDIRECT_TARGETS = ["http://169.254.169.254/latest/meta-data/", "http://[::1]/", "http://2130706434/", "http://10.0.0.1/", "file:///etc/passwd"]


@pytest.mark.parametrize("target", REDIRECT_TARGETS)
def test_httpx_client_revalidates_redirect_hops(server, target):
    base, _ = server
    import httpx
    with guarded_httpx_client(timeout=3, **LOOPBACK_ONLY) as client:
        with pytest.raises((SSRFBlocked, httpx.UnsupportedProtocol)):
            client.get(f"{base}/redirect?to={target}")


@pytest.mark.parametrize("target", REDIRECT_TARGETS)
def test_stdlib_safe_get_revalidates_redirect_hops(server, target):
    base, _ = server
    with pytest.raises(SSRFBlocked):
        safe_get(f"{base}/redirect?to={target}", timeout=3, **LOOPBACK_ONLY)


def test_clients_work_inside_policy(server):
    base, _ = server
    with guarded_httpx_client(timeout=3, **LOOPBACK_ONLY) as client:
        assert client.get(f"{base}/ok").text == "internal-only"
    assert safe_get(f"{base}/ok", timeout=3, **LOOPBACK_ONLY)[2] == b"internal-only"


@pytest.fixture
def rebinding(monkeypatch):
    """getaddrinfo answers 1.1.1.1 on the first lookup of the probe name, 127.0.0.1 afterwards."""
    real = socket.getaddrinfo
    calls = {"n": 0}

    def fake(host, port, *a, **kw):
        if host == "rebind.websec-probe.test":
            calls["n"] += 1
            ip = "1.1.1.1" if calls["n"] == 1 else "127.0.0.1"
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port))]
        return real(host, port, *a, **kw)

    monkeypatch.setattr(socket, "getaddrinfo", fake)
    return calls


def test_validate_then_fetch_is_bypassed_by_rebinding(server, rebinding):
    import httpx
    _, port = server
    _Handler.hits.clear()
    url = f"http://rebind.websec-probe.test:{port}/secret"
    validate_url(url, allowed_ports=None)  # check passes: sees 1.1.1.1
    httpx.get(url, timeout=3)  # connection re-resolves: 127.0.0.1
    assert "/secret" in _Handler.hits


def test_guarded_clients_resist_rebinding(server, rebinding):
    import httpx
    _, port = server
    _Handler.hits.clear()
    url = f"http://rebind.websec-probe.test:{port}/secret"
    with guarded_httpx_client(timeout=2, allowed_ports=None) as client:
        with pytest.raises((httpx.TransportError, SSRFBlocked)):
            client.get(url)  # pinned to 1.1.1.1 -> times out, never reaches loopback
    rebinding["n"] = 0
    with pytest.raises((OSError, SSRFBlocked)):
        safe_get(url, timeout=2, allowed_ports=None)
    assert _Handler.hits == []


def test_real_https_still_verifies_hostname():
    with guarded_httpx_client(timeout=10) as client:
        r = client.get("https://example.com/")
        assert r.status_code == 200
    status, _, body = safe_get("https://example.com/", timeout=10)
    assert status == 200 and b"Example Domain" in body


def test_env_proxy_is_ignored(monkeypatch, server):
    base, _ = server
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:9")  # would bypass the guard if honored
    with guarded_httpx_client(timeout=3, **LOOPBACK_ONLY) as client:
        assert client.get(f"{base}/ok").status_code == 200


# ---------------------------------------------------------------- webhooks
def test_standard_webhooks_published_vector():
    # Test vector from the Standard Webhooks spec / svix libraries
    secret = "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw"
    msg_id, ts = "msg_p5jXN8AQM9LWM0D4loKWxJek", "1614265330"
    body = b'{"test": 2432232314}'
    sig = "v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE="
    assert vw.verify_standard_webhook(body, msg_id, ts, sig, secret, now=1614265330)
    assert not vw.verify_standard_webhook(body + b" ", msg_id, ts, sig, secret, now=1614265330)
    assert not vw.verify_standard_webhook(body, msg_id, ts, sig, secret)  # 2021 timestamp: replay window exceeded


def _stripe_header(body, secret, t):
    return f"t={t},v1=" + hmac.new(secret.encode(), f"{t}.".encode() + body, hashlib.sha256).hexdigest()


def test_stripe_and_rotation_and_replay():
    body, now = b'{"id":"evt_1"}', int(time.time())
    h = _stripe_header(body, "whsec_new", now)
    assert vw.verify_stripe(body, h, ["whsec_old", "whsec_new"])
    assert not vw.verify_stripe(body, h, "whsec_old")
    assert not vw.verify_stripe(body.replace(b"1", b"2"), h, "whsec_new")
    assert not vw.verify_stripe(body, _stripe_header(body, "whsec_new", now - 3600), "whsec_new")
    reserialized = json.dumps(json.loads(body)).encode()  # '{"id": "evt_1"}': different bytes
    assert not vw.verify_stripe(reserialized, h, "whsec_new")


def test_github_and_slack():
    body = b"payload=1"
    gh = "sha256=" + hmac.new(b"s3", body, hashlib.sha256).hexdigest()
    assert vw.verify_github(body, gh, "s3") and not vw.verify_github(body, gh.replace("sha256", "sha1"), "s3")
    ts = str(int(time.time()))
    sl = "v0=" + hmac.new(b"s3", f"v0:{ts}:".encode() + body, hashlib.sha256).hexdigest()
    assert vw.verify_slack(body, sl, ts, "s3")
    assert not vw.verify_slack(body, sl, str(int(ts) - 600), "s3")
    assert not vw.verify_hmac(body, "zz-not-hex", "s3")
