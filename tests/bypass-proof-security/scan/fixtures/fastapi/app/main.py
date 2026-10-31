import os, pickle, yaml, random, subprocess, tarfile, hmac, json, ipaddress, socket
import requests
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse, FileResponse
from jinja2 import Environment
from flask import render_template_string
from urllib.parse import urlparse
app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True)  # EXPECT cors-reflect-any-origin
env = Environment()                                                               # EXPECT jinja-autoescape-off
@app.get("/preview")
def preview(request: Request):
    return requests.get(request.query_params["url"]).text                         # EXPECT ssrf-user-url
def fetch_checked(url):
    ip = socket.gethostbyname(urlparse(url).hostname)
    if not ipaddress.ip_address(ip).is_global:                                    # EXPECT ssrf-is-global-only
        raise ValueError()
    return requests.get(url)                                                      # EXPECT ssrf-validate-then-fetch
@app.get("/done")
def done(request: Request):
    return RedirectResponse(request.query_params.get("next"))                     # EXPECT open-redirect
def safe_next(nxt):
    if not urlparse(nxt).netloc:                                                  # EXPECT redirect-netloc-check
        return nxt
@app.get("/file")
def file(request: Request):
    return FileResponse(os.path.join("/srv/files", request.query_params["name"])) # EXPECT path-user-input
def inside(base_dir, p):
    return str(os.path.realpath(p)).startswith(str(base_dir))                     # EXPECT path-startswith-base
def extract(f):
    with tarfile.open(f) as t:
        t.extractall("/tmp/x")                                                    # EXPECT tar-extractall-no-filter
def users(cur, name):
    cur.execute(f"SELECT * FROM users WHERE name = '{name}'")                     # EXPECT sqli-interpolated
    cur.execute("SELECT * FROM users WHERE name = '%s'" % name)                   # EXPECT sqli-interpolated
def convert(name):
    subprocess.run(f"convert {name} out.png", shell=True)                         # EXPECT cmd-injection
def hello(name):
    return render_template_string(f"Hello {name}")                                # EXPECT ssti
def load(blob):
    return pickle.loads(blob)                                                     # EXPECT unsafe-deserialization
def cfg(s):
    return yaml.load(s, Loader=yaml.Loader)                                       # EXPECT unsafe-deserialization
reset_token = "".join(random.choice("abc") for _ in range(20))                    # EXPECT weak-random-token
def verify(body, sig):
    expected = hmac.new(b"k", json.dumps(body).encode(), "sha256").hexdigest()    # EXPECT webhook-reserialized-body
    return signature == expected                                                  # EXPECT timing-unsafe-compare
def decode(t):
    import jwt
    return jwt.decode(t, options={"verify_signature": False})                     # EXPECT jwt-no-verify
def safe_cfg(s):
    return yaml.safe_load(s)                                                      # safe: no finding
