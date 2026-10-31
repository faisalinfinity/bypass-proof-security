# SSRF and outbound requests

Any time the server fetches a URL that a user influenced: link previews, webhooks you send, "import from URL", image proxies and resizers, PDF/screenshot renderers, OAuth/OIDC discovery (`jwks_uri`, `.well-known`), SAML metadata, RSS readers, avatar URLs, and integrations where a customer supplies a base URL.

## Contents
- [Spot it](#spot-it)
- [Fixes that don't hold](#fixes-that-dont-hold)
- [The fix that holds](#the-fix-that-holds)
- [Node](#node) · [Python](#python) · [Go](#go) · [Java](#java) · [PHP](#php) · [Ruby](#ruby)
- [Headless browsers and renderers](#headless-browsers-and-renderers)
- [Network layer (do this too)](#network-layer-do-this-too)
- [Regression tests](#regression-tests)

## Spot it

```bash
# Node: request libraries fed by request data
grep -rnE "(fetch|axios(\.(get|post|request))?|got|request|needle|superagent|undici\.request|http\.get|https\.get)\(\s*(req\.|request\.|body\.|params\.|query\.|input|url|link|target|endpoint|callback|webhook)" --include=*.{js,ts,mjs,cjs,jsx,tsx} .
# Python
grep -rnE "(requests|httpx|urllib3|aiohttp|urlopen|session)\.?(get|post|request|urlopen)?\(\s*[a-z_]*(url|link|target|endpoint|callback|webhook|uri)" --include=*.py .
# Renderers
grep -rnE "puppeteer|playwright|wkhtmltopdf|weasyprint|chrome-headless|gotenberg|libreoffice|imagemagick|ffmpeg" .
```

Then trace each hit back: can a user set any part of the URL, including the host, port, path prefix, or a redirect it follows? A "fixed" base URL plus a user-controlled path can still be SSRF (`/..;/`, `@`, or an open redirect on the target host).

## Fixes that don't hold

| Fix you'll be tempted to write | Input that breaks it | Why |
|---|---|---|
| Blocklist strings: `host !== 'localhost' && !host.startsWith('10.')` | `http://0x7f.1/`, `http://2130706433/`, `http://[::ffff:127.0.0.1]/`, `http://127。0。0。1/` | Dozens of encodings reach the same address. The URL parser and resolver normalize them *after* your string check. |
| Resolve, check the IP, then `fetch(url)` | A DNS name with TTL 0 answering `1.1.1.1` then `127.0.0.1` (rebinding) | The HTTP client resolves again. You checked one address and connected to another. `probe-validator.mjs ssrf-fetch` demonstrates this against your code. |
| Check only the first URL | A public URL that 302-redirects to `http://169.254.169.254/` | Clients follow redirects by default (`fetch`, `requests`, `axios`, `got`). |
| `redirect: 'manual'` / `allow_redirects=False` and stop there | Your code (or the next developer) follows `Location` by hand without re-checking | Each hop needs the same check. |
| `ipaddress.ip_address(ip).is_global` (Python) | `64:ff9b::7f00:1` (NAT64 → 127.0.0.1) is reported global; `2002:7f00:1::` was too before 3.12.4 | The stdlib classifier isn't an SSRF policy. |
| Python `getaddrinfo` result for `0177.0.0.1` | macOS resolves it to 177.0.0.1, glibc and browsers to 127.0.0.1 | Resolvers disagree about numeric hosts. Reject non-canonical numeric hosts outright. |
| Allowlist by `url.startsWith('https://api.partner.com')` | `https://api.partner.com.evil.example/`, `https://api.partner.com@evil.example/` | Compare the parsed `hostname` exactly, never the raw string. |
| Block `169.254.169.254` only | `fd00:ec2::254` (AWS IPv6 IMDS), `100.100.100.200` (Alibaba), `metadata.google.internal` | Metadata lives at several addresses and names. Block whole ranges. |
| Protocol check missing | `file:///etc/passwd`, `gopher://127.0.0.1:6379/_...`, `dict://` | curl-based clients (PHP `curl_*`, pycurl, `libcurl` bindings) speak many schemes. |
| Proxy through an env `HTTP_PROXY` | Proxy connects to internal addresses on your behalf | The proxy, not your check, picks the destination IP. |

## The fix that holds

In order of strength. Do as many as the deployment allows:

1. **Remove user control of the host.** If users pick from a few integrations, store an ID and map it to a hardcoded base URL server-side.
2. **Allowlist exact hostnames** when the set is known (for example, partner APIs). Compare `new URL(x).hostname` exactly, still apply the IP policy below, and pin.
3. **Otherwise use an IP policy enforced at connect time:**
   - Resolve, then reject if **any** answer is non-public. Connect to the address you checked.
   - Re-validate every redirect hop, or disable redirects.
   - Allow only `http:` and `https:`, ports 80 and 443 (widen deliberately), and no credentials in URLs.
   - Cap the timeout and the response size, and don't return raw upstream errors or bodies to the user (blind SSRF probing reads them).
4. **Enforce egress at the network layer as well:**
   - An egress proxy such as [smokescreen](https://github.com/stripe/smokescreen), or a security group or NetworkPolicy that only reaches the internet.
   - IMDSv2 with hop limit 1 on AWS.

"Public" means globally routable unicast. Block all of these:
- IPv4: `0/8 10/8 100.64/10 127/8 169.254/16 172.16/12 192.0.0/24 192.0.2/24 192.88.99/24 192.168/16 198.18/15 198.51.100/24 203.0.113/24 224/4 240/4`.
- IPv6: everything outside `2000::/3`, plus `2001::/23`, `2001:db8::/32`, and `3fff::/20`.
- IPv6 forms that embed IPv4 (`::ffff:0:0/96`, `64:ff9b::/96`, `2002::/16`): judge them by the embedded IPv4 address.

The shipped helpers implement exactly this.

### Node

Copy `assets/fixes/node/safe-fetch.mjs` (zero dependencies):

```js
import { safeFetch, validateUrl, SsrfBlockedError } from './lib/safe-fetch.mjs';

// at save time (e.g. webhook URL form): fail fast with a clear message
await validateUrl(body.webhookUrl);           // throws SsrfBlockedError

// at send time: the only call that actually protects you
try {
  const res = await safeFetch(webhook.url, { method: 'POST', body: JSON.stringify(event),
    headers: { 'content-type': 'application/json' }, timeoutMs: 5000, maxResponseBytes: 64 * 1024 });
} catch (err) {
  if (err.code === 'ERR_SSRF_BLOCKED') { /* mark the webhook disabled, don't retry */ }
  throw err;
}
```

Link previews and scrapers: pass `truncate: true` with a small `maxResponseBytes` (e.g. 512 KB). You get the first bytes (`res.truncated === true`) instead of an error. Python: `safe_get(url, max_bytes=..., truncate=True)`.

How it works:
- It validates inside the socket `lookup` hook, which runs once per connection. IP literals skip DNS, so they are validated before connecting.
- It uses its own agents, so it never reuses a pooled socket that other code opened to an internal host.
- TLS still verifies the certificate against the hostname. The tests confirm that a mis-pinned IP fails with `ERR_TLS_CERT_ALTNAME_INVALID`.

If the code uses `fetch` everywhere, use `assets/fixes/node/safe-fetch-undici.mjs`. It needs `npm i undici`:

```js
import { createSsrfSafeAgent } from './lib/safe-fetch-undici.mjs';
const untrusted = createSsrfSafeAgent();                 // once, module scope
const res = await fetch(userUrl, { dispatcher: untrusted });  // Node global fetch or undici's
```

The guard runs in the connector, so redirect hops (including those to IP literals) are checked too. Don't install it as the global dispatcher. It's for untrusted URLs only.

Other clients:
- axios (Node adapter): accepts `lookup`. Pass `createGuardedLookup()` from safe-fetch.mjs, plus `maxRedirects: 0`, and re-validate `Location` yourself. Also pass `httpAgent`/`httpsAgent` instances dedicated to untrusted traffic.
- got: `dnsLookup: createGuardedLookup()`, plus `followRedirect: false` or a `beforeRedirect` hook that calls `assertSafeUrl`.
- Literals still need `assertSafeUrl(url)` first with any client that only hooks DNS.

### Python

Copy `assets/fixes/python/safe_fetch.py`:

```python
from safe_fetch import guarded_httpx_client, validate_url, SSRFBlocked

validate_url(form.webhook_url)                   # save time: raises SSRFBlocked

with guarded_httpx_client(timeout=5) as client:  # send time: checks every connection, every hop
    r = client.post(hook.url, json=event)
```

How it works:
- `guarded_httpx_client` replaces httpcore's network backend. Resolution and the policy check happen inside `connect_tcp`, and the socket connects to the checked IP. TLS uses the original hostname.
- It forces `trust_env=False`, because an `HTTP_PROXY` from the environment would make the proxy do the connecting.
- Tested on httpx 0.28 and httpcore 1.0. It replaces `HTTPTransport._pool`, so re-run the tests after major httpx upgrades.

Stdlib only: `safe_get(url)` uses urllib with guarded connection classes, installs only the http and https handlers, and re-checks redirects.

**requests**: requests/urllib3 has no supported per-connection DNS hook. For untrusted URLs, switch that call site to the httpx client above or route it through an egress proxy. A `validate_url()` call before `requests.get()` still has the rebinding gap. The tests reproduce the bypass.

**aiohttp**: subclass `aiohttp.abc.AbstractResolver`. In `resolve()`, call the real resolver and raise if any address fails `is_public_address`, then pass it as `TCPConnector(resolver=...)`. Literals don't go through the resolver, so call `validate_url(url, resolve=False)` first. Set `allow_redirects=False` and re-validate each `Location`.

### Go

`net.Dialer.Control` runs after resolution with the exact IP being dialed, so it's TOCTOU-free:

```go
func ssrfSafeClient() *http.Client {
	dialer := &net.Dialer{Timeout: 5 * time.Second, Control: func(network, address string, _ syscall.RawConn) error {
		host, port, err := net.SplitHostPort(address)
		if err != nil { return err }
		ip, err := netip.ParseAddr(host)
		if err != nil { return err }
		ip = ip.Unmap()                                   // ::ffff:a.b.c.d -> a.b.c.d
		if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() ||
			cgnat.Contains(ip) || nat64.Contains(ip) || (port != "80" && port != "443") {
			return fmt.Errorf("ssrf: blocked %s", address)
		}
		return nil
	}}
	tr := &http.Transport{DialContext: dialer.DialContext, Proxy: nil} // Proxy nil: ignore env proxies
	return &http.Client{Transport: tr, Timeout: 10 * time.Second}
}
// var cgnat = netip.MustParsePrefix("100.64.0.0/10"); var nat64 = netip.MustParsePrefix("64:ff9b::/96")
```

`IsGlobalUnicast` is true for RFC 1918 addresses, which is why `IsPrivate` is checked too. Redirects reuse the transport, so every hop is dialed through `Control`. Wrap the body in `io.LimitReader`.

### Java

- Resolve with `InetAddress.getAllByName(host)` and reject if any address `isAnyLocalAddress() || isLoopbackAddress() || isLinkLocalAddress() || isSiteLocalAddress() || isMulticastAddress()`. Also add explicit CIDR checks for CGNAT, NAT64, and IPv6 ULA (`fc00::/7` isn't "site local" to Java).
- Then **connect to that `InetAddress`**: with OkHttp, implement `Dns` to return only the vetted addresses; with Apache HttpClient 5, use a custom `DnsResolver`.
- Disable automatic redirects (`followRedirects(false)`) and re-check each hop.
- Spring `RestTemplate` and `WebClient`: configure the underlying client the same way.

### PHP

- curl: set `CURLOPT_PROTOCOLS` and `CURLOPT_REDIR_PROTOCOLS` to `CURLPROTO_HTTP | CURLPROTO_HTTPS`.
- Resolve with `dns_get_record`/`gethostbynamel`, validate every IP with `filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_GLOBAL_RANGE)` (PHP 8.2+; older: `FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE`) plus explicit CGNAT, NAT64, and 6to4 checks, then **pin** with `CURLOPT_RESOLVE => ["$host:$port:$ip"]`.
- Set `CURLOPT_FOLLOWLOCATION => false` and re-check each `Location`.
- Laravel's `Http::` is Guzzle on curl: pass the same options via `withOptions(['curl' => [...]])`.

### Ruby

- Resolve with `Resolv.getaddresses`, validate each address with `IPAddr` (`private?`, `loopback?`, `link_local?`, plus CGNAT/NAT64/ULA), then connect to that IP.
- With `Net::HTTP`, set `http.ipaddr = ip` before `start`. TLS still uses the hostname.
- The `ssrf_filter` gem wraps this pattern. It re-checks redirects; keep it updated.

## Headless browsers and renderers

HTML-to-PDF and screenshot services fetch every subresource in the document: `<img>`, `<iframe>`, CSS `url()`, `<link>`, and `@import`. That makes any user-controlled HTML a full SSRF.
- Run them in a network namespace or container with egress only through a filtering proxy.
- Puppeteer/Playwright: `page.setRequestInterception(true)` / `page.route('**', ...)`. Abort any request whose URL fails `assertSafeUrl`. Interception sees the URL but not the resolved IP, so the network-layer control is still required.
- Disable JavaScript where you can (`javaScriptEnabled: false`), and never render `file://` origins. wkhtmltopdf: `--disable-local-file-access`. WeasyPrint: pass a custom `url_fetcher` that applies the policy.

## Network layer (do this too)

- AWS: `HttpTokens=required` (IMDSv2) and `HttpPutResponseHopLimit=1` on every instance and launch template. ECS/EKS: block 169.254.169.254 from task/pod networks except via the provided credential endpoints.
- GCP: metadata needs the `Metadata-Flavor: Google` header. Never forward user-supplied headers to fetches.
- Kubernetes: a default-deny egress NetworkPolicy for the service that fetches.
- Send untrusted fetches through a dedicated egress proxy (smokescreen, or Squid with ACLs) that enforces the same IP policy. Then the app check and the network check fail independently.

## Regression tests

```bash
# your validator (save-time check)
node <skill-dir>/scripts/probe-validator.mjs ssrf src/lib/url-policy.ts validateWebhookUrl
# your actual fetch wrapper: DNS rebinding, IP literals, mapped IPv6, 0.0.0.0 against a loopback server
node <skill-dir>/scripts/probe-validator.mjs ssrf-fetch src/lib/http.ts fetchUntrusted
```

The `ssrf-fetch` probe sends requests to a random high port. If your wrapper allows only ports 80 and 443, write a 3-line adapter that allows the probe port. Templates: `assets/tests/vitest.template.ts` and `assets/tests/pytest_template.py` (SSRF section). They need the test to fail on the old code first.

Report residual risk honestly. An app-level guard does not stop SSRF through a renderer, a proxy, or a library that opens its own connections. Say which outbound paths you checked.
