# wcdscan

**Evidence-first Web Cache Deception scanner for pentesters and security engineers.**

`wcdscan` tests whether personalized content can accidentally become retrievable from a shared cache through static-looking path variants — without dumping private response bodies and without pretending every weird cache header is a vulnerability.

> Built for authorized security testing. Use a dedicated test account.

## Why wcdscan?

Most cache tooling gives you raw headers and leaves you to guess. `wcdscan` focuses on **proof quality**:

- compares authenticated vs anonymous baselines;
- tests static-looking route variants;
- repeats anonymous requests to confirm cache behavior;
- compares body hashes instead of printing sensitive content;
- fingerprints common CDN/cache signals;
- explains *why* a finding was classified;
- exports human-readable HTML and machine-readable JSON;
- works cleanly through Burp Suite or another HTTP proxy.

A high-confidence finding requires more than a `HIT` header:

```text
authenticated baseline != anonymous baseline
                     +
authenticated variant == anonymous variant
                     +
      shared-cache evidence is confirmed
```

That keeps false positives low and makes findings easier to reproduce and report.

## Quick start

### Install with Go

```bash
go install github.com/AmpedWasTaken/wcdscan/cmd/wcdscan@latest
```

### Build from source

```bash
git clone https://github.com/AmpedWasTaken/wcdscan.git
cd wcdscan
go build -o wcdscan ./cmd/wcdscan
```

### Scan an authenticated endpoint

```bash
./wcdscan \
  --authorized \
  --url "https://app.example.test/account" \
  --cookie "session=YOUR_TEST_SESSION"
```

Example output:

```text
wcdscan 0.1.0
Target: https://app.example.test/account
CDN:    Cloudflare
Baseline: auth=200 f64bb92d0e2a  anon=302 9ae81ad7b11c

[HIGH/SUSPICIOUS] https://app.example.test/account/wcd-lab.css
  confidence=high match=true cache_confirmed=true
  authenticated content appears reproducible anonymously on a static-looking path with shared-cache evidence
  evidence: Age=13, CF-Cache-Status=HIT

Summary: 5 variants · 1 suspicious · 1 high · 0 medium · 0 low
```

## Burp Suite workflow

Send every request through Burp:

```bash
./wcdscan \
  --authorized \
  --url "https://app.example.test/account" \
  --cookie "session=YOUR_TEST_SESSION" \
  --proxy "http://127.0.0.1:8080" \
  --insecure
```

You can then inspect every request in **Proxy → HTTP history** while keeping `wcdscan`'s evidence model and reports.

## Reports

```bash
./wcdscan \
  --authorized \
  --url "https://app.example.test/account" \
  --cookie "session=YOUR_TEST_SESSION" \
  --html-file reports/wcd.html \
  --json-file reports/wcd.json
```

For automation:

```bash
./wcdscan --authorized --url https://app.example.test/account --cookie "$SESSION" --json
```

Fail CI only when a chosen severity is reached:

```bash
./wcdscan \
  --authorized \
  --url "https://staging.example.test/account" \
  --cookie "$TEST_SESSION" \
  --fail-on high
```

Exit code `2` means the selected severity threshold was reached.

Or only print suspicious variant URLs:

```bash
./wcdscan --authorized --url https://app.example.test/account --cookie "$SESSION" --quiet
```

## Authentication

Cookie session:

```bash
--cookie "session=..."
```

Bearer/API token:

```bash
--authorization "Bearer ..."
```

Additional headers can be repeated:

```bash
--header "X-Tenant: acme" \
--header "Accept-Language: en"
```

`Host`, `Cookie`, and `Authorization` are intentionally not accepted through `--header`; use the dedicated options.

## What it analyzes

Cache/CDN indicators include:

```text
Age
Cache-Control
CDN-Cache-Control
Surrogate-Control
Vary
ETag
Last-Modified
X-Cache
X-Cache-Hits
CF-Cache-Status
Akamai-Cache-Status
X-Proxy-Cache
X-Cacheable
Via
Server-Timing
```

Current variants are deliberately conservative:

```text
/account/wcd-<token>.css
/account/wcd-<token>.js
/account/wcd-<token>.png
/account/wcd-<token>.woff2
/account;wcd-<token>.css
```

The goal is useful evidence, not maximum request volume.

## Severity model

| Severity | Meaning |
|---|---|
| **High** | Personalized baseline differs, anonymous variant matches authenticated variant, and shared-cache behavior is confirmed. |
| **Medium** | Authenticated and anonymous variants match, but cache evidence is not strong enough yet. |
| **Low** | Suspicious cache policy/cache evidence exists, but anonymous content does not match the authenticated variant. |
| **Info** | Interesting behavior with no strong WCD signal. |

See [`docs/DETECTION.md`](docs/DETECTION.md) for the full detection model.

## Privacy-first by design

`wcdscan` does **not** print response bodies. It stores:

- status code;
- body length;
- SHA-256 body hash;
- cache-related headers;
- classification evidence.

This makes the output safer to share in issue trackers, pentest notes, and CI logs.

## CLI reference

```text
--url             target URL
--authorized      confirm authorized testing
--cookie          test-account Cookie header
--authorization   test-account Authorization header
--header          additional header (repeatable)
--proxy           HTTP(S) proxy
--insecure        skip TLS verification for labs/local proxies
--timeout         per-request timeout
--pause           delay between confirmation requests
--confirm         number of anonymous confirmation requests
--max-body        max response bytes hashed
--json            JSON to stdout
--json-file       JSON report path
--html-file       HTML report path
--quiet           suspicious URLs only
--version         print version
--fail-on         CI exit threshold: low, medium, or high
```

## Roadmap

Planned features are intentionally focused on evidence quality rather than request count:

- [ ] HAR/Burp request import
- [ ] multiple endpoint batch scanning
- [ ] richer CDN fingerprinting
- [ ] cache-key differential mode
- [ ] SARIF output for CI
- [ ] passive mode for captured traffic
- [ ] configurable variant profiles
- [ ] reproducible sanitized request snippets
- [ ] signed release binaries

Have an idea? Open a feature request.

## How it fits with other cache tools

`wcdscan` is intentionally a focused verification tool rather than an all-in-one cache scanner. See [`docs/COMPARISON.md`](docs/COMPARISON.md) for the project philosophy and where it fits alongside broader scanners and Burp-based workflows.

## Philosophy

A pentest tool should help you answer:

> **“What evidence do I have, and can another researcher reproduce it?”**

—not merely print `VULNERABLE` in red.

## Legal / ethical use

Use `wcdscan` only against systems you own or have explicit permission to test. Prefer test accounts and non-production environments where possible.

## Contributing

Contributions are welcome. See [`CONTRIBUTING.md`](CONTRIBUTING.md).

## Security

Please do not open public issues for vulnerabilities in `wcdscan` itself. See [`SECURITY.md`](SECURITY.md).

## License

MIT — see [`LICENSE`](LICENSE).
