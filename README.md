<p align="center">
  <img src="logo.png" alt="tlsscope" width="160" height="160" />
</p>

# tlsscope

Inspect a live TLS handshake from the command line. Print the certificate chain, negotiated protocol, and policy findings as JSON or SARIF.

[![CI](https://github.com/theworker02/tlsscope/actions/workflows/ci.yml/badge.svg)](https://github.com/theworker02/tlsscope/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/@magnexis/tlsscope.svg)](https://www.npmjs.com/package/@magnexis/tlsscope)
[![license](https://img.shields.io/badge/license-Proprietary%20(source--available)-blue.svg)](LICENSE)

## Install

```bash
npm install -g @magnexis/tlsscope
npx @magnexis/tlsscope --help
```

Requires Node.js 20+.

## Why

`openssl s_client` is powerful and noisy. CI jobs usually want: is this host still on TLS 1.2+, is the leaf trusted, and how many days until expiry Ã¢â‚¬â€ as JSON (or SARIF for GitHub code scanning).

tlsscope does that handshake with the platform TLS stack and a small policy engine.

## CLI

```text
tlsscope inspect example.com
tlsscope inspect example.com:8443
tlsscope inspect https://example.com/health
tlsscope check example.com --min-days 30 --min-protocol TLSv1.2
tlsscope check example.com --sarif -o tls.sarif
tlsscope policy
```

### inspect

Emits a report with protocol, cipher, authorization status, and the chain (subject, issuer, SAN, SHA-256 fingerprint, days remaining).

### check

Applies policy and exits `1` on any **error** finding:

| Finding | When |
| --- | --- |
| `tls-unauthorized` | chain not trusted (unless `--allow-unauthorized`) |
| `tls-protocol` | negotiated protocol below `--min-protocol` |
| `tls-expiry` | leaf `daysRemaining` below `--min-days` (warning until it is negative) |
| `tls-name` | host not covered by SAN/CN (supports `*.example.com`) |

### SARIF

`--sarif` writes SARIF 2.1. Upload in GitHub Actions:

```yaml
- run: npx @magnexis/tlsscope check api.example.com --sarif -o tls.sarif
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: tls.sarif
```

## Library

```ts
import { inspectTarget, evaluate, defaultPolicy } from "@magnexis/tlsscope";

const report = await inspectTarget("example.com", 443);
const findings = evaluate(report, defaultPolicy());
```

This tool **inspects** endpoints you operate or are authorized to test. It does not exploit TLS implementations.

## Development

```bash
git clone https://github.com/theworker02/tlsscope.git
cd tlsscope
npm install
npm test
npm run build
```

## License

**Source-available proprietary** â€” evaluation under [LICENSE](./LICENSE); commercial / production use via [COMMERCIAL.md](./COMMERCIAL.md). See [LICENSE_TRANSITION_NOTICE.md](./LICENSE_TRANSITION_NOTICE.md) and [NOTICE](./NOTICE).


---

## License & acquisition

This project is **proprietary**. Production use, redistribution, and commercial deployment require a written commercial license or completed acquisition. See [LICENSE](./LICENSE) and [ACQUISITION.md](./ACQUISITION.md). Contact [@theworker02](https://github.com/theworker02).

## Status

tlsscope is actively packaged for commercial licensing and acquisition diligence. See [ACQUISITION.md](./ACQUISITION.md) and [docs/acquisition/](./docs/acquisition/).
