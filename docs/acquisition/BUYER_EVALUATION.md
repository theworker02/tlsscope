# Buyer evaluation â€” tlsscope

## Goal

In 15â€“45 minutes, verify the Product builds or runs as documented and that proprietary notices are present.

## Steps

1. Confirm root `LICENSE` is proprietary and `ACQUISITION.md` exists.
2. Skim `README.md` install/run claims.
3. Execute:

```
```bash
npm install -g @magnexis/tlsscope
npx @magnexis/tlsscope --help
```
```text
tlsscope inspect example.com
tlsscope inspect example.com:8443
tlsscope inspect https://example.com/health
tlsscope check example.com --min-days 30 --min-protocol TLSv1.2
tlsscope check example.com --sarif -o tls.sarif
tlsscope policy
```
```yaml
- run: npx @magnexis/tlsscope check api.example.com --sarif -o tls.sarif
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: tls.sarif
```
```ts
import { inspectTarget, evaluate, defaultPolicy } from "@magnexis/tlsscope";

const report = await inspectTarget("example.com", 443);
const findings = evaluate(report, defaultPolicy());
```
```bash
git clone https://github.com/theworker02/tlsscope.git
cd tlsscope
npm install
npm test
npm run build
```
```

4. Run tests if present (`npm test`, `pytest`, `cargo test`, `go test ./...`, etc.).
5. Record README vs observed behavior gaps in workpapers.

## Pass criteria

- [ ] Clone succeeds
- [ ] Documented happy path works **or** failure is explained
- [ ] Minimal path needs no surprise secrets
- [ ] License notices intact

*Updated: 2026-09-22*
