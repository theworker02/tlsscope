import { describe, expect, it } from "vitest";
import { parseTarget } from "../src/inspect.js";
import { evaluate, namesCover } from "../src/policy.js";
import { toSarif } from "../src/sarif.js";
import { defaultPolicy, type TlsReport } from "../src/types.js";

describe("parseTarget", () => {
  it("defaults https to 443", () => {
    expect(parseTarget("https://example.com/path")).toEqual({
      host: "example.com",
      port: 443,
    });
  });
});

describe("namesCover", () => {
  it("matches wildcards", () => {
    expect(namesCover("www.example.com", ["*.example.com"])).toBe(true);
    expect(namesCover("example.com", ["*.example.com"])).toBe(false);
  });
});

describe("evaluate", () => {
  const base = (): TlsReport => ({
    host: "example.com",
    port: 443,
    protocol: "TLSv1.3",
    authorized: true,
    authorizationError: null,
    alpn: "h2",
    cipher: "TLS_AES_128_GCM_SHA256 TLSv1.3",
    certificates: [
      {
        subject: "example.com",
        issuer: "CA",
        validFrom: "Jan 1 00:00:00 2026 GMT",
        validTo: "Jan 1 00:00:00 2027 GMT",
        daysRemaining: 90,
        serialNumber: "1",
        fingerprint256: "aa",
        subjectAltName: ["example.com"],
        authorized: true,
      },
    ],
  });

  it("is clean for a healthy leaf", () => {
    expect(evaluate(base(), defaultPolicy())).toHaveLength(0);
  });

  it("flags short remaining lifetime", () => {
    const report = base();
    report.certificates[0].daysRemaining = 3;
    const findings = evaluate(report, defaultPolicy());
    expect(findings.some((f) => f.id === "tls-expiry")).toBe(true);
  });

  it("builds SARIF results", () => {
    const report = base();
    report.authorized = false;
    report.authorizationError = "UNABLE_TO_VERIFY_LEAF_SIGNATURE";
    const sarif = toSarif(report, evaluate(report, defaultPolicy()));
    expect(sarif.runs[0].results.length).toBeGreaterThan(0);
  });
});
