import type { Finding, Policy, TlsReport } from "./types.js";

const rank: Record<string, number> = {
  TLSv1: 1,
  "TLSv1.1": 2,
  "TLSv1.2": 3,
  "TLSv1.3": 4,
};

export function evaluate(report: TlsReport, policy: Policy): Finding[] {
  const findings: Finding[] = [];
  if (policy.requireAuthorization && !report.authorized) {
    findings.push({
      id: "tls-unauthorized",
      severity: "error",
      message: report.authorizationError ?? "certificate is not trusted",
    });
  }
  const proto = report.protocol ?? "";
  if ((rank[proto] ?? 0) < rank[policy.minProtocol]) {
    findings.push({
      id: "tls-protocol",
      severity: "error",
      message: `negotiated ${proto || "unknown"} below ${policy.minProtocol}`,
    });
  }
  const leaf = report.certificates[0];
  if (leaf && leaf.daysRemaining < policy.minDaysRemaining) {
    findings.push({
      id: "tls-expiry",
      severity: leaf.daysRemaining < 0 ? "error" : "warning",
      message: `leaf certificate expires in ${leaf.daysRemaining} days`,
    });
  }
  if (leaf && !namesCover(report.host, leaf.subjectAltName.concat(leaf.subject))) {
    findings.push({
      id: "tls-name",
      severity: "error",
      message: `host ${report.host} is not in SAN/CN`,
    });
  }
  return findings;
}

export function namesCover(host: string, names: string[]): boolean {
  const h = host.toLowerCase();
  return names.some((name) => {
    const n = name.toLowerCase();
    if (n === h) return true;
    if (n.startsWith("*.")) {
      const rest = n.slice(2);
      const idx = h.indexOf(".");
      return idx > 0 && h.slice(idx + 1) === rest;
    }
    return false;
  });
}
