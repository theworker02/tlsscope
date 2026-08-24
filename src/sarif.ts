import type { Finding, TlsReport } from "./types.js";

export function toSarif(report: TlsReport, findings: Finding[]) {
  return {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "tlsscope",
            version: "1.0.0",
            informationUri: "https://github.com/theworker02/tlsscope",
            rules: findings.map((f) => ({
              id: f.id,
              shortDescription: { text: f.message },
            })),
          },
        },
        results: findings.map((f) => ({
          ruleId: f.id,
          level: f.severity === "error" ? "error" : "warning",
          message: { text: f.message },
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri: `tls://${report.host}:${report.port}` },
              },
            },
          ],
        })),
      },
    ],
  };
}
