import { createHash } from "node:crypto";
import tls from "node:tls";
import type { CertSummary, TlsReport } from "./types.js";

export function parseTarget(input: string): { host: string; port: number } {
  const trimmed = input.replace(/^https?:\/\//, "").replace(/\/.*$/, "");
  const [host, portText] = trimmed.split(":");
  if (!host) throw new Error("host is required");
  const port = portText ? Number(portText) : 443;
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error(`invalid port: ${portText}`);
  }
  return { host, port };
}

function altNames(peer: tls.DetailedPeerCertificate): string[] {
  const san = peer.subjectaltname ?? "";
  return san
    .split(",")
    .map((part) => part.trim())
    .filter((part) => part.startsWith("DNS:"))
    .map((part) => part.slice(4));
}

function cn(value: string | string[] | undefined, fallback: object): string {
  if (Array.isArray(value)) return value.join(", ");
  if (value) return value;
  return JSON.stringify(fallback);
}

function summarize(peer: tls.DetailedPeerCertificate): CertSummary {
  const validTo = new Date(peer.valid_to);
  const daysRemaining = Math.floor((validTo.getTime() - Date.now()) / 86_400_000);
  const der = peer.raw;
  return {
    subject: cn(peer.subject.CN, peer.subject),
    issuer: cn(peer.issuer.CN, peer.issuer),
    validFrom: peer.valid_from,
    validTo: peer.valid_to,
    daysRemaining,
    serialNumber: peer.serialNumber,
    fingerprint256: der
      ? createHash("sha256").update(der).digest("hex")
      : peer.fingerprint256.replace(/:/g, "").toLowerCase(),
    subjectAltName: altNames(peer),
    authorized: true,
  };
}

export function inspectTarget(
  host: string,
  port: number,
  timeoutMs = 10_000,
): Promise<TlsReport> {
  return new Promise((resolve, reject) => {
    const socket = tls.connect(
      {
        host,
        port,
        servername: host,
        rejectUnauthorized: false,
      },
      () => {
        try {
          const chain: CertSummary[] = [];
          let current: tls.DetailedPeerCertificate | undefined =
            socket.getPeerCertificate(true);
          const seen = new Set<string>();
          while (current && current.raw) {
            const fp = createHash("sha256").update(current.raw).digest("hex");
            if (seen.has(fp)) break;
            seen.add(fp);
            chain.push(summarize(current));
            const issuer: tls.DetailedPeerCertificate | undefined =
              current.issuerCertificate;
            if (!issuer || issuer === current) break;
            current = issuer;
          }
          const cipher = socket.getCipher();
          const report: TlsReport = {
            host,
            port,
            protocol: socket.getProtocol(),
            authorized: socket.authorized,
            authorizationError: socket.authorizationError
              ? String(socket.authorizationError)
              : null,
            alpn: socket.alpnProtocol || null,
            cipher: cipher ? `${cipher.name} ${cipher.version}` : null,
            certificates: chain.map((c, i) => ({
              ...c,
              authorized: i === 0 ? socket.authorized : true,
            })),
          };
          socket.end();
          resolve(report);
        } catch (error) {
          socket.destroy();
          reject(error);
        }
      },
    );
    socket.setTimeout(timeoutMs, () => {
      socket.destroy();
      reject(new Error(`timeout connecting to ${host}:${port}`));
    });
    socket.on("error", reject);
  });
}
