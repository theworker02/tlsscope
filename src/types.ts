export interface CertSummary {
  subject: string;
  issuer: string;
  validFrom: string;
  validTo: string;
  daysRemaining: number;
  serialNumber: string;
  fingerprint256: string;
  subjectAltName: string[];
  authorized: boolean;
}

export interface TlsReport {
  host: string;
  port: number;
  protocol: string | null;
  authorized: boolean;
  authorizationError: string | null;
  alpn: string | null;
  cipher: string | null;
  certificates: CertSummary[];
}

export interface Policy {
  minDaysRemaining: number;
  minProtocol: "TLSv1.2" | "TLSv1.3";
  requireAuthorization: boolean;
}

export interface Finding {
  id: string;
  severity: "error" | "warning";
  message: string;
}

export const defaultPolicy = (): Policy => ({
  minDaysRemaining: 14,
  minProtocol: "TLSv1.2",
  requireAuthorization: true,
});
