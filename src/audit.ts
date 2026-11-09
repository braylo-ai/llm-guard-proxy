/**
 * Audit log of guard decisions. Contract: NO raw PII, secrets, prompts or
 * model output ever enter an audit record. Values are represented only by a
 * salted SHA-256 fingerprint (first 12 hex chars) so repeat offenders can be
 * correlated without storing the value.
 */

export interface Finding {
  stage: "inbound" | "outbound" | "relay";
  detector: "pii" | "injection" | "classifier" | "canary" | "exfil" | "secret";
  /** PII type or injection family / rule id; never the matched text */
  label: string;
  action: string;
  count: number;
  fingerprints?: string[];
}

export interface AuditRecord {
  ts: string;
  request_id: string;
  tenant: string;
  route: string;
  decision: "allow" | "redacted" | "flagged" | "blocked" | "neutralized";
  findings: Finding[];
  upstream_status?: number;
  guard_ms?: number;
}

export interface AuditSink {
  write(r: AuditRecord): void | Promise<void>;
}

export class ConsoleAuditSink implements AuditSink {
  write(r: AuditRecord) {
    console.log(JSON.stringify({ type: "llm_guard_audit", ...r }));
  }
}

export class MemoryAuditSink implements AuditSink {
  records: AuditRecord[] = [];
  write(r: AuditRecord) {
    this.records.push(r);
  }
}

const enc = new TextEncoder();

export async function fingerprint(value: string, salt: string): Promise<string> {
  const d = new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(`${salt}\u0000${value}`)));
  return [...d.slice(0, 6)].map((b) => b.toString(16).padStart(2, "0")).join("");
}
