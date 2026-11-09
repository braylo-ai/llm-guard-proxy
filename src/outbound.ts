import { detectPii, type Entity, type PiiType } from "./pii";
import { PLACEHOLDER_RE } from "./vault";

/**
 * Outbound (model -> client) scanners:
 *  - secret / PII leakage (values the model emitted that were never placeholders)
 *  - canary tokens (proves the model is repeating its system prompt)
 *  - exfiltration URLs (markdown images/links that smuggle data in the query)
 */

export function canaryHit(text: string, canaries: string[]): string | undefined {
  const squash = (s: string) => s.toLowerCase().replace(/[^a-z0-9]/g, "");
  const t = squash(text);
  for (const c of canaries) {
    const sc = squash(c);
    if (sc.length >= 8 && t.includes(sc)) return c;
    // base64-encoded canary
    try {
      if (text.includes(btoa(c)) || text.includes(btoa(c).replace(/=+$/, ""))) return c;
    } catch {
      /* non-latin canary */
    }
    // reversed canary
    if (sc.length >= 8 && t.includes([...sc].reverse().join(""))) return c;
  }
  return undefined;
}

export interface ExfilHit {
  url: string;
  reason: "image_with_query" | "link_with_placeholder" | "link_with_pii" | "link_with_long_param";
}

const MD_URL = /(!?)\[[^\]]*\]\(\s*(https?:\/\/[^\s)]+)\s*\)|(?<![\w(])(https?:\/\/[^\s<>"')]+)/g;

export function findExfilUrls(text: string, allowHosts: string[]): ExfilHit[] {
  const hits: ExfilHit[] = [];
  for (const m of text.matchAll(MD_URL)) {
    const isImage = m[1] === "!";
    const url = m[2] ?? m[3];
    if (!url) continue;
    let u: URL;
    try {
      u = new URL(url);
    } catch {
      continue;
    }
    if (allowHosts.some((h) => u.hostname === h || u.hostname.endsWith(`.${h}`))) continue;
    const q = decodeURIComponent(u.search + u.hash);
    const pathAndQuery = decodeURIComponent(u.pathname) + q;
    if (isImage && u.search.length > 1) {
      hits.push({ url: u.origin, reason: "image_with_query" });
      continue;
    }
    if (new RegExp(PLACEHOLDER_RE.source).test(pathAndQuery)) {
      hits.push({ url: u.origin, reason: "link_with_placeholder" });
      continue;
    }
    if (detectPii(pathAndQuery, ["EMAIL", "PHONE", "SSN", "CREDIT_CARD", "IBAN", "SECRET"]).length) {
      hits.push({ url: u.origin, reason: "link_with_pii" });
      continue;
    }
    for (const v of u.searchParams.values()) {
      if (v.length >= 64) {
        hits.push({ url: u.origin, reason: "link_with_long_param" });
        break;
      }
    }
  }
  return hits;
}

export interface LeakScan {
  secrets: Entity[];
  pii: Entity[];
}

/** Leak scan on raw model output (before rehydration, so placeholders are not PII). */
export function scanLeaks(text: string, enabled: PiiType[], allowlist: string[]): LeakScan {
  const all = detectPii(text, enabled, allowlist);
  return { secrets: all.filter((e) => e.type === "SECRET"), pii: all.filter((e) => e.type !== "SECRET") };
}

export function maskEntities(text: string, entities: Entity[]): string {
  let out = text;
  for (const e of [...entities].sort((a, b) => b.start - a.start)) {
    out = out.slice(0, e.start) + `[REDACTED_${e.type}]` + out.slice(e.end);
  }
  return out;
}
