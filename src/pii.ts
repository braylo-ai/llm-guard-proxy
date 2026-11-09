/**
 * PII + secret detectors. Pure functions, no I/O, deterministic.
 * Each detector returns character spans. Overlaps are resolved by detector
 * priority (secrets > cards > IBAN > SSN > email > phone > address).
 */

export type PiiType =
  | "SECRET"
  | "CREDIT_CARD"
  | "IBAN"
  | "SSN"
  | "EMAIL"
  | "PHONE"
  | "ADDRESS";

export const ALL_PII_TYPES: PiiType[] = [
  "SECRET",
  "CREDIT_CARD",
  "IBAN",
  "SSN",
  "EMAIL",
  "PHONE",
  "ADDRESS",
];

export interface Entity {
  type: PiiType;
  start: number;
  end: number;
  value: string;
}

// ---------- validators ----------

export function luhnValid(digits: string): boolean {
  if (!/^\d+$/.test(digits)) return false;
  let sum = 0;
  let dbl = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = digits.charCodeAt(i) - 48;
    if (dbl) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
    dbl = !dbl;
  }
  return sum % 10 === 0;
}

/** Issuer prefix + length check (Visa, MC, Amex, Discover, JCB, Diners). */
function cardPrefixOk(d: string): boolean {
  const n = d.length;
  if (/^4/.test(d)) return n === 13 || n === 16 || n === 19;
  if (/^(5[1-5]|2(2[2-9]|[3-6]\d|7[01]|720))/.test(d)) return n === 16;
  if (/^3[47]/.test(d)) return n === 15;
  if (/^(6011|65|64[4-9])/.test(d)) return n >= 16 && n <= 19;
  if (/^35(2[89]|[3-8]\d)/.test(d)) return n >= 16 && n <= 19;
  if (/^3(0[0-5]|[68])/.test(d)) return n >= 14 && n <= 19;
  return false;
}

const IBAN_LENGTHS: Record<string, number> = {
  AD: 24, AT: 20, BE: 16, CH: 21, CY: 28, CZ: 24, DE: 22, DK: 18, EE: 20,
  ES: 24, FI: 18, FR: 27, GB: 22, GR: 27, HR: 21, HU: 28, IE: 22, IS: 26,
  IT: 27, LI: 21, LT: 20, LU: 20, LV: 21, MC: 27, MT: 31, NL: 18, NO: 15,
  PL: 28, PT: 25, RO: 24, SE: 24, SI: 19, SK: 24, SM: 27, TR: 26, SA: 24,
  AE: 23, IL: 23, QA: 29, BR: 29, MU: 30,
};

export function ibanValid(raw: string): boolean {
  const s = raw.replace(/\s+/g, "").toUpperCase();
  if (!/^[A-Z]{2}\d{2}[A-Z0-9]+$/.test(s)) return false;
  const expected = IBAN_LENGTHS[s.slice(0, 2)];
  if (expected !== undefined && s.length !== expected) return false;
  if (expected === undefined && (s.length < 15 || s.length > 34)) return false;
  const rearranged = s.slice(4) + s.slice(0, 4);
  let rem = 0;
  for (const ch of rearranged) {
    const v = ch >= "A" && ch <= "Z" ? (ch.charCodeAt(0) - 55).toString() : ch;
    for (const c of v) rem = (rem * 10 + (c.charCodeAt(0) - 48)) % 97;
  }
  return rem === 1;
}

function ssnValid(area: string, group: string, serial: string): boolean {
  if (area === "000" || area === "666" || area[0] === "9") return false;
  if (group === "00" || serial === "0000") return false;
  return true;
}

/** Shannon entropy in bits/char; used to reject low-entropy "secret" values. */
function entropy(s: string): number {
  const f = new Map<string, number>();
  for (const c of s) f.set(c, (f.get(c) ?? 0) + 1);
  let h = 0;
  for (const n of f.values()) {
    const p = n / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

// ---------- detectors ----------

type Raw = { start: number; end: number; value: string };

function scan(re: RegExp, text: string, group = 0, keep?: (m: RegExpExecArray) => boolean): Raw[] {
  const out: Raw[] = [];
  const g = new RegExp(re.source, re.flags.includes("g") ? re.flags : re.flags + "g");
  let m: RegExpExecArray | null;
  while ((m = g.exec(text))) {
    if (m[0].length === 0) {
      g.lastIndex++;
      continue;
    }
    if (keep && !keep(m)) continue;
    const value = m[group];
    if (value === undefined) continue;
    const start = m.index + m[0].indexOf(value);
    out.push({ start, end: start + value.length, value });
  }
  return out;
}

const SECRET_PATTERNS: Array<{ re: RegExp; group?: number; keep?: (m: RegExpExecArray) => boolean }> = [
  { re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----[\s\S]*?(?:-----END (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----|$)/ },
  { re: /\bsk-(?:ant-|proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}/ },
  { re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/ },
  { re: /\bgh[pousr]_[A-Za-z0-9]{30,}\b/ },
  { re: /\bgithub_pat_[A-Za-z0-9_]{40,}\b/ },
  { re: /\bxox[abprs]-[A-Za-z0-9-]{10,}/ },
  { re: /\b(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{16,}\b/ },
  { re: /\bAIza[0-9A-Za-z_-]{35}\b/ },
  { re: /\bglpat-[A-Za-z0-9_-]{20,}\b/ },
  { re: /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/ },
  { re: /\bBearer\s+([A-Za-z0-9._~+/-]{20,}=*)/, group: 1 },
  {
    // key = value assignments; value must look random (entropy + mixed classes)
    re: /\b(?:api[_-]?key|apikey|secret(?:[_-]?key)?|access[_-]?token|auth[_-]?token|client[_-]?secret|password|passwd|pwd)\b["']?\s*[:=]\s*["']?([^\s"',;]{8,})/i,
    group: 1,
    keep: (m) => {
      const v = m[1] ?? "";
      const classes = [/[a-z]/, /[A-Z]/, /\d/, /[^A-Za-z0-9]/].filter((r) => r.test(v)).length;
      return entropy(v) >= 3.0 && classes >= 2 && !/^\[\[[A-Z_]+_\d+\]\]$/.test(v);
    },
  },
];

function detectSecrets(t: string): Raw[] {
  return SECRET_PATTERNS.flatMap((p) => scan(p.re, t, p.group ?? 0, p.keep));
}

function detectCards(t: string): Raw[] {
  return scan(/(?<![\d.-])(?:\d[ .-]?){12,18}\d(?![\d-]|\.\d)/, t).filter((r) => {
    const d = r.value.replace(/[ .-]/g, "");
    if (d.length < 13 || d.length > 19) return false;
    // separators, if any, must be consistent groups (avoid matching "1 2 3 ...")
    if (/[ .-]/.test(r.value) && !/^\d{4}([ .-])\d{4,6}(\1\d{4,5}){0,3}(\1\d{1,4})?$/.test(r.value)) return false;
    return luhnValid(d) && cardPrefixOk(d);
  });
}

function detectIban(t: string): Raw[] {
  return scan(/\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,3})?\b/, t).filter((r) => ibanValid(r.value));
}

function detectSsn(t: string): Raw[] {
  const dashed = scan(/(?<![\d-])(\d{3})-(\d{2})-(\d{4})(?![\d-])/, t, 0, (m) => ssnValid(m[1]!, m[2]!, m[3]!));
  const keyworded = scan(
    /\b(?:ssn|social security(?: number| no\.?| #)?|ss#)\s*(?:is|:|#)?\s*((\d{3}) ?(\d{2}) ?(\d{4}))\b/i,
    t,
    1,
    (m) => ssnValid(m[2]!, m[3]!, m[4]!),
  );
  return [...dashed, ...keyworded];
}

function detectEmail(t: string): Raw[] {
  return scan(/(?<![A-Za-z0-9._%+'-])[A-Za-z0-9._%+-]+(?:'[A-Za-z0-9._%+-]+)*@(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,24}\b/, t);
}

function detectPhone(t: string): Raw[] {
  // NANP with separators or parentheses, optional +1
  const nanp = scan(
    /(?<![\d\w.+-])(?:\+?1[ .-]?)?(?:\(([2-9]\d{2})\)\s?|([2-9]\d{2})[ .-])([2-9]\d{2})[ .-](\d{4})(?![\d-]|\.\d)/,
    t,
  );
  // E.164 / international with leading +
  const intl = scan(/(?<![\w+])\+(?:[2-9]\d{0,2})(?:[ .-]?\(?\d{1,4}\)?)(?:[ .-]?\d{2,4}){2,4}(?![\d-])/, t).filter((r) => {
    const n = r.value.replace(/\D/g, "").length;
    return n >= 8 && n <= 15;
  });
  // bare 10 digits only right after a phone keyword
  const keyworded = scan(/\b(?:call|phone|tel|mobile|cell|text|fax|whatsapp)\b[^\d\n]{0,12}(\+?1?[2-9]\d{2}[2-9]\d{6})\b/i, t, 1);
  return [...nanp, ...intl, ...keyworded];
}

const STREET_SUFFIX =
  "(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct|Way|Place|Pl|Terrace|Ter|Parkway|Pkwy|Circle|Cir|Highway|Hwy|Square|Sq)";

function detectAddress(t: string): Raw[] {
  const street = new RegExp(
    String.raw`\b\d{1,6}[A-Z]?\s+(?:[NSEW]\.?\s+)?(?:[A-Z][a-z]+\.?\s+|\d{1,3}(?:st|nd|rd|th)\s+){1,4}${STREET_SUFFIX}\b` +
      String.raw`(?:,?\s+(?:Apt|Apartment|Suite|Ste|Unit|#)\.?\s*[A-Za-z0-9-]+)?` +
      String.raw`(?:,\s*[A-Z][a-z]+(?:\s[A-Z][a-z]+){0,2},\s*[A-Z]{2}(?:\s+\d{5}(?:-\d{4})?)?)?`,
  );
  const pobox = /\bP\.?\s?O\.?\s+Box\s+\d{1,6}\b/i;
  return [...scan(street, t), ...scan(pobox, t)];
}

const ORDERED: Array<[PiiType, (t: string) => Raw[]]> = [
  ["SECRET", detectSecrets],
  ["CREDIT_CARD", detectCards],
  ["IBAN", detectIban],
  ["SSN", detectSsn],
  ["EMAIL", detectEmail],
  ["PHONE", detectPhone],
  ["ADDRESS", detectAddress],
];

/** Detect entities of the enabled types; non-overlapping, sorted by start. */
export function detectPii(text: string, enabled: PiiType[] = ALL_PII_TYPES, allowlist: string[] = []): Entity[] {
  const allow = new Set(allowlist.map((a) => a.toLowerCase()));
  const taken: Entity[] = [];
  const overlaps = (s: number, e: number) => taken.some((x) => s < x.end && e > x.start);
  for (const [type, fn] of ORDERED) {
    if (!enabled.includes(type)) continue;
    const found = fn(text).sort((a, b) => a.start - b.start || b.end - a.end);
    for (const r of found) {
      if (overlaps(r.start, r.end)) continue;
      if (allow.has(r.value.toLowerCase()) || isAllowedDomain(r.value, allow)) continue;
      taken.push({ type, ...r });
    }
  }
  return taken.sort((a, b) => a.start - b.start);
}

/** Allowlist entries like "@example.com" allow every email at that domain. */
function isAllowedDomain(value: string, allow: Set<string>): boolean {
  const at = value.lastIndexOf("@");
  return at > 0 && allow.has(value.slice(at).toLowerCase());
}
