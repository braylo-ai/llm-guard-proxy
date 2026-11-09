/**
 * Produce de-obfuscated "views" of a text so that injection rules see through
 * common encoding tricks. Each view records how it was derived, so a hit in a
 * decoded view can be reported (and weighted) as obfuscated.
 */

export interface View {
  kind: "plain" | "leet" | "despaced" | "base64" | "hex" | "url" | "rot13" | "reversed";
  text: string;
}

const ZERO_WIDTH = /[​-‏‪-‮⁠-⁤﻿­]/g;

// Cyrillic / Greek look-alikes -> Latin
const HOMOGLYPHS: Record<string, string> = {
  "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j",
  "ѕ": "s", "ԁ": "d", "ɡ": "g", "һ": "h", "ӏ": "l", "м": "m", "т": "t", "к": "k", "в": "b",
  "н": "h", "А": "a", "Е": "e", "О": "o", "Р": "p", "С": "c", "Т": "t", "Х": "x", "І": "i",
  "ο": "o", "α": "a", "ε": "e", "ι": "i", "ν": "v", "ρ": "p", "τ": "t", "υ": "u",
};

const LEET: Record<string, string> = { "0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s", "!": "i", "|": "l" };

export function basicNormalize(s: string): string {
  let t = s.normalize("NFKC").replace(ZERO_WIDTH, "");
  t = t.replace(/[^\u0000-\u007F]/g, (c) => HOMOGLYPHS[c] ?? c);
  return t.toLowerCase().replace(/[ \t]+/g, " ");
}

function leet(s: string): string {
  // map digits/symbols only inside tokens that also contain a letter, so "version 1.0" stays intact
  return s.replace(/[a-z0-9@$!|]+/g, (tok) => (/[a-z]/.test(tok) ? tok.replace(/[013457@$!|]/g, (c) => LEET[c] ?? c) : tok));
}

/** "i g n o r e  a l l" -> "ignore all" (runs of single chars separated by one space/punct) */
function despace(raw: string): string {
  // 2+ spaces mark a word gap; single separators inside a run of single letters are removed
  const s = raw.normalize("NFKC").replace(ZERO_WIDTH, "").toLowerCase().replace(/[ \t]{2,}/g, " | ");
  return s
    .replace(/\b(?:[a-z][ .\-_*]){2,}[a-z]\b/g, (run) => run.replace(/[ .\-_*]/g, ""))
    .replace(/ \| /g, " ")
    .replace(/ {2,}/g, " ");
}

function rot13(s: string): string {
  return s.replace(/[a-z]/gi, (c) => {
    const b = c <= "Z" ? 65 : 97;
    return String.fromCharCode(((c.charCodeAt(0) - b + 13) % 26) + b);
  });
}

function printableRatio(s: string): number {
  if (!s.length) return 0;
  let ok = 0;
  for (const c of s) if (/[\x20-\x7E\n\r\t]/.test(c)) ok++;
  return ok / s.length;
}

function decodeBase64Segments(s: string): string[] {
  const out: string[] = [];
  for (const m of s.matchAll(/[A-Za-z0-9+/]{16,}={0,2}|[A-Za-z0-9_-]{24,}/g)) {
    try {
      const b = m[0].replace(/-/g, "+").replace(/_/g, "/");
      const padded = b + "=".repeat((4 - (b.length % 4)) % 4);
      const dec = atob(padded);
      if (printableRatio(dec) > 0.9 && /[a-z]{3,}\s/i.test(dec)) out.push(dec);
    } catch {
      /* not base64 */
    }
  }
  return out;
}

function decodeHexSegments(s: string): string[] {
  const out: string[] = [];
  for (const m of s.matchAll(/(?:(?:0x|\\x)?[0-9a-f]{2}[ :]?){8,}/gi)) {
    const hex = m[0].replace(/0x|\\x|[ :]/gi, "");
    if (hex.length % 2) continue;
    let dec = "";
    for (let i = 0; i < hex.length; i += 2) dec += String.fromCharCode(parseInt(hex.slice(i, i + 2), 16));
    if (printableRatio(dec) > 0.9 && /[a-z]{3,}/i.test(dec)) out.push(dec);
  }
  return out;
}

export function views(raw: string): View[] {
  const plain = basicNormalize(raw);
  const v: View[] = [{ kind: "plain", text: plain }];
  const l = leet(plain);
  if (l !== plain) v.push({ kind: "leet", text: l });
  const d = leet(basicNormalize(despace(raw)));
  if (d !== l && d !== plain) v.push({ kind: "despaced", text: d });
  for (const dec of decodeBase64Segments(raw)) v.push({ kind: "base64", text: basicNormalize(dec) });
  for (const dec of decodeHexSegments(raw)) v.push({ kind: "hex", text: basicNormalize(dec) });
  if (/%[0-9a-f]{2}/i.test(raw)) {
    try {
      const u = decodeURIComponent(raw);
      if (u !== raw) v.push({ kind: "url", text: basicNormalize(u) });
    } catch {
      /* malformed */
    }
  }
  // rot13 / reversal only when the text itself hints at the trick, to bound false positives
  if (/\brot[- ]?13\b|caesar/i.test(raw)) v.push({ kind: "rot13", text: basicNormalize(rot13(raw)) });
  if (/\brevers(e|ed)\b|backwards/i.test(raw)) v.push({ kind: "reversed", text: basicNormalize([...raw].reverse().join("")) });
  return v;
}
