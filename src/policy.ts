import type { PiiType } from "./pii";
import { ALL_PII_TYPES } from "./pii";
import defaultPolicy from "../policies/default.json";
import strictPolicy from "../policies/strict.json";
import observePolicy from "../policies/observe.json";
import tenants from "../policies/tenants.json";

export type Action = "block" | "redact" | "flag" | "off";

export interface ClassifierConfig {
  /** HTTP endpoint: POST {text, channel} -> {score: 0..1} */
  url: string;
  /** score >= threshold adds `weight` to the rule score */
  threshold: number;
  weight: number;
  timeout_ms: number;
  fail: "open" | "closed";
}

export interface Policy {
  name: string;
  pii: {
    enabled: PiiType[];
    action: Action;
    per_type: Partial<Record<PiiType, Action>>;
    allowlist: string[];
    rehydrate: PiiType[] | "all" | "none";
    scan_system: boolean;
  };
  injection: {
    action: Action;
    threshold: number;
    scan_assistant: boolean;
    classifier: ClassifierConfig | null;
  };
  outbound: {
    pii_action: Action;
    secret_action: Action;
    canary_action: Action;
    exfil_action: Action;
    block_message: string;
    /** hosts whose image/link URLs are never treated as exfiltration */
    url_allowlist: string[];
  };
  canary: { inject: boolean; static: string[] };
  inter_agent: { action: "neutralize" | "block" | "flag"; threshold: number; wrap: boolean };
  limits: { max_body_bytes: number };
}

const ACTIONS = new Set(["block", "redact", "flag", "off"]);

function isObj(x: unknown): x is Record<string, unknown> {
  return typeof x === "object" && x !== null && !Array.isArray(x);
}

function deepMerge<T>(base: T, over: unknown): T {
  if (!isObj(over)) return base;
  const out: Record<string, unknown> = { ...(base as Record<string, unknown>) };
  for (const [k, v] of Object.entries(over)) {
    out[k] = isObj(v) && isObj(out[k]) ? deepMerge(out[k], v) : v;
  }
  return out as T;
}

/** Throws on an invalid policy. Fail closed: a broken policy never loads. */
export function validatePolicy(p: Policy): Policy {
  const errs: string[] = [];
  for (const t of p.pii.enabled) if (!ALL_PII_TYPES.includes(t)) errs.push(`unknown pii type ${t}`);
  if (!ACTIONS.has(p.pii.action)) errs.push(`bad pii.action ${p.pii.action}`);
  for (const [t, a] of Object.entries(p.pii.per_type)) {
    if (!ALL_PII_TYPES.includes(t as PiiType)) errs.push(`unknown per_type ${t}`);
    if (!ACTIONS.has(a as string)) errs.push(`bad per_type action ${a}`);
  }
  if (!ACTIONS.has(p.injection.action)) errs.push(`bad injection.action`);
  for (const k of ["pii_action", "secret_action", "canary_action", "exfil_action"] as const)
    if (!ACTIONS.has(p.outbound[k])) errs.push(`bad outbound.${k}`);
  if (!(p.injection.threshold > 0)) errs.push("injection.threshold must be > 0");
  if (!["neutralize", "block", "flag"].includes(p.inter_agent.action)) errs.push("bad inter_agent.action");
  const r = p.pii.rehydrate;
  if (!(r === "all" || r === "none" || (Array.isArray(r) && r.every((t) => ALL_PII_TYPES.includes(t)))))
    errs.push("bad pii.rehydrate");
  if (errs.length) throw new Error(`invalid policy '${p.name}': ${errs.join("; ")}`);
  return p;
}

const BASE = defaultPolicy as unknown as Policy;
const BUILTIN: Record<string, Policy> = {
  default: validatePolicy(BASE),
  strict: validatePolicy(deepMerge(BASE, strictPolicy)),
  observe: validatePolicy(deepMerge(BASE, observePolicy)),
};

export function buildPolicy(override: unknown): Policy {
  return validatePolicy(deepMerge(BASE, override));
}

/**
 * Resolve the policy for a tenant.
 * `envPolicies` (JSON string from env POLICIES_JSON) maps tenant -> partial policy
 * merged over default, and takes precedence over the bundled tenants.json map.
 */
export function policyForTenant(tenant: string, envPolicies?: string): Policy {
  if (envPolicies) {
    const parsed = JSON.parse(envPolicies) as Record<string, unknown>;
    if (parsed[tenant] !== undefined) return buildPolicy({ name: tenant, ...(parsed[tenant] as object) });
  }
  const mapped = (tenants as Record<string, string>)[tenant];
  return BUILTIN[mapped ?? "default"] ?? BUILTIN.default!;
}

export function piiActionFor(p: Policy, t: PiiType): Action {
  return p.pii.per_type[t] ?? p.pii.action;
}
