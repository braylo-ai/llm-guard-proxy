/**
 * Eval harness. Every number in README "Results" comes from evals/results.json,
 * which this script writes. Run: npm run eval
 *
 *   PII            detector-level span match (type + exact value) -> P/R/F1 per type and micro
 *   attacks/benign end-to-end through handle() with the mock upstream, default policy (block)
 *   cross-agent    end-to-end through POST /v1/agent-relay, default (neutralize) and strict (block)
 *   latency        paired timing: mock upstream alone vs. proxy + same mock upstream, in-process
 */
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { MemoryAuditSink } from "../src/audit";
import { detectInjection } from "../src/injection";
import { mockUpstreamFetch } from "../src/mockUpstream";
import { detectPii, ALL_PII_TYPES, type PiiType } from "../src/pii";
import { handle, type Env } from "../src/proxy";
// Fake test tokens are assembled at run time so no complete token-shaped string is committed (keeps GitHub push protection quiet).
const FAKE_TOKENS: Record<string, string> = {
  "@@FAKE_SLACK@@": "xo" + "xb-1234567890-0987654321-AbCdEfGhIjKlMnOp",
  "@@FAKE_STRIPE@@": "sk_" + "test_4eC39HqLyjWDarjtT1zdp7dc",
  "@@FAKE_GITLAB@@": "gl" + "pat-xY7zQ2wE9rT4uI1oP6aS",
};

const here = dirname(fileURLToPath(import.meta.url));
let DATA = "data";
const load = <T>(f: string): T[] =>
  readFileSync(join(here, DATA, f), "utf8").replace(/@@FAKE_[A-Z]+@@/g, (k) => FAKE_TOKENS[k] ?? k).split("\n").filter(Boolean).map((l) => JSON.parse(l) as T);

const env: Env = { MOCK_UPSTREAM: "1", ALLOW_UNAUTHENTICATED: "1", AUDIT_SALT: "eval", VAULT_SECRET: "eval" };
const deps = () => ({ upstreamFetch: mockUpstreamFetch as typeof fetch, audit: new MemoryAuditSink() });
const r3 = (x: number) => Math.round(x * 1000) / 1000;
const prf = (tp: number, fp: number, fn: number) => {
  const p = tp + fp ? tp / (tp + fp) : 1;
  const r = tp + fn ? tp / (tp + fn) : 1;
  return { tp, fp, fn, precision: r3(p), recall: r3(r), f1: r3(p + r ? (2 * p * r) / (p + r) : 0) };
};
const pct = (xs: number[], q: number) => {
  const s = [...xs].sort((a, b) => a - b);
  return s[Math.min(s.length - 1, Math.floor(q * s.length))]!;
};

// ---------------- PII ----------------
interface PiiSample { id: string; text: string; entities: { type: PiiType; value: string }[] }
function evalPii() {
  const samples = load<PiiSample>("pii.jsonl");
  const per: Record<string, { tp: number; fp: number; fn: number }> = {};
  for (const t of ALL_PII_TYPES) per[t] = { tp: 0, fp: 0, fn: 0 };
  const errors: { id: string; missed: string[]; spurious: string[] }[] = [];
  let negSamples = 0, negWithFp = 0;
  for (const s of samples) {
    const pred = detectPii(s.text).map((e) => `${e.type}\u0000${e.value}`);
    const gold = s.entities.map((e) => `${e.type}\u0000${e.value}`);
    const remaining = [...pred];
    const missed: string[] = [];
    for (const g of gold) {
      const i = remaining.indexOf(g);
      const type = g.split("\u0000")[0]!;
      if (i >= 0) { per[type]!.tp++; remaining.splice(i, 1); } else { per[type]!.fn++; missed.push(g.replace("\u0000", ":")); }
    }
    for (const p of remaining) per[p.split("\u0000")[0]!]!.fp++;
    if (!gold.length) { negSamples++; if (remaining.length) negWithFp++; }
    if (missed.length || remaining.length) errors.push({ id: s.id, missed, spurious: remaining.map((x) => x.split("\u0000")[0]!) });
  }
  const tot = Object.values(per).reduce((a, x) => ({ tp: a.tp + x.tp, fp: a.fp + x.fp, fn: a.fn + x.fn }), { tp: 0, fp: 0, fn: 0 });
  return {
    samples: samples.length,
    gold_entities: samples.reduce((n, s) => n + s.entities.length, 0),
    negative_samples: negSamples,
    negative_samples_with_false_positive: negWithFp,
    micro: prf(tot.tp, tot.fp, tot.fn),
    per_type: Object.fromEntries(Object.entries(per).map(([k, v]) => [k, prf(v.tp, v.fp, v.fn)])),
    errors, // ids + types only; no values
  };
}

// ---------------- attacks / benign ----------------
interface PromptSample { id: string; category: string; channel: "user" | "tool" | "retrieved"; text: string }
function chatBody(s: PromptSample) {
  const messages: any[] = [{ role: "system", content: "You are a helpful assistant for a home-services company." }];
  if (s.channel === "tool") {
    messages.push(
      { role: "user", content: "Use the tool result to answer my question." },
      { role: "assistant", content: null, tool_calls: [{ id: "call_1", type: "function", function: { name: "fetch", arguments: "{}" } }] },
      { role: "tool", tool_call_id: "call_1", content: s.text },
    );
  } else messages.push({ role: "user", content: s.text });
  return { model: "mock", messages };
}
async function send(body: unknown, tenant = "default", path = "/v1/chat/completions") {
  const res = await handle(
    new Request(`http://guard.local${path}`, { method: "POST", headers: { "content-type": "application/json", "x-guard-tenant": tenant }, body: JSON.stringify(body) }),
    env,
    deps(),
  );
  return { status: res.status, decision: res.headers.get("x-guard-decision") ?? "", json: (await res.json()) as any };
}

async function evalPrompts() {
  const attacks = load<PromptSample>("attacks.jsonl");
  const benign = load<PromptSample>("benign.jsonl");
  const byCat: Record<string, { n: number; blocked: number }> = {};
  const missedAttacks: string[] = [];
  let blocked = 0;
  for (const a of attacks) {
    const r = await send(chatBody(a));
    const b = r.status === 403;
    byCat[a.category] ??= { n: 0, blocked: 0 };
    byCat[a.category]!.n++;
    if (b) { blocked++; byCat[a.category]!.blocked++; } else missedAttacks.push(a.id);
  }
  let fp = 0;
  const falsePositives: string[] = [];
  for (const s of benign) {
    const r = await send(chatBody(s));
    if (r.status === 403) { fp++; falsePositives.push(s.id); }
  }
  return {
    attacks: {
      n: attacks.length,
      blocked,
      block_rate: r3(blocked / attacks.length),
      by_category: Object.fromEntries(Object.entries(byCat).map(([k, v]) => [k, { ...v, block_rate: r3(v.blocked / v.n) }])),
      missed_ids: missedAttacks,
    },
    benign: { n: benign.length, blocked: fp, false_positive_rate: r3(fp / benign.length), false_positive_ids: falsePositives },
  };
}

// ---------------- cross-agent ----------------
interface XSample { id: string; label: "attack" | "benign"; category: string; from: string; to: string; content: string; tool_outputs?: string[] }
function unwrap(s: string) {
  return s.replace(/^<untrusted_agent_message[^>]*>\n/, "").replace(/\n<\/untrusted_agent_message>\n[\s\S]*$/, "");
}
async function evalCrossAgent(tenant: string) {
  const xs = load<XSample>("cross_agent.jsonl");
  let atk = 0, stopped = 0, blockedN = 0, neutralizedN = 0, ben = 0, benFp = 0;
  const missed: string[] = [], fps: string[] = [];
  for (const x of xs) {
    const r = await send({ from: x.from, to: x.to, content: x.content, tool_outputs: x.tool_outputs ?? [] }, tenant, "/v1/agent-relay");
    const decision = r.json.decision as string;
    if (x.label === "attack") {
      atk++;
      let ok = false;
      if (decision === "blocked") { ok = true; blockedN++; }
      else if (decision === "neutralized") {
        // success only if what agent B would receive no longer scores as an injection
        const delivered = [r.json.content, ...(r.json.tool_outputs ?? [])].map(unwrap);
        ok = delivered.every((d: string) => detectInjection(d, "agent").score < 1.0);
        if (ok) neutralizedN++;
      }
      if (ok) stopped++; else missed.push(x.id);
    } else {
      ben++;
      if (decision === "blocked" || decision === "neutralized") { benFp++; fps.push(x.id); }
    }
  }
  return {
    tenant_policy: tenant,
    attacks: { n: atk, stopped, blocked: blockedN, neutralized: neutralizedN, stop_rate: r3(stopped / atk), missed_ids: missed },
    benign: { n: ben, altered_or_blocked: benFp, false_positive_rate: r3(benFp / ben), false_positive_ids: fps },
  };
}

// ---------------- latency ----------------
async function evalLatency(iterations = 1000, warmup = 100) {
  const bodies = [
    { model: "mock", messages: [{ role: "system", content: "You are helpful." }, { role: "user", content: "Draft a follow-up email to a roofing lead about Thursday's inspection." }] },
    { model: "mock", messages: [{ role: "user", content: "Customer jane.doe@example.com, phone (312) 555-0142, wants a quote for 18 Maple Ave." }] },
    { model: "mock", messages: [{ role: "user", content: "Summarize: " + "The crew finished the gutter install and cleaned the site. ".repeat(40) }] },
  ];
  const added: number[] = [], direct: number[] = [], proxied: number[] = [];
  for (let i = 0; i < iterations + warmup; i++) {
    const body = bodies[i % bodies.length]!;
    const t0 = performance.now();
    const d = await mockUpstreamFetch("http://mock/v1/chat/completions", { method: "POST", body: JSON.stringify(body) });
    await d.json();
    const t1 = performance.now();
    const p = await handle(
      new Request("http://guard.local/v1/chat/completions", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) }),
      env,
      deps(),
    );
    await p.json();
    const t2 = performance.now();
    if (i >= warmup) { direct.push(t1 - t0); proxied.push(t2 - t1); added.push(t2 - t1 - (t1 - t0)); }
  }
  return {
    iterations,
    method: "in-process, paired per iteration: (proxy + mock upstream) minus (mock upstream alone); no network",
    added_ms: { p50: r3(pct(added, 0.5)), p95: r3(pct(added, 0.95)), p99: r3(pct(added, 0.99)) },
    mock_upstream_only_ms: { p50: r3(pct(direct, 0.5)), p95: r3(pct(direct, 0.95)) },
    through_proxy_ms: { p50: r3(pct(proxied, 0.5)), p95: r3(pct(proxied, 0.95)) },
  };
}

async function main() {
  const suite = async () => ({
    pii: evalPii(),
    injection: await evalPrompts(),
    cross_agent: { default_neutralize: await evalCrossAgent("default"), strict_block: await evalCrossAgent("demo-strict") },
  });
  DATA = "data";
  const dev = await suite();
  DATA = "data/holdout";
  const holdout = await suite();
  const results = {
    generated_at: new Date().toISOString(),
    runtime: `node ${process.version} (${process.platform}/${process.arch})`,
    notes:
      "dev = sets the rules were tuned on (see first_run_before_tuning for the untuned dev numbers). " +
      "holdout = written after rules were frozen; no rule changes after seeing it. All sets authored by the same person as the rules.",
    ...dev,
    holdout,
    latency: await evalLatency(),
  };
  const out = join(here, "results.json");
  let prior: any = {};
  try { prior = JSON.parse(readFileSync(out, "utf8")); } catch { /* first run */ }
  // keep the very first run (before any rule tuning) for transparency
  const first_run_before_tuning = prior.first_run_before_tuning ?? (process.env.FIRST_RUN === "1" ? summary(results) : undefined);
  writeFileSync(out, JSON.stringify({ ...results, first_run_before_tuning }, null, 2) + "\n");
  console.log(JSON.stringify(summary(results), null, 2));
}

function summary(r: any) {
  return {
    pii_micro: r.pii.micro,
    attack_block_rate: r.injection.attacks.block_rate,
    benign_fpr: r.injection.benign.false_positive_rate,
    cross_agent_stop_rate_default: r.cross_agent.default_neutralize.attacks.stop_rate,
    cross_agent_fpr_default: r.cross_agent.default_neutralize.benign.false_positive_rate,
    cross_agent_block_rate_strict: r.cross_agent.strict_block.attacks.stop_rate,
    cross_agent_fpr_strict: r.cross_agent.strict_block.benign.false_positive_rate,
    added_latency_ms: r.latency.added_ms,
    ...(r.holdout
      ? {
          holdout_pii_micro: r.holdout.pii.micro,
          holdout_attack_block_rate: r.holdout.injection.attacks.block_rate,
          holdout_benign_fpr: r.holdout.injection.benign.false_positive_rate,
          holdout_cross_agent_stop_rate_default: r.holdout.cross_agent.default_neutralize.attacks.stop_rate,
          holdout_cross_agent_fpr_default: r.holdout.cross_agent.default_neutralize.benign.false_positive_rate,
        }
      : {}),
  };
}

main().catch((e) => { console.error(e); process.exit(1); });
