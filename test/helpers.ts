import { MemoryAuditSink } from "../src/audit";
import { mockUpstreamFetch } from "../src/mockUpstream";
import { handle, type Deps, type Env } from "../src/proxy";
import { MemoryVaultStore } from "../src/vault";

export const env: Env = { MOCK_UPSTREAM: "1", ALLOW_UNAUTHENTICATED: "1", AUDIT_SALT: "t", VAULT_SECRET: "t" };

export function mkDeps(over: Partial<Deps> = {}) {
  const audit = new MemoryAuditSink();
  const calls: any[] = [];
  const upstreamFetch = (async (u: any, init?: RequestInit) => {
    calls.push({ url: String(u), headers: init?.headers, body: JSON.parse(String(init?.body)) });
    return mockUpstreamFetch(u, init);
  }) as typeof fetch;
  return { deps: { upstreamFetch, audit, vaultStore: new MemoryVaultStore(), ...over }, audit, calls };
}

export async function post(path: string, body: unknown, opts: { headers?: Record<string, string>; env?: Env; deps?: Deps } = {}) {
  const d = opts.deps ?? mkDeps().deps;
  const res = await handle(
    new Request(`http://guard.local${path}`, {
      method: "POST",
      headers: { "content-type": "application/json", ...(opts.headers ?? {}) },
      body: typeof body === "string" ? body : JSON.stringify(body),
    }),
    opts.env ?? env,
    d,
  );
  return { res, json: (await res.json()) as any };
}

export const chat = (content: string, extra: any[] = []) => ({ model: "m", messages: [...extra, { role: "user", content }] });
