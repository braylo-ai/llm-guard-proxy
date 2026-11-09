import type { Entity, PiiType } from "./pii";

/**
 * Reversible placeholder vault.
 *
 * Placeholders look like `[[EMAIL:1b4e28ba-2fa1-4d2a-883f-0016d3cca427]]`.
 * The UUID is derived with HMAC-SHA256(sessionKey, type + value), so the same
 * value maps to the same placeholder for the whole session (across requests)
 * without the vault ever storing value -> uuid. Only uuid -> value is stored,
 * in a VaultStore (in-memory Map with TTL, or Workers KV), and only for
 * rehydration on allowed egress.
 */
export const PLACEHOLDER_RE =
  /\[\[([A-Z_]+):([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\]\]/g;

export interface VaultEntry {
  type: PiiType;
  value: string;
}

export interface VaultStore {
  get(session: string, uuid: string): Promise<VaultEntry | undefined>;
  put(session: string, uuid: string, entry: VaultEntry): Promise<void>;
}

/** Process-local store. Fine for a single isolate / tests; use KV across isolates. */
export class MemoryVaultStore implements VaultStore {
  private m = new Map<string, { e: VaultEntry; exp: number }>();
  constructor(private ttlMs = 60 * 60 * 1000, private maxEntries = 50_000) {}
  async get(session: string, uuid: string) {
    const k = `${session}:${uuid}`;
    const hit = this.m.get(k);
    if (!hit) return undefined;
    if (hit.exp < Date.now()) {
      this.m.delete(k);
      return undefined;
    }
    return hit.e;
  }
  async put(session: string, uuid: string, e: VaultEntry) {
    if (this.m.size >= this.maxEntries) {
      const oldest = this.m.keys().next().value;
      if (oldest !== undefined) this.m.delete(oldest);
    }
    this.m.set(`${session}:${uuid}`, { e, exp: Date.now() + this.ttlMs });
  }
}

/** Minimal shape of a Workers KV namespace (avoids a hard type dependency). */
export interface KVLike {
  get(key: string): Promise<string | null>;
  put(key: string, value: string, opts?: { expirationTtl?: number }): Promise<void>;
}

export class KVVaultStore implements VaultStore {
  constructor(private kv: KVLike, private ttlSeconds = 3600) {}
  async get(session: string, uuid: string) {
    const v = await this.kv.get(`vault:${session}:${uuid}`);
    return v ? (JSON.parse(v) as VaultEntry) : undefined;
  }
  async put(session: string, uuid: string, e: VaultEntry) {
    await this.kv.put(`vault:${session}:${uuid}`, JSON.stringify(e), { expirationTtl: this.ttlSeconds });
  }
}

const enc = new TextEncoder();

async function hmacUuid(key: CryptoKey, data: string): Promise<string> {
  const sig = new Uint8Array(await crypto.subtle.sign("HMAC", key, enc.encode(data)));
  const b = sig.slice(0, 16);
  b[6] = (b[6]! & 0x0f) | 0x80; // version 8 (custom, RFC 9562)
  b[8] = (b[8]! & 0x3f) | 0x80; // variant 10
  const h = [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}

export class Vault {
  private key?: CryptoKey;
  /** uuids issued or resolved during this request (allowed to rehydrate) */
  private local = new Map<string, VaultEntry>();

  constructor(
    readonly session: string,
    private secret: string,
    private store: VaultStore,
  ) {}

  private async k(): Promise<CryptoKey> {
    if (!this.key) {
      this.key = await crypto.subtle.importKey(
        "raw",
        enc.encode(`${this.secret}\u0000${this.session}`),
        { name: "HMAC", hash: "SHA-256" },
        false,
        ["sign"],
      );
    }
    return this.key;
  }

  async placeholderFor(type: PiiType, value: string): Promise<string> {
    const uuid = await hmacUuid(await this.k(), `${type}\u0000${value}`);
    if (!this.local.has(uuid)) {
      this.local.set(uuid, { type, value });
      await this.store.put(this.session, uuid, { type, value });
    }
    return `[[${type}:${uuid}]]`;
  }

  /** Replace entity spans with placeholders. Entities must be non-overlapping. */
  async redact(text: string, entities: Entity[]): Promise<string> {
    let out = text;
    for (const e of [...entities].sort((a, b) => b.start - a.start)) {
      out = out.slice(0, e.start) + (await this.placeholderFor(e.type, e.value)) + out.slice(e.end);
    }
    return out;
  }

  private async resolve(uuid: string): Promise<VaultEntry | undefined> {
    const l = this.local.get(uuid);
    if (l) return l;
    const s = await this.store.get(this.session, uuid);
    if (s) this.local.set(uuid, s);
    return s;
  }

  /**
   * Restore placeholders issued in THIS session, for allowed types only.
   * Unknown placeholders (or ones from another session) are left as-is.
   */
  async rehydrate(text: string, allowed: PiiType[] | "all" | "none"): Promise<{ text: string; restored: number }> {
    if (allowed === "none") return { text, restored: 0 };
    const matches = [...text.matchAll(PLACEHOLDER_RE)];
    if (!matches.length) return { text, restored: 0 };
    const resolved = new Map<string, string>();
    for (const m of matches) {
      const [ph, type, uuid] = m as unknown as [string, string, string];
      if (resolved.has(ph)) continue;
      const hit = await this.resolve(uuid);
      if (!hit || hit.type !== type) continue;
      if (allowed !== "all" && !allowed.includes(hit.type)) continue;
      resolved.set(ph, hit.value);
    }
    let restored = 0;
    const out = text.replace(PLACEHOLDER_RE, (ph) => {
      const v = resolved.get(ph);
      if (v === undefined) return ph;
      restored++;
      return v;
    });
    return { text: out, restored };
  }

  get size(): number {
    return this.local.size;
  }
}
