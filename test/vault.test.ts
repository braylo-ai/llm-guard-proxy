import { describe, expect, it } from "vitest";
import { detectPii } from "../src/pii";
import { MemoryVaultStore, PLACEHOLDER_RE, Vault } from "../src/vault";

describe("vault", () => {
  it("issues UUID placeholders that are stable for a value within a session", async () => {
    const v = new Vault("s1", "k", new MemoryVaultStore());
    const a = await v.placeholderFor("EMAIL", "a@example.com");
    expect(a).toMatch(/^\[\[EMAIL:[0-9a-f]{8}-[0-9a-f]{4}-8[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\]\]$/);
    expect(await v.placeholderFor("EMAIL", "a@example.com")).toBe(a);
    expect(await v.placeholderFor("EMAIL", "b@example.com")).not.toBe(a);
  });
  it("is stable across requests in the same session and differs across sessions", async () => {
    const store = new MemoryVaultStore();
    const p1 = await new Vault("s1", "k", store).placeholderFor("PHONE", "312-555-0142");
    const p2 = await new Vault("s1", "k", store).placeholderFor("PHONE", "312-555-0142");
    const p3 = await new Vault("s2", "k", store).placeholderFor("PHONE", "312-555-0142");
    expect(p1).toBe(p2);
    expect(p1).not.toBe(p3);
  });
  it("rehydrates only allowed types and only placeholders from its own session", async () => {
    const store = new MemoryVaultStore();
    const v = new Vault("s1", "k", store);
    const text = "mail jane@example.com, ssn 512-38-4471";
    const red = await v.redact(text, detectPii(text));
    expect(red).not.toContain("jane@example.com");
    const back = await new Vault("s1", "k", store).rehydrate(red, ["EMAIL"]);
    expect(back.text).toContain("jane@example.com");
    expect(back.text).not.toContain("512-38-4471");
    const other = await new Vault("s2", "k", store).rehydrate(red, "all");
    expect(other.restored).toBe(0);
  });
  it("never invents a value for an unknown placeholder", async () => {
    const v = new Vault("s1", "k", new MemoryVaultStore());
    const fake = "[[EMAIL:00000000-0000-8000-8000-000000000000]]";
    expect((await v.rehydrate(fake, "all")).text).toBe(fake);
  });
  it("placeholder regex matches issued placeholders", async () => {
    const v = new Vault("s", "k", new MemoryVaultStore());
    const ph = await v.placeholderFor("IBAN", "GB82WEST12345698765432");
    expect([...ph.matchAll(PLACEHOLDER_RE)].length).toBe(1);
  });
});
