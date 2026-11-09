# Placeholder + relay design

Summary: PII placeholders are `[[TYPE:uuid]]`, with uuid = HMAC-SHA256(VAULT_SECRET + session, type + value) as a v8 UUID.

- Same value gives the same placeholder for the whole `x-guard-session`. No session header means a per-request vault.
- The store keeps only uuid -> value (MemoryVaultStore, or KV through the `VAULT_KV` binding). It is used only for rehydration on allowed egress (`pii.rehydrate`).
- `/v1/agent-relay` is NOT egress. It never rehydrates.
- Outbound runs the exfil check before AND after rehydration. Reason: an injected tool result can make the model put a placeholder in a URL, and rehydration would then put the real value in that URL.
- Zero-width characters and homoglyphs fold into the "plain" view, so they do not set `obfuscated`.
