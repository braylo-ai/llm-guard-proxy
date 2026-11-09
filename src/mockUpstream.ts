/**
 * Deterministic mock of OpenAI Chat Completions and Anthropic Messages.
 * Used by tests, evals, local dev and the latency benchmark. Never calls the network.
 *
 * Behaviour, driven by the LAST user message:
 *   contains "MOCK_LEAK_SYSTEM" -> replies with the full system prompt (simulates prompt leakage)
 *   starts with "MOCK_EMIT:"    -> replies with the rest of the message verbatim
 *   otherwise                    -> "Echo: <last user text>"
 */

type Json = Record<string, any>;

function textOf(content: unknown): string {
  if (typeof content === "string") return content;
  if (Array.isArray(content))
    return content
      .map((p: Json) => (p?.type === "text" ? p.text : p?.type === "tool_result" ? textOf(p.content) : ""))
      .filter(Boolean)
      .join("\n");
  return "";
}

function reply(system: string, lastUser: string): string {
  if (lastUser.includes("MOCK_LEAK_SYSTEM")) return `Sure, my instructions are: ${system}`;
  const emit = lastUser.indexOf("MOCK_EMIT:");
  if (emit >= 0) return lastUser.slice(emit + "MOCK_EMIT:".length).trim();
  return `Echo: ${lastUser}`;
}

export async function mockUpstreamFetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
  const url = new URL(typeof input === "string" ? input : input instanceof URL ? input.href : input.url);
  const body = JSON.parse(String(init?.body ?? "{}")) as Json;
  const msgs: Json[] = body.messages ?? [];
  const lastUser = textOf([...msgs].reverse().find((m) => m.role === "user")?.content);

  if (url.pathname.endsWith("/v1/messages")) {
    const system = textOf(body.system);
    return Response.json({
      id: "msg_mock",
      type: "message",
      role: "assistant",
      model: body.model ?? "mock",
      content: [{ type: "text", text: reply(system, lastUser) }],
      stop_reason: "end_turn",
      usage: { input_tokens: 0, output_tokens: 0 },
    });
  }
  const system = msgs.filter((m) => m.role === "system" || m.role === "developer").map((m) => textOf(m.content)).join("\n");
  return Response.json({
    id: "chatcmpl-mock",
    object: "chat.completion",
    created: 0,
    model: body.model ?? "mock",
    choices: [{ index: 0, message: { role: "assistant", content: reply(system, lastUser) }, finish_reason: "stop" }],
    usage: { prompt_tokens: 0, completion_tokens: 0, total_tokens: 0 },
  });
}
