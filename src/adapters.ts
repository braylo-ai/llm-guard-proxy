import type { Channel } from "./injection";

/**
 * Wire-format adapters. Each exposes the text segments of a request/response
 * as mutable handles so the pipeline is format-agnostic.
 */

export interface Segment {
  channel: Channel;
  get(): string;
  set(v: string): void;
}

type Json = Record<string, any>;

function textParts(container: Json, key: string, channel: Channel, out: Segment[]) {
  const c = container[key];
  if (typeof c === "string") {
    out.push({ channel, get: () => container[key], set: (v) => (container[key] = v) });
  } else if (Array.isArray(c)) {
    for (const part of c) {
      if (part && typeof part === "object" && part.type === "text" && typeof part.text === "string") {
        out.push({ channel, get: () => part.text, set: (v) => (part.text = v) });
      }
    }
  }
}

function roleChannel(role: unknown): Channel {
  if (role === "system" || role === "developer") return "system";
  if (role === "assistant") return "assistant";
  if (role === "tool" || role === "function") return "tool";
  return "user";
}

// ---------------- OpenAI Chat Completions ----------------

export function openaiRequestSegments(body: Json): Segment[] {
  const out: Segment[] = [];
  if (!Array.isArray(body.messages)) throw new Error("messages must be an array");
  for (const m of body.messages) {
    if (!m || typeof m !== "object") continue;
    textParts(m, "content", roleChannel(m.role), out);
  }
  return out;
}

export function openaiInjectSystem(body: Json, text: string) {
  const sys = body.messages.find((m: Json) => m.role === "system" || m.role === "developer");
  if (sys && typeof sys.content === "string") sys.content = `${sys.content}\n\n${text}`;
  else body.messages.unshift({ role: "system", content: text });
}

export function openaiResponseSegments(resp: Json): Segment[] {
  const out: Segment[] = [];
  for (const ch of resp.choices ?? []) {
    const msg = ch?.message;
    if (!msg) continue;
    textParts(msg, "content", "assistant", out);
    for (const tc of msg.tool_calls ?? []) {
      if (tc?.function && typeof tc.function.arguments === "string") {
        out.push({ channel: "assistant", get: () => tc.function.arguments, set: (v) => (tc.function.arguments = v) });
      }
    }
  }
  return out;
}

export function openaiBlockedResponse(resp: Json, message: string) {
  for (const ch of resp.choices ?? []) {
    ch.message = { role: "assistant", content: message };
    ch.finish_reason = "content_filter";
  }
}

// ---------------- Anthropic Messages ----------------

export function anthropicRequestSegments(body: Json): Segment[] {
  const out: Segment[] = [];
  if (body.system !== undefined) textParts(body, "system", "system", out);
  if (!Array.isArray(body.messages)) throw new Error("messages must be an array");
  for (const m of body.messages) {
    if (!m || typeof m !== "object") continue;
    const ch = roleChannel(m.role);
    textParts(m, "content", ch, out);
    if (Array.isArray(m.content)) {
      for (const block of m.content) {
        if (block?.type === "tool_result") {
          if (typeof block.content === "string") textParts(block, "content", "tool", out);
          else if (Array.isArray(block.content)) textParts(block, "content", "tool", out);
        }
      }
    }
  }
  return out;
}

export function anthropicInjectSystem(body: Json, text: string) {
  if (typeof body.system === "string") body.system = `${body.system}\n\n${text}`;
  else if (Array.isArray(body.system)) body.system.push({ type: "text", text });
  else body.system = text;
}

export function anthropicResponseSegments(resp: Json): Segment[] {
  const out: Segment[] = [];
  for (const block of resp.content ?? []) {
    if (block?.type === "text" && typeof block.text === "string") {
      out.push({ channel: "assistant", get: () => block.text, set: (v) => (block.text = v) });
    } else if (block?.type === "tool_use" && block.input !== undefined) {
      // expose tool input as JSON text; writes are parsed back (invalid JSON -> caller blocks)
      out.push({
        channel: "assistant",
        get: () => JSON.stringify(block.input),
        set: (v) => (block.input = JSON.parse(v)),
      });
    }
  }
  return out;
}

export function anthropicBlockedResponse(resp: Json, message: string) {
  resp.content = [{ type: "text", text: message }];
  resp.stop_reason = "end_turn";
}
