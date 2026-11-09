import { handle, type Env } from "./proxy";

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    try {
      return await handle(req, env);
    } catch {
      // never echo internals (could include request content)
      return new Response(JSON.stringify({ error: { type: "guard_internal_error", message: "internal error" } }), {
        status: 500,
        headers: { "content-type": "application/json" },
      });
    }
  },
};
