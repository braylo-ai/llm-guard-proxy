/**
 * Local dev server (Node, no wrangler needed). Uses the mock upstream unless
 * OPENAI_API_KEY / ANTHROPIC_API_KEY are set in the environment.
 *   npm run dev:local            -> http://localhost:8787
 */
import { createServer } from "node:http";
import { handle, type Env } from "../src/proxy";

const env: Env = {
  ...(process.env as Record<string, string>),
  MOCK_UPSTREAM: process.env.OPENAI_API_KEY || process.env.ANTHROPIC_API_KEY ? process.env.MOCK_UPSTREAM : "1",
  ALLOW_UNAUTHENTICATED: process.env.PROXY_AUTH_TOKEN ? undefined : "1",
};
const port = Number(process.env.PORT ?? 8787);

createServer(async (req, res) => {
  const chunks: Buffer[] = [];
  for await (const c of req) chunks.push(c as Buffer);
  const headers = new Headers();
  for (const [k, v] of Object.entries(req.headers)) if (typeof v === "string") headers.set(k, v);
  const r = await handle(
    new Request(`http://localhost:${port}${req.url}`, {
      method: req.method,
      headers,
      body: req.method === "GET" || req.method === "HEAD" ? undefined : Buffer.concat(chunks),
    }),
    env,
  );
  res.writeHead(r.status, Object.fromEntries(r.headers));
  res.end(Buffer.from(await r.arrayBuffer()));
}).listen(port, () => console.log(`llm-guard-proxy (local) on http://localhost:${port}  mock=${env.MOCK_UPSTREAM === "1"}`));
