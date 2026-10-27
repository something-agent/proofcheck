import { Hono } from "hono";
import { cors } from "hono/cors";
import { BadRequest, handlers } from "./handlers";
import { aiCatalog, landing, llmsTxt, openapi, serverCard, VERSION } from "./docs";
import { handleMcp } from "./mcp";
import { BlockedTarget } from "./safe";
import { Ctx } from "./verify";

const MAX_BODY = 65_536;
const SUBREQ_BUDGET = 40; // Workers Free allows 50 per invocation
const hits = new Map<string, { n: number; t: number }>();
/** Best-effort per-isolate limiter. Not a security boundary; Cloudflare's own edge limits apply on top. */
export function limited(ip: string, cost: number, now = Date.now(), cap = 40): boolean {
  const e = hits.get(ip);
  if (!e || now - e.t > 60_000) { hits.set(ip, { n: cost, t: now }); if (hits.size > 5000) hits.clear(); return false; }
  e.n += cost; return e.n > cap;
}

export function makeCtx(fetchImpl?: typeof fetch): Ctx {
  const base = fetchImpl ?? fetch;
  let n = 0;
  const counted = ((input: any, init?: any) => {
    if (++n > SUBREQ_BUDGET) throw new Error("subrequest budget exhausted for this request");
    return base(input, init);
  }) as typeof fetch;
  return { fetchImpl: counted };
}

export function buildApp(opts: { fetchImpl?: typeof fetch; now?: () => number } = {}) {
  const app = new Hono();
  app.use("*", cors({ origin: "*", allowMethods: ["GET", "POST", "OPTIONS"], allowHeaders: ["content-type", "mcp-protocol-version", "mcp-session-id"] }));
  const origin = (c: any) => new URL(c.req.url).origin;
  const ctx = (): Ctx => ({ ...makeCtx(opts.fetchImpl), now: opts.now?.() });
  const ip = (c: any) => c.req.header("cf-connecting-ip") ?? "local";

  app.get("/", (c) => c.html(landing(origin(c))));
  app.get("/health", (c) => c.json({ ok: true, service: "proofcheck", version: VERSION }));
  app.get("/llms.txt", (c) => c.text(llmsTxt(origin(c))));
  app.get("/openapi.json", (c) => c.json(openapi(origin(c))));
  app.get("/.well-known/mcp-server-card.json", (c) => c.json(serverCard(origin(c))));
  app.get("/server-card", (c) => c.json(serverCard(origin(c))));
  app.get("/.well-known/ai-catalog.json", (c) => c.json(aiCatalog(origin(c))));
  app.get("/.well-known/ard.json", (c) => c.json(aiCatalog(origin(c))));

  const run = (name: keyof typeof handlers, cost: number, source: "json" | "query") => async (c: any) => {
    if (limited(ip(c), cost, opts.now ? opts.now() * 1000 : Date.now())) return c.json({ error: "rate_limited", detail: "free tier: slow down (best-effort limit per IP per minute)" }, 429);
    let args: any;
    if (source === "query") args = Object.fromEntries(new URL(c.req.url).searchParams);
    else {
      const raw = await c.req.text();
      if (raw.length > MAX_BODY) return c.json({ error: "too_large", detail: `body over ${MAX_BODY} bytes` }, 413);
      try { args = JSON.parse(raw); } catch { return c.json({ error: "bad_json" }, 400); }
    }
    try { return c.json(await (handlers[name] as any)(args, ctx())); }
    catch (e) {
      if (e instanceof BadRequest || e instanceof BlockedTarget) return c.json({ error: "bad_request", detail: (e as Error).message }, 400);
      return c.json({ error: "upstream_error", detail: (e as Error).message.slice(0, 200) }, 502);
    }
  };
  app.get("/v1/preflight", run("preflight", 4, "query"));
  app.post("/v1/offer/verify", run("verify_offer", 2, "json"));
  app.post("/v1/receipt/verify", run("verify_receipt", 2, "json"));
  app.post("/v1/payment-required/verify", run("verify_payment_required", 3, "json"));
  app.get("/v1/erc8004/agent", run("lookup_erc8004_agent", 2, "query"));

  app.post("/mcp", async (c) => {
    if (limited(ip(c), 2, opts.now ? opts.now() * 1000 : Date.now(), 60)) return c.json({ jsonrpc: "2.0", id: null, error: { code: -32000, message: "rate limited" } }, 429);
    const raw = await c.req.text();
    if (raw.length > MAX_BODY) return c.json({ jsonrpc: "2.0", id: null, error: { code: -32600, message: "body too large" } }, 413);
    let msg: any;
    try { msg = JSON.parse(raw); } catch { return c.json({ jsonrpc: "2.0", id: null, error: { code: -32700, message: "Parse error" } }, 400); }
    const one = (m: any) => handleMcp(m, ctx(), VERSION);
    if (Array.isArray(msg)) {
      const outs = (await Promise.all(msg.slice(0, 5).map(one))).filter((x) => x !== null);
      return outs.length ? c.json(outs) : c.body(null, 202);
    }
    const out = await one(msg);
    return out === null ? c.body(null, 202) : c.json(out);
  });
  app.get("/mcp", (c) => c.json({ error: "method_not_allowed", detail: "POST JSON-RPC to /mcp (stateless Streamable HTTP; no SSE stream offered)" }, 405));
  app.delete("/mcp", (c) => c.body(null, 405));

  app.notFound((c) => c.json({ error: "not_found", docs: `${origin(c)}/llms.txt` }, 404));
  app.onError((e, c) => c.json({ error: "internal", detail: e.message.slice(0, 200) }, 500));
  return app;
}
