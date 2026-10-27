import { describe, expect, it } from "vitest";
import { buildApp, limited } from "../src/app";
import { NOW, USDC, json, newAccount, offerPayload, receiptPayload, signOffer, signReceipt, stubFetch } from "./helpers";

const B = "https://proofcheck.test";
const mk = (routes: any[] = []) => { const s = stubFetch(routes); return { app: buildApp({ fetchImpl: s.f, now: () => NOW }), ...s }; };
const post = (app: any, path: string, body: unknown, ip = "1.1.1.1") => app.request(B + path, { method: "POST", body: typeof body === "string" ? body : JSON.stringify(body), headers: { "cf-connecting-ip": ip } });

describe("docs & discovery", () => {
  it("serves landing, llms.txt, openapi, server card, ai-catalog, health", async () => {
    const { app } = mk();
    expect((await app.request(B + "/")).status).toBe(200);
    expect(await (await app.request(B + "/llms.txt")).text()).toContain("# ProofCheck");
    expect(((await (await app.request(B + "/openapi.json")).json()) as any).paths["/v1/offer/verify"]).toBeTruthy();
    const card: any = await (await app.request(B + "/.well-known/mcp-server-card.json")).json();
    expect(card.remotes[0].url).toBe(B + "/mcp");
    const cat: any = await (await app.request(B + "/.well-known/ai-catalog.json")).json();
    expect(cat.entries.length).toBeGreaterThan(1);
    expect((await app.request(B + "/health")).status).toBe(200);
    expect((await app.request(B + "/nope")).status).toBe(404);
  });
  it("CORS is open", async () => {
    const { app } = mk();
    const r = await app.request(B + "/health", { headers: { origin: "https://x.example" } });
    expect(r.headers.get("access-control-allow-origin")).toBe("*");
  });
});

describe("HTTP API", () => {
  it("offer/verify end to end", async () => {
    const { app } = mk();
    const a = newAccount(); const p = offerPayload();
    const r = await post(app, "/v1/offer/verify", { offer: { format: "eip712", payload: p, signature: await signOffer(a, p) }, accepts: [{ scheme: "exact", network: p.network, asset: USDC, payTo: p.payTo, amount: p.amount }] });
    const j: any = await r.json();
    expect(r.status).toBe(200); expect(j.signature_valid).toBe(true); expect(j.signer.address).toBe(a.address);
  });
  it("receipt/verify end to end", async () => {
    const { app } = mk();
    const a = newAccount(); const p = receiptPayload();
    const j: any = await (await post(app, "/v1/receipt/verify", { receipt: { format: "eip712", payload: p, signature: await signReceipt(a, p) }, payer: p.payer }, "2.2.2.2")).json();
    expect(j.signature_valid).toBe(true); expect(j.checks.find((c: any) => c.id === "payer_match").status).toBe("pass");
  });
  it("payment-required/verify accepts base64 header strings", async () => {
    const { app } = mk();
    const a = newAccount(); const p = offerPayload();
    const pr = { x402Version: 2, accepts: [{ scheme: "exact", network: p.network, asset: USDC, payTo: p.payTo, amount: p.amount }], extensions: { "offer-receipt": { info: { offers: [{ format: "eip712", acceptIndex: 0, payload: p, signature: await signOffer(a, p) }] } } } };
    const j: any = await (await post(app, "/v1/payment-required/verify", { payment_required: btoa(JSON.stringify(pr)) }, "3.3.3.3")).json();
    expect(j.offers_checked).toBe(1); expect(j.results[0].signature_valid).toBe(true);
  });
  it("validates input", async () => {
    const { app } = mk();
    expect((await post(app, "/v1/offer/verify", "{not json", "4.4.4.4")).status).toBe(400);
    expect((await post(app, "/v1/offer/verify", {}, "4.4.4.4")).status).toBe(400);
    expect((await post(app, "/v1/offer/verify", { offer: {}, trusted_pay_to: ["nope"] }, "4.4.4.4")).status).toBe(400);
    expect((await post(app, "/v1/offer/verify", { offer: {}, agent: { chain_id: 999, agent_id: "1" } }, "4.4.4.4")).status).toBe(400);
    expect((await post(app, "/v1/offer/verify", "x".repeat(70_000), "4.4.4.4")).status).toBe(413);
    expect((await app.request(B + "/v1/preflight", { headers: { "cf-connecting-ip": "4.4.4.5" } })).status).toBe(400);
  });
  it("preflight refuses private targets without fetching", async () => {
    const { app, calls } = mk();
    for (const u of ["https://127.0.0.1/", "http://169.254.169.254/latest/meta-data", "https://localhost/x", "file:///etc/passwd"]) {
      const r = await app.request(B + "/v1/preflight?url=" + encodeURIComponent(u), { headers: { "cf-connecting-ip": "5.5.5.5" } });
      expect(r.status).toBe(400);
    }
    expect(calls).toEqual([]);
  });
  it("preflight on a 402 with a signed offer", async () => {
    const a = newAccount(); const p = offerPayload({ resourceUrl: "https://svc.example/api" });
    const pr = { x402Version: 2, resource: { url: "https://svc.example/api" }, accepts: [{ scheme: "exact", network: p.network, asset: USDC, payTo: p.payTo, amount: p.amount }], extensions: { bazaar: {}, "offer-receipt": { info: { offers: [{ format: "eip712", acceptIndex: 0, payload: p, signature: await signOffer(a, p) }] } } } };
    const { app } = mk([(u: string) => (u === "https://svc.example/api" ? new Response("{}", { status: 402, headers: { "payment-required": btoa(JSON.stringify(pr)) } }) : undefined)]);
    const j: any = await (await app.request(B + "/v1/preflight?url=https://svc.example/api", { headers: { "cf-connecting-ip": "6.6.6.6" } })).json();
    expect(j.is_402).toBe(true); expect(j.payment_required_from).toBe("header");
    expect(j.accepts[0].amount).toBe("10000"); expect(j.offer_receipt.results[0].signature_valid).toBe(true);
    expect(j.notes.join(" ")).toContain("not bound to the domain");
  });
  it("preflight on non-402 and 405", async () => {
    const { app } = mk([(u: string) => (u.endsWith("/ok") ? new Response("hi", { status: 200 }) : u.endsWith("/post") ? new Response("", { status: 405 }) : undefined)]);
    const j: any = await (await app.request(B + "/v1/preflight?url=https://svc.example/ok", { headers: { "cf-connecting-ip": "7.7.7.7" } })).json();
    expect(j.is_402).toBe(false); expect(j.notes[0]).toContain("expected HTTP 402");
    const k: any = await (await app.request(B + "/v1/preflight?url=https://svc.example/post", { headers: { "cf-connecting-ip": "7.7.7.7" } })).json();
    expect(k.notes[0]).toContain("method=POST");
  });
  it("rate limiter", () => {
    expect(limited("rl", 30, 0)).toBe(false); expect(limited("rl", 10, 1)).toBe(false); expect(limited("rl", 1, 2)).toBe(true); expect(limited("rl", 1, 70_000)).toBe(false);
  });
  it("enforces the subrequest budget", async () => {
    const { app } = mk([() => new Response(null, { status: 302, headers: { location: "https://svc.example/again" } })]);
    const r = await app.request(B + "/v1/preflight?url=https://svc.example/", { headers: { "cf-connecting-ip": "8.8.8.8" } });
    expect([400, 502]).toContain(r.status);
  });
});

describe("MCP", () => {
  const rpc = (app: any, body: unknown, ip = "9.9.9.9") => app.request(B + "/mcp", { method: "POST", body: JSON.stringify(body), headers: { "cf-connecting-ip": ip } });
  it("initialize / tools/list / tools/call / ping / notifications / unknown", async () => {
    const { app } = mk();
    const init: any = await (await rpc(app, { jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "t", version: "1" } } })).json();
    expect(init.result.protocolVersion).toBe("2025-06-18"); expect(init.result.serverInfo.name).toBe("proofcheck");
    expect((await rpc(app, { jsonrpc: "2.0", method: "notifications/initialized" })).status).toBe(202);
    const list: any = await (await rpc(app, { jsonrpc: "2.0", id: 2, method: "tools/list" })).json();
    expect(list.result.tools.map((t: any) => t.name)).toEqual(["verify_offer", "verify_receipt", "verify_payment_required", "preflight_x402_endpoint", "lookup_erc8004_agent"]);
    const a = newAccount(); const p = offerPayload();
    const call: any = await (await rpc(app, { jsonrpc: "2.0", id: 3, method: "tools/call", params: { name: "verify_offer", arguments: { offer: { format: "eip712", payload: p, signature: await signOffer(a, p) } } } })).json();
    expect(call.result.isError).toBe(false); expect(call.result.structuredContent.signer.address).toBe(a.address);
    const bad: any = await (await rpc(app, { jsonrpc: "2.0", id: 4, method: "tools/call", params: { name: "verify_offer", arguments: {} } })).json();
    expect(bad.result.isError).toBe(true);
    expect((await (await rpc(app, { jsonrpc: "2.0", id: 5, method: "tools/call", params: { name: "nope" } })).json() as any).error.code).toBe(-32602);
    expect((await (await rpc(app, { jsonrpc: "2.0", id: 6, method: "nope" })).json() as any).error.code).toBe(-32601);
    expect((await (await rpc(app, { jsonrpc: "2.0", id: 7, method: "ping" })).json() as any).result).toEqual({});
  });
  it("batches and parse errors", async () => {
    const { app } = mk();
    const out: any = await (await rpc(app, [{ jsonrpc: "2.0", id: 1, method: "ping" }, { jsonrpc: "2.0", id: 2, method: "tools/list" }], "9.9.9.8")).json();
    expect(out).toHaveLength(2);
    const r = await app.request(B + "/mcp", { method: "POST", body: "{{", headers: { "cf-connecting-ip": "9.9.9.7" } });
    expect(r.status).toBe(400);
    expect((await app.request(B + "/mcp")).status).toBe(405);
  });
});

describe("ERC-8004 lookup", () => {
  it("falls back across RPCs on 429 and reports rpc_error honestly when all fail", async () => {
    const down = mk([(u: string) => (u.includes("rpc") || u.includes("drpc") || u.includes("base.org") ? new Response("", { status: 429 }) : undefined)]);
    const j: any = await (await down.app.request(B + "/v1/erc8004/agent?chain_id=8453&agent_id=1", { headers: { "cf-connecting-ip": "10.0.0.1" } })).json();
    expect(j.status).toBe("rpc_error"); expect(j.exists).toBe(false);
    expect(down.calls.filter((c) => c.includes("publicnode") || c.includes("drpc") || c.includes("base.org")).length).toBe(3);
  });
  it("reads an agent via one batched call", async () => {
    const pad = (a: string) => "0x" + "0".repeat(24) + a.slice(2);
    const owner = "0x" + "ab".repeat(20);
    const m = mk([async (u: string, init: any) => (u.includes("publicnode") ? json(JSON.parse(String(init.body)).map((c: any, i: number) => (i === 0 ? { jsonrpc: "2.0", id: c.id, result: pad(owner) } : { jsonrpc: "2.0", id: c.id, error: { message: "execution reverted" } }))) : undefined)]);
    const j: any = await (await m.app.request(B + "/v1/erc8004/agent?chain_id=8453&agent_id=42", { headers: { "cf-connecting-ip": "10.0.0.2" } })).json();
    expect(j.exists).toBe(true); expect(j.owner).toBe(owner); expect(m.calls.length).toBe(1);
  });
});
