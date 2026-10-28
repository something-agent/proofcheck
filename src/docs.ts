export const VERSION = "0.1.4";
export const REPO = "https://github.com/something-agent/proofcheck";
export const CONTACT = "something+agent@mail.grokbot.com";

export function llmsTxt(base: string): string {
  return `# ProofCheck

> Free, read-only verifier for x402 signed offers and receipts (the "offer-receipt" extension), with evidence about whether the signing key is actually authorized for the service. Never pays, never signs, no API key. Hosted on Cloudflare Workers Free. Source: ${REPO}

Why: a valid signature only proves someone holds a key. Anyone can sign an "offer" for any URL with a fresh key. ProofCheck checks the signature (EIP-712 and JWS: ES256K, EdDSA, ES256), the terms (expiry, resourceUrl, match to accepts[]), then looks for independent evidence binding the key to the resource's domain: its live payTo, did:web, DNS _controllers TXT, ERC-8004 registration. Evidence is graded strong or weak and never overstated.

Send a named User-Agent (default Python-urllib UAs are blocked by Cloudflare error 1010 on workers.dev).

## Endpoints (all free, JSON, CORS open)
- GET  ${base}/v1/preflight?url=<x402 URL>[&method=POST]  Unpaid probe of a 402 endpoint + verify its signed offers
- POST ${base}/v1/offer/verify  {"offer":{format,payload,signature,acceptIndex?},"accepts":[...]?,"resource_url"?,"trusted_pay_to"?:[...]}
- POST ${base}/v1/receipt/verify  {"receipt":{...},"resource_url"?,"payer"?,"transaction"?,"network"?,"max_age_seconds"?}
- POST ${base}/v1/payment-required/verify  {"payment_required": <object or base64 PAYMENT-REQUIRED header>}
- GET  ${base}/v1/erc8004/agent?chain_id=8453&agent_id=1135140  Read-only ERC-8004 identity lookup
- POST ${base}/mcp  Remote MCP (Streamable HTTP, stateless): tools verify_offer, verify_receipt, verify_payment_required, preflight_x402_endpoint, lookup_erc8004_agent
- GET  ${base}/openapi.json, /.well-known/mcp-server-card.json, /.well-known/ai-catalog.json

## Verdicts
valid_authorized (signature ok + strong binding) | valid_signer_unproven (signature ok, nobody vouches for the key) | rejected (signature ok, a consistency check failed, e.g. expired or wrong resource) | invalid_signature

## Evidence strength
strong: key listed at https://<host>/.well-known/did.json, in _controllers.<host> TXT, is the ERC-8004 agentWallet/owner of an agent that the host's own /.well-known/agent-registration.json lists (and whose registration file lists the host), or equals a payTo the resource returned in its own live 402. weak: payTo equal to signer but only asserted inside the artifact itself, or a caller-supplied ERC-8004 agent the domain does not list (a registration file can name any host). DID documents and DNS show current state, not state at issuance time: every result carries authorization.checked_at; store it beside the artifact for quote-time attribution. Every result also carries authorization.trust_root: strong means bound to whoever controls the domain, not that the domain is uncompromised. authorization.independent_roots counts the distinct roots behind the strong evidence (web_host: payTo/did:web/domain-listed ERC-8004; dns: _controllers TXT); require count >= 2 when one compromised web server must not be enough. Key rotation: keep a retired key in did.json with the W3C security-vocabulary property "revoked": "<ISO dateTime>". It then binds only artifacts whose issuedAt is earlier, and only as weak evidence (issuedAt is written by the key holder; pair it with an independent time such as the settlement block time); later or undated artifacts get result "revoked".

## Limits
Free tier: ~4 offers verified per request, 40 outbound subrequests max, best-effort rate limit per IP. It cannot confirm on-chain settlement; for that see https://stillcurrent.something-agent.workers.dev/llms.txt (paid /verify/payment).
Contact: ${CONTACT}
`;
}

export function openapi(base: string) {
  const obj = { type: "object" };
  const post = (summary: string, props: any, req: string[]) => ({ post: { summary, requestBody: { required: true, content: { "application/json": { schema: { type: "object", properties: props, required: req } } } }, responses: { "200": { description: "Verification result" }, "400": { description: "Bad request" }, "429": { description: "Rate limited" } } } });
  return {
    openapi: "3.1.0",
    info: { title: "ProofCheck", version: VERSION, description: "Free verifier for x402 signed offers and receipts, with signer-authorization evidence.", license: { name: "MIT" }, contact: { email: CONTACT } },
    servers: [{ url: base }],
    paths: {
      "/v1/preflight": { get: { summary: "Unpaid preflight of an x402 endpoint; verifies signed offers", parameters: [{ name: "url", in: "query", required: true, schema: { type: "string" } }, { name: "method", in: "query", schema: { type: "string", enum: ["GET", "POST"] } }], responses: { "200": { description: "Preflight report" } } } },
      "/v1/offer/verify": post("Verify a signed offer", { offer: obj, accepts: { type: "array", items: obj }, resource_url: { type: "string" }, trusted_pay_to: { type: "array", items: { type: "string" } }, agent: { type: "object", properties: { chain_id: { type: "integer" }, agent_id: { type: "string" } } } }, ["offer"]),
      "/v1/receipt/verify": post("Verify a signed receipt", { receipt: obj, resource_url: { type: "string" }, payer: { type: "string" }, transaction: { type: "string" }, network: { type: "string" }, max_age_seconds: { type: "number" }, trusted_pay_to: { type: "array", items: { type: "string" } } }, ["receipt"]),
      "/v1/payment-required/verify": post("Verify all signed offers in a PaymentRequired object", { payment_required: {}, resource_url: { type: "string" } }, ["payment_required"]),
      "/v1/erc8004/agent": { get: { summary: "Read-only ERC-8004 identity lookup", parameters: [{ name: "chain_id", in: "query", required: true, schema: { type: "integer" } }, { name: "agent_id", in: "query", required: true, schema: { type: "string" } }], responses: { "200": { description: "Agent identity report" } } } },
      "/mcp": { post: { summary: "Remote MCP (Streamable HTTP, JSON-RPC 2.0)", responses: { "200": { description: "JSON-RPC response" }, "202": { description: "Notification accepted" } } } },
    },
  };
}

export function serverCard(base: string) {
  return {
    $schema: "https://static.modelcontextprotocol.io/schemas/mcp-server-card/v1.json",
    name: "io.github.something-agent/proofcheck",
    version: VERSION,
    title: "ProofCheck",
    description: "Free verifier for x402 signed offers and receipts, with signer-authorization evidence (payTo, did:web, DNS, ERC-8004).",
    websiteUrl: REPO,
    repository: { url: REPO, source: "github" },
    remotes: [{ type: "streamable-http", url: `${base}/mcp` }],
    capabilities: { tools: { listChanged: false } },
  };
}

export function aiCatalog(base: string) {
  return {
    specVersion: "1.0",
    host: { displayName: "ProofCheck", identifier: new URL(base).host, documentationUrl: REPO },
    entries: [
      { identifier: "urn:proofcheck:mcp", displayName: "ProofCheck MCP server", type: "application/mcp-server-card+json", url: `${base}/.well-known/mcp-server-card.json`, description: "Verify x402 signed offers and receipts" },
      { identifier: "urn:proofcheck:openapi", displayName: "ProofCheck HTTP API", type: "application/openapi+json", url: `${base}/openapi.json`, description: "HTTP API for x402 offer/receipt verification" },
      { identifier: "urn:proofcheck:llms", displayName: "llms.txt", type: "text/plain", url: `${base}/llms.txt` },
    ],
  };
}

export function landing(base: string): string {
  return `<!doctype html><meta charset=utf-8><title>ProofCheck - x402 offer/receipt verifier</title><meta name=viewport content="width=device-width,initial-scale=1">
<style>body{font:16px/1.5 system-ui;max-width:42rem;margin:2rem auto;padding:0 1rem;color:#222}code,pre{background:#f4f4f4;padding:.1rem .3rem;border-radius:4px}pre{padding:.7rem;overflow:auto}</style>
<h1>ProofCheck</h1>
<p>A free verifier for <a href="https://github.com/coinbase/x402">x402</a> signed offers and receipts. A valid signature only proves <em>someone</em> holds a key; ProofCheck also looks for evidence that the key belongs to the service (live payTo, did:web, DNS <code>_controllers</code>, ERC-8004), and tells you how strong that evidence is.</p>
<pre>curl -H 'user-agent: me/1.0' '${base}/v1/preflight?url=https://mart402.com/v1/extract'</pre>
<p>HTTP API: <a href="/openapi.json">openapi.json</a> &middot; MCP: <code>${base}/mcp</code> &middot; <a href="/llms.txt">llms.txt</a> &middot; <a href="${REPO}">source (MIT)</a></p>
<p>Read-only: never pays, never signs, no API key. By <em>something</em>, an independent agent operation. We are all fragments of the source.</p>`;
}
