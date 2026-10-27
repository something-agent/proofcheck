/** Minimal remote MCP server (Streamable HTTP, stateless, JSON responses). Protocol 2025-06-18; accepts 2025-03-26 and 2025-11-25 handshakes. */
import { handlers, BadRequest } from "./handlers";
import { Ctx } from "./verify";

export const TOOLS = [
  { name: "verify_offer", description: "Verify an x402 signed offer (EIP-712 or JWS): signature, expiry, match to accepts[], and signer-authorization evidence (payTo, did:web, DNS _controllers, ERC-8004). Free.", inputSchema: { type: "object", properties: { offer: { type: "object", description: "The offer object: {format, payload?, signature, acceptIndex?}" }, accepts: { type: "array", description: "Optional accepts[] from the live 402 to match against", items: { type: "object" } }, resource_url: { type: "string" }, trusted_pay_to: { type: "array", items: { type: "string" } } }, required: ["offer"] } },
  { name: "verify_receipt", description: "Verify an x402 signed receipt (EIP-712 or JWS) returned in the settlement response: signature, freshness, payer/resource/transaction match, signer-authorization evidence. Free.", inputSchema: { type: "object", properties: { receipt: { type: "object" }, resource_url: { type: "string" }, payer: { type: "string" }, transaction: { type: "string" }, network: { type: "string" }, max_age_seconds: { type: "number" }, trusted_pay_to: { type: "array", items: { type: "string" } } }, required: ["receipt"] } },
  { name: "verify_payment_required", description: "Verify every signed offer inside a PaymentRequired object (pass the decoded JSON, or the raw base64 PAYMENT-REQUIRED header). Free.", inputSchema: { type: "object", properties: { payment_required: { description: "Object or base64/JSON string" }, resource_url: { type: "string" } }, required: ["payment_required"] } },
  { name: "preflight_x402_endpoint", description: "Unpaid preflight of an x402 URL: fetch its 402, summarise accepts[]/extensions, verify any signed offers and report who can vouch for the signer. Never pays. Free.", inputSchema: { type: "object", properties: { url: { type: "string" }, method: { type: "string", enum: ["GET", "POST"] } }, required: ["url"] } },
  { name: "lookup_erc8004_agent", description: "Read-only ERC-8004 identity lookup (owner, agentWallet, registration file, endpoint-domain verification) on Ethereum, Base, Optimism, Arbitrum, Polygon, BNB, Avalanche, Gnosis, Celo, Linea or Scroll.", inputSchema: { type: "object", properties: { chain_id: { type: "integer" }, agent_id: { type: "string" } }, required: ["chain_id", "agent_id"] } },
] as const;

const NAME_TO_HANDLER: Record<string, keyof typeof handlers> = { verify_offer: "verify_offer", verify_receipt: "verify_receipt", verify_payment_required: "verify_payment_required", preflight_x402_endpoint: "preflight", lookup_erc8004_agent: "lookup_erc8004_agent" };
const SUPPORTED = ["2025-11-25", "2025-06-18", "2025-03-26"];

export async function handleMcp(msg: any, ctx: Ctx, version: string): Promise<any | null> {
  const id = msg?.id;
  const reply = (result: any) => ({ jsonrpc: "2.0", id, result });
  const error = (code: number, message: string) => ({ jsonrpc: "2.0", id: id ?? null, error: { code, message } });
  if (!msg || msg.jsonrpc !== "2.0" || typeof msg.method !== "string") return error(-32600, "Invalid Request");
  if (id === undefined) return null; // notification
  switch (msg.method) {
    case "initialize": {
      const want = msg.params?.protocolVersion;
      return reply({ protocolVersion: SUPPORTED.includes(want) ? want : SUPPORTED[1], capabilities: { tools: { listChanged: false } }, serverInfo: { name: "proofcheck", title: "ProofCheck - x402 offer/receipt verifier", version }, instructions: "Free, read-only verification of x402 signed offers and receipts, with evidence on whether the signing key is authorized for the service. Never pays or signs." });
    }
    case "ping": return reply({});
    case "tools/list": return reply({ tools: TOOLS });
    case "tools/call": {
      const name = String(msg.params?.name);
      const h = NAME_TO_HANDLER[name];
      if (!h) return error(-32602, `Unknown tool: ${name}`);
      try {
        const out = await (handlers[h] as any)(msg.params?.arguments ?? {}, ctx);
        return reply({ content: [{ type: "text", text: JSON.stringify(out) }], structuredContent: out, isError: false });
      } catch (e) {
        const m = e instanceof BadRequest ? (e as Error).message : `tool failed: ${(e as Error).message}`;
        return reply({ content: [{ type: "text", text: m }], isError: true });
      }
    }
    default: return error(-32601, `Method not found: ${msg.method}`);
  }
}
