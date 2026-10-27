/** Transport-agnostic handlers shared by the HTTP API and the MCP server. */
import { isAddress } from "./bytes";
import { IDENTITY_REGISTRY, CHAIN_RPCS, loadRegistration, readAgent } from "./chain";
import { probe, parsePaymentRequired } from "./probe";
import { BlockedTarget } from "./safe";
import { Ctx, verifyOffer, verifyPaymentRequired, verifyReceipt } from "./verify";
import { b64Decode, dec } from "./bytes";
import { wellKnownRegistration } from "./did";

export class BadRequest extends Error {}
const obj = (v: unknown, name: string): any => { if (!v || typeof v !== "object" || Array.isArray(v)) throw new BadRequest(`'${name}' must be an object`); return v; };
const optStr = (v: unknown, name: string) => { if (v === undefined || v === null) return undefined; if (typeof v !== "string" || v.length > 2048) throw new BadRequest(`'${name}' must be a string`); return v; };
const optAddrs = (v: unknown, name: string): string[] | undefined => {
  if (v === undefined || v === null) return undefined;
  const a = Array.isArray(v) ? v : [v];
  if (a.length > 8 || !a.every((x) => typeof x === "string" && isAddress(x))) throw new BadRequest(`'${name}' must be an EVM address or array of them`);
  return a;
};
function agentRef(v: unknown) {
  if (v === undefined || v === null) return undefined;
  const a = obj(v, "agent");
  const chainId = Number(a.chain_id), agentId = String(a.agent_id);
  if (!Number.isInteger(chainId) || !/^\d{1,30}$/.test(agentId)) throw new BadRequest("agent needs chain_id (int) and agent_id (decimal)");
  if (!CHAIN_RPCS[chainId]) throw new BadRequest(`unsupported chain_id ${chainId}; supported: ${Object.keys(CHAIN_RPCS).join(",")}`);
  return { chainId, agentId };
}

export const handlers = {
  async verify_offer(a: any, ctx: Ctx) {
    obj(a, "body");
    return verifyOffer(obj(a.offer, "offer"), { accepts: Array.isArray(a.accepts) ? a.accepts.slice(0, 16) : undefined, resourceUrl: optStr(a.resource_url, "resource_url"), trustedPayTo: optAddrs(a.trusted_pay_to, "trusted_pay_to"), agent: agentRef(a.agent) }, ctx);
  },
  async verify_receipt(a: any, ctx: Ctx) {
    obj(a, "body");
    const age = a.max_age_seconds === undefined ? undefined : Number(a.max_age_seconds);
    if (age !== undefined && !(age >= 0 && age < 1e9)) throw new BadRequest("max_age_seconds must be a non-negative number");
    return verifyReceipt(obj(a.receipt, "receipt"), { resourceUrl: optStr(a.resource_url, "resource_url"), payer: optStr(a.payer, "payer"), transaction: optStr(a.transaction, "transaction"), network: optStr(a.network, "network"), maxAgeSeconds: age, trustedPayTo: optAddrs(a.trusted_pay_to, "trusted_pay_to"), agent: agentRef(a.agent) }, ctx);
  },
  async verify_payment_required(a: any, ctx: Ctx) {
    obj(a, "body");
    let pr = a.payment_required;
    if (typeof pr === "string") { try { pr = JSON.parse(dec.decode(b64Decode(pr.trim()))); } catch { try { pr = JSON.parse(pr); } catch { throw new BadRequest("payment_required string is neither base64 JSON nor JSON"); } } }
    return verifyPaymentRequired(obj(pr, "payment_required"), { resourceUrl: optStr(a.resource_url, "resource_url") }, ctx);
  },
  async preflight(a: any, ctx: Ctx) {
    obj(a, "query");
    const url = optStr(a.url, "url");
    if (!url) throw new BadRequest("'url' is required");
    const method = a.method === "POST" ? "POST" : "GET";
    try { return await probe(url, { method }, ctx); }
    catch (e) { if (e instanceof BlockedTarget) throw new BadRequest(`target refused: ${e.message}`); throw e; }
  },
  async lookup_erc8004_agent(a: any, ctx: Ctx) {
    obj(a, "query");
    const ref = agentRef({ chain_id: a.chain_id, agent_id: a.agent_id });
    if (!ref) throw new BadRequest("chain_id and agent_id are required");
    const on = await readAgent(ref.chainId, ref.agentId, { fetchImpl: ctx.fetchImpl });
    const out: any = { chain_id: ref.chainId, registry: IDENTITY_REGISTRY, agent_id: ref.agentId, owner: on.owner, agent_wallet: on.agentWallet, agent_uri: on.agentURI && on.agentURI.startsWith("data:") ? on.agentURI.slice(0, 60) + "…(inline data URI)" : on.agentURI, exists: !!on.owner, rpc_notes: on.errors };
    const notes: string[] = [];
    if (on.agentURI) {
      try {
        const reg = await loadRegistration(on.agentURI, ctx.fetchImpl);
        const services = Array.isArray(reg.services) ? reg.services : Array.isArray(reg.endpoints) ? reg.endpoints : [];
        out.registration = { name: reg.name, description: typeof reg.description === "string" ? reg.description.slice(0, 300) : undefined, type: reg.type, x402_support: reg.x402Support ?? reg.x402support, active: reg.active, services: services.slice(0, 12).map((s: any) => ({ name: s?.name, endpoint: s?.endpoint })), supported_trust: reg.supportedTrust };
        if (!services.length) notes.push("registration file lists no services/endpoints");
        if (!reg.type) notes.push("registration file has no 'type' field");
        // Endpoint-domain verification (ERC-8004): each https endpoint's domain should publish /.well-known/agent-registration.json pointing back at this agent. Check the first one only (subrequest budget).
        const ep = services.map((s: any) => String(s?.endpoint ?? "")).find((e: string) => /^https:\/\//.test(e));
        if (ep) {
          const host = new URL(ep).hostname;
          try {
            const wk = await wellKnownRegistration(host, ctx.fetchImpl);
            const hit = (wk.registrations ?? []).some((r: any) => String(r?.agentId) === ref.agentId && new RegExp(`^eip155:${ref.chainId}:`).test(String(r?.agentRegistry)));
            out.endpoint_domain_verification = { host, status: hit ? "verified" : "mismatch", detail: hit ? "domain's agent-registration.json points back to this agent" : "domain publishes agent-registration.json but it does not list this agent" };
          } catch (e) { out.endpoint_domain_verification = { host, status: "unverified", detail: (e as Error).message.slice(0, 120) }; }
        }
      } catch (e) { notes.push(`registration file not loadable: ${(e as Error).message.slice(0, 120)}`); }
    } else if (out.exists) notes.push("agent exists but tokenURI is empty/unreadable");
    if (!out.exists) {
      const rpcDown = on.errors.length >= 3 && on.errors.every((e) => /rpc http|rpc|fetch|timeout|abort|network/i.test(e) && !/revert|execution|nonexistent|invalid token/i.test(e));
      if (rpcDown) { out.status = "rpc_error"; notes.push("could not read the chain (public RPCs unavailable or rate-limited); result is unknown, retry later"); }
      else notes.push("no such agent id on this registry/chain");
    }
    out.notes = notes;
    return out;
  },
};
export { parsePaymentRequired };
