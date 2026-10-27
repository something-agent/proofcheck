import { privateKeyToAccount, generatePrivateKey } from "viem/accounts";
import { ed25519 } from "@noble/curves/ed25519";
import { secp256k1 } from "@noble/curves/secp256k1";
import { p256 } from "@noble/curves/nist";
import { sha256 } from "@noble/hashes/sha2";
import { b64urlEncode, enc } from "../src/bytes";

export const OFFER_TYPES = { Offer: [{ name: "version", type: "uint256" }, { name: "resourceUrl", type: "string" }, { name: "scheme", type: "string" }, { name: "network", type: "string" }, { name: "asset", type: "string" }, { name: "payTo", type: "string" }, { name: "amount", type: "string" }, { name: "validUntil", type: "uint256" }] } as const;
export const RECEIPT_TYPES = { Receipt: [{ name: "version", type: "uint256" }, { name: "network", type: "string" }, { name: "resourceUrl", type: "string" }, { name: "payer", type: "string" }, { name: "issuedAt", type: "uint256" }, { name: "transaction", type: "string" }] } as const;

export const NOW = 1_800_000_000;
export const USDC = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";

export function newAccount() { return privateKeyToAccount(generatePrivateKey()); }

export function offerPayload(over: Record<string, any> = {}) {
  return { version: 1, resourceUrl: "https://api.example.com/data", scheme: "exact", network: "eip155:8453", asset: USDC, payTo: "0x209693Bc6afc0C5328bA36FaF03C514EF312287C", amount: "10000", validUntil: NOW + 60, ...over };
}
export async function signOffer(acct: ReturnType<typeof newAccount>, payload: any) {
  return acct.signTypedData({ domain: { name: "x402 offer", version: "1", chainId: 1 }, types: OFFER_TYPES, primaryType: "Offer", message: { ...payload, version: BigInt(payload.version), validUntil: BigInt(payload.validUntil ?? 0) } });
}
export function receiptPayload(over: Record<string, any> = {}) {
  return { version: 1, network: "eip155:8453", resourceUrl: "https://api.example.com/data", payer: "0x857b06519E91e3A54538791bDbb0E22373e36b66", issuedAt: NOW - 5, transaction: "", ...over };
}
export async function signReceipt(acct: ReturnType<typeof newAccount>, payload: any) {
  return acct.signTypedData({ domain: { name: "x402 receipt", version: "1", chainId: 1 }, types: RECEIPT_TYPES, primaryType: "Receipt", message: { ...payload, version: BigInt(payload.version), issuedAt: BigInt(payload.issuedAt) } });
}

const j = (o: unknown) => enc.encode(JSON.stringify(o));
export function makeJws(alg: "EdDSA" | "ES256K" | "ES256", kid: string, payload: unknown, priv: Uint8Array) {
  const si = `${b64urlEncode(j({ alg, kid }))}.${b64urlEncode(j(payload))}`;
  let sig: Uint8Array;
  if (alg === "EdDSA") sig = ed25519.sign(enc.encode(si), priv);
  else if (alg === "ES256K") sig = secp256k1.sign(sha256(enc.encode(si)), priv).toCompactRawBytes();
  else sig = p256.sign(sha256(enc.encode(si)), priv).toCompactRawBytes();
  return `${si}.${b64urlEncode(sig)}`;
}
export { ed25519, secp256k1, p256, b64urlEncode };

export type Route = (url: string, init?: RequestInit) => Response | undefined | Promise<Response | undefined>;
/** Fetch stub: first route returning a Response wins; unmatched = 404. Records calls. */
export function stubFetch(routes: Route[]) {
  const calls: string[] = [];
  const f = (async (input: any, init?: RequestInit) => {
    const url = typeof input === "string" ? input : input.url;
    calls.push(url);
    for (const r of routes) { const res = await r(url, init); if (res) return res; }
    return new Response("not found", { status: 404 });
  }) as typeof fetch;
  return { f, calls };
}
export const json = (o: unknown, status = 200, headers: Record<string, string> = {}) => new Response(JSON.stringify(o), { status, headers: { "content-type": "application/json", ...headers } });
export const dohTxt = (name: string, txts: string[], ad = false) => (url: string) => url.startsWith("https://cloudflare-dns.com/dns-query") && decodeURIComponent(url).includes(`name=${name}`) ? json({ Status: 0, AD: ad, Answer: txts.map((t) => ({ name, type: 16, TTL: 60, data: `"${t}"` })) }) : undefined;
