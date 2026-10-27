import { describe, expect, it } from "vitest";
import { verifyOffer, verifyPaymentRequired, verifyReceipt } from "../src/verify";
import { IDENTITY_REGISTRY } from "../src/chain";
import { NOW, USDC, dohTxt, json, newAccount, offerPayload, receiptPayload, signOffer, signReceipt, stubFetch } from "./helpers";
import { keccak_256 } from "@noble/hashes/sha3";
import { bytesToHex, enc } from "../src/bytes";

const ctx = (f?: typeof fetch, extra: any = {}) => ({ fetchImpl: f, now: NOW, ...extra });
const status = (r: any, id: string) => r.checks.find((c: any) => c.id === id)?.status;
const ev = (r: any, m: string) => r.authorization.evidence.find((e: any) => e.method === m);

describe("offer checks", () => {
  it("valid, unexpired, matching accepts, no network evidence -> signer unproven (honest)", async () => {
    const a = newAccount(); const p = offerPayload();
    const r = await verifyOffer({ format: "eip712", payload: p, signature: await signOffer(a, p) }, { accepts: [{ scheme: "exact", network: p.network, asset: p.asset, payTo: p.payTo, amount: p.amount }] }, ctx(undefined, { skipNetwork: true }));
    expect(r.signature_valid).toBe(true);
    expect(status(r, "expiry")).toBe("pass"); expect(status(r, "accepts_match")).toBe("pass");
    expect(r.verdict).toBe("valid_signer_unproven");
    expect(r.authorization.status).toBe("unproven");
  });
  it("expired offer is rejected", async () => {
    const a = newAccount(); const p = offerPayload({ validUntil: NOW - 10 });
    const r = await verifyOffer({ format: "eip712", payload: p, signature: await signOffer(a, p) }, {}, ctx(undefined, { skipNetwork: true }));
    expect(r.verdict).toBe("rejected"); expect(status(r, "expiry")).toBe("fail");
  });
  it("missing validUntil warns (replayable)", async () => {
    const a = newAccount(); const p = offerPayload({ validUntil: 0 });
    const r = await verifyOffer({ format: "eip712", payload: p, signature: await signOffer(a, p) }, {}, ctx(undefined, { skipNetwork: true }));
    expect(status(r, "expiry")).toBe("warn"); // validUntil 0 == unused/no expiry
  });
  it("absent validUntil warns", async () => {
    const a = newAccount(); const { validUntil, ...p } = offerPayload(); void validUntil;
    const r = await verifyOffer({ format: "eip712", payload: p as any, signature: await signOffer(a, { ...p, validUntil: 0 }) }, {}, ctx(undefined, { skipNetwork: true }));
    expect(r.signature_valid).toBe(true); expect(status(r, "expiry")).toBe("warn");
  });
  it("tampered payload -> different signer, but flagged only through authorization (signature 'valid' for a random key)", async () => {
    const a = newAccount(); const p = offerPayload();
    const r = await verifyOffer({ format: "eip712", payload: { ...p, amount: "1" }, signature: await signOffer(a, p) }, {}, ctx(undefined, { skipNetwork: true }));
    expect(r.signer?.address).not.toBe(a.address);
    expect(r.verdict).toBe("valid_signer_unproven");
  });
  it("terms differ from accepts[] -> rejected", async () => {
    const a = newAccount(); const p = offerPayload();
    const r = await verifyOffer({ format: "eip712", payload: p, signature: await signOffer(a, p) }, { accepts: [{ scheme: "exact", network: p.network, asset: p.asset, payTo: p.payTo, amount: "99999" }] }, ctx(undefined, { skipNetwork: true }));
    expect(r.verdict).toBe("rejected"); expect(status(r, "accepts_match")).toBe("fail");
  });
  it("resource mismatch -> rejected; trailing slash tolerated", async () => {
    const a = newAccount(); const p = offerPayload();
    const o = { format: "eip712", payload: p, signature: await signOffer(a, p) };
    expect((await verifyOffer(o, { resourceUrl: "https://api.example.com/other" }, ctx(undefined, { skipNetwork: true }))).verdict).toBe("rejected");
    expect(status(await verifyOffer(o, { resourceUrl: "https://api.example.com/data/" }, ctx(undefined, { skipNetwork: true })), "resource_match")).toBe("pass");
  });
  it("bad inputs yield invalid_signature, never throw", async () => {
    for (const o of [{ format: "eip712" }, { format: "eip712", payload: offerPayload(), signature: "0xnope" }, { format: "wat" }, { format: "jws", signature: "a.b.c" }, { format: "jws", signature: 5 }] as any[]) {
      const r = await verifyOffer(o, {}, ctx(undefined, { skipNetwork: true }));
      expect(r.verdict).toBe("invalid_signature");
    }
  });
});

describe("signer authorization evidence", () => {
  const HOST = "api.example.com";
  it("payTo == signer is WEAK unless payTo is independently trusted", async () => {
    const a = newAccount(); const p = offerPayload({ payTo: a.address });
    const o = { format: "eip712", payload: p, signature: await signOffer(a, p) };
    const weak = await verifyOffer(o, {}, ctx(undefined, { skipNetwork: true }));
    expect(ev(weak, "payTo")).toMatchObject({ result: "authorized", strength: "weak" });
    expect(weak.verdict).toBe("valid_signer_unproven"); expect(weak.authorization.status).toBe("weak_only");
    const strong = await verifyOffer(o, { trustedPayTo: [a.address] }, ctx(undefined, { skipNetwork: true }));
    expect(strong.verdict).toBe("valid_authorized");
  });
  it("did:web document at the host lists the signer", async () => {
    const a = newAccount(); const p = offerPayload();
    const { f } = stubFetch([(u) => (u === `https://${HOST}/.well-known/did.json` ? json({ id: `did:web:${HOST}`, verificationMethod: [{ id: "#k", blockchainAccountId: `eip155:8453:${a.address.toLowerCase()}` }] }) : undefined)]);
    const r = await verifyOffer({ format: "eip712", payload: p, signature: await signOffer(a, p) }, {}, ctx(f));
    expect(ev(r, "did_web")).toMatchObject({ result: "authorized", strength: "strong" });
    expect(r.verdict).toBe("valid_authorized");
  });
  it("did:web document listing someone else is not_found", async () => {
    const a = newAccount(); const b = newAccount(); const p = offerPayload();
    const { f } = stubFetch([(u) => (u.endsWith("/did.json") ? json({ id: `did:web:${HOST}`, verificationMethod: [{ id: "#k", ethereumAddress: b.address }] }) : undefined)]);
    const r = await verifyOffer({ format: "eip712", payload: p, signature: await signOffer(a, p) }, {}, ctx(f));
    expect(ev(r, "did_web").result).toBe("not_found"); expect(r.verdict).toBe("valid_signer_unproven");
  });
  it("DNS _controllers TXT with did:pkh; reports DNSSEC state", async () => {
    const a = newAccount(); const p = offerPayload();
    for (const ad of [true, false]) {
      const { f } = stubFetch([dohTxt(`_controllers.${HOST}`, [`did:pkh:eip155:8453:${a.address.toLowerCase()}`], ad)]);
      const r = await verifyOffer({ format: "eip712", payload: p, signature: await signOffer(a, p) }, {}, ctx(f));
      expect(ev(r, "dns_controllers")).toMatchObject({ result: "authorized", strength: "strong" });
      expect(ev(r, "dns_controllers").detail).toContain(ad ? "DNSSEC-validated" : "did NOT report");
    }
  });
  it("ERC-8004: domain well-known -> on-chain agentWallet == signer, registration lists host", async () => {
    const a = newAccount(); const p = offerPayload();
    const sel = (s: string) => bytesToHex(keccak_256(enc.encode(s)).slice(0, 4));
    const pad = (addr: string) => "0x" + "0".repeat(24) + addr.slice(2).toLowerCase();
    const strEnc = (s: string) => { const b = bytesToHex(enc.encode(s)); const len = (b.length / 2).toString(16).padStart(64, "0"); return "0x" + "20".padStart(64, "0") + len + b.padEnd(Math.ceil(b.length / 64) * 64, "0"); };
    const regFile = { type: "https://eips.ethereum.org/EIPS/eip-8004#registration-v1", name: "svc", services: [{ name: "web", endpoint: `https://${HOST}/` }] };
    const uri = "data:application/json;base64," + btoa(JSON.stringify(regFile));
    const { f, calls } = stubFetch([
      (u) => (u === `https://${HOST}/.well-known/agent-registration.json` ? json({ registrations: [{ agentId: 7, agentRegistry: `eip155:8453:${IDENTITY_REGISTRY}` }] }) : undefined),
      async (u, init) => {
        if (!u.includes("mainnet.base.org")) return undefined;
        const batch = JSON.parse(String(init!.body));
        return json(batch.map((c: any) => {
          const d: string = c.params[0].data;
          if (d.startsWith("0x" + sel("ownerOf(uint256)"))) return { jsonrpc: "2.0", id: c.id, result: pad(newAccount().address) };
          if (d.startsWith("0x" + sel("tokenURI(uint256)"))) return { jsonrpc: "2.0", id: c.id, result: strEnc(uri) };
          if (d.startsWith("0x" + sel("getAgentWallet(uint256)"))) return { jsonrpc: "2.0", id: c.id, result: pad(a.address) };
          return { jsonrpc: "2.0", id: c.id, error: { message: "x" } };
        }));
      },
    ]);
    const r = await verifyOffer({ format: "eip712", payload: p, signature: await signOffer(a, p) }, {}, ctx(f));
    expect(ev(r, "erc8004")).toMatchObject({ result: "authorized", strength: "strong" });
    expect(ev(r, "erc8004").detail).toContain("agentWallet == signer");
    expect(ev(r, "erc8004").detail).toContain("lists this domain");
    expect(calls.filter((c) => c.includes("mainnet.base.org")).length).toBe(1); // one batched RPC subrequest
  });
  it("ERC-8004: wallet matches but registration does NOT list the host -> not authorized", async () => {
    const a = newAccount(); const p = offerPayload();
    const sel = (s: string) => bytesToHex(keccak_256(enc.encode(s)).slice(0, 4));
    const pad = (addr: string) => "0x" + "0".repeat(24) + addr.slice(2).toLowerCase();
    const uri = "data:application/json," + encodeURIComponent(JSON.stringify({ services: [{ endpoint: "https://elsewhere.example/" }] }));
    const b = bytesToHex(enc.encode(uri));
    const strEnc = "0x" + "20".padStart(64, "0") + (b.length / 2).toString(16).padStart(64, "0") + b.padEnd(Math.ceil(b.length / 64) * 64, "0");
    const { f } = stubFetch([
      (u) => (u.endsWith("agent-registration.json") ? json({ registrations: [{ agentId: 7, agentRegistry: `eip155:8453:${IDENTITY_REGISTRY}` }] }) : undefined),
      async (u, init) => u.includes("mainnet.base.org") ? json(JSON.parse(String(init!.body)).map((c: any) => { const d = c.params[0].data; return { jsonrpc: "2.0", id: c.id, result: d.startsWith("0x" + sel("tokenURI(uint256)")) ? strEnc : pad(a.address) }; })) : undefined,
    ]);
    const r = await verifyOffer({ format: "eip712", payload: p, signature: await signOffer(a, p) }, {}, ctx(f));
    expect(ev(r, "erc8004").result).toBe("not_found"); expect(r.verdict).toBe("valid_signer_unproven");
  });
  it.each([
    [false, "weak"],
    [true, "strong"],
  ])("ERC-8004 caller-supplied agent (domain lists it: %s) -> %s", async (domainLists, strength) => {
    const a = newAccount(); const p = offerPayload();
    const sel = (s: string) => bytesToHex(keccak_256(enc.encode(s)).slice(0, 4));
    const pad = (addr: string) => "0x" + "0".repeat(24) + addr.slice(2).toLowerCase();
    // attacker-style registration: the file names the victim host, but only the registrant wrote that
    const uri = "data:application/json," + encodeURIComponent(JSON.stringify({ services: [{ endpoint: `https://${HOST}/` }] }));
    const b = bytesToHex(enc.encode(uri));
    const strEnc = "0x" + "20".padStart(64, "0") + (b.length / 2).toString(16).padStart(64, "0") + b.padEnd(Math.ceil(b.length / 64) * 64, "0");
    const { f } = stubFetch([
      (u) => (u === `https://${HOST}/.well-known/agent-registration.json` ? (domainLists ? json({ registrations: [{ agentId: 9, agentRegistry: `eip155:8453:${IDENTITY_REGISTRY}` }] }) : new Response("nf", { status: 404 })) : undefined),
      async (u, init) => u.includes("mainnet.base.org") ? json(JSON.parse(String(init!.body)).map((c: any) => { const d = c.params[0].data; return { jsonrpc: "2.0", id: c.id, result: d.startsWith("0x" + sel("tokenURI(uint256)")) ? strEnc : pad(a.address) }; })) : undefined,
    ]);
    const r = await verifyOffer({ format: "eip712", payload: p, signature: await signOffer(a, p) }, { agent: { chainId: 8453, agentId: "9" } }, ctx(f));
    expect(ev(r, "erc8004")).toMatchObject({ result: "authorized", strength });
    expect(r.authorization.status).toBe(domainLists ? "authorized" : "weak_only");
    expect(r.authorization.checked_at).toMatch(/^\d{4}-/);
    expect(r.authorization.time_scope).toMatch(/not at issuance/);
  });
  it("network errors become evidence errors, not exceptions", async () => {
    const a = newAccount(); const p = offerPayload();
    const f = (async () => { throw new Error("boom"); }) as unknown as typeof fetch;
    const r = await verifyOffer({ format: "eip712", payload: p, signature: await signOffer(a, p) }, {}, ctx(f));
    expect(r.signature_valid).toBe(true); expect(r.authorization.evidence.filter((e) => e.result === "error").length).toBeGreaterThan(0);
  });
});

describe("receipts", () => {
  it("fresh matching receipt", async () => {
    const a = newAccount(); const p = receiptPayload({ transaction: "0x" + "ab".repeat(32) });
    const r = await verifyReceipt({ format: "eip712", payload: p, signature: await signReceipt(a, p) }, { resourceUrl: p.resourceUrl, payer: p.payer, transaction: p.transaction, network: p.network }, ctx(undefined, { skipNetwork: true }));
    expect(r.signature_valid).toBe(true);
    for (const id of ["issued_at", "resource_match", "payer_match", "transaction_match", "network_match"]) expect(status(r, id)).toBe("pass");
  });
  it("wrong payer / future / stale", async () => {
    const a = newAccount();
    const mk = async (over: any) => { const p = receiptPayload(over); return { format: "eip712", payload: p, signature: await signReceipt(a, p) }; };
    const r1 = await verifyReceipt(await mk({}), { payer: newAccount().address }, ctx(undefined, { skipNetwork: true }));
    expect(r1.verdict).toBe("rejected");
    const r2 = await verifyReceipt(await mk({ issuedAt: NOW + 3600 }), {}, ctx(undefined, { skipNetwork: true }));
    expect(status(r2, "issued_at")).toBe("fail");
    const r3 = await verifyReceipt(await mk({ issuedAt: NOW - 86400 }), {}, ctx(undefined, { skipNetwork: true }));
    expect(status(r3, "issued_at")).toBe("warn"); expect(r3.verdict).not.toBe("rejected");
    const r4 = await verifyReceipt(await mk({ issuedAt: NOW - 86400 }), { maxAgeSeconds: 10 ** 6 }, ctx(undefined, { skipNetwork: true }));
    expect(status(r4, "issued_at")).toBe("pass");
  });
  it("receipt without tx explains the privacy-minimal trade-off", async () => {
    const a = newAccount(); const p = receiptPayload();
    const r = await verifyReceipt({ format: "eip712", payload: p, signature: await signReceipt(a, p) }, {}, ctx(undefined, { skipNetwork: true }));
    expect(r.checks.find((c) => c.id === "transaction")?.detail).toContain("privacy-minimal");
  });
});

describe("payment-required", () => {
  it("caps offers at 4 and dedupes authorization lookups per signer", async () => {
    const a = newAccount();
    const offers = [] as any[];
    for (let i = 0; i < 6; i++) { const p = offerPayload({ amount: String(1000 + i) }); offers.push({ format: "eip712", acceptIndex: i, payload: p, signature: await signOffer(a, p) }); }
    const accepts = offers.map((o) => ({ scheme: "exact", network: o.payload.network, asset: USDC, payTo: o.payload.payTo, amount: o.payload.amount }));
    const { f, calls } = stubFetch([]);
    const out = await verifyPaymentRequired({ accepts, resource: { url: "https://api.example.com/data" }, extensions: { "offer-receipt": { info: { offers } } } }, {}, ctx(f));
    expect(out.offers_checked).toBe(4); expect(out.truncated).toBe(true);
    expect(calls.filter((c) => c.endsWith("did.json")).length).toBe(1);
  });
  it("no extension", async () => {
    const out = await verifyPaymentRequired({ accepts: [] }, {}, ctx());
    expect(out.has_offer_receipt_extension).toBe(false);
  });
});
