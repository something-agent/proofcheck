/** Artifacts produced by the official @x402/extensions SDK must verify in ProofCheck, and vice versa. */
import { describe, expect, it } from "vitest";
import { createOfferEIP712, createOfferJWS, createReceiptEIP712, createReceiptJWS, verifyOfferSignatureEIP712, verifyReceiptSignatureEIP712 } from "@x402/extensions/offer-receipt";
import { verifyOffer, verifyReceipt } from "../src/verify";
import { b64urlEncode, ed25519, json, newAccount, offerPayload, signOffer, stubFetch, USDC } from "./helpers";

const URL_ = "https://sdk.example.com/paid";
const terms = { acceptIndex: 0, scheme: "exact", network: "eip155:8453", asset: USDC, payTo: "0x209693Bc6afc0C5328bA36FaF03C514EF312287C", amount: "5000" } as const;
const noNet = { skipNetwork: true };

describe("SDK -> ProofCheck", () => {
  it("EIP-712 offer + receipt", async () => {
    const a = newAccount();
    const sign = (p: any) => a.signTypedData(p);
    const offer = await createOfferEIP712(URL_, terms as any, sign as any);
    const r = await verifyOffer(offer as any, { accepts: [terms] }, noNet);
    expect(r.signature_valid).toBe(true); expect(r.signer?.address).toBe(a.address);
    expect(r.checks.filter((c) => c.status === "fail")).toEqual([]);
    const rc = await createReceiptEIP712({ resourceUrl: URL_, payer: a.address, network: "eip155:8453", transaction: "0x" + "11".repeat(32) }, sign as any);
    const rr = await verifyReceipt(rc as any, { resourceUrl: URL_, payer: a.address }, noNet);
    expect(rr.signature_valid).toBe(true); expect(rr.signer?.address).toBe(a.address);
  });
  it("JWS EdDSA offer + receipt via did:web, strongly authorized", async () => {
    const priv = ed25519.utils.randomPrivateKey(); const pub = ed25519.getPublicKey(priv);
    const kid = "did:web:sdk.example.com#k1";
    const signer = { kid, algorithm: "EdDSA", sign: async (b: Uint8Array) => b64urlEncode(ed25519.sign(b, priv)) };
    const doc = { id: "did:web:sdk.example.com", verificationMethod: [{ id: kid, publicKeyJwk: { kty: "OKP", crv: "Ed25519", x: b64urlEncode(pub) } }] };
    const { f } = stubFetch([(u) => (u === "https://sdk.example.com/.well-known/did.json" ? json(doc) : undefined)]);
    const offer = await createOfferJWS(URL_, terms as any, signer as any);
    const r = await verifyOffer(offer as any, { accepts: [terms] }, { fetchImpl: f });
    expect(r.signature_valid).toBe(true); expect(r.verdict).toBe("valid_authorized");
    const rc = await createReceiptJWS({ resourceUrl: URL_, payer: "0x857b06519E91e3A54538791bDbb0E22373e36b66", network: "eip155:8453" }, signer as any);
    expect((await verifyReceipt(rc as any, {}, { fetchImpl: f })).verdict).toBe("valid_authorized");
  });
});

describe("ProofCheck -> SDK", () => {
  it("offers signed with viem verify in the SDK too (agreement on signer)", async () => {
    const a = newAccount(); const p = offerPayload();
    const offer = { format: "eip712", acceptIndex: 0, payload: p, signature: await signOffer(a, p) };
    const sdk = await verifyOfferSignatureEIP712(offer as any);
    const mine = await verifyOffer(offer as any, {}, { ...noNet, now: 1_800_000_000 });
    expect(mine.signer?.address).toBe(sdk.signer);
    void verifyReceiptSignatureEIP712;
  });
});
