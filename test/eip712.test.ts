import { describe, expect, it } from "vitest";
import { hashTypedData } from "viem";
import { offerDigest, receiptDigest, recoverSigner, toChecksumAddress } from "../src/eip712";
import { bytesToHex } from "../src/bytes";
import { NOW, OFFER_TYPES, RECEIPT_TYPES, newAccount, offerPayload, receiptPayload, signOffer, signReceipt } from "./helpers";

describe("EIP-712 digests match viem (independent implementation)", () => {
  it("offer", () => {
    const p = offerPayload();
    const want = hashTypedData({ domain: { name: "x402 offer", version: "1", chainId: 1 }, types: OFFER_TYPES, primaryType: "Offer", message: { ...p, version: 1n, validUntil: BigInt(p.validUntil) } });
    expect("0x" + bytesToHex(offerDigest(p))).toBe(want);
  });
  it("receipt, with and without transaction", () => {
    for (const tx of ["", "0x" + "ab".repeat(32)]) {
      const p = receiptPayload({ transaction: tx });
      const want = hashTypedData({ domain: { name: "x402 receipt", version: "1", chainId: 1 }, types: RECEIPT_TYPES, primaryType: "Receipt", message: { ...p, version: 1n, issuedAt: BigInt(p.issuedAt) } });
      expect("0x" + bytesToHex(receiptDigest(p))).toBe(want);
    }
  });
  it("omitted optional fields hash as empty/zero", () => {
    const { validUntil, ...p } = offerPayload();
    void validUntil;
    expect(bytesToHex(offerDigest(p as any))).toBe(bytesToHex(offerDigest({ ...p, validUntil: 0 } as any)));
    const { transaction, ...r } = receiptPayload();
    void transaction;
    expect(bytesToHex(receiptDigest(r as any))).toBe(bytesToHex(receiptDigest({ ...r, transaction: "" } as any)));
  });
});

describe("signer recovery", () => {
  it("recovers viem signer for offers and receipts", async () => {
    const a = newAccount();
    const p = offerPayload();
    expect(recoverSigner(offerDigest(p), await signOffer(a, p)).signer).toBe(a.address);
    const r = receiptPayload();
    expect(recoverSigner(receiptDigest(r), await signReceipt(a, r)).signer).toBe(a.address);
  });
  it("tampering changes the recovered signer", async () => {
    const a = newAccount();
    const p = offerPayload();
    const sig = await signOffer(a, p);
    expect(recoverSigner(offerDigest({ ...p, amount: "1" }), sig).signer).not.toBe(a.address);
  });
  it("rejects malformed signatures", () => {
    const d = offerDigest(offerPayload());
    expect(() => recoverSigner(d, "0x1234")).toThrow();
    expect(() => recoverSigner(d, "0x" + "00".repeat(64) + "05")).toThrow();
    expect(() => recoverSigner(d, "zz")).toThrow();
  });
  it("accepts v of 0/1 or 27/28", async () => {
    const a = newAccount(); const p = offerPayload(); const sig = await signOffer(a, p);
    const v = parseInt(sig.slice(-2), 16);
    const alt = sig.slice(0, -2) + (v >= 27 ? v - 27 : v + 27).toString(16).padStart(2, "0");
    expect(recoverSigner(offerDigest(p), alt).signer).toBe(a.address);
  });
  it("checksums addresses (EIP-55 vector)", () => {
    expect(toChecksumAddress("0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed")).toBe("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed");
  });
  it("rejects uint fields out of range / wrong types", () => {
    expect(() => offerDigest(offerPayload({ validUntil: -1 }))).toThrow();
    expect(() => offerDigest(offerPayload({ amount: 5 }))).toThrow();
    void NOW;
  });
});
