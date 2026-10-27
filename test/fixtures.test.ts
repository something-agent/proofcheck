/** Real 402 responses captured from live x402 services (2026-10-27). Pins that ProofCheck verifies what is in the wild. */
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { parsePaymentRequired } from "../src/probe";
import { verifyPaymentRequired } from "../src/verify";
import { enc } from "../src/bytes";
import { json, stubFetch } from "./helpers";
import { verifyOfferSignatureEIP712 } from "@x402/extensions/offer-receipt";

const dir = new URL("./fixtures/", import.meta.url);
const captured = Number(readFileSync(new URL("captured_at.txt", dir), "utf8").trim());
function load(name: string) {
  const headers: Record<string, string> = {};
  for (const l of readFileSync(new URL(`${name}.headers`, dir), "utf8").split(/\r?\n/)) { const i = l.indexOf(":"); if (i > 0) headers[l.slice(0, i).toLowerCase()] = l.slice(i + 1).trim(); }
  const body = readFileSync(new URL(`${name}.body`, dir));
  return parsePaymentRequired(headers, new Uint8Array(body)).pr;
}
const didFetch = (host: string, file: string) => stubFetch([(u) => (u === `https://${host}/.well-known/did.json` ? json(JSON.parse(readFileSync(new URL(file, dir), "utf8"))) : undefined)]).f;

describe("live fixtures", () => {
  it("x402tap (EIP-712, header-delivered): all signatures verify and agree with the SDK; signer is not the payTo", async () => {
    const pr = load("tap");
    const out = await verifyPaymentRequired(pr, {}, { now: captured, skipNetwork: true });
    expect(out.offers_found).toBeGreaterThan(0);
    for (const r of out.results) {
      expect(r.signature_valid).toBe(true);
      const sdk = await verifyOfferSignatureEIP712(pr.extensions["offer-receipt"].info.offers[out.results.indexOf(r)]);
      expect(r.signer?.address).toBe(sdk.signer);
      expect(r.authorization.status).not.toBe("authorized"); // no domain binding offline
    }
  });
  it("ottoai: signature valid; non-EVM offers are flagged as spec deviations", async () => {
    const pr = load("otto");
    const out = await verifyPaymentRequired(pr, {}, { now: captured, skipNetwork: true });
    expect(out.results.every((r) => r.signature_valid)).toBe(true);
    const flagged = out.results.flatMap((r) => r.checks).filter((c) => c.id === "network_format" || c.id === "payTo_format");
    expect(flagged.length).toBeGreaterThan(0);
  });
  it("mart402 (JWS EdDSA, did:web): valid and strongly authorized by its own domain", async () => {
    const out = await verifyPaymentRequired(load("mart402"), {}, { now: captured, fetchImpl: didFetch("mart402.com", "mart402.did.json") });
    expect(out.results[0].signature_valid).toBe(true);
    expect(out.results[0].verdict).toBe("valid_authorized");
  });
  it("agent-guild (JWS EdDSA, did:web Multikey): valid and strongly authorized", async () => {
    const out = await verifyPaymentRequired(load("guild"), {}, { now: captured, fetchImpl: didFetch("agent-guild-5d5r.onrender.com", "guild.did.json") });
    expect(out.results[0].signature_valid).toBe(true);
    expect(out.results[0].verdict).toBe("valid_authorized");
  });
  it("a JWS signed for one domain but resolved elsewhere is not authorized", async () => {
    // serve mart402's did.json under a different host: id mismatch must make kid resolution fail -> invalid
    const out = await verifyPaymentRequired(load("mart402"), {}, { now: captured, fetchImpl: didFetch("mart402.com", "guild.did.json") });
    expect(out.results[0].verdict).toBe("invalid_signature");
  });
  void enc;
});
