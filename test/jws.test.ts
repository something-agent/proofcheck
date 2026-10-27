import { describe, expect, it } from "vitest";
import { parseJws, pubKeyFromJwk, pubKeyFromMultibase, verifyJws } from "../src/jws";
import { resolveKid, didWebUrl } from "../src/did";
import { b64urlEncode, ed25519, makeJws, p256, secp256k1, json, stubFetch } from "./helpers";
import { base58Decode } from "../src/bytes";

const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
function b58(bytes: Uint8Array) { let n = 0n; for (const b of bytes) n = n * 256n + BigInt(b); let s = ""; while (n > 0n) { s = B58[Number(n % 58n)] + s; n /= 58n; } for (const b of bytes) { if (b === 0) s = "1" + s; else break; } return s; }

describe("JWS verification", () => {
  it("EdDSA via did:key", () => {
    const priv = ed25519.utils.randomPrivateKey(); const pub = ed25519.getPublicKey(priv);
    const mb = "z" + b58(new Uint8Array([0xed, 0x01, ...pub]));
    const jws = makeJws("EdDSA", `did:key:${mb}#k`, { version: 1 }, priv);
    expect(verifyJws(parseJws(jws), pubKeyFromMultibase(mb)).ok).toBe(true);
    const t = jws.slice(0, -4) + (jws.endsWith("AAAA") ? "BBBB" : "AAAA");
    expect(verifyJws(parseJws(t), pubKeyFromMultibase(mb)).ok).toBe(false);
  });
  it("ES256K and ES256 via JWK", () => {
    const k = secp256k1.utils.randomPrivateKey(); const pk = secp256k1.getPublicKey(k, false);
    const jwk = { kty: "EC", crv: "secp256k1", x: b64urlEncode(pk.slice(1, 33)), y: b64urlEncode(pk.slice(33)) };
    const key = pubKeyFromJwk(jwk);
    expect(key.evmAddress).toMatch(/^0x[0-9a-fA-F]{40}$/);
    expect(verifyJws(parseJws(makeJws("ES256K", "did:jwk:x", { a: 1 }, k)), key).ok).toBe(true);
    const k2 = p256.utils.randomPrivateKey(); const pk2 = p256.getPublicKey(k2, false);
    const key2 = pubKeyFromJwk({ kty: "EC", crv: "P-256", x: b64urlEncode(pk2.slice(1, 33)), y: b64urlEncode(pk2.slice(33)) });
    expect(verifyJws(parseJws(makeJws("ES256", "did:jwk:x", { a: 1 }, k2)), key2).ok).toBe(true);
  });
  it("alg/key mismatch and unsupported alg are rejected, not thrown", () => {
    const priv = ed25519.utils.randomPrivateKey();
    const key = pubKeyFromJwk({ kty: "OKP", crv: "Ed25519", x: b64urlEncode(ed25519.getPublicKey(priv)) });
    const bad = parseJws(makeJws("ES256K", "k", {}, secp256k1.utils.randomPrivateKey()));
    expect(verifyJws(bad, key).ok).toBe(false);
    const none = parseJws(makeJws("EdDSA", "k", {}, priv)); none.header.alg = "none";
    expect(verifyJws(none, key).reason).toMatch(/unsupported/);
  });
  it("parseJws rejects garbage", () => {
    expect(() => parseJws("a.b")).toThrow();
    expect(() => parseJws("!!.!!.!!")).toThrow();
  });
  it("base58 decode round-trips", () => { const b = new Uint8Array([0, 0, 1, 2, 255]); expect(Array.from(base58Decode(b58(b)))).toEqual(Array.from(b)); });
});

describe("kid resolution", () => {
  it("did:web url forms", () => {
    expect(didWebUrl("did:web:example.com").url).toBe("https://example.com/.well-known/did.json");
    expect(didWebUrl("did:web:example.com:a:b").url).toBe("https://example.com/a/b/did.json");
    expect(() => didWebUrl("did:web:exa mple.com")).toThrow();
  });
  it("did:web resolves keys and enforces id match", async () => {
    const pk = ed25519.getPublicKey(ed25519.utils.randomPrivateKey());
    const doc = { id: "did:web:svc.example", verificationMethod: [{ id: "did:web:svc.example#key-1", publicKeyJwk: { kty: "OKP", crv: "Ed25519", x: b64urlEncode(pk) } }] };
    const { f } = stubFetch([(u) => (u === "https://svc.example/.well-known/did.json" ? json(doc) : undefined)]);
    const r = await resolveKid("did:web:svc.example#key-1", f);
    expect(r.domain).toBe("svc.example"); expect(r.keys).toHaveLength(1);
    const { f: f2 } = stubFetch([() => json({ ...doc, id: "did:web:evil.example" })]);
    await expect(resolveKid("did:web:svc.example#key-1", f2)).rejects.toThrow(/does not match/);
    await expect(resolveKid("did:web:svc.example#nope", f)).rejects.toThrow(/no usable/);
  });
  it("unsupported kid", async () => { await expect(resolveKid("https://x/y")).rejects.toThrow(); });
});
