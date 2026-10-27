import { describe, expect, it } from "vitest";
import { assertPublicUrl, safeFetch } from "../src/safe";
import { stubFetch } from "./helpers";

describe("SSRF guard", () => {
  const bad = ["http://example.com", "https://localhost/x", "https://127.0.0.1/", "https://10.0.0.1/", "https://169.254.169.254/latest", "https://[::1]/", "https://example.com:8443/", "https://user:pw@example.com/", "https://2130706433/", "https://intranet/", "https://foo.internal/", "https://0x7f.1/", "file:///etc/passwd", "ftp://example.com", "not a url", "https://192.168.1.1/", "https://example.com.local/"];
  for (const u of bad) it(`blocks ${u}`, () => expect(() => assertPublicUrl(u)).toThrow());
  it("allows plain public https", () => expect(assertPublicUrl("https://api.example.com/x?y=1").hostname).toBe("api.example.com"));
  it("allows http only when asked", () => { expect(() => assertPublicUrl("http://api.example.com")).toThrow(); expect(assertPublicUrl("http://api.example.com", true).protocol).toBe("http:"); });
  it("re-checks redirect targets", async () => {
    const { f } = stubFetch([(u) => (u === "https://a.example.com/" ? new Response(null, { status: 302, headers: { location: "https://169.254.169.254/" } }) : undefined)]);
    await expect(safeFetch("https://a.example.com/", { fetchImpl: f })).rejects.toThrow(/non-public|IP-literal/);
  });
  it("follows safe redirects, caps redirects and size", async () => {
    const { f } = stubFetch([(u) => (u === "https://a.example.com/" ? new Response(null, { status: 301, headers: { location: "/b" } }) : u === "https://a.example.com/b" ? new Response("x".repeat(1000)) : undefined)]);
    const r = await safeFetch("https://a.example.com/", { fetchImpl: f, maxBytes: 100 });
    expect(r.redirects).toEqual(["https://a.example.com/b"]); expect(r.body.length).toBe(100); expect(r.truncated).toBe(true);
    const loop = stubFetch([(u) => new Response(null, { status: 302, headers: { location: u } })]);
    await expect(safeFetch("https://a.example.com/", { fetchImpl: loop.f })).rejects.toThrow(/too many/);
  });
});
