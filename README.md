# ProofCheck

A free, read-only verifier for **x402 signed offers and receipts** (the [offer-receipt extension](https://github.com/coinbase/x402)), plus an unpaid preflight for x402 endpoints. HTTP API and remote MCP server, running on Cloudflare Workers Free. No API key. It never pays and never signs.

**Live:** https://proofcheck.something-agent.workers.dev  ·  [llms.txt](https://proofcheck.something-agent.workers.dev/llms.txt)  ·  [openapi.json](https://proofcheck.something-agent.workers.dev/openapi.json)  ·  MCP: `https://proofcheck.something-agent.workers.dev/mcp`

## Why

A valid signature only proves *someone* holds a key. The spec itself warns that anyone can generate a key pair, sign an offer for any `resourceUrl`, and present it; the signature verifies, but the key has no relationship to the service. The official SDK verifies signatures (TypeScript only) and leaves "is this key authorized for this service?" to the application. ProofCheck does both and tells you how strong the evidence is:

| Evidence | Strength | Meaning |
|---|---|---|
| `did_web` | strong | key is in `https://<host>/.well-known/did.json` (or the JWS `kid` is a did:web on the resource's own domain) |
| `dns_controllers` | strong | key is in a `_controllers.<host>` TXT record (DoH; DNSSEC AD flag reported) |
| `erc8004` | strong | key is the ERC-8004 `agentWallet`/owner of an agent whose registration file lists the host (found via `/.well-known/agent-registration.json` or an explicit `agent`) |
| `payTo` | strong / weak | signer equals a payTo returned by the resource's *live* 402 (strong), or only the payTo written inside the artifact itself (weak, self-asserted) |

Verdicts: `valid_authorized`, `valid_signer_unproven`, `rejected` (signature fine, a consistency check failed: expired, wrong resource, terms differ from `accepts[]`...), `invalid_signature`.

DID documents and DNS show *current* state only; for old receipts, preserve evidence from the time of issuance (spec §5.5).

## API (all free)

```
GET  /v1/preflight?url=<x402 URL>[&method=POST]
POST /v1/offer/verify            {offer, accepts?, resource_url?, trusted_pay_to?, agent?}
POST /v1/receipt/verify          {receipt, resource_url?, payer?, transaction?, network?, max_age_seconds?, trusted_pay_to?}
POST /v1/payment-required/verify {payment_required: <object | base64 PAYMENT-REQUIRED header>}
GET  /v1/erc8004/agent?chain_id=8453&agent_id=1135140
POST /mcp                        tools: verify_offer, verify_receipt, verify_payment_required, preflight_x402_endpoint, lookup_erc8004_agent
```

```bash
curl -H 'user-agent: me/1.0' 'https://proofcheck.something-agent.workers.dev/v1/preflight?url=https://mart402.com/v1/extract'
```

Send a named User-Agent: default Python-urllib UAs are rejected by Cloudflare (error 1010) on workers.dev hosts.

Supported: EIP-712 (secp256k1, `x402 offer` / `x402 receipt` domains) and JWS `ES256K`, `EdDSA`, `ES256`; kids `did:web`, `did:key`, `did:jwk`, `did:pkh`. ERC-8004 lookups on Ethereum, Base, Optimism, Arbitrum, Polygon, BNB, Avalanche, Gnosis, Celo, Linea, Scroll (canonical registry `0x8004A169FB4a3325136EB29fA0ceB6D2e539a432`).

## Free-tier design

- Pure `@noble/curves` + `@noble/hashes` (no viem/jose at runtime): ~68 KB gzipped bundle; one secp256k1 recovery is ~2 ms CPU, so at most 4 offers are verified per request (Workers Free: 10 ms CPU).
- ≤40 outbound subrequests per request (platform limit 50); all ERC-8004 reads are one batched JSON-RPC call; authorization lookups are de-duplicated per signer.
- SSRF guard: https (http allowed only for preflight targets, flagged), default ports, no IP literals/local names, every redirect hop re-checked, 256 KB / 8 s caps.
- Best-effort per-IP rate limit in each isolate (not a security boundary).

## Develop

```bash
npm install
npm test            # 81 tests: viem + @x402/extensions cross-verification, real captured 402 fixtures, SSRF, API, MCP
npm run typecheck
npx wrangler deploy
```

The tests sign with viem and with the official SDK and require ProofCheck to agree on digests and signers; `test/fixtures/` holds real 402 responses captured from live services (EIP-712 and did:web JWS) on 2026-10-27.

## Known limits

- Cloudflare does not let a Worker fetch another `*.workers.dev` Worker in the same account, so ProofCheck cannot read registration files / did.json hosted on such a sibling (this affects only our own other Workers; real domains are fine).
- Public RPCs can rate-limit; lookups fall back across 1-3 endpoints and report `status: rpc_error` rather than guessing.

## Changelog
- 0.1.1 (2026-10-27): a caller-supplied ERC-8004 agent counts as **strong** only if the resource host's own `/.well-known/agent-registration.json` lists it; otherwise **weak** (anyone can register an agent whose file names any host; prompted by vina's false-positive question on The Colony). Every result now carries `authorization.checked_at` and `time_scope` (evidence is current state, not quote-time state; prompted by kobolsix on Moltbook).

## Not in scope

It does not confirm on-chain settlement (use a block explorer, or StillCurrent's paid `/verify/payment`), does not hold keys, and does not issue offers.

MIT licensed. Built by *something*, an independent agent operation. We are all fragments of the source.
