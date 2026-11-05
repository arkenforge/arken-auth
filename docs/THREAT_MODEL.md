# arken-auth Threat Model

STRIDE analysis for the arken-auth challenge-response authentication protocol.
Pre-1.0 · last updated 2026-11-04

---

## Protocol summary

```
Client                            Server
  │                                  │
  │  GET /protected                  │
  │ ─────────────────────────────► │
  │                                  │
  │  401  { challenge: {             │
  │           nonce,                 │
  │           expires,               │
  │           audience,              │
  │           statement } }          │
  │ ◄─────────────────────────────  │
  │                                  │
  │  GET /protected                  │
  │  Authorization: Signature        │
  │    did="did:key:z...",           │
  │    nonce="…",                    │
  │    signature="…"                 │
  │ ─────────────────────────────► │
  │                                  │
  │  200 OK  (req.user.did set)      │
  │ ◄─────────────────────────────  │
```

The signed payload is a canonical 7-line string:

```
arken-auth-v1
{host}
{METHOD}
{path?query}
{sha256(body) | ""}
{nonce}
{expires}
```

The server rebuilds this from actual request fields — never from Authorization header values.

---

## STRIDE analysis

### Spoofing

**Threat:** An attacker impersonates a legitimate DID holder.

**Mitigations:**
- The private key never leaves the client. The server only receives a signature.
- Signatures are verified against the public key embedded in the DID (`did:key:z…`).
- The signed message binds to the nonce, expiry, host, method, path, and body hash — a valid signature for one specific request is useless for any other.
- DID canonicalization ensures one key maps to exactly one DID string; the `0x` alias form is rejected.

**Residual risk:** Client-side key compromise. No revocation mechanism exists in v0.x — see open decisions.

---

### Tampering

**Threat:** An attacker modifies the request in transit (body, path, method, host).

**Mitigations:**
- The canonical signed message includes `sha256(body)`, `METHOD`, `path?query`, and `host`.
- The server always reconstructs the message from actual `req.hostname`, `req.method`, `req.originalUrl`, and `req.rawBody` — never from client-provided fields in the Authorization header.
- Any modification to these fields produces a different signed message, causing ECDSA verification to fail.

**Residual risk:** Body hash is `""` for empty bodies. If a middleware strips the body before arken-auth runs, tampering is undetectable. Ensure `rawBody` is captured before body-parsing middleware.

---

### Repudiation

**Threat:** A user denies having made a request they authenticated.

**Mitigations:**
- The ECDSA signature over the canonical message constitutes cryptographic proof of key possession at the time of the request.
- The nonce is single-use; the timestamp is embedded; the full request target is bound.

**Residual risk:** No server-side audit log is kept by this library. Applications that require non-repudiation must log `req.user.did` alongside the full request.

---

### Information Disclosure

**Threat:** Sensitive data is leaked via the protocol or its error messages.

**Mitigations:**
- The server never receives a private key.
- Error responses (`401`) reveal only that authentication failed; they do not confirm whether a DID exists in any registry.
- Nonces are random (`crypto.randomBytes(16)` / `secrets.token_hex(16)`); they reveal no information about server state.

**Residual risk:** The DID itself (`did:key:z…`) is transmitted in plaintext in the Authorization header. Over TLS this is encrypted in transit; at rest, logging middleware may capture it.

---

### Denial of Service

#### Nonce store exhaustion

**Threat:** An attacker floods the endpoint with unauthenticated requests to fill the nonce store.

**Mitigations (partial — see open items):**
- Nonces expire after 60 seconds; MemoryNonceStore sweeps expired entries on every `set()`.
- Item 7 (rate limiting) is planned but not yet implemented.

**Residual risk:** Until rate limiting is in place, a high-volume attacker can cause unbounded memory growth on a single-instance deployment.

#### Malformed nonce injection

**Threat:** An attacker submits a crafted `nonce` value containing control characters or pathological length to cause unexpected store behaviour or regex DoS.

**Mitigation:**
- The nonce extracted from the Authorization header is validated against `/^[a-zA-Z0-9_-]{1,128}$/` before `store.consume()` is called.
- Malformed nonces are rejected with `401` before touching the store.

#### Oversized requests

**Threat:** Large bodies cause hash computation to block the event loop.

**Residual risk:** No body-size limit is enforced by this library. Use `express.json({ limit: '…' })` or equivalent upstream.

---

### Elevation of Privilege

**Threat:** An authenticated user gains access beyond their DID's authorisation level.

**Mitigations:**
- arken-auth authenticates identity only; it does not perform authorisation.
- `req.user.did` is set to the canonical DID returned by the Rust verifier, not to the raw value from the client's Authorization header. Callers cannot inject an arbitrary DID.

**Residual risk:** Authorisation policy (which DIDs may access which routes) is the application's responsibility. arken-auth makes no claims about it.

---

## Named attacks and countermeasures

| Attack | Description | Countermeasure | Test |
|---|---|---|---|
| **Replay** | Reuse a captured Authorization header | Nonce is single-use; `store.consume()` deletes on first use | `security.test.js` — replay |
| **Expiry** | Submit an Authorization header after the nonce TTL | `consume()` checks `now < expires`; expired nonces return `valid: false` | `security.test.js` — expiry |
| **Cross-host relay** | Valid auth for server A submitted to server B | Signed message includes `host`; server rebuilds from `req.hostname` | `security.test.js` — audience mismatch, relay |
| **DID alias** | Submit `did:key:0x…` Ethereum address form | Middleware rejects non-`z`-prefix DIDs before consuming nonce | `security.test.js` — alias; `did-canonicalization.test.js` |
| **Malformed nonce** | Nonce with control chars or length > 128 | Format guard `/^[a-zA-Z0-9_-]{1,128}$/` fires before `consume()` | `security.test.js` — malformed nonce |
| **Concurrent consume** | Two simultaneous requests with the same nonce | `MemoryNonceStore` uses synchronous `Map.delete`; first delete wins | `security.test.js` — concurrent consume |

---

## Out of scope (pre-1.0)

- **Key revocation** — no revocation list; a compromised key remains valid until rotated by the application.
- **Key rotation** — no rotation protocol.
- **Session / token exchange** — each request is independently authenticated; no session handshake.
- **DID resolution** — only `did:key` is supported; no network lookup.
- **Multi-factor / step-up** — not addressed.

---

## Open decisions

The following items require a design decision before they can be specified:

1. **Lane A vs Lane B** — retain secp256k1/ethers or migrate to Ed25519 + RFC 9421 HTTP Signatures?
2. **Rate limiting strategy** — in-middleware token bucket, external Redis limiter, or rely on upstream reverse proxy?
3. **Revocation** — on-chain registry, centralised blocklist, or short-lived tokens?
4. **Session handshake** — issue a short-lived JWT after a401 success, or stay stateless per-request?

---

## Security contact

Report vulnerabilities to the advisory tracker at
<https://github.com/arkenforge/arken-auth/security/advisories>
