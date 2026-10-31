# @arkenforge/arken-auth

<p align="center">
  Passwordless auth middleware for Express. No passwords, no sessions, no user database to breach.
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/@arkenforge/arken-auth"><img src="https://img.shields.io/npm/v/@arkenforge/arken-auth.svg" alt="npm version"></a>
  <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License: MIT"></a>
</p>

<p align="center">
  <a href="https://github.com/ArkenForge/arken-docs/tree/main/arken-auth">Docs</a> ·
  <a href="https://github.com/ArkenForge/arken-docs/blob/main/arken-auth/mcp-quickstart.md">MCP Quickstart</a> ·
  <a href="https://github.com/ArkenForge/arken-docs/blob/main/arken-auth/how-it-works.md">How It Works</a> ·
  <a href="https://github.com/ArkenForge/arken-docs/blob/main/arken-auth/production.md">Production</a>
</p>

---

## Install

```bash
npm install @arkenforge/arken-auth
```

No Rust required — prebuilt native binaries are downloaded automatically for your platform.

---

## Protect a route

```js
const express = require('express');
const { arkenAuth } = require('@arkenforge/arken-auth');

const app = express();

app.get('/protected', arkenAuth(), (req, res) => {
  res.json({ did: req.user.did });
});

app.listen(3000);
```

That's it. An unsigned request gets a `401` with a one-time nonce. The client signs the nonce with its private key and retries with an `Authorization: Signature` header. The middleware verifies the signature cryptographically and sets `req.user.did` — no database lookup, no session, nothing stored.

---

## Options

```js
arkenAuth({
  statement: 'Sign to access the API.',  // shown to the user during signing; optional
  store: new RedisNonceStore(redisClient) // multi-instance deployments; optional
})
```

---

## Use arken-client on the client side

[arken-client](https://www.npmjs.com/package/arken-client) is a drop-in `fetch` replacement that handles the full challenge-response flow automatically:

```js
const { createClient } = require('arken-client');

const { fetch, did } = await createClient(); // generates a key pair if none provided

const res = await fetch('http://localhost:3000/protected');
// handled the 401 → sign → retry automatically
console.log(await res.json()); // { did: "did:key:zQ3s…" }
```

---

## Multi-instance deployments (Redis)

By default nonces are stored in memory and won't work across multiple server instances. Pass a Redis client to share nonce state:

```js
const { createClient: createRedis } = require('redis');
const { arkenAuth, RedisNonceStore } = require('@arkenforge/arken-auth');

const redis = createRedis({ url: process.env.REDIS_URL });
await redis.connect();

app.use('/protected', arkenAuth({ store: new RedisNonceStore(redis) }));
```

---

## How it works

```
Client                              Server
  │                                   │
  │── GET /protected ─────────────────▶│
  │                                   │ generate nonce, store with 60s TTL
  │◀── 401 { challenge: { nonce } } ──│
  │                                   │
  │  sign(nonce, privateKey)          │
  │                                   │
  │── GET /protected ─────────────────▶│
  │   Authorization: Signature         │ verify ECDSA signature
  │   did="…",nonce="…",sig="…"       │ consume nonce (single-use)
  │                                   │ set req.user.did
  │◀── 200 { did: "did:key:zQ3s…" } ──│
```

1. Server issues a random nonce on `401` — stored in memory (or Redis) with a 60-second TTL
2. Client signs the nonce with its secp256k1 private key using the Ethereum personal sign scheme
3. Server verifies the ECDSA signature in Rust via [ethers-rs](https://github.com/gakonst/ethers-rs) — no credentials stored, nonce consumed

---

## Security model

| | |
|---|---|
| **No passwords** | Nothing to phish, crack, or reuse across sites |
| **No sessions** | No cookies, no JWTs, no server-side token store |
| **No user database** | Nothing to breach — the server forgets after each request |
| **Single-use nonces** | Replay attacks are blocked; nonces expire after 60 seconds |
| **Rust crypto core** | Signature verification uses [k256](https://github.com/RustCrypto/elliptic-curves) — audited, constant-time |

---

## Identity: `did:key`

Each client is identified by a [W3C DID Key](https://w3c-ccg.github.io/did-method-key/) — a self-describing string derived from their public key:

```
did:key:zQ3shXgnkuyqVxf3NGBsK1q3J…
```

No registration. No central authority. The DID is derived from the key pair and authenticates to any server running `@arkenforge/arken-auth`.

---

## Exports

```js
const {
  arkenAuth,       // Express middleware factory
  ArkenCore,       // direct FFI access to the Rust crypto core
  MemoryNonceStore,// default in-process nonce store
  RedisNonceStore, // Redis-backed nonce store for multi-instance
} = require('@arkenforge/arken-auth');
```

---

## Python

For FastAPI, see [arken-auth on PyPI](https://pypi.org/project/arken-auth/).

---

## License

[MIT](../../LICENSE) — Arken Protocol
