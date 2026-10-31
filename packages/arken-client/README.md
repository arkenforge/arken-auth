# arken-client

<p align="center">
  Drop-in <code>fetch</code> that handles the <a href="https://github.com/ArkenForge/arken-protocol">arken-auth</a> challenge-response flow automatically.
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/arken-client"><img src="https://img.shields.io/npm/v/arken-client.svg" alt="npm version"></a>
  <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License: MIT"></a>
</p>

<p align="center">
  <a href="https://github.com/ArkenForge/arken-docs/blob/main/arken-auth/mcp-quickstart.md">MCP Quickstart</a> ·
  <a href="https://github.com/ArkenForge/arken-docs/blob/main/arken-auth/testing.md">Testing Guide</a>
</p>

---

## Install

```bash
npm install arken-client
```

---

## Usage

```js
const { createClient } = require('arken-client');

const { fetch, did } = await createClient();
// generates a secp256k1 key pair if none is provided
// `did` is the did:key identifier for this client

const res = await fetch('https://api.example.com/protected');
// automatically handles 401 → sign nonce → retry
console.log(await res.json()); // { did: "did:key:zQ3s…" }
```

Works with any server running [`@arkenforge/arken-auth`](https://www.npmjs.com/package/@arkenforge/arken-auth).

---

## Bring your own key

```js
const { createClient } = require('arken-client');

// persist this key — it's the agent's long-term identity
const privateKey = process.env.AGENT_PRIVATE_KEY;

const { fetch, did } = await createClient(privateKey);
console.log(did); // did:key:zQ3s… — deterministic from the key
```

If no key is provided, a new one is generated on each call. For agents that need a stable identity, generate once, store the private key, and reuse it.

---

## How it works

1. Makes the request normally
2. If the response is `401` with a `{ challenge: { nonce } }` body, signs the nonce with the private key using `eth_sign`
3. Retries the original request with `Authorization: Signature did="…",nonce="…",signature="…"`
4. Returns the final response — caller never sees the 401

---

## Python

For Python agents, see [arken-client on PyPI](https://pypi.org/project/arken-client/).

---

## License

[MIT](../../LICENSE) — Arken Protocol
