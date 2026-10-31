# arken-auth MCP example

An MCP server protected by arken-auth and an agent client using arken-client.

The agent has a `did:key` — no API key, no stored credential. Every request is signed and verified cryptographically.

## Run it

**Terminal 1 — start the MCP server**

```bash
npm install
node server.js
```

**Terminal 2 — run the agent**

```bash
node client.js
```

You'll see the agent's DID, then two authenticated tool calls: `time` and `echo`.

## How it works

1. Agent calls `/mcp/tools/time`
2. Server returns `401` with a one-time nonce
3. `arken-client` signs the nonce with the agent's private key
4. Agent retries with `Authorization: Signature did="...",nonce="...",signature="..."`
5. Server verifies the signature — no database, no session, nothing stored
6. `req.user.did` is set to the agent's DID

## Persistent agent identity

To give an agent a stable DID across restarts, persist its private key:

```bash
# First run — print the key
node -e "const { createClient } = require('arken-client'); const a = createClient(); console.log(a.privateKey);"

# Subsequent runs
AGENT_PRIVATE_KEY=0x... node client.js
```

## Redis nonce store (multi-instance)

For deployments behind a load balancer, pass a Redis client to `arkenAuth`:

```js
const { createClient: redisClient } = require('redis');
const { arkenAuth, RedisNonceStore } = require('@arkenforge/arken-auth');

const redis = redisClient({ url: process.env.REDIS_URL });
await redis.connect();

app.use('/mcp/tools', arkenAuth({ store: new RedisNonceStore(redis) }));
```
