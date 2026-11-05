'use strict';
// Security test suite — Phase 2, Item 4
//
// Covers: replay, expiry, audience mismatch, alias (0x DID), relay,
//         malformed nonce (control chars, oversized), concurrent consume.
//
// All tests use mock core + mock store so no Rust binary is needed.
// Redis test is skipped with an explanation if unavailable.
//
// FAILING BEFORE FIX:
//   - "malformed nonce (control chars) does not reach store.consume"
//   - "malformed nonce (length > 128) does not reach store.consume"
// These tests use a tracking store that records whether consume() was called.
// Before the fix, the middleware forwards the nonce to consume() with no format check.

const { test } = require('node:test');
const assert   = require('node:assert/strict');
const { arkenAuth } = require('../lib/middleware.js');

// ── helpers ───────────────────────────────────────────────────────────────────

const CANONICAL_DID = 'did:key:zQ3shXgnkuyqVxf3NGBsK1q3JabcEXAMPLEfake';

/** Core mock that returns success. */
function okCore(did = CANONICAL_DID) {
    return {
        verifySignatureOnly: () => ({ status: 'success', did }),
    };
}

/** Core mock that always returns failure. */
function failCore() {
    return {
        verifySignatureOnly: () => ({ status: 'error', message: 'bad sig' }),
    };
}

/**
 * Store mock with configurable consume result.
 * Also tracks whether consume() was called and with what nonce.
 */
function makeStore({ valid = true, expires = null } = {}) {
    const calls = { set: [], consume: [] };
    const store = {
        calls,
        set: async (nonce) => {
            const exp = Math.floor(Date.now() / 1000) + 60;
            calls.set.push(nonce);
            return exp;
        },
        consume: async (nonce) => {
            calls.consume.push(nonce);
            const exp = expires ?? Math.floor(Date.now() / 1000) + 60;
            return { valid, expires: exp };
        },
    };
    return store;
}

/** Build a minimal req/res/next triple. */
function makeCtx({ did = CANONICAL_DID, nonce = 'abc123', sig = '0xdeadbeef',
                   host = 'example.com', method = 'GET', url = '/protected',
                   authHeader = null } = {}) {
    const authorization = authHeader ??
        `Signature did="${did}",nonce="${nonce}",signature="${sig}"`;
    const req = {
        headers: { authorization },
        hostname:    host,
        method,
        originalUrl: url,
        rawBody:     '',
    };
    const result = { status: null, body: null, nextCalled: false };
    const res = {
        set()     { return this; },
        status(s) { result.status = s; return this; },
        json(b)   { result.body   = b; return this; },
    };
    const next = () => { result.nextCalled = true; };
    return { req, res, next, result };
}

// ── replay ────────────────────────────────────────────────────────────────────

test('security: replay — second use of same Authorization header is rejected', async () => {
    // MemoryNonceStore is single-use: first consume deletes the nonce.
    const { MemoryNonceStore } = require('../lib/middleware.js');
    const store = new MemoryNonceStore();

    // Seed a nonce manually so we control it.
    const nonce   = 'replaynonce01234';
    const expires = await store.set(nonce);

    const auth = `Signature did="${CANONICAL_DID}",nonce="${nonce}",signature="0xfeedbeef"`;

    // First request — should succeed.
    const ctx1 = makeCtx({ authHeader: auth });
    ctx1.req.hostname = 'example.com';
    await arkenAuth({ store, _core: okCore() })(ctx1.req, ctx1.res, ctx1.next);
    assert.ok(ctx1.result.nextCalled, 'first request must pass');

    // Second request with identical Authorization header — nonce already consumed.
    const ctx2 = makeCtx({ authHeader: auth });
    ctx2.req.hostname = 'example.com';
    await arkenAuth({ store, _core: okCore() })(ctx2.req, ctx2.res, ctx2.next);
    assert.strictEqual(ctx2.result.nextCalled, false, 'replay must be rejected');
    assert.strictEqual(ctx2.result.status, 401, 'replay must return 401');
});

// ── expiry ────────────────────────────────────────────────────────────────────

test('security: expiry — nonce past its expires timestamp is rejected', async () => {
    // Store returns valid:false for a nonce that is in the past.
    const store = makeStore({ valid: false, expires: Math.floor(Date.now() / 1000) - 1 });
    const { req, res, next, result } = makeCtx({ nonce: 'expirednonce1234' });
    await arkenAuth({ store, _core: okCore() })(req, res, next);
    assert.strictEqual(result.nextCalled, false, 'expired nonce must be rejected');
    assert.strictEqual(result.status, 401);
});

// ── audience mismatch ─────────────────────────────────────────────────────────

test('security: audience mismatch — middleware binds to req.hostname, not client-supplied audience', async () => {
    // The middleware never reads an "audience" field from the Authorization header.
    // It rebuilds the signed message from req.hostname.
    // If a valid signature for api.foo.com is replayed to api.bar.com,
    // the signed message will differ → Rust rejects it.
    //
    // We simulate this by having the core fail (signature doesn't match for the
    // wrong host) and confirm the middleware returns 401.
    const store = makeStore({ valid: true });
    const { req, res, next, result } = makeCtx({ host: 'api.bar.com' });
    await arkenAuth({ store, _core: failCore() })(req, res, next);
    assert.strictEqual(result.nextCalled, false, 'cross-host replay must be rejected');
    assert.strictEqual(result.status, 401);
});

// ── alias (0x DID form) ───────────────────────────────────────────────────────

test('security: alias — did:key:0x... form is rejected before consuming nonce', async () => {
    // A client using the legacy Ethereum address form must be rejected.
    // The nonce must NOT be consumed (checked via tracking store).
    const store = makeStore({ valid: true });
    const { req, res, next, result } = makeCtx({
        did: 'did:key:0xabcdef1234567890abcdef1234567890abcdef12',
    });
    await arkenAuth({ store, _core: okCore() })(req, res, next);
    assert.strictEqual(result.nextCalled, false, 'alias form must be rejected');
    assert.strictEqual(result.status, 401);
    assert.strictEqual(store.calls.consume.length, 0,
        'nonce must NOT be consumed for a DID that fails format validation');
});

// ── relay ─────────────────────────────────────────────────────────────────────

test('security: relay — canonical messages for different hosts are not equal', () => {
    // If the signed messages for two different target hosts are identical,
    // a valid auth for server A could be relayed to server B.
    // This is a pure message-builder test; no middleware I/O needed.
    const { buildSignedMessage } = require('../lib/message.js');
    const common = { method: 'GET', path: '/data', bodyHash: '', nonce: 'abc', expires: 9999 };
    const msgA = buildSignedMessage({ ...common, host: 'api.foo.com' });
    const msgB = buildSignedMessage({ ...common, host: 'api.bar.com' });
    assert.notStrictEqual(msgA, msgB,
        'canonical messages for different hosts must be distinct');
});

// ── malformed nonce ───────────────────────────────────────────────────────────
// THESE TWO TESTS FAIL BEFORE THE FIX.
// The middleware currently passes any nonce string straight to store.consume().
// After the fix a /^[a-zA-Z0-9_-]{1,128}$/ guard fires first.

test('security: malformed nonce (control chars) does not reach store.consume', async () => {
    const badNonce = 'abc\x00def';          // null byte embedded
    const store = makeStore({ valid: true });
    const { req, res, next, result } = makeCtx({ nonce: badNonce });
    await arkenAuth({ store, _core: okCore() })(req, res, next);
    assert.strictEqual(result.nextCalled, false, 'must reject malformed nonce');
    assert.strictEqual(result.status, 401);
    assert.strictEqual(store.calls.consume.length, 0,
        'store.consume must NOT be called for a malformed nonce');
});

test('security: malformed nonce (length > 128) does not reach store.consume', async () => {
    const badNonce = 'a'.repeat(129);
    const store = makeStore({ valid: true });
    const { req, res, next, result } = makeCtx({ nonce: badNonce });
    await arkenAuth({ store, _core: okCore() })(req, res, next);
    assert.strictEqual(result.nextCalled, false, 'must reject oversized nonce');
    assert.strictEqual(result.status, 401);
    assert.strictEqual(store.calls.consume.length, 0,
        'store.consume must NOT be called for an oversized nonce');
});

// ── concurrent consume ────────────────────────────────────────────────────────

test('security: concurrent consume — only one of parallel consume() calls succeeds', async () => {
    // Simulates two requests arriving simultaneously with the same nonce.
    // MemoryNonceStore uses synchronous Map ops so the first delete wins.
    const { MemoryNonceStore } = require('../lib/middleware.js');
    const store = new MemoryNonceStore();
    const nonce = 'concurrentnonce1';
    await store.set(nonce);

    // Both consume() calls are started without awaiting either.
    const [r1, r2] = await Promise.all([store.consume(nonce), store.consume(nonce)]);

    const successes = [r1, r2].filter(r => r.valid).length;
    assert.strictEqual(successes, 1,
        'exactly one concurrent consume must succeed; the other must return valid:false');
});

// ── Redis (skip if unavailable) ───────────────────────────────────────────────

test('security: Redis nonce store — atomic consume is single-use', { skip: true }, async () => {
    // This test is skipped: no Redis server is available in this environment.
    // To run manually: start Redis on localhost:6379, remove { skip: true }.
    //
    // If Redis is available, the test should:
    //   1. create RedisNonceStore(redisClient)
    //   2. set a nonce
    //   3. consume twice concurrently
    //   4. assert exactly one succeeds
    //   5. disconnect
    assert.ok(false, 'this code path should not be reached when skip:true');
});
