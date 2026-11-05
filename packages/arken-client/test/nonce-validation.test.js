'use strict';
// Client-side nonce validation tests — Phase 2, Item 6
//
// The client receives a nonce from the server's 401 challenge.
// Before signing it must validate the nonce format:
//   /^[a-zA-Z0-9_-]{1,128}$/
// If validation fails the client must return the original 401 unchanged —
// it must NEVER sign a suspicious nonce.
//
// FAILING BEFORE THE FIX:
//   - "client: refuses to sign nonce with control characters"
//   - "client: refuses to sign nonce longer than 128 chars"
//   Both tests assert retried === false, but before the fix the client signs
//   any non-empty nonce without a format check.

const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { createClient } = require('../index.js');

const TEST_KEY = '0x' + 'ab'.repeat(32);

// ── helpers ───────────────────────────────────────────────────────────────────

let _origFetch;
before(() => { _origFetch = globalThis.fetch; });
after(()   => { globalThis.fetch = _origFetch; });

/**
 * Install a fetch mock that returns a 401 challenge on the first call and
 * tracks whether a second (signed) call was made.
 */
function mockChallenge(nonce) {
    let retried = false;
    globalThis.fetch = async (url, opts = {}) => {
        if (opts?.headers?.Authorization) {
            retried = true;
            return { status: 200, json: async () => ({ ok: true }) };
        }
        return {
            status: 401,
            json: async () => ({
                challenge: { nonce, expires: 9_999_999_999, audience: 'localhost' },
            }),
            headers: { get: () => null },
        };
    };
    return () => retried;
}

// ── baseline — valid nonce is signed ─────────────────────────────────────────

test('client: signs a valid nonce (baseline)', async () => {
    const wasRetried = mockChallenge('abc123_-XYZ');
    const client = createClient(TEST_KEY);
    const res = await client.fetch('http://localhost:3000/protected');
    assert.ok(wasRetried(), 'client must sign a valid nonce and retry');
    assert.strictEqual(res.status, 200);
});

// ── malformed nonces — must NOT sign ─────────────────────────────────────────

test('client: refuses to sign nonce with control characters', async () => {
    const wasRetried = mockChallenge('abc\x00def');   // null byte
    const client = createClient(TEST_KEY);
    const res = await client.fetch('http://localhost:3000/protected');
    assert.strictEqual(wasRetried(), false,
        'client must NOT sign a nonce containing control characters');
    assert.strictEqual(res.status, 401,
        'original 401 must be returned when nonce is malformed');
});

test('client: refuses to sign nonce longer than 128 chars', async () => {
    const wasRetried = mockChallenge('a'.repeat(129));
    const client = createClient(TEST_KEY);
    const res = await client.fetch('http://localhost:3000/protected');
    assert.strictEqual(wasRetried(), false,
        'client must NOT sign an oversized nonce');
    assert.strictEqual(res.status, 401,
        'original 401 must be returned when nonce is oversized');
});

test('client: refuses to sign nonce with space character', async () => {
    const wasRetried = mockChallenge('nonce with space');
    const client = createClient(TEST_KEY);
    const res = await client.fetch('http://localhost:3000/protected');
    assert.strictEqual(wasRetried(), false,
        'client must NOT sign a nonce containing a space');
    assert.strictEqual(res.status, 401);
});

test('client: accepts nonce of exactly 128 chars', async () => {
    const wasRetried = mockChallenge('a'.repeat(128));
    const client = createClient(TEST_KEY);
    const res = await client.fetch('http://localhost:3000/protected');
    assert.ok(wasRetried(), 'nonce of exactly 128 chars is valid and must be signed');
    assert.strictEqual(res.status, 200);
});
