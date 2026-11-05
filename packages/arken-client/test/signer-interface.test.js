'use strict';
// Signer interface tests — Phase 3, Item 10
//
// createClient currently only accepts a raw hex private key.
// The new signer interface lets callers inject an opaque signing function:
//
//   createClient({ did: 'did:key:z…', signer: async (msgBytes) => hexSig })
//
// This enables hardware wallets, KMS, MCP agents, and test harnesses that
// cannot expose the private key as a plain hex string.
//
// FAILING BEFORE THE FIX:
//   - "signer: createClient accepts { did, signer } object form"
//   - "signer: injected signer is called with Uint8Array of canonical message"
//   - "signer: { did, signer } form does not expose privateKey"
//   - "signer: missing did with signer throws synchronously"
//   - "signer: missing signer with did throws synchronously"
// All fail because createClient currently treats any object first arg as a
// private-key string and passes it to ethers.Wallet, which throws or behaves
// unexpectedly.

const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { createClient, buildSignedMessage } = require('../index.js');
const { ethers } = require('ethers');

// ── fixtures ──────────────────────────────────────────────────────────────────

// A real key pair so we can produce verifiable signatures in tests.
const TEST_KEY    = '0x' + 'ab'.repeat(32);
const testWallet  = new ethers.Wallet(TEST_KEY);
const TEST_DID    = (() => {
    // derive DID the same way walletToDidKey does (re-use the exported helper)
    const { walletToDidKey } = require('../index.js');
    return walletToDidKey(testWallet);
})();

/** An async signer backed by the test wallet — same as the built-in path. */
async function testSigner(msgBytes) {
    return testWallet.signMessage(msgBytes);
}

// ── fetch mock helpers ────────────────────────────────────────────────────────

let _origFetch;
before(() => { _origFetch = globalThis.fetch; });
after(()   => { globalThis.fetch = _origFetch; });

function mockChallenge(nonce = 'valid123', extra = {}) {
    const calls = { retryHeaders: null };
    globalThis.fetch = async (url, opts = {}) => {
        if (opts?.headers?.Authorization) {
            calls.retryHeaders = opts.headers;
            return { status: 200, json: async () => ({ ok: true }) };
        }
        return {
            status: 401,
            json: async () => ({
                challenge: { nonce, expires: 9_999_999_999, audience: 'localhost', ...extra },
            }),
            headers: { get: () => null },
        };
    };
    return calls;
}

// ── tests ─────────────────────────────────────────────────────────────────────

test('signer: createClient accepts { did, signer } object form', async () => {
    const calls = mockChallenge();
    const client = createClient({ did: TEST_DID, signer: testSigner });
    assert.strictEqual(client.did, TEST_DID, 'client.did must equal the provided DID');

    const res = await client.fetch('http://localhost:3000/protected');
    assert.strictEqual(res.status, 200, 'fetch must succeed via signer path');
    assert.ok(calls.retryHeaders?.Authorization?.includes(`did="${TEST_DID}"`),
        'Authorization header must contain the provided DID');
});

test('signer: injected signer is called with Uint8Array of canonical message', async () => {
    let signerArg = null;
    const capturingSigner = async (msgBytes) => {
        signerArg = msgBytes;
        return testWallet.signMessage(msgBytes);
    };

    mockChallenge('nonce99');
    const client = createClient({ did: TEST_DID, signer: capturingSigner });
    await client.fetch('http://localhost:3000/api');

    assert.ok(signerArg instanceof Uint8Array,
        'signer must receive a Uint8Array');

    // Verify the bytes decode to the expected canonical message.
    const decoded = Buffer.from(signerArg).toString('utf8');
    assert.ok(decoded.startsWith('arken-auth-v1\n'),
        'canonical message must start with arken-auth-v1');
    assert.ok(decoded.includes('nonce99'),
        'canonical message must include the nonce');
    assert.ok(decoded.includes('localhost'),
        'canonical message must include the host');
});

test('signer: { did, signer } form does not expose privateKey', () => {
    const client = createClient({ did: TEST_DID, signer: testSigner });
    assert.strictEqual(client.privateKey, undefined,
        'signer-form client must not expose a privateKey property');
});

test('signer: existing createClient(privateKey) form still works', async () => {
    // Regression guard — the old form must be unaffected.
    const calls = mockChallenge();
    const client = createClient(TEST_KEY);
    assert.ok(typeof client.did === 'string' && client.did.startsWith('did:key:z'),
        'old form must still return a valid DID');
    assert.ok(typeof client.privateKey === 'string',
        'old form must still expose privateKey');

    await client.fetch('http://localhost:3000/protected');
    assert.ok(calls.retryHeaders?.Authorization,
        'old form must still sign and retry');
});

test('signer: missing did with signer throws synchronously', () => {
    assert.throws(
        () => createClient({ signer: testSigner }),
        /did/i,
        'must throw with a helpful message when signer is provided without did'
    );
});

test('signer: missing signer with did throws synchronously', () => {
    assert.throws(
        () => createClient({ did: TEST_DID }),
        /signer/i,
        'must throw with a helpful message when did is provided without signer'
    );
});

test('signer: signer path respects nonce format validation', async () => {
    // The nonce guard (Item 6) must still fire even when using the signer path.
    let signerCalled = false;
    const guardedSigner = async (msgBytes) => { signerCalled = true; return '0xdead'; };

    mockChallenge('bad nonce!');  // space — invalid charset
    const client = createClient({ did: TEST_DID, signer: guardedSigner });
    const res = await client.fetch('http://localhost:3000/protected');

    assert.strictEqual(signerCalled, false,
        'signer must NOT be called when nonce fails format validation');
    assert.strictEqual(res.status, 401,
        'original 401 must be returned for invalid nonce');
});
