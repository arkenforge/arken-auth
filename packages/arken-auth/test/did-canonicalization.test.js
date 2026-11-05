'use strict';
// DID canonicalization tests — Phase 1, Item 2
//
// Tests in this file use a mock _core so they run without the native Rust lib.
//
// BEFORE THE FIX the middleware forwards 0x-form DIDs to the core and accepts
// whatever it returns.  After the fix the middleware rejects them with 401
// before calling the core.

const { test } = require('node:test');
const assert   = require('node:assert/strict');
const { arkenAuth } = require('../lib/middleware.js');

// ── helpers ───────────────────────────────────────────────────────────────────

const CANONICAL_DID = 'did:key:zQ3shXgnkuyqVxf3NGBsK1q3JabcEXAMPLEfake';

/** A core mock that always succeeds and returns whatever DID is passed in. */
function coreThatAcceptsAll(did = CANONICAL_DID) {
    return {
        verifySignatureOnly: () => ({
            status: 'success',
            did,
            nonce: 'testnonce',
        }),
    };
}

/** A nonce store mock that always considers the nonce valid. */
function validStore() {
    return {
        set:     async () => Math.floor(Date.now() / 1000) + 60,
        consume: async () => ({ valid: true, expires: Math.floor(Date.now() / 1000) + 60 }),
    };
}

/** Minimal Express-compatible req/res/next objects. */
function makeCtx(did, nonce = 'testnonce') {
    const req = {
        headers: {
            authorization: `Signature did="${did}",nonce="${nonce}",signature="0xdeadbeef"`,
        },
        hostname:    'example.com',
        method:      'GET',
        originalUrl: '/protected',
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

// ── tests ─────────────────────────────────────────────────────────────────────

test('did: canonical z-form DID is accepted and passes through', async () => {
    const { req, res, next, result } = makeCtx(CANONICAL_DID);
    await arkenAuth({ store: validStore(), _core: coreThatAcceptsAll(CANONICAL_DID) })(req, res, next);
    assert.ok(result.nextCalled, 'next() should be called for a valid z-form DID');
    assert.strictEqual(req.user.did, CANONICAL_DID);
});

test('did: 0x-lowercase form is rejected with 401', async () => {
    // Before fix: core is called, returns success, next() is called → FAIL
    // After fix:  middleware rejects before calling core → 401
    const { req, res, next, result } = makeCtx('did:key:0xabcdef1234567890abcdef1234567890abcdef12');
    await arkenAuth({ store: validStore(), _core: coreThatAcceptsAll() })(req, res, next);
    assert.strictEqual(result.nextCalled, false, 'next() must NOT be called for 0x DID');
    assert.strictEqual(result.status, 401, '0x-form DID must be rejected with 401');
});

test('did: 0x-checksum form is rejected with 401', async () => {
    const { req, res, next, result } = makeCtx('did:key:0xAbCdEf1234567890AbCdEf1234567890AbCdEf12');
    await arkenAuth({ store: validStore(), _core: coreThatAcceptsAll() })(req, res, next);
    assert.strictEqual(result.nextCalled, false);
    assert.strictEqual(result.status, 401, '0x-checksum DID must be rejected with 401');
});

test('did: 0x-uppercase prefix form is rejected with 401', async () => {
    const { req, res, next, result } = makeCtx('did:key:0XABCDEF1234567890ABCDEF1234567890ABCDEF12');
    await arkenAuth({ store: validStore(), _core: coreThatAcceptsAll() })(req, res, next);
    assert.strictEqual(result.nextCalled, false);
    assert.strictEqual(result.status, 401, '0X-uppercase DID must be rejected with 401');
});

test('did: req.user.did is set to the canonical DID returned by core (not raw header value)', async () => {
    // This is a regression guard: the DID on req.user must come from core's return value,
    // NOT by copying the raw 'did' field from the Authorization header.
    const rawHeaderDid = 'did:key:zQ3shXgnkRAWFROMHEADER';
    const canonicalDid = 'did:key:zQ3shXgnkCANONICALFROMRUST';

    const { req, res, next, result } = makeCtx(rawHeaderDid);
    await arkenAuth({
        store: validStore(),
        _core: coreThatAcceptsAll(canonicalDid),
    })(req, res, next);

    assert.ok(result.nextCalled, 'next() should be called');
    assert.strictEqual(req.user.did, canonicalDid,
        'req.user.did must be the canonical DID from core, not the raw header value');
    assert.notStrictEqual(req.user.did, rawHeaderDid);
});
