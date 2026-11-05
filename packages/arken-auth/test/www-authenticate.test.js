'use strict';
// WWW-Authenticate header tests — Phase 2, Item 8
//
// RFC 7235 §4.1 requires that every 401 response include a WWW-Authenticate
// header naming the scheme. The Express middleware must set it on every 401 it
// emits — challenge, bad DID, bad nonce, verification failure — but NOT on
// 429 (rate limit) or 500 (internal error).
//
// FAILING BEFORE THE FIX:
//   Every test that checks res.headers['www-authenticate'] will fail because
//   the middleware currently never sets that header.

const { test } = require('node:test');
const assert   = require('node:assert/strict');
const { arkenAuth } = require('../lib/middleware.js');

// ── helpers ───────────────────────────────────────────────────────────────────

const CANONICAL_DID = 'did:key:zQ3shXgnkuyqVxf3NGBsK1q3JabcEXAMPLEfake';

function okCore() {
    return { verifySignatureOnly: () => ({ status: 'success', did: CANONICAL_DID }) };
}
function failCore() {
    return { verifySignatureOnly: () => ({ status: 'error', message: 'bad sig' }) };
}
function validStore(expires = Math.floor(Date.now() / 1000) + 60) {
    return {
        set:     async () => expires,
        consume: async () => ({ valid: true, expires }),
    };
}
function invalidStore() {
    return {
        set:     async () => Math.floor(Date.now() / 1000) + 60,
        consume: async () => ({ valid: false, expires: null }),
    };
}

/** Minimal res that captures status, body, and headers. */
function makeRes() {
    const result = { status: null, body: null, headers: {} };
    const res = {
        _result: result,
        status(s)        { result.status = s; return this; },
        json(b)          { result.body = b;   return this; },
        set(name, value) { result.headers[name.toLowerCase()] = value; return this; },
    };
    return res;
}

function unauthReq(ip = '1.2.3.4') {
    return {
        headers:     {},
        hostname:    'example.com',
        method:      'GET',
        originalUrl: '/protected',
        rawBody:     '',
        ip,
    };
}

function authReq({ did = CANONICAL_DID, nonce = 'abc123', sig = '0xdeadbeef' } = {}) {
    return {
        headers: { authorization: `Signature did="${did}",nonce="${nonce}",signature="${sig}"` },
        hostname:    'example.com',
        method:      'GET',
        originalUrl: '/protected',
        rawBody:     '',
        ip:          '1.2.3.4',
    };
}

// ── tests ─────────────────────────────────────────────────────────────────────

test('www-authenticate: challenge 401 includes WWW-Authenticate: Arken', async () => {
    const res  = makeRes();
    const mw   = arkenAuth({ store: validStore() });
    await mw(unauthReq(), res, () => {});
    assert.strictEqual(res._result.status, 401);
    assert.strictEqual(res._result.headers['www-authenticate'], 'Arken',
        'challenge 401 must include WWW-Authenticate: Arken');
});

test('www-authenticate: invalid DID 401 includes WWW-Authenticate: Arken', async () => {
    const res = makeRes();
    const req = authReq({ did: 'did:key:0xBADADDRESS' });
    const mw  = arkenAuth({ store: validStore() });
    await mw(req, res, () => {});
    assert.strictEqual(res._result.status, 401);
    assert.strictEqual(res._result.headers['www-authenticate'], 'Arken',
        'invalid-DID 401 must include WWW-Authenticate: Arken');
});

test('www-authenticate: malformed nonce 401 includes WWW-Authenticate: Arken', async () => {
    const res = makeRes();
    const req = authReq({ nonce: 'bad nonce!' });
    const mw  = arkenAuth({ store: validStore() });
    await mw(req, res, () => {});
    assert.strictEqual(res._result.status, 401);
    assert.strictEqual(res._result.headers['www-authenticate'], 'Arken',
        'malformed-nonce 401 must include WWW-Authenticate: Arken');
});

test('www-authenticate: invalid/expired nonce 401 includes WWW-Authenticate: Arken', async () => {
    const res = makeRes();
    const req = authReq({ nonce: 'abc123' });
    const mw  = arkenAuth({ store: invalidStore() });
    await mw(req, res, () => {});
    assert.strictEqual(res._result.status, 401);
    assert.strictEqual(res._result.headers['www-authenticate'], 'Arken',
        'invalid-nonce 401 must include WWW-Authenticate: Arken');
});

test('www-authenticate: bad signature 401 includes WWW-Authenticate: Arken', async () => {
    const res = makeRes();
    const req = authReq({ nonce: 'abc123' });
    const mw  = arkenAuth({ store: validStore(), _core: failCore() });
    await mw(req, res, () => {});
    assert.strictEqual(res._result.status, 401);
    assert.strictEqual(res._result.headers['www-authenticate'], 'Arken',
        'bad-signature 401 must include WWW-Authenticate: Arken');
});

test('www-authenticate: 429 does NOT include WWW-Authenticate', async () => {
    // Rate-limited response is not an authentication challenge — no header.
    const mw = arkenAuth({ rateLimit: { maxRequests: 0, windowMs: 60_000 } });
    const res = makeRes();
    await mw(unauthReq(), res, () => {});
    assert.strictEqual(res._result.status, 429);
    assert.ok(!res._result.headers['www-authenticate'],
        '429 must NOT include WWW-Authenticate');
});

test('www-authenticate: successful auth sets no WWW-Authenticate', async () => {
    const res = makeRes();
    const req = authReq({ nonce: 'abc123' });
    const mw  = arkenAuth({ store: validStore(), _core: okCore() });
    let nextCalled = false;
    await mw(req, res, () => { nextCalled = true; });
    assert.ok(nextCalled, 'next() must be called on success');
    assert.ok(!res._result.headers['www-authenticate'],
        'successful auth must not set WWW-Authenticate');
});
