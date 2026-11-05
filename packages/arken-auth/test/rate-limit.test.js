'use strict';
// Rate-limit tests — Phase 2, Item 7
//
// The middleware must reject unauthenticated nonce-minting requests that exceed
// a configurable per-IP threshold with 429, not 401.
//
// FAILING BEFORE THE FIX:
//   - "rate-limit: 4th request from same IP returns 429 (limit=3)"
//   - "rate-limit: 429 is not issued on the first maxRequests requests"
//   - "rate-limit: different IPs are tracked independently"
// Before the fix every unauthenticated request issues a 401 challenge
// regardless of how many times the same IP has asked.

const { test } = require('node:test');
const assert   = require('node:assert/strict');
const { arkenAuth } = require('../lib/middleware.js');

// ── helpers ───────────────────────────────────────────────────────────────────

/** Minimal req with no Authorization header (challenge path). */
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

/** Fire n unauthenticated requests through the same middleware instance. */
async function fireN(middleware, n, ip = '1.2.3.4') {
    const statuses = [];
    for (let i = 0; i < n; i++) {
        const result = { status: null };
        const res = {
            set()     { return this; },
            status(s) { result.status = s; return this; },
            json()    { return this; },
        };
        await middleware(unauthReq(ip), res, () => {});
        statuses.push(result.status);
    }
    return statuses;
}

// ── tests ─────────────────────────────────────────────────────────────────────

test('rate-limit: first maxRequests unauthenticated requests return 401', async () => {
    const mw = arkenAuth({ rateLimit: { maxRequests: 3, windowMs: 60_000 } });
    const statuses = await fireN(mw, 3);
    assert.deepStrictEqual(statuses, [401, 401, 401],
        'first 3 requests must all return 401 challenge');
});

test('rate-limit: 4th request from same IP returns 429 (limit=3)', async () => {
    const mw = arkenAuth({ rateLimit: { maxRequests: 3, windowMs: 60_000 } });
    const statuses = await fireN(mw, 4);
    assert.strictEqual(statuses[3], 429,
        '4th request must be rate-limited with 429');
});

test('rate-limit: different IPs are tracked independently', async () => {
    const mw = arkenAuth({ rateLimit: { maxRequests: 2, windowMs: 60_000 } });

    // Exhaust IP A
    await fireN(mw, 2, '10.0.0.1');
    const [blocked] = await fireN(mw, 1, '10.0.0.1');
    assert.strictEqual(blocked, 429, 'IP A must be rate-limited after 2 requests');

    // IP B is fresh — should still get a 401 challenge
    const [fresh] = await fireN(mw, 1, '10.0.0.2');
    assert.strictEqual(fresh, 401, 'IP B must still receive a 401 challenge');
});

test('rate-limit: window reset allows requests again', async () => {
    // Use a 50 ms window so we can test reset without real delay.
    const mw = arkenAuth({ rateLimit: { maxRequests: 1, windowMs: 50 } });

    const [first]   = await fireN(mw, 1);
    assert.strictEqual(first, 401, 'first request must be a 401');

    const [blocked] = await fireN(mw, 1);
    assert.strictEqual(blocked, 429, 'second request in same window must be 429');

    // Wait for the window to expire.
    await new Promise(r => setTimeout(r, 60));

    const [renewed] = await fireN(mw, 1);
    assert.strictEqual(renewed, 401, 'first request after window reset must be 401 again');
});

test('rate-limit: authenticated requests (Signature header) are never rate-limited', async () => {
    // The rate limiter must only apply to the challenge-minting path,
    // not to signed verification requests.
    const mw = arkenAuth({ rateLimit: { maxRequests: 1, windowMs: 60_000 } });

    // Exhaust the unauthenticated budget for this IP.
    await fireN(mw, 1);
    const [blocked] = await fireN(mw, 1);
    assert.strictEqual(blocked, 429, 'unauthenticated must be blocked');

    // A signed request must still be processed (goes to verify path → 401 invalid nonce,
    // not 429). We use a mock store that always returns valid:false to get a clean 401.
    const req = {
        headers: { authorization: 'Signature did="did:key:zFAKE",nonce="abc123",signature="0xdeadbeef"' },
        hostname:    'example.com',
        method:      'GET',
        originalUrl: '/protected',
        rawBody:     '',
        ip:          '1.2.3.4',
    };
    const result = { status: null };
    const res = {
        set()     { return this; },
        status(s) { result.status = s; return this; },
        json()    { return this; },
    };
    await mw(req, res, () => {});
    // 401 (invalid nonce) not 429 — the signed path is not rate-limited
    assert.strictEqual(result.status, 401,
        'signed requests must not be rate-limited (expected 401 invalid nonce, not 429)');
    assert.notStrictEqual(result.status, 429);
});
