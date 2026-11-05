'use strict';
// Client-side audience-binding tests — Phase 1, Item 1
// All tests in this file FAIL before the client enforces audience / https checks.

const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');

const { createClient } = require('../index.js');

// A fixed 32-byte key for deterministic tests.
const TEST_KEY = '0x' + 'ab'.repeat(32);

// ── helpers ───────────────────────────────────────────────────────────────────

let _origFetch;
before(() => { _origFetch = globalThis.fetch; });
after(()   => { globalThis.fetch = _origFetch; });

function mockFirstResponse(body, status = 401) {
  let called = 0;
  globalThis.fetch = async (url, opts = {}) => {
    if (++called === 1) {
      return {
        status,
        json: async () => body,
        headers: { get: () => null },
      };
    }
    // second call (retry with signature)
    return {
      status: 200,
      json: async () => ({ ok: true }),
      headers: { get: () => null },
      _retried: true,
    };
  };
  return () => called;
}

// ── tests ─────────────────────────────────────────────────────────────────────

test('client: refuses challenge whose audience differs from request host', async () => {
  // Challenge says "evil.com" but we are calling "victim.com".
  // The client must NOT sign — it should return the original 401.
  mockFirstResponse({
    challenge: { nonce: 'nonce1', expires: 9_999_999_999, audience: 'evil.com' },
  });

  const client = createClient(TEST_KEY);
  const res = await client.fetch('https://victim.com/protected');

  assert.strictEqual(res.status, 401,
    'Client must return the 401 unchanged when audience mismatches');
});

test('client: refuses non-https unless URL host is localhost', async () => {
  // Over plain http the client should NOT sign (downgrade / MITM risk).
  let retried = false;
  globalThis.fetch = async (url, opts = {}) => {
    if (opts?.headers?.Authorization) retried = true;
    return {
      status: 401,
      json: async () => ({
        challenge: { nonce: 'nonce2', expires: 9_999_999_999, audience: 'example.com' },
      }),
      headers: { get: () => null },
    };
  };

  const client = createClient(TEST_KEY);
  await client.fetch('http://example.com/protected');   // non-https!

  assert.strictEqual(retried, false,
    'Client must not sign over non-https (unless localhost)');
});

test('client: allows http on localhost', async () => {
  // localhost is explicitly exempted from the https requirement.
  let retried = false;
  globalThis.fetch = async (url, opts = {}) => {
    if (opts?.headers?.Authorization) { retried = true; return { status: 200, json: async () => ({}) }; }
    return {
      status: 401,
      json: async () => ({
        challenge: { nonce: 'nonce3', expires: 9_999_999_999, audience: 'localhost' },
      }),
      headers: { get: () => null },
    };
  };

  const client = createClient(TEST_KEY);
  await client.fetch('http://localhost:3000/protected');

  assert.strictEqual(retried, true,
    'Client should sign on localhost even without https');
});
