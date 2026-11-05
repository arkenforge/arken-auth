'use strict';
// Audience-binding tests — Phase 1, Item 1
// All tests in this file FAIL before lib/message.js exists.

const { test } = require('node:test');
const assert   = require('node:assert/strict');
const crypto   = require('node:crypto');

// This require throws MODULE_NOT_FOUND before the fix.
const { buildSignedMessage } = require('../lib/message.js');

test('message: canonical format is 7-line arken-auth-v1 record', () => {
  const msg = buildSignedMessage({
    host:     'example.com',
    method:   'GET',
    path:     '/api?q=1',
    bodyHash: '',
    nonce:    'abc123',
    expires:  9999999999,
  });
  const lines = msg.split('\n');
  assert.strictEqual(lines[0], 'arken-auth-v1');
  assert.strictEqual(lines[1], 'example.com');
  assert.strictEqual(lines[2], 'GET');
  assert.strictEqual(lines[3], '/api?q=1');
  assert.strictEqual(lines[4], '');           // empty body hash
  assert.strictEqual(lines[5], 'abc123');
  assert.strictEqual(lines[6], '9999999999');
  assert.strictEqual(lines.length, 7);
});

test('relay: same nonce + different host → different signed message', () => {
  const common = { method: 'GET', path: '/data', bodyHash: '', nonce: 'nonce1', expires: 9999 };
  const victim = buildSignedMessage({ host: 'victim.com',  ...common });
  const evil   = buildSignedMessage({ host: 'evil.com',    ...common });
  assert.notStrictEqual(victim, evil,
    'Messages must differ so a relay-forwarded sig is rejected by the victim server');
});

test('audience: different METHOD → different message', () => {
  const common = { host: 'example.com', path: '/api', bodyHash: '', nonce: 'n', expires: 1 };
  assert.notStrictEqual(
    buildSignedMessage({ method: 'GET',  ...common }),
    buildSignedMessage({ method: 'POST', ...common }),
  );
});

test('audience: different path → different message', () => {
  const common = { host: 'example.com', method: 'GET', bodyHash: '', nonce: 'n', expires: 1 };
  assert.notStrictEqual(
    buildSignedMessage({ path: '/admin', ...common }),
    buildSignedMessage({ path: '/user',  ...common }),
  );
});

test('audience: different body hash → different message', () => {
  const hash = (s) => crypto.createHash('sha256').update(s).digest('hex');
  const common = { host: 'example.com', method: 'POST', path: '/api', nonce: 'n', expires: 1 };
  assert.notStrictEqual(
    buildSignedMessage({ bodyHash: hash('{"a":1}'), ...common }),
    buildSignedMessage({ bodyHash: hash('{"a":2}'), ...common }),
  );
});
