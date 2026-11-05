'use strict';
// Threat model doc tests — Phase 2, Item 5
//
// Checks that docs/THREAT_MODEL.md exists at the repo root and covers
// all six STRIDE categories plus the named attack scenarios from Item 4.
//
// FAILING BEFORE THE FIX: the file does not exist yet.

const { test } = require('node:test');
const assert   = require('node:assert/strict');
const fs       = require('node:fs');
const path     = require('node:path');

const REPO_ROOT   = path.resolve(__dirname, '../../..');
const THREAT_MODEL = path.join(REPO_ROOT, 'docs', 'THREAT_MODEL.md');

function content() {
    return fs.readFileSync(THREAT_MODEL, 'utf8');
}

test('threat-model: docs/THREAT_MODEL.md exists', () => {
    assert.ok(fs.existsSync(THREAT_MODEL), 'docs/THREAT_MODEL.md must exist at repo root');
});

test('threat-model: covers all six STRIDE categories', () => {
    const md = content();
    for (const cat of ['Spoofing', 'Tampering', 'Repudiation', 'Information Disclosure',
                        'Denial of Service', 'Elevation of Privilege']) {
        assert.ok(md.includes(cat), `THREAT_MODEL.md must cover STRIDE category: ${cat}`);
    }
});

test('threat-model: addresses replay attack', () => {
    assert.ok(content().toLowerCase().includes('replay'),
        'THREAT_MODEL.md must address replay attacks');
});

test('threat-model: addresses nonce expiry', () => {
    const md = content().toLowerCase();
    assert.ok(md.includes('expir'), 'THREAT_MODEL.md must address nonce expiry');
});

test('threat-model: addresses audience / cross-host relay', () => {
    const md = content().toLowerCase();
    assert.ok(md.includes('audience') || md.includes('relay'),
        'THREAT_MODEL.md must address audience binding / cross-host relay');
});

test('threat-model: addresses DID aliasing / canonicalization', () => {
    const md = content().toLowerCase();
    assert.ok(md.includes('alias') || md.includes('canonical'),
        'THREAT_MODEL.md must address DID aliasing / canonicalization');
});

test('threat-model: addresses malformed nonce / DoS', () => {
    const md = content().toLowerCase();
    assert.ok(md.includes('malformed') || md.includes('dos') || md.includes('denial'),
        'THREAT_MODEL.md must address malformed nonce / DoS');
});
