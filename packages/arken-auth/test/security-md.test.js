'use strict';
// SECURITY.md correctness tests — Phase 2, Item 9
//
// SECURITY.md must not contain references to documentation that does not exist.
//
// FAILING BEFORE THE FIX:
//   - "SECURITY.md: nonce-exhaustion out-of-scope note references THREAT_MODEL, not README"
//     SECURITY.md currently says "(see README)" for nonce store exhaustion, but the
//     README contains no such explanation. The reference is a dead link.

const { test } = require('node:test');
const assert   = require('node:assert/strict');
const fs       = require('node:fs');
const path     = require('node:path');

const REPO_ROOT    = path.resolve(__dirname, '../../..');
const SECURITY_MD  = path.join(REPO_ROOT, 'SECURITY.md');
const README_MD    = path.join(REPO_ROOT, 'packages', 'arken-auth', 'README.md');
const THREAT_MODEL = path.join(REPO_ROOT, 'docs', 'THREAT_MODEL.md');

test('SECURITY.md: file exists', () => {
    assert.ok(fs.existsSync(SECURITY_MD), 'SECURITY.md must exist');
});

test('SECURITY.md: nonce-exhaustion out-of-scope note references THREAT_MODEL, not README', () => {
    const security = fs.readFileSync(SECURITY_MD, 'utf8');

    // The README has no explanation of the nonce-exhaustion limitation;
    // the reference must point to docs/THREAT_MODEL.md where it actually lives.
    assert.ok(
        !security.match(/nonce store exhaustion[^)]*see README/i),
        'SECURITY.md must not say "(see README)" for nonce-store exhaustion — README has no such section'
    );
    assert.ok(
        security.match(/nonce store exhaustion[^)]*THREAT_MODEL/i) ||
        security.match(/THREAT_MODEL[^)]*nonce/i),
        'SECURITY.md must reference docs/THREAT_MODEL.md for nonce-store exhaustion'
    );
});

test('SECURITY.md: advisory link points to arkenforge/arken-auth', () => {
    // Regression guard from Item 3 — keep it here too.
    const security = fs.readFileSync(SECURITY_MD, 'utf8');
    assert.ok(
        security.includes('arkenforge/arken-auth'),
        'SECURITY.md advisory link must reference arkenforge/arken-auth'
    );
    assert.ok(
        !security.includes('zacharybenson/arken-protocol'),
        'SECURITY.md must not reference the old zacharybenson/arken-protocol repo'
    );
});

test('SECURITY.md: does not reference README for any topic the README does not cover', () => {
    const security = fs.readFileSync(SECURITY_MD, 'utf8');
    const readme   = fs.readFileSync(README_MD,   'utf8');

    // Extract every "see README" parenthetical and check each referenced topic
    // appears somewhere in the README.
    // Currently there is exactly one such reference; this test generalises the check.
    const seeReadmeRe = /\(([^)]*see README[^)]*)\)/gi;
    let match;
    while ((match = seeReadmeRe.exec(security)) !== null) {
        const context = match[1]; // e.g. "known limitation; see README"
        // Extract the subject from the surrounding line
        const lineStart = security.lastIndexOf('\n', match.index) + 1;
        const lineEnd   = security.indexOf('\n', match.index);
        const line      = security.slice(lineStart, lineEnd === -1 ? undefined : lineEnd);

        // Any "see README" reference should have a corresponding section in README.
        // We flag the reference if the line contains "nonce" and README has no "exhaustion".
        if (/nonce/i.test(line)) {
            assert.ok(
                /exhaustion/i.test(readme) || /nonce.*limitation/i.test(readme),
                `SECURITY.md references README for nonce exhaustion but README has no such section.\n` +
                `Offending line: "${line.trim()}"\n` +
                `Point the reference to docs/THREAT_MODEL.md instead.`
            );
        }
    }
});
