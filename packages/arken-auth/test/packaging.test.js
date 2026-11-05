'use strict';
// Packaging hygiene tests — Phase 1, Item 3
// All tests run from the filesystem only (node:fs / node:path, no network).

const { test } = require('node:test');
const assert   = require('node:assert/strict');
const fs       = require('node:fs');
const path     = require('node:path');

// Paths relative to this test file
const AUTH_PKG     = path.resolve(__dirname, '..');                        // packages/arken-auth
const CLIENT_PKG   = path.resolve(__dirname, '../../arken-client');        // packages/arken-client
const AUTH_PY_PKG  = path.resolve(__dirname, '../../arken-auth-py');       // packages/arken-auth-py
const CLIENT_PY_PKG= path.resolve(__dirname, '../../arken-client-py');     // packages/arken-client-py
const REPO_ROOT    = path.resolve(__dirname, '../../..');                  // arken-auth repo root (packages/arken-auth/test → 3 levels up)

// ── License ──────────────────────────────────────────────────────────────────

test('packaging: arken-auth-py pyproject.toml license is Apache-2.0', () => {
    const toml = fs.readFileSync(path.join(AUTH_PY_PKG, 'pyproject.toml'), 'utf8');
    assert.ok(toml.includes('Apache-2.0'), 'arken-auth-py must declare Apache-2.0');
    assert.ok(!toml.match(/license.*MIT/i), 'arken-auth-py must not declare MIT');
});

test('packaging: arken-client-py pyproject.toml license is Apache-2.0', () => {
    const toml = fs.readFileSync(path.join(CLIENT_PY_PKG, 'pyproject.toml'), 'utf8');
    assert.ok(toml.includes('Apache-2.0'), 'arken-client-py must declare Apache-2.0');
    assert.ok(!toml.match(/license.*MIT/i), 'arken-client-py must not declare MIT');
});

test('packaging: arken-auth-py README does not say MIT license', () => {
    const md = fs.readFileSync(path.join(AUTH_PY_PKG, 'README.md'), 'utf8');
    assert.ok(!md.match(/^## License\s+MIT\b/m), 'arken-auth-py README must not list MIT as license');
});

// ── URLs / repo references ────────────────────────────────────────────────────

test('packaging: SECURITY.md advisory link points to arkenforge/arken-auth', () => {
    const md = fs.readFileSync(path.join(REPO_ROOT, 'SECURITY.md'), 'utf8');
    assert.ok(
        md.includes('github.com/arkenforge/arken-auth'),
        'SECURITY.md must link to arkenforge/arken-auth, not a personal fork',
    );
    assert.ok(!md.includes('zacharybenson'), 'SECURITY.md must not reference personal account');
});

test('packaging: arken-auth-py URLs point to arkenforge/arken-auth', () => {
    const toml = fs.readFileSync(path.join(AUTH_PY_PKG, 'pyproject.toml'), 'utf8');
    assert.ok(toml.includes('arkenforge/arken-auth'), 'arken-auth-py URLs must point to arkenforge/arken-auth');
    assert.ok(!toml.includes('arken-protocol/arken-auth-py'), 'must not reference old repo path');
    assert.ok(!toml.includes('arkenprotocol.dev'), 'must not reference old homepage');
});

test('packaging: arken-client-py URLs point to arkenforge/arken-auth', () => {
    const toml = fs.readFileSync(path.join(CLIENT_PY_PKG, 'pyproject.toml'), 'utf8');
    assert.ok(toml.includes('arkenforge/arken-auth'), 'arken-client-py URLs must point to arkenforge/arken-auth');
    assert.ok(!toml.includes('ArkenForge/arken-protocol'), 'must not reference old repo path');
});

// ── Stale prebuilt-binary claim ────────────────────────────────────────────────

test('packaging: arken-auth README does not falsely claim prebuilt binaries', () => {
    const md = fs.readFileSync(path.join(AUTH_PKG, 'README.md'), 'utf8');
    assert.ok(
        !md.includes('prebuilt native binaries are downloaded automatically'),
        'README must not claim prebuilt binaries exist (pre-1.0 — Rust toolchain required)',
    );
});

// ── README.md files exist and install lines match real package names ──────────

test('packaging: arken-client-py has a README.md', () => {
    assert.ok(
        fs.existsSync(path.join(CLIENT_PY_PKG, 'README.md')),
        'arken-client-py/README.md must exist (pyproject.toml references it)',
    );
});

test('packaging: arken-client README install line matches package name', () => {
    const md = fs.readFileSync(path.join(CLIENT_PKG, 'README.md'), 'utf8');
    assert.ok(md.includes('npm install arken-client'), 'README must have correct install command');
});

test('packaging: arken-auth README install line matches package name', () => {
    const md = fs.readFileSync(path.join(AUTH_PKG, 'README.md'), 'utf8');
    assert.ok(md.includes('npm install @arkenforge/arken-auth'), 'README must have correct install command');
});

// ── pyproject.toml build-backend ─────────────────────────────────────────────

test('packaging: arken-auth-py uses setuptools.build_meta', () => {
    const toml = fs.readFileSync(path.join(AUTH_PY_PKG, 'pyproject.toml'), 'utf8');
    assert.ok(toml.includes('setuptools.build_meta'), 'must use standard setuptools.build_meta backend');
    assert.ok(!toml.includes('setuptools.backends.legacy'), 'must not use deprecated legacy backend');
});

test('packaging: arken-client-py uses setuptools.build_meta', () => {
    const toml = fs.readFileSync(path.join(CLIENT_PY_PKG, 'pyproject.toml'), 'utf8');
    assert.ok(toml.includes('setuptools.build_meta'), 'must use standard setuptools.build_meta backend');
    assert.ok(!toml.includes('setuptools.backends.legacy'), 'must not use deprecated legacy backend');
});

// ── npm pack: test files excluded ────────────────────────────────────────────

test('packaging: arken-auth package.json has a files field (excludes test/ and rust/src)', () => {
    const pkg = JSON.parse(fs.readFileSync(path.join(AUTH_PKG, 'package.json'), 'utf8'));
    assert.ok(Array.isArray(pkg.files), 'package.json must have a files allowlist');
    assert.ok(!pkg.files.some(f => f === 'test' || f === 'test/'), 'test/ must not be in files');
    assert.ok(!pkg.files.some(f => f === 'rust' || f === 'rust/'), 'rust/ must not be in files');
});

test('packaging: arken-client package.json has a files field (excludes test/)', () => {
    const pkg = JSON.parse(fs.readFileSync(path.join(CLIENT_PKG, 'package.json'), 'utf8'));
    assert.ok(Array.isArray(pkg.files), 'package.json must have a files allowlist');
    assert.ok(!pkg.files.some(f => f === 'test' || f === 'test/'), 'test/ must not be in files');
});
