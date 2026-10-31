'use strict';

const koffi = require('koffi');
const path = require('path');
const os = require('os');
const crypto = require('crypto');

const BUF_SIZE = 65536;

// ---------------------------------------------------------------------------
// Native library loader
// ---------------------------------------------------------------------------

function getLibPath() {
    const pkgName = `@arkenforge/arken-auth-${os.platform()}-${os.arch()}`;
    try {
        return require(pkgName);
    } catch (_) {}

    const ext = { win32: '.dll', darwin: '.dylib' }[os.platform()] ?? '.so';
    const prefix = os.platform() === 'win32' ? '' : 'lib';
    return path.join(__dirname, '..', 'bin', `${prefix}arken_core${ext}`);
}

class ArkenCore {
    constructor() {
        const libPath = getLibPath();
        try {
            const lib = koffi.load(libPath);
            this._generate    = lib.func('int generate_challenge_into(const char *statement, char *out, int cap)');
            this._verify      = lib.func('int verify_request_into(const char *header, char *out, int cap)');
            this._verifySigOnly = lib.func('int verify_signature_only_into(const char *header, char *out, int cap)');
        } catch (err) {
            throw new Error(
                `arken-auth: could not load native library at ${libPath}.\n` +
                `Run 'cargo build --release' in the rust/ directory.\n` +
                `Requires Rust: https://rustup.rs\n\nOriginal error: ${err.message}`
            );
        }
    }

    _call(fn, ...args) {
        const buf = Buffer.alloc(BUF_SIZE);
        const len = fn(...args, buf, BUF_SIZE);
        if (len < 0) throw new Error('arken-auth: output buffer too small');
        return JSON.parse(buf.slice(0, len).toString('utf8'));
    }

    generateChallenge(statement = 'Sign this message to prove you control this DID.') {
        return this._call(this._generate, statement);
    }

    verifyRequest(authHeader) {
        return this._call(this._verify, authHeader);
    }

    // Crypto-only verification — nonce not checked against internal store.
    // Node.js manages nonce lifecycle (MemoryNonceStore or RedisNonceStore).
    verifySignatureOnly(authHeader) {
        return this._call(this._verifySigOnly, authHeader);
    }
}

let _core = null;
function getCore() {
    if (!_core) _core = new ArkenCore();
    return _core;
}

// ---------------------------------------------------------------------------
// Nonce stores
// ---------------------------------------------------------------------------

const NONCE_TTL_MS = 60_000;

class MemoryNonceStore {
    constructor() {
        this._store = new Map();
        // Sweep expired nonces every 30 seconds
        this._sweep = setInterval(() => {
            const now = Date.now();
            for (const [nonce, exp] of this._store) {
                if (exp < now) this._store.delete(nonce);
            }
        }, 30_000).unref();
    }

    async set(nonce) {
        this._store.set(nonce, Date.now() + NONCE_TTL_MS);
    }

    async consume(nonce) {
        const exp = this._store.get(nonce);
        if (!exp) return false;
        this._store.delete(nonce);
        return exp > Date.now();
    }
}

class RedisNonceStore {
    constructor(client, ttlSeconds = 60) {
        this._client = client;
        this._ttl = ttlSeconds;
    }

    async set(nonce) {
        await this._client.set(`arken:nonce:${nonce}`, '1', { EX: this._ttl });
    }

    async consume(nonce) {
        const key = `arken:nonce:${nonce}`;
        // getDel is atomic — get and delete in one round trip (Redis 6.2+).
        // Prevents a race where two concurrent requests both pass the nonce check.
        const val = await this._client.getDel(key);
        return val !== null;
    }
}

// ---------------------------------------------------------------------------
// Middleware
// ---------------------------------------------------------------------------

const _defaultStore = new MemoryNonceStore();

function arkenAuth(options = {}) {
    const { statement, store = _defaultStore } = options;

    return async (req, res, next) => {
        const authHeader = req.headers.authorization;

        if (!authHeader || !authHeader.startsWith('Signature ')) {
            try {
                const nonce = crypto.randomBytes(16).toString('hex');
                await store.set(nonce);
                const stmt = statement || 'Sign this message to prove you control this DID.';
                return res.status(401).json({ challenge: { nonce, statement: stmt } });
            } catch (err) {
                console.error('[arken-auth] challenge error:', err.message);
                return res.status(500).json({ error: 'Could not generate challenge' });
            }
        }

        try {
            // Crypto verification (no internal nonce check)
            const result = getCore().verifySignatureOnly(authHeader);

            if (result.status !== 'success') {
                return res.status(401).json({ error: result.message });
            }

            // Node.js nonce check — single-use enforcement
            const valid = await store.consume(result.nonce);
            if (!valid) {
                return res.status(401).json({ error: 'Invalid or expired nonce' });
            }

            req.user = { did: result.did };
            return next();
        } catch (err) {
            console.error('[arken-auth] verify error:', err.message);
            return res.status(500).json({ error: 'Verification failed' });
        }
    };
}

module.exports = { arkenAuth, ArkenCore, MemoryNonceStore, RedisNonceStore };
