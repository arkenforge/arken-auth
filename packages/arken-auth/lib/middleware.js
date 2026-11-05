'use strict';

const crypto = require('node:crypto');
const { getCore, MemoryNonceStore, RedisNonceStore } = require('@arkenforge/core');
const { buildSignedMessage, bodyHashOf } = require('./message.js');

const _defaultStore = new MemoryNonceStore();

// Extract the nonce from an Authorization header before a full parse.
// Used to look up the stored expiry before calling Rust.
const NONCE_RE = /nonce="([^"]+)"/;
function extractNonce(header) {
    const m = NONCE_RE.exec(header);
    return m ? m[1] : null;
}

// Extract the DID from an Authorization header.
const DID_RE = /did="([^"]+)"/;
function extractDid(header) {
    const m = DID_RE.exec(header);
    return m ? m[1] : null;
}

// Validate DID format: only canonical multibase did:key:z... is accepted.
// The 0x Ethereum-address form (did:key:0x...) is rejected — one key, one DID.
function isCanonicalDid(did) {
    return typeof did === 'string' && did.startsWith('did:key:z');
}

/**
 * arkenAuth — Express middleware factory.
 *
 * Options:
 *   statement  {string}      – shown to the signer; optional
 *   store      {NonceStore}  – MemoryNonceStore (default) or RedisNonceStore
 *   rateLimit  {object}      – { maxRequests: 10, windowMs: 60_000 }
 *                               Per-IP cap on unauthenticated challenge requests.
 *                               Exceeding the limit returns 429.
 *   _core      {ArkenCore}   – inject a mock core for tests; not for production use
 */
function arkenAuth(options = {}) {
    const { statement, store = _defaultStore, _core, rateLimit = {} } = options;
    const { maxRequests = 10, windowMs = 60_000 } = rateLimit;

    // Per-IP rate-limit state: ip → { count, resetAt }
    // Only tracks the unauthenticated challenge-minting path.
    const _rlMap = new Map();

    return async (req, res, next) => {
        const authHeader = req.headers.authorization;

        // ── No auth header → issue challenge ───────────────────────────────
        if (!authHeader || !authHeader.startsWith('Signature ')) {
            // Per-IP rate limit on nonce minting.
            const ip  = req.ip || req.socket?.remoteAddress || 'unknown';
            const now = Date.now();
            let entry = _rlMap.get(ip);
            if (!entry || now >= entry.resetAt) {
                entry = { count: 0, resetAt: now + windowMs };
                _rlMap.set(ip, entry);
            }
            entry.count++;
            if (entry.count > maxRequests) {
                return res.status(429).json({ error: 'Too many authentication attempts' });
            }

            try {
                const nonce   = crypto.randomBytes(16).toString('hex');
                const expires = await store.set(nonce);              // Unix seconds
                const host    = req.hostname;
                const stmt    = statement || 'Sign this message to prove you control this DID.';
                return res.set('WWW-Authenticate', 'Arken').status(401).json({
                    challenge: { nonce, expires, audience: host, statement: stmt },
                });
            } catch (err) {
                console.error('[arken-auth] challenge error:', err.message);
                return res.status(500).json({ error: 'Could not generate challenge' });
            }
        }

        // ── Verify ─────────────────────────────────────────────────────────
        try {
            // Validate DID format before consuming the nonce or calling Rust.
            const did = extractDid(authHeader);
            if (!did || !isCanonicalDid(did)) {
                return res.set('WWW-Authenticate', 'Arken').status(401).json({ error: 'Invalid DID format: only did:key:z... (multibase) is accepted' });
            }

            const nonce = extractNonce(authHeader);
            if (!nonce) {
                return res.set('WWW-Authenticate', 'Arken').status(401).json({ error: 'Missing nonce in Authorization header' });
            }

            // Validate nonce format before touching the store.
            // Reject anything outside the allowed charset or over 128 chars to
            // prevent injection into nonce-store keys and to bound DoS surface.
            const NONCE_FORMAT_RE = /^[a-zA-Z0-9_-]{1,128}$/;
            if (!NONCE_FORMAT_RE.test(nonce)) {
                return res.set('WWW-Authenticate', 'Arken').status(401).json({ error: 'Malformed nonce format' });
            }

            // Consume nonce first (single-use) and retrieve stored expiry.
            // We consume before cryptographic verification so a replay never
            // reaches the crypto path, even if verification is slow.
            const { valid, expires } = await store.consume(nonce);
            if (!valid) {
                return res.set('WWW-Authenticate', 'Arken').status(401).json({ error: 'Invalid or expired nonce' });
            }

            // Rebuild the canonical signed message from ACTUAL request fields.
            // The server NEVER copies host/method/path/body from client-supplied
            // Authorization header fields — only from the real incoming request.
            const rawBody   = req.rawBody ?? '';
            const bodyHash  = bodyHashOf(rawBody);
            const urlPath   = req.originalUrl || req.url || '/';

            const signedMessage = buildSignedMessage({
                host:    req.hostname,
                method:  req.method,
                path:    urlPath,
                bodyHash,
                nonce,
                expires,
            });

            // Rust verifies the ECDSA signature against the full canonical message.
            const core   = _core || getCore();
            const result = core.verifySignatureOnly(authHeader, signedMessage);

            if (result.status !== 'success') {
                return res.set('WWW-Authenticate', 'Arken').status(401).json({ error: result.message });
            }

            req.user = { did: result.did };
            return next();
        } catch (err) {
            console.error('[arken-auth] verify error:', err.message);
            return res.status(500).json({ error: 'Verification failed' });
        }
    };
}

module.exports = { arkenAuth, MemoryNonceStore, RedisNonceStore };
