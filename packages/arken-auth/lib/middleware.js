'use strict';

const crypto = require('crypto');
const { getCore, MemoryNonceStore, RedisNonceStore } = require('@arkenforge/core');

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

module.exports = { arkenAuth, MemoryNonceStore, RedisNonceStore };
