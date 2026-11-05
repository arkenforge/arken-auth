'use strict';

const { ethers } = require('ethers');
const bs58 = require('bs58');
const crypto = require('node:crypto');

// ---------------------------------------------------------------------------
// Canonical signed-message builder
//
// MUST stay byte-for-byte identical to packages/arken-auth/lib/message.js.
// If you update the format, update BOTH files and bump the version prefix.
// ---------------------------------------------------------------------------

/**
 * Build the canonical 7-line signed message.
 *
 * @param {{ host, method, path, bodyHash, nonce, expires }} opts
 * @returns {string}
 */
function buildSignedMessage({ host, method, path, bodyHash, nonce, expires }) {
    return [
        'arken-auth-v1',
        host,
        method.toUpperCase(),
        path || '/',
        bodyHash || '',
        String(nonce),
        String(expires),
    ].join('\n');
}

/** SHA-256 hex of body; '' for empty. */
function bodyHashOf(body) {
    if (!body || body === '') return '';
    return crypto.createHash('sha256').update(body).digest('hex');
}

// ---------------------------------------------------------------------------
// DID derivation
// ---------------------------------------------------------------------------

function walletToDidKey(wallet) {
    const signingKey   = new ethers.utils.SigningKey(wallet.privateKey);
    const keyBytes     = Buffer.from(signingKey.compressedPublicKey.slice(2), 'hex');
    const multicodecKey = Buffer.concat([Buffer.from([0xe7, 0x01]), keyBytes]);
    return `did:key:z${bs58.encode(multicodecKey)}`;
}

// ---------------------------------------------------------------------------
// createClient
// ---------------------------------------------------------------------------

/**
 * Create an arken-auth client.
 *
 * Two call forms:
 *
 *   createClient(privateKey?, opts?)
 *     privateKey {string}  – hex private key; generates a fresh one if omitted
 *     opts.allowHttp       – allow signing over plain HTTP (non-localhost)
 *
 *   createClient({ did, signer, allowHttp? })
 *     did    {string}   – the caller's did:key:z… identifier
 *     signer {Function} – async (msgBytes: Uint8Array) => hexSignatureString
 *     allowHttp         – same as above
 *
 * The signer form is for hardware wallets, KMS, MCP agents, and test harnesses
 * that cannot expose the private key as a plain hex string.
 *
 * @returns {{ fetch: Function, did: string, privateKey?: string }}
 */
function createClient(privateKey, opts = {}) {
    // ── Detect signer-object form ──────────────────────────────────────────
    if (privateKey !== null && typeof privateKey === 'object') {
        const { did, signer, allowHttp = false } = privateKey;
        if (!signer) throw new Error('arken-client: { signer } is required when using the signer-object form');
        if (!did)    throw new Error('arken-client: { did } is required when using the signer-object form');
        return _createWithSigner({ did, signer, allowHttp });
    }

    // ── Original private-key form ──────────────────────────────────────────
    const { allowHttp = false } = opts;

    const wallet = privateKey
        ? new ethers.Wallet(privateKey)
        : ethers.Wallet.createRandom();

    const did = walletToDidKey(wallet);

    const signerFn = async (msgBytes) => wallet.signMessage(msgBytes);
    const { fetch } = _createWithSigner({ did, signer: signerFn, allowHttp });
    return { fetch, did, privateKey: wallet.privateKey };
}

/**
 * Internal: build a client around an arbitrary async signer function.
 * @param {{ did, signer, allowHttp }} opts
 * @returns {{ fetch: Function, did: string }}
 */
function _createWithSigner({ did, signer, allowHttp }) {
    /**
     * Drop-in replacement for globalThis.fetch that handles the a401 flow.
     *
     * Security checks before signing:
     *  1. challenge.audience must equal the hostname of `url`.
     *  2. `url` must be https unless the host is localhost (or allowHttp is set).
     *
     * If either check fails the original 401 response is returned unchanged —
     * the client never signs.
     */
    async function fetch(url, options = {}) {
        const fetchFn = globalThis.fetch;
        const r1 = await fetchFn(url, options);

        if (r1.status !== 401) return r1;

        let body;
        try {
            body = await r1.json();
        } catch {
            return r1;
        }

        const challenge = body?.challenge;
        const nonce     = challenge?.nonce;
        const expires   = challenge?.expires;
        const audience  = challenge?.audience;

        if (!nonce || !expires) return r1;

        // ── 0. Nonce format check ───────────────────────────────────────────
        // Reject nonces outside the allowed charset or over 128 chars before
        // signing. A rogue or compromised server cannot force the client to
        // sign an injected or pathological value.
        const NONCE_FORMAT_RE = /^[a-zA-Z0-9_-]{1,128}$/;
        if (!NONCE_FORMAT_RE.test(String(nonce))) return r1;

        // ── 1. Audience check ───────────────────────────────────────────────
        const parsedUrl  = new URL(url);
        const reqHost    = parsedUrl.hostname;

        if (audience && audience !== reqHost) {
            // Challenge is for a different server — refuse to sign.
            return r1;
        }

        // ── 2. Transport check ─────────────────────────────────────────────
        const isLocalhost = reqHost === 'localhost' || reqHost === '127.0.0.1' || reqHost === '::1';
        const isHttps     = parsedUrl.protocol === 'https:';

        if (!isHttps && !isLocalhost && !allowHttp) {
            // Plain HTTP over a non-localhost host is a downgrade / MITM risk.
            return r1;
        }

        // ── 3. Build and sign the canonical message ─────────────────────────
        // The body hash covers the ORIGINAL request body (options.body), not the response.
        const bodyHash = bodyHashOf(options.body ?? '');
        const urlPath  = parsedUrl.pathname + parsedUrl.search;

        const signedMessage = buildSignedMessage({
            host:    reqHost,
            method:  options.method?.toUpperCase() ?? 'GET',
            path:    urlPath || '/',
            bodyHash,
            nonce,
            expires,
        });

        const msgBytes  = ethers.utils.toUtf8Bytes(signedMessage);
        const signature = await signer(msgBytes);

        return fetchFn(url, {
            ...options,
            headers: {
                ...(options.headers ?? {}),
                Authorization: `Signature did="${did}",nonce="${nonce}",signature="${signature}"`,
            },
        });
    }

    return { fetch, did };
}

module.exports = { createClient, walletToDidKey, buildSignedMessage, bodyHashOf };
