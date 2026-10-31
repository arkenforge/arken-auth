'use strict';

const { ethers } = require('ethers');
const bs58 = require('bs58');

// ---------------------------------------------------------------------------
// DID derivation
// ---------------------------------------------------------------------------

function walletToDidKey(wallet) {
    const signingKey = new ethers.utils.SigningKey(wallet.privateKey);
    const keyBytes = Buffer.from(signingKey.compressedPublicKey.slice(2), 'hex');
    const multicodecKey = Buffer.concat([Buffer.from([0xe7, 0x01]), keyBytes]);
    return `did:key:z${bs58.encode(multicodecKey)}`;
}

// ---------------------------------------------------------------------------
// createClient
// ---------------------------------------------------------------------------

/**
 * Create an arken-auth client.
 *
 * @param {string} [privateKey]  Hex private key. Generates a fresh key if omitted.
 * @returns {{ fetch: Function, did: string, privateKey: string }}
 *
 * @example
 * const { fetch, did } = createClient();
 * const res = await fetch('https://api.example.com/protected');
 */
function createClient(privateKey) {
    const wallet = privateKey
        ? new ethers.Wallet(privateKey)
        : ethers.Wallet.createRandom();

    const did = walletToDidKey(wallet);

    /**
     * Drop-in replacement for global fetch that automatically handles the
     * a401 challenge-response flow.
     *
     * - First request arrives as normal.
     * - On 401, extracts the nonce from the challenge body, signs it, and retries.
     * - Returns the final Response (either the 200 or a non-401 error).
     */
    async function fetch(url, options = {}) {
        // globalThis.fetch is available in Node.js 18+ (required by engines field).
        const fetchFn = globalThis.fetch;

        const r1 = await fetchFn(url, options);

        if (r1.status !== 401) return r1;

        let body;
        try {
            body = await r1.json();
        } catch {
            return r1;
        }

        const nonce = body?.challenge?.nonce;
        if (!nonce) return r1;

        const signature = await wallet.signMessage(ethers.utils.toUtf8Bytes(nonce));

        return fetchFn(url, {
            ...options,
            headers: {
                ...(options.headers ?? {}),
                Authorization: `Signature did="${did}",nonce="${nonce}",signature="${signature}"`,
            },
        });
    }

    return { fetch, did, privateKey: wallet.privateKey };
}

module.exports = { createClient, walletToDidKey };
