#!/usr/bin/env node
'use strict';

/**
 * Example a401 client — works with any Arken-protected endpoint.
 * Generates a spec-compliant did:key:z... DID from an ethers wallet.
 */

const { ethers } = require('ethers');
const bs58 = require('bs58');

function walletToDidKey(wallet) {
    const signingKey = new ethers.utils.SigningKey(wallet.privateKey);
    const keyBytes = Buffer.from(signingKey.compressedPublicKey.slice(2), 'hex');
    const multicodecKey = Buffer.concat([Buffer.from([0xe7, 0x01]), keyBytes]);
    return `did:key:z${bs58.encode(multicodecKey)}`;
}

async function authenticate(url) {
    const wallet = ethers.Wallet.createRandom();
    const did = walletToDidKey(wallet);

    console.log(`DID: ${did}`);

    // 1. Hit the endpoint — get a 401 challenge
    const challengeRes = await fetch(url);
    if (challengeRes.status !== 401) throw new Error(`Expected 401, got ${challengeRes.status}`);

    const { challenge } = await challengeRes.json();
    const { nonce } = challenge;
    console.log(`Nonce: ${nonce}`);

    // 2. Sign the nonce
    const signature = await wallet.signMessage(ethers.utils.toUtf8Bytes(nonce));

    // 3. Send signed auth header
    const authHeader = `Signature did="${did}",nonce="${nonce}",signature="${signature}"`;
    const authRes = await fetch(url, { headers: { Authorization: authHeader } });

    if (!authRes.ok) {
        const body = await authRes.text();
        throw new Error(`Auth failed ${authRes.status}: ${body}`);
    }

    return authRes.json();
}

const url = process.argv[2] || 'http://localhost:3000/protected';
authenticate(url)
    .then(data => {
        console.log('Success:', JSON.stringify(data, null, 2));
    })
    .catch(err => {
        console.error('Error:', err.message);
        process.exit(1);
    });
