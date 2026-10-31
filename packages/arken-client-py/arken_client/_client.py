"""
arken-client — Python SDK for arken-auth

Handles the a401 challenge-response flow automatically.

Usage:
    from arken_client import create_client

    client = create_client()               # fresh key pair
    client = create_client(private_key)    # reuse existing key

    response = await client.fetch("https://api.example.com/protected")
    print(client.did)            # did:key:zQ3s...
    print(client.private_key_hex)
"""

import secrets
from typing import Optional

import base58
import httpx
from eth_account import Account
from eth_account.messages import encode_defunct
from eth_keys import keys as eth_keys


# ---------------------------------------------------------------------------
# DID derivation
# ---------------------------------------------------------------------------

def _private_key_to_did(private_key_bytes: bytes) -> str:
    """Derive a did:key:zQ3s... identifier from a secp256k1 private key."""
    pk = eth_keys.PrivateKey(private_key_bytes)
    compressed = pk.public_key.to_compressed_bytes()

    # Multicodec prefix for secp256k1-pub: 0xe7 0x01
    multicodec = bytes([0xe7, 0x01]) + compressed

    # Multibase base58btc encoding (z prefix)
    encoded = base58.b58encode(multicodec).decode('ascii')
    return f"did:key:z{encoded}"


# ---------------------------------------------------------------------------
# ArkenClient
# ---------------------------------------------------------------------------

class ArkenClient:
    """
    An authenticated agent client.

    Attributes:
        did (str): The agent's DID — its stable cryptographic identity.
        private_key_hex (str): Hex-encoded private key. Persist this to reuse the DID.
    """

    def __init__(self, private_key_bytes: bytes):
        self._private_key = private_key_bytes
        self.private_key_hex = private_key_bytes.hex()
        self.did = _private_key_to_did(private_key_bytes)

    def _sign_nonce(self, nonce: str) -> str:
        """Sign a nonce with the agent's private key using eth_sign."""
        msg = encode_defunct(text=nonce)
        signed = Account.sign_message(msg, private_key=self._private_key)
        return signed.signature.hex()

    async def fetch(
        self,
        url: str,
        method: str = "GET",
        client: Optional[httpx.AsyncClient] = None,
        **kwargs,
    ) -> httpx.Response:
        """
        Drop-in replacement for httpx.AsyncClient.request() that automatically
        handles the a401 challenge-response flow.

        - First request arrives as normal.
        - On 401, extracts the nonce, signs it, and retries with Authorization header.
        - Returns the final Response.

        Args:
            url: The URL to request.
            method: HTTP method (default GET).
            client: Optional shared httpx.AsyncClient for connection reuse.
            **kwargs: Passed through to httpx (headers, json, content, etc.)
        """
        own_client = client is None
        if own_client:
            client = httpx.AsyncClient()

        try:
            r1 = await client.request(method, url, **kwargs)

            if r1.status_code != 401:
                return r1

            try:
                body = r1.json()
            except Exception:
                return r1

            nonce = (body.get("challenge") or {}).get("nonce")
            if not nonce:
                return r1

            signature = self._sign_nonce(nonce)
            auth_header = f'Signature did="{self.did}",nonce="{nonce}",signature="{signature}"'

            # Build new headers without mutating the caller's kwargs dict
            existing_headers = kwargs.get("headers") or {}
            merged_headers = {**existing_headers, "Authorization": auth_header}
            retry_kwargs = {k: v for k, v in kwargs.items() if k != "headers"}

            return await client.request(method, url, headers=merged_headers, **retry_kwargs)

        finally:
            if own_client:
                await client.aclose()


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------

def create_client(private_key: Optional[str] = None) -> ArkenClient:
    """
    Create an arken-auth client.

    Args:
        private_key: Hex-encoded private key (with or without 0x prefix).
                     Generates a fresh key pair if omitted.

    Returns:
        ArkenClient with .fetch(), .did, and .private_key_hex attributes.

    Example:
        client = create_client()
        print(client.did)               # did:key:zQ3s...
        print(client.private_key_hex)   # persist this

        response = await client.fetch("https://api.example.com/protected")
    """
    if private_key is not None:
        key_hex = private_key.removeprefix("0x")
        key_bytes = bytes.fromhex(key_hex)
    else:
        key_bytes = secrets.token_bytes(32)

    return ArkenClient(key_bytes)
