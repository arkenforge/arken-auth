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

import hashlib
import re
import secrets
from typing import Awaitable, Callable, Optional
from urllib.parse import urlparse

import base58
import httpx
from eth_account import Account
from eth_account.messages import encode_defunct
from eth_keys import keys as eth_keys


# ---------------------------------------------------------------------------
# Canonical message builder
#
# MUST stay byte-for-byte identical to buildSignedMessage() in
# packages/arken-auth/lib/message.js and build_signed_message() in
# packages/arken-auth-py/arken_auth/_core.py.
# ---------------------------------------------------------------------------

def build_signed_message(
    *,
    host: str,
    method: str,
    path: str,
    body_hash: str,
    nonce: str,
    expires: int,
) -> str:
    """Build the canonical 7-line signed message."""
    return "\n".join([
        "arken-auth-v1",
        host,
        method.upper(),
        path or "/",
        body_hash or "",
        str(nonce),
        str(expires),
    ])


def _body_hash_of(body: bytes | str | None) -> str:
    if not body:
        return ""
    if isinstance(body, str):
        body = body.encode("utf-8")
    return hashlib.sha256(body).hexdigest() if body else ""


# ---------------------------------------------------------------------------
# DID derivation
# ---------------------------------------------------------------------------

def _private_key_to_did(private_key_bytes: bytes) -> str:
    """Derive a did:key:zQ3s... identifier from a secp256k1 private key."""
    pk = eth_keys.PrivateKey(private_key_bytes)
    compressed = pk.public_key.to_compressed_bytes()
    multicodec = bytes([0xe7, 0x01]) + compressed
    encoded = base58.b58encode(multicodec).decode('ascii')
    return f"did:key:z{encoded}"


# ---------------------------------------------------------------------------
# ArkenClient
# ---------------------------------------------------------------------------

_LOCALHOST        = {"localhost", "127.0.0.1", "::1"}
_NONCE_FORMAT_RE  = re.compile(r'^[a-zA-Z0-9_-]{1,128}$')


Signer = Callable[[bytes], Awaitable[str]]


class ArkenClient:
    """
    An authenticated agent client.

    Attributes:
        did (str): The agent's DID — its stable cryptographic identity.
        private_key_hex (str): Hex-encoded private key. Only set when created from a
                               raw private key; None when created with an injected signer.
    """

    def __init__(
        self,
        private_key_bytes: Optional[bytes] = None,
        *,
        did: Optional[str] = None,
        signer: Optional[Signer] = None,
        allow_http: bool = False,
    ):
        if signer is not None:
            # Signer-injection form: caller supplies DID + async signer.
            if not did:
                raise ValueError("arken-client: 'did' is required when using the signer form")
            self.did             = did
            self.private_key_hex = None
            self._signer         = signer
        else:
            # Private-key form: derive DID and signer from key bytes.
            if private_key_bytes is None:
                raise ValueError("arken-client: private_key_bytes is required when not using signer")
            self._private_key    = private_key_bytes
            self.did             = _private_key_to_did(private_key_bytes)
            self.private_key_hex = private_key_bytes.hex()

            async def _default_signer(msg_bytes: bytes) -> str:
                msg    = encode_defunct(primitive=msg_bytes)
                signed = Account.sign_message(msg, private_key=self._private_key)
                return signed.signature.hex()

            self._signer = _default_signer

        self._allow_http = allow_http

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

        Security checks before signing:
          1. challenge.audience must equal the hostname of ``url``.
          2. ``url`` must be https unless the host is localhost (or allow_http=True).

        Args:
            url: The URL to request.
            method: HTTP method (default GET).
            client: Optional shared httpx.AsyncClient for connection reuse.
            allow_http: Set True to permit signing over plain HTTP even for
                        non-localhost hosts. Do NOT set this in production.
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

            challenge = (body.get("challenge") or {})
            nonce     = challenge.get("nonce")
            expires   = challenge.get("expires")
            audience  = challenge.get("audience")

            if not nonce or not expires:
                return r1

            # ── 0. Nonce format check ────────────────────────────────────
            if not _NONCE_FORMAT_RE.match(str(nonce)):
                return r1

            parsed  = urlparse(url)
            req_host = parsed.hostname or ""

            # ── 1. Audience check ───────────────────────────────────────
            if audience and audience != req_host:
                return r1

            # ── 2. Transport check ──────────────────────────────────────
            is_https     = parsed.scheme == "https"
            is_localhost = req_host in _LOCALHOST

            if not is_https and not is_localhost and not self._allow_http:
                return r1

            # ── 3. Build and sign the canonical message ─────────────────
            raw_body  = kwargs.get("content") or kwargs.get("data") or ""
            body_hash = _body_hash_of(raw_body)
            path      = parsed.path
            query     = parsed.query
            url_path  = f"{path}?{query}" if query else path

            signed_message = build_signed_message(
                host=req_host,
                method=method.upper(),
                path=url_path or "/",
                body_hash=body_hash,
                nonce=nonce,
                expires=int(expires),
            )

            msg_bytes   = signed_message.encode("utf-8")
            signature   = await self._signer(msg_bytes)
            auth_header = f'Signature did="{self.did}",nonce="{nonce}",signature="{signature}"'

            existing_headers = kwargs.get("headers") or {}
            merged_headers   = {**existing_headers, "Authorization": auth_header}
            retry_kwargs     = {k: v for k, v in kwargs.items() if k != "headers"}

            return await client.request(method, url, headers=merged_headers, **retry_kwargs)

        finally:
            if own_client:
                await client.aclose()


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------

def create_client(
    private_key: Optional[str] = None,
    *,
    did: Optional[str] = None,
    signer: Optional[Signer] = None,
    allow_http: bool = False,
) -> ArkenClient:
    """
    Create an arken-auth client.

    Two call forms:

    Key form (default):
        create_client(private_key?)
            private_key: hex-encoded private key (with or without 0x prefix).
                         Generates a fresh key pair if omitted.

    Signer form:
        create_client(did=..., signer=...)
            did:    the caller's did:key:z… identifier
            signer: async (msg_bytes: bytes) -> hex_signature_str
                    For hardware wallets, KMS, MCP agents that cannot expose
                    the private key as a plain hex string.

    Args:
        allow_http: Allow signing over plain HTTP for non-localhost hosts.
                    Do NOT set this in production.

    Returns:
        ArkenClient with .fetch(), .did, and (key form only) .private_key_hex.
    """
    if signer is not None or did is not None:
        # Signer-injection form.
        return ArkenClient(did=did, signer=signer, allow_http=allow_http)

    if private_key is not None:
        key_hex   = private_key.removeprefix("0x")
        key_bytes = bytes.fromhex(key_hex)
    else:
        key_bytes = secrets.token_bytes(32)

    return ArkenClient(key_bytes, allow_http=allow_http)
