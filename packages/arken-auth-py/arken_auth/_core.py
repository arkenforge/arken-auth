"""
arken-auth Python core — FastAPI dependency, nonce stores, FFI wrapper.

Canonical signed-message format (must mirror packages/arken-auth/lib/message.js):
    arken-auth-v1\\n{host}\\n{METHOD}\\n{path+query}\\n{bodyHash}\\n{nonce}\\n{expires}
"""

import ctypes
import hashlib
import json
import os
import platform
import re
import secrets
import threading
import time
from typing import Optional, Tuple

from fastapi import Request, HTTPException

BUF_SIZE = 65536  # 64 KB
NONCE_TTL = 60    # seconds


# ---------------------------------------------------------------------------
# Canonical message builder
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
    """
    Build the canonical 7-line signed message.

    MUST stay byte-for-byte identical to buildSignedMessage() in
    packages/arken-auth/lib/message.js.
    """
    return "\n".join([
        "arken-auth-v1",
        host,
        method.upper(),
        path or "/",
        body_hash or "",
        str(nonce),
        str(expires),
    ])


def body_hash_of(body: bytes | str | None) -> str:
    """SHA-256 hex of body; '' for empty."""
    if not body:
        return ""
    if isinstance(body, str):
        body = body.encode("utf-8")
    if len(body) == 0:
        return ""
    return hashlib.sha256(body).hexdigest()


# ---------------------------------------------------------------------------
# Nonce stores
# BREAKING (v1):
#   set(nonce)     → now returns int (expires, Unix seconds)
#   consume(nonce) → now returns (valid: bool, expires: int | None)
# ---------------------------------------------------------------------------

class MemoryNonceStore:
    """In-process nonce store. Default. Does not survive restarts."""

    def __init__(self):
        # value: Unix-second expiry
        self._store: dict[str, int] = {}
        self._lock = threading.Lock()

    async def set(self, nonce: str) -> int:
        """Store nonce, return expiry as Unix seconds."""
        expires = int(time.time()) + NONCE_TTL
        with self._lock:
            self._store[nonce] = expires
            # Sweep expired nonces on every insert
            now = int(time.time())
            expired = [k for k, v in self._store.items() if v < now]
            for k in expired:
                del self._store[k]
        return expires

    async def consume(self, nonce: str) -> Tuple[bool, Optional[int]]:
        """Consume nonce. Returns (valid, expires). expires is None if not found."""
        with self._lock:
            expires = self._store.pop(nonce, None)
            if expires is None:
                return False, None
            return int(time.time()) < expires, expires


class RedisNonceStore:
    """
    Redis-backed nonce store for multi-instance deployments.

    Requires redis-py (async):
        pip install redis

    Example:
        import redis.asyncio as redis
        r = redis.from_url(os.environ["REDIS_URL"])
        auth = ArkenAuth(store=RedisNonceStore(r))
    """

    def __init__(self, client, ttl: int = NONCE_TTL):
        self._client = client
        self._ttl = ttl

    async def set(self, nonce: str) -> int:
        """Store nonce with expiry value. Returns expiry as Unix seconds."""
        expires = int(time.time()) + self._ttl
        await self._client.set(f"arken:nonce:{nonce}", str(expires), ex=self._ttl)
        return expires

    async def consume(self, nonce: str) -> Tuple[bool, Optional[int]]:
        """Consume nonce atomically. Returns (valid, expires)."""
        key = f"arken:nonce:{nonce}"
        # getdel is atomic — get and delete in one round trip (Redis 6.2+)
        val = await self._client.getdel(key)
        if val is None:
            return False, None
        expires = int(val)
        return int(time.time()) < expires, expires


# ---------------------------------------------------------------------------
# Native library
# ---------------------------------------------------------------------------

_NONCE_RE        = re.compile(r'nonce="([^"]+)"')
_DID_RE          = re.compile(r'did="([^"]+)"')
_NONCE_FORMAT_RE = re.compile(r'^[a-zA-Z0-9_-]{1,128}$')


def _is_canonical_did(did: str) -> bool:
    """Only did:key:z... (multibase base58btc) is accepted; did:key:0x... is not."""
    return isinstance(did, str) and did.startswith("did:key:z")


class ArkenCore:
    def __init__(self, lib_path: Optional[str] = None):
        if lib_path is None:
            lib_path = self._find_lib()

        try:
            self._lib = ctypes.CDLL(lib_path)
        except OSError as e:
            raise RuntimeError(
                f"Could not load shared library at '{lib_path}'. "
                f"Compile it with 'cargo build --release'.\n"
                f"Requires Rust: https://rustup.rs\n"
                f"Original error: {e}"
            ) from e

        # generate_challenge_into and verify_request_into: (char*, char*, int) -> int
        for fn_name in ("generate_challenge_into", "verify_request_into"):
            fn = getattr(self._lib, fn_name)
            fn.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int]
            fn.restype  = ctypes.c_int

        # BREAKING (v1): verify_signature_only_into gains a 'message' parameter
        # Signature: (header: char*, message: char*, out: char*, cap: int) -> int
        fn = self._lib.verify_signature_only_into
        fn.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int]
        fn.restype  = ctypes.c_int

        self._lock = threading.Lock()

    def _find_lib(self) -> str:
        base = os.path.join(os.path.dirname(__file__), '../rust/target/release')
        system = platform.system()
        if system == "Windows":
            return os.path.join(base, 'arken_core.dll')
        elif system == "Darwin":
            return os.path.join(base, 'libarken_core.dylib')
        else:
            return os.path.join(base, 'libarken_core.so')

    def _call(self, func, *args) -> dict:
        encoded = [a.encode('utf-8') for a in args]
        buf = ctypes.create_string_buffer(BUF_SIZE)
        with self._lock:
            length = func(*encoded, buf, BUF_SIZE)
        if length < 0:
            raise RuntimeError("arken-auth: output buffer too small")
        return json.loads(buf.raw[:length].decode('utf-8'))

    def generate_challenge(self, statement: str = "Sign this message to prove you control this DID.") -> dict:
        return self._call(self._lib.generate_challenge_into, statement)

    def verify_request(self, auth_header: str) -> dict:
        return self._call(self._lib.verify_request_into, auth_header)

    def verify_signature_only(self, auth_header: str, signed_message: str) -> dict:
        """
        Crypto verification without internal nonce check.

        signed_message is the canonical message built by build_signed_message()
        from actual request fields. Returns {status, did, nonce}.
        """
        return self._call(self._lib.verify_signature_only_into, auth_header, signed_message)


# ---------------------------------------------------------------------------
# Singleton core
# ---------------------------------------------------------------------------

_core: Optional[ArkenCore] = None
_core_lock = threading.Lock()


def get_core() -> ArkenCore:
    global _core
    if _core is None:
        with _core_lock:
            if _core is None:
                _core = ArkenCore()
    return _core


# ---------------------------------------------------------------------------
# Middleware
# ---------------------------------------------------------------------------

_default_store = MemoryNonceStore()


class ArkenAuth:
    """
    FastAPI dependency for arken-auth.

    Usage:
        @app.get("/protected")
        async def protected(did: str = Depends(ArkenAuth())):
            return {"did": did}

    With Redis (multi-instance):
        import redis.asyncio as redis
        r = redis.from_url(os.environ["REDIS_URL"])
        auth = ArkenAuth(store=RedisNonceStore(r))
    """

    def __init__(
        self,
        statement: str = "Sign this message to prove you control this DID.",
        store=None,
        _core: Optional[ArkenCore] = None,
    ):
        self.statement = statement
        self.store = store or _default_store
        self._core = _core  # for testing only

    async def __call__(self, request: Request) -> str:
        auth_header = request.headers.get("authorization", "")

        # ── No auth header → issue challenge ──────────────────────────────
        if not auth_header.lower().startswith("signature "):
            nonce   = secrets.token_hex(16)
            expires = await self.store.set(nonce)             # Unix seconds
            host    = request.url.hostname or request.headers.get("host", "")
            raise HTTPException(
                status_code=401,
                detail={"challenge": {
                    "nonce":     nonce,
                    "expires":   expires,
                    "audience":  host,
                    "statement": self.statement,
                }},
                headers={"WWW-Authenticate": "Arken"},
            )

        # ── Verify ────────────────────────────────────────────────────────
        # Validate DID format before consuming nonce or calling Rust.
        did_m = _DID_RE.search(auth_header)
        if not did_m or not _is_canonical_did(did_m.group(1)):
            raise HTTPException(
                status_code=401,
                detail={"error": "Invalid DID format: only did:key:z... (multibase) is accepted"},
            )

        m = _NONCE_RE.search(auth_header)
        if not m:
            raise HTTPException(status_code=401,
                                detail={"error": "Missing nonce in Authorization header"})
        nonce = m.group(1)

        # Validate nonce format before touching the store.
        # Reject anything outside the allowed charset or over 128 chars.
        if not _NONCE_FORMAT_RE.match(nonce):
            raise HTTPException(status_code=401,
                                detail={"error": "Malformed nonce format"})

        # Consume nonce first (single-use) and retrieve stored expiry.
        valid, expires = await self.store.consume(nonce)
        if not valid:
            raise HTTPException(status_code=401,
                                detail={"error": "Invalid or expired nonce"})

        # Rebuild canonical message from ACTUAL request fields — never from
        # client-supplied Authorization header values.
        host    = request.url.hostname or request.headers.get("host", "")
        method  = request.method
        path    = request.url.path
        query   = request.url.query
        url_path = f"{path}?{query}" if query else path

        raw_body   = await request.body()
        body_hash  = body_hash_of(raw_body)

        signed_message = build_signed_message(
            host=host,
            method=method,
            path=url_path,
            body_hash=body_hash,
            nonce=nonce,
            expires=expires,
        )

        core   = self._core or get_core()
        result = core.verify_signature_only(auth_header, signed_message)

        if result.get("status") != "success":
            raise HTTPException(
                status_code=401,
                detail={"error": result.get("message", "Authentication failed")},
            )

        return result["did"]
