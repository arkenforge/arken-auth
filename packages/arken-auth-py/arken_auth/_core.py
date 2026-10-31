import ctypes
import json
import os
import platform
import secrets
import threading
import time
from typing import Optional

from fastapi import Request, HTTPException

BUF_SIZE = 65536  # 64 KB

NONCE_TTL = 60  # seconds


# ---------------------------------------------------------------------------
# Nonce stores
# ---------------------------------------------------------------------------

class MemoryNonceStore:
    """In-process nonce store. Default. Does not survive restarts."""

    def __init__(self):
        self._store: dict[str, float] = {}
        self._lock = threading.Lock()

    async def set(self, nonce: str) -> None:
        with self._lock:
            self._store[nonce] = time.monotonic() + NONCE_TTL
            # Sweep expired
            now = time.monotonic()
            expired = [k for k, v in self._store.items() if v < now]
            for k in expired:
                del self._store[k]

    async def consume(self, nonce: str) -> bool:
        with self._lock:
            exp = self._store.pop(nonce, None)
            if exp is None:
                return False
            return time.monotonic() < exp


class RedisNonceStore:
    """
    Redis-backed nonce store. Use this for multi-instance deployments.

    Requires redis-py (async):
        pip install redis

    Example:
        import redis.asyncio as redis
        r = redis.from_url(os.environ["REDIS_URL"])
        app = ArkenAuth(store=RedisNonceStore(r))
    """

    def __init__(self, client, ttl: int = NONCE_TTL):
        self._client = client
        self._ttl = ttl

    async def set(self, nonce: str) -> None:
        await self._client.set(f"arken:nonce:{nonce}", "1", ex=self._ttl)

    async def consume(self, nonce: str) -> bool:
        key = f"arken:nonce:{nonce}"
        # getdel is atomic — get and delete in one round trip (Redis 6.2+).
        # Prevents a race where two concurrent requests both pass the nonce check.
        val = await self._client.getdel(key)
        return val is not None


# ---------------------------------------------------------------------------
# Native library
# ---------------------------------------------------------------------------

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

        # Buffer-based FFI — caller owns the output buffer
        for fn_name in ("generate_challenge_into", "verify_request_into", "verify_signature_only_into"):
            fn = getattr(self._lib, fn_name)
            fn.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int]
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

    def verify_signature_only(self, auth_header: str) -> dict:
        """Crypto verification without internal nonce check. Returns {status, did, nonce}."""
        return self._call(self._lib.verify_signature_only_into, auth_header)


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
    ):
        self.statement = statement
        self.store = store or _default_store

    async def __call__(self, request: Request) -> str:
        auth_header = request.headers.get("authorization", "")

        if not auth_header.lower().startswith("signature "):
            nonce = secrets.token_hex(16)
            await self.store.set(nonce)
            raise HTTPException(
                status_code=401,
                detail={"challenge": {"nonce": nonce, "statement": self.statement}},
                headers={"WWW-Authenticate": "Arken"},
            )

        result = get_core().verify_signature_only(auth_header)

        if result.get("status") != "success":
            raise HTTPException(
                status_code=401,
                detail={"error": result.get("message", "Authentication failed")},
            )

        valid = await self.store.consume(result["nonce"])
        if not valid:
            raise HTTPException(
                status_code=401,
                detail={"error": "Invalid or expired nonce"},
            )

        return result["did"]
