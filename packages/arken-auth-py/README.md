# arken-auth (Python)

Zero-storage authentication dependency for FastAPI. No passwords. No sessions. Nothing to breach.

## Install

Requires [Rust](https://rustup.rs) — used once to compile the native crypto core.

```bash
pip install arken-auth
python -m arken_auth.build  # compiles the Rust core
```

## Usage

```python
from fastapi import FastAPI, Depends
from arken_auth import ArkenAuth

app = FastAPI()

@app.get("/protected")
async def protected(did: str = Depends(ArkenAuth())):
    return {"user": did}
```

## How it works

1. First request hits your route with no `Authorization` header
2. Dependency raises a `401` HTTPException with a JSON challenge
3. Client signs the nonce and resends with `Authorization: Signature did="...",nonce="...",signature="..."`
4. Dependency verifies the signature and returns the authenticated DID
5. FastAPI injects it as the `did` parameter

## Options

```python
ArkenAuth(statement="Sign to access the API.")
```

## 401 response format

```json
{
  "challenge": {
    "nonce": "a7b3c9...",
    "statement": "Sign this message to prove you control this DID."
  }
}
```

## Security model

- The server never sees a private key
- Nonces are single-use and expire after 60 seconds
- Signature verification runs in Rust (ethers/k256, audited)
- Thread-safe: uses a Mutex in the native library

## License

MIT
