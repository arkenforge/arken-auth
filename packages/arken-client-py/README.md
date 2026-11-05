# arken-client (Python)

Async Python client for [arken-auth](https://github.com/arkenforge/arken-auth).
Handles the a401 challenge-response flow automatically.

## Install

```bash
pip install arken-client
```

> **Pre-1.0:** building from source requires a [Rust toolchain](https://rustup.rs).
> Run `cargo build --release` in `packages/arken-auth-py/rust/` before first use.

## Usage

```python
from arken_client import create_client

client = create_client()                # fresh secp256k1 key pair
print(client.did)                       # did:key:zQ3s...
print(client.private_key_hex)          # persist this to reuse the DID

response = await client.fetch("https://api.example.com/protected")
# automatically handles 401 → sign → retry
```

## Bring your own key

```python
import os
from arken_client import create_client

client = create_client(os.environ["AGENT_PRIVATE_KEY"])
print(client.did)   # deterministic from the key
```

## Security notes

- The client checks that `challenge.audience` matches the hostname of the URL
  being fetched. If they differ it refuses to sign (relay-attack protection).
- The client refuses to sign over plain HTTP unless the host is `localhost`.
  Pass `allow_http=True` only in development.

## License

Apache-2.0
