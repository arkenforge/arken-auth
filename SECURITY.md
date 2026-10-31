# Security Policy

## Scope

The following are in scope:

- Signature verification bypass (forging authentication without a valid key)
- Nonce replay attacks
- DID parsing that incorrectly accepts a key it should reject
- Memory safety issues in the Rust FFI layer
- Timing attacks against the verification logic

The following are out of scope:

- Issues requiring physical access to the server
- Denial of service via nonce store exhaustion (known limitation; see README)
- Vulnerabilities in dependencies not introduced by this project

## Reporting a Vulnerability

Please report security issues privately using GitHub's built-in advisory system:

**[Open a private security advisory](https://github.com/zacharybenson/arken-protocol/security/advisories/new)**

Do not open a public issue for security vulnerabilities.

Include as much detail as you can: the affected component, steps to reproduce, and the potential impact. You will receive a response within 72 hours.

## Hall of Finders

*Everyone who finds and responsibly discloses a verified security flaw is credited here.*

| Researcher | Finding | Date |
|---|---|---|
| — | — | — |
