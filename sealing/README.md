# sealing — server-side primitives: at-rest / PII protection + PQ signature verification

Source-for-visibility copies of Endiavo's server-side cryptography. These files are developed in the
main application repository (`backend/app/`) and mirrored here as published encryption source.

**These are not standalone-buildable.** They import the rest of the application (config, models) and
are shown here for source transparency, not as an installable package.

| File | What it does |
|---|---|
| `crypto.py` | The primitive layer: libsodium **sealed boxes** (X25519 + XSalsa20-Poly1305), an **HMAC-SHA256 blind index**, **AES-256-GCM**, and SHA-256 digest helpers for opaque bearer secrets. |
| `phone.py` | Applies the primitives to a phone number: a **blind index** (`HMAC-SHA256(E.164, server_key)`) for one-account-per-person / ban checks **without storing the number**, plus a **sealed box** openable only by an offline private key. |
| `email_addr.py` | The email twin of `phone.py` — same blind-index + sealed-box design over an email address (domain-separated from the phone index). |
| `pqsig.py` | **ML-DSA-87** ([FIPS 204](https://csrc.nist.gov/pubs/fips/204/final)) signature **verification** — the server half of post-quantum identity auth. The client signs a login challenge with the ML-DSA key held on the device (minted by [`../mls/`](../mls/)); this verifies it. **Verification only:** no signing key reaches the server, and `verify_mldsa` returns `False` rather than raising on malformed, attacker-suppliable input. Byte-compatibility with the Rust crate is the load-bearing contract, held by a cross-implementation known-answer test. |

## The design in one line

*(applies to the identifier files — `pqsig.py` is signature verification, not identifier protection)*

Identifiers (phone, email) are **never stored raw**. Each is kept only as (1) an irreversible
**blind index** — a keyed HMAC, so duplicate/ban checks work without the server holding the value —
and (2) a **sealed box** to an offline public key, openable only with a private key held outside the
running system.

**No keys live here.** The HMAC key and the seal keypair are runtime configuration. The blind index's
strength is its secret key, not the (standard, published) HMAC construction.
