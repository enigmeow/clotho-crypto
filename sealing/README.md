# sealing — at-rest / PII protection primitives

Source-for-visibility copies of Endiavo's at-rest cryptography. These files are developed in the main
application repository (`backend/app/`) and mirrored here as published encryption source.

**These are not standalone-buildable.** They import the rest of the application (config, models) and
are shown here for source transparency, not as an installable package.

| File | What it does |
|---|---|
| `crypto.py` | The primitive layer: libsodium **sealed boxes** (X25519 + XSalsa20-Poly1305), an **HMAC-SHA256 blind index**, **AES-256-GCM**, and SHA-256 digest helpers for opaque bearer secrets. |
| `phone.py` | Applies the primitives to a phone number: a **blind index** (`HMAC-SHA256(E.164, server_key)`) for one-account-per-person / ban checks **without storing the number**, plus a **sealed box** openable only by an offline private key. |
| `email_addr.py` | The email twin of `phone.py` — same blind-index + sealed-box design over an email address (domain-separated from the phone index). |

## The design in one line

Identifiers (phone, email) are **never stored raw**. Each is kept only as (1) an irreversible
**blind index** — a keyed HMAC, so duplicate/ban checks work without the server holding the value —
and (2) a **sealed box** to an offline public key, openable only with a private key held outside the
running system.

**No keys live here.** The HMAC key and the seal keypair are runtime configuration. The blind index's
strength is its secret key, not the (standard, published) HMAC construction.
