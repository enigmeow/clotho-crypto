"""Pure cryptographic primitives — the publishable crypto layer (see docs/export.md §2, Path A).

This module is deliberately dependency-free of the rest of the app: no config, no DB, no HTTP, no
application logic (in particular, none of the break-glass / onboarding logic that lives in phone.py).
It is just the standard-crypto building blocks the app composes, so it can be published as
publicly-available encryption source (§742.15(b) decontrol) WITHOUT exposing the surrounding
proprietary code. Only Python stdlib + PyNaCl (libsodium) are used.

Primitives:
  - blind_index: HMAC-SHA256(key, domain + value) — a deterministic, non-reversible index that lets
    the app dedup / look up a secret value (a phone number, an email) without storing it. Used for
    one-account-per-person, ban checks, and OTP hashing. Determinism is load-bearing: the same input
    must always produce the same bytes, or dedup silently breaks.
  - seal / unseal: libsodium sealed box (X25519 + XSalsa20-Poly1305) — anonymous public-key
    encryption. The app seals PII to an OFFLINE public key, so the online server can encrypt but can
    never decrypt; only the offline private-key holder can open it. `seal` is non-deterministic
    (fresh ephemeral key per call), so it is never used where a stable value is needed — that's what
    blind_index is for.
"""
from __future__ import annotations

import base64
import hashlib
import hmac

import nacl.exceptions
import nacl.public
import nacl.signing


def blind_index(key: str, value: str | bytes, *, domain: bytes = b"") -> bytes:
    """HMAC-SHA256(key, domain + value). `domain` prefixes the MESSAGE (not the key) so that several
    namespaces sharing one key (e.g. phone vs. b"email:") can't collide or cross-correlate."""
    msg = domain + (value.encode() if isinstance(value, str) else value)
    return hmac.new(key.encode(), msg, hashlib.sha256).digest()


def seal(public_key_b64: str, plaintext: str | bytes) -> bytes:
    """Anonymous sealed box to a base64-encoded X25519 public key. Non-deterministic; only the holder
    of the matching private key can open it (see `unseal`)."""
    pub = nacl.public.PublicKey(base64.b64decode(public_key_b64))
    data = plaintext.encode() if isinstance(plaintext, str) else plaintext
    return nacl.public.SealedBox(pub).encrypt(data)


def unseal(private_key_b64: str, sealed: bytes) -> bytes:
    """Open a sealed box with a base64-encoded X25519 private key. In production the private key is
    held OFFLINE (not by the server) — this is here for completeness + testability of the primitive."""
    sk = nacl.public.PrivateKey(base64.b64decode(private_key_b64))
    return nacl.public.SealedBox(sk).decrypt(sealed)


def verify_ed25519(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """True iff `signature` is a valid Ed25519 signature over `message` by `public_key`. Returns
    False (never raises) on a bad signature OR malformed key/signature bytes — the caller treats
    any failure as "unauthenticated". This is the primitive behind the identity challenge-response
    auth (the app prepends its own domain-separation tag to `message`)."""
    try:
        nacl.signing.VerifyKey(public_key).verify(message, signature)
        return True
    except (nacl.exceptions.BadSignatureError, nacl.exceptions.CryptoError, ValueError):
        return False


def hash_secret(value: str | bytes) -> bytes:
    """SHA-256 of an opaque bearer secret (a session token, a share-link capability secret) so only
    its digest is stored — a DB leak then can't replay the secret. NOT for low-entropy inputs a
    dictionary attack could reverse (a phone number, an OTP) — use blind_index (keyed) for those."""
    data = value.encode() if isinstance(value, str) else value
    return hashlib.sha256(data).digest()


def constant_time_eq(a: str | bytes, b: str | bytes) -> bool:
    """Constant-time equality (hmac.compare_digest) — compare a presented secret/hash against the
    stored one without leaking a match position via timing. str args are UTF-8 encoded first so the
    comparison is always bytes-vs-bytes."""
    a_bytes = a.encode() if isinstance(a, str) else a
    b_bytes = b.encode() if isinstance(b, str) else b
    return hmac.compare_digest(a_bytes, b_bytes)
