# ⚠️ PUBLISHED CRYPTO SOURCE — kept byte-for-byte in sync with the public `clotho-crypto` repo
# (EAR §742.15(b) publicly-available-source decontrol). Any edit here MUST be mirrored to that repo in
# the SAME change; if it alters crypto behavior, re-send the BIS/NSA notification. See CLAUDE.md →
# "Published crypto mirror".
"""ML-DSA-87 (FIPS 204) signatures, isolated behind one module.

The frontend signs identity/auth challenges with the RustCrypto `ml-dsa` crate compiled to wasm
(`frontend/mls-crypto`); the backend verifies them here with dilithium-py. Byte-compatibility between
the two implementations is the load-bearing contract — proven by the cross-impl KAT in
`tests/test_pqsig.py` (a vector produced by the crate). The dependency is confined to this file so the
library can be swapped (e.g. to liboqs) without touching `auth.py`. See
`docs/superpowers/specs/2026-06-22-messaging-pq-identity-auth-design.md` (Slices B/C).

Production only ever calls `verify_mldsa`; `mldsa_keypair`/`_sign_for_test` exist for tests + fixtures.
"""
from __future__ import annotations

from dilithium_py.ml_dsa import ML_DSA_87


def verify_mldsa(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """True iff `signature` is a valid ML-DSA-87 signature over `message` by `public_key`.

    Never raises: the key/signature are attacker-suppliable on the auth path, so any malformed input
    returns False rather than crashing the endpoint (mirrors the crate's non-panicking verify twin).
    """
    try:
        return bool(ML_DSA_87.verify(public_key, message, signature))
    except Exception:  # noqa: BLE001 — a bad key/sig must degrade to "invalid", never to a 500
        return False


def mldsa_keypair(seed: bytes) -> tuple[bytes, bytes]:
    """Derive the (public_key, secret_key) pair from a 32-byte seed — byte-identical to the crate's
    `mldsa87_public_from_seed`. Test/fixture helper."""
    pk, sk = ML_DSA_87.key_derive(seed)
    return pk, sk


def _sign_for_test(secret_key: bytes, message: bytes) -> bytes:
    """Sign `message` with an ML-DSA-87 secret key (empty FIPS-204 context). Test fixtures only."""
    return ML_DSA_87.sign(secret_key, message)
