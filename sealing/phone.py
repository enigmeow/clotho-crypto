"""Phone-number handling for the registration gate (Z3 / open-thread T9).

The raw number is NEVER persisted. It exists only in memory during a verify request, then is
reduced to two stored values:
  - phone_index: HMAC-SHA256(e164, secret) — a *blind index* for one-account-per-person + ban
    checks. Not reversible without the key (and even with it, only confirms a guessed number).
  - phone_sealed: a libsodium sealed box of e164 to an offline public key. Only the matching
    private key (held offline by Caly + Josh) can open it — the server can't. This is the Z3/T1
    "sealed attestation under governance" envelope.
"""
from __future__ import annotations

import re
import secrets

from app import crypto
from app.config import settings


class PhoneError(ValueError):
    """A phone number couldn't be normalized/validated."""


def normalize_e164(raw: str) -> str:
    """Best-effort E.164 normalization (US-first).

    Accepts a leading '+' with country code, a bare 10-digit US number (assumes +1), or 11 digits
    starting with 1. Raises PhoneError on anything implausible.

    Intentionally minimal — production should use the `phonenumbers` library (Google
    libphonenumber) for real validation + international canonicalization (hardening follow-up). The
    one hard requirement here is determinism: the same input must always normalize to the same
    string, or the blind index won't dedup.
    """
    if not raw or not raw.strip():
        raise PhoneError("empty phone number")
    s = raw.strip()
    plus = s.startswith("+")
    digits = re.sub(r"\D", "", s)
    if plus:
        if not (8 <= len(digits) <= 15):
            raise PhoneError("invalid international number")
        return "+" + digits
    if len(digits) == 10:                      # bare US number
        return "+1" + digits
    if len(digits) == 11 and digits.startswith("1"):
        return "+" + digits
    raise PhoneError("expected a 10-digit US number or +<country code><number>")


def phone_index(e164: str) -> bytes:
    """Blind index: HMAC-SHA256(number, server secret). Crypto in app.crypto; this wraps it with the
    app's config + error semantics."""
    key = settings.phone_index_key
    if not key:
        raise PhoneError("phone verification not configured (CLOTHO_PHONE_INDEX_KEY unset)")
    return crypto.blind_index(key, e164)


def seal_text(plaintext: str) -> bytes:
    """Seal an arbitrary string (a phone number, a real name, …) to the offline governance public
    key. Only the Caly + Josh private key can open it (scripts/phone_unseal.py). The server holds
    only the public key, so it can encrypt but never decrypt."""
    pub_b64 = settings.phone_seal_pubkey
    if not pub_b64:
        raise PhoneError("sealing not configured (CLOTHO_PHONE_SEAL_PUBKEY unset)")
    return crypto.seal(pub_b64, plaintext)


def seal_phone(e164: str) -> bytes:
    """Sealed box of the number to the offline public key — only Caly + Josh's private key opens it."""
    return seal_text(e164)


def seal_configured() -> bool:
    """The offline seal public key is present (needed to seal any governance-held PII)."""
    return bool(settings.phone_seal_pubkey)


def gen_code() -> str:
    """A 6-digit numeric verification code."""
    return f"{secrets.randbelow(1_000_000):06d}"


def hash_code(code: str) -> bytes:
    """HMAC the OTP with the server secret so a DB leak doesn't expose the (low-entropy) code.
    Compare with hmac.compare_digest. L-9: domain-separated with a b"otp:" prefix so the OTP hash lives
    in its own namespace from phone_index / email_index (which share this key) — no cross-namespace
    confusion, and OTP-hash rotation isn't coupled to index-key rotation."""
    key = settings.phone_index_key
    if not key:
        raise PhoneError("phone verification not configured (CLOTHO_PHONE_INDEX_KEY unset)")
    return crypto.blind_index(key, code, domain=b"otp:")


def phone_configured() -> bool:
    """Both the index key and the seal public key must be present to verify phones."""
    return bool(settings.phone_index_key and settings.phone_seal_pubkey)


def _breakglass_map() -> dict[str, str]:
    """Normalized E.164 → the code to accept for it. Entries in CLOTHO_BREAKGLASS_NUMBERS are either
    `number` (uses the shared CLOTHO_BREAKGLASS_CODE) or `number:code` (its own code, so different
    test accounts can have distinct codes). Empty unless both the numbers and a default code are set."""
    if not (settings.breakglass_numbers and settings.breakglass_code):
        return {}
    out: dict[str, str] = {}
    for raw in settings.breakglass_numbers.split(","):
        raw = raw.strip()
        if not raw:
            continue
        num, _, code = raw.partition(":")
        try:
            out[normalize_e164(num.strip())] = code.strip() or settings.breakglass_code
        except PhoneError:
            continue
    return out


def breakglass_numbers() -> set[str]:
    """Normalized E.164 numbers that SKIP real SMS (founder/admin/test break-glass)."""
    return set(_breakglass_map().keys())


def _demo_map() -> dict[str, str]:
    """Normalized E.164 → the code to accept, for CLOTHO_DEMO_NUMBERS. Same `number` or `number:code`
    format as break-glass: bare uses the shared CLOTHO_BREAKGLASS_CODE, `number:code` sets its own.
    Demo accounts land in the isolated DEMO world and ride the break-glass path (skip SMS + dedup)."""
    out: dict[str, str] = {}
    for raw in (settings.demo_numbers or "").split(","):
        raw = raw.strip()
        if not raw:
            continue
        num, _, code = raw.partition(":")
        c = code.strip() or settings.breakglass_code
        if not c:   # #17: never register an EMPTY accepted code (bare demo number + no breakglass_code)
            continue
        try:
            out[normalize_e164(num.strip())] = c
        except PhoneError:
            continue
    return out


def _demo_venue_map() -> dict[str, str]:
    """Normalized E.164 → code, for CLOTHO_DEMO_VENUE_NUMBERS. These are demo numbers too (isolated demo
    world, ride break-glass), but on login they become the seeded venue's OPERATOR account — see
    is_demo_venue_number + the demo-login branch in main.post_phone_verify. Same number:code format."""
    out: dict[str, str] = {}
    for raw in (settings.demo_venue_numbers or "").split(","):
        raw = raw.strip()
        if not raw:
            continue
        num, _, code = raw.partition(":")
        c = code.strip() or settings.breakglass_code
        if not c:   # #17: never register an EMPTY accepted code (bare demo number + no breakglass_code)
            continue
        try:
            out[normalize_e164(num.strip())] = c
        except PhoneError:
            continue
    return out


def demo_numbers() -> set[str]:
    return set(_demo_map().keys()) | set(_demo_venue_map().keys())


def is_demo_number(e164: str) -> bool:
    return e164 in _demo_map() or e164 in _demo_venue_map()


def is_demo_venue_number(e164: str) -> bool:
    """A demo number that logs in as the Friends On The Hill VENUE operator (not a plain presenter)."""
    return e164 in _demo_venue_map()


def is_breakglass(e164: str) -> bool:
    # Demo numbers (presenter + venue) ride the break-glass path (skip SMS + dedup); their code comes
    # from the demo maps.
    return e164 in _breakglass_map() or is_demo_number(e164)


def breakglass_code_for(e164: str) -> str:
    """The code to accept — a break-glass number's own, a demo number's own, or the shared default."""
    return (_breakglass_map().get(e164) or _demo_map().get(e164)
            or _demo_venue_map().get(e164) or settings.breakglass_code)
