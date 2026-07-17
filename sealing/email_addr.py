# ⚠️ PUBLISHED CRYPTO SOURCE — kept byte-for-byte in sync with the public `clotho-crypto` repo
# (EAR §742.15(b) publicly-available-source decontrol). Any edit here MUST be mirrored to that repo in
# the SAME change; if it alters crypto behavior, re-send the BIS/NSA notification. See CLAUDE.md →
# "Published crypto mirror".
"""Email handling for the registration gate (Project 1). Mirrors app.phone: the address is NEVER
persisted raw — only an HMAC blind index (one-account-per-email dedup) + a sealed box (offline
Caly+Josh key). Reuses CLOTHO_PHONE_INDEX_KEY (domain-separated with a b"email:" prefix) and the
phone seal key, so no new secrets are introduced."""
from __future__ import annotations

import re

from app import crypto
from app.config import settings


class EmailError(ValueError):
    """An email address couldn't be normalized/validated."""


_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def normalize_email(raw: str) -> str:
    """Trim + lowercase + validate a single local@domain.tld. Raises EmailError otherwise. No MX
    lookup — control of the address is proven by the OTP. Determinism matters: the same address must
    always normalize identically or the blind index won't dedup."""
    if not raw or not raw.strip():
        raise EmailError("empty email")
    s = raw.strip().lower()
    if not _EMAIL_RE.match(s):
        raise EmailError("invalid email address")
    return s


def email_index(addr: str) -> bytes:
    """Blind index: HMAC-SHA256(b"email:" + addr, server secret). The "email:" prefix domain-separates
    it from the phone index so the two channels can't collide or cross-correlate. Crypto in app.crypto."""
    key = settings.phone_index_key
    if not key:
        raise EmailError("email verification not configured (CLOTHO_PHONE_INDEX_KEY unset)")
    return crypto.blind_index(key, addr, domain=b"email:")


def email_configured() -> bool:
    """Both the index key and the seal public key must be present (email reuses the phone secrets)."""
    return bool(settings.phone_index_key and settings.phone_seal_pubkey)


def is_reviewer_email(addr: str) -> bool:
    """True iff `addr` (already normalized) is a configured Play-review address AND the fixed reviewer
    code is set — fail closed unless BOTH knobs are live (mirror of phone.is_breakglass). Configured
    addresses are normalized the same way, so comparison is exact."""
    if not settings.reviewer_emails or not settings.reviewer_email_code:
        return False
    configured = set()
    for raw in settings.reviewer_emails.split(","):
        try:
            configured.add(normalize_email(raw))
        except EmailError:
            continue   # a malformed entry never matches anything
    return addr in configured
