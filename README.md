# clotho-crypto

Published **encryption source code** for **Endiavo** (the app) / **Clotho** (its engine). This
repository exists so the cryptography Endiavo ships is available as public source. It is a **source
mirror for transparency and export-compliance**, not a packaged, separately-installable library —
the code here is developed in the main application repository and copied here.

## What's here

| Path | What it is |
|---|---|
| [`mls/`](mls/) | The **`clotho-mls`** crate — post-quantum **MLS** (Messaging Layer Security, [RFC 9420](https://www.rfc-editor.org/rfc/rfc9420)) compiled to WebAssembly. This is the end-to-end group-messaging core. Built on [OpenMLS](https://github.com/openmls/openmls) + [libcrux](https://github.com/cryspen/libcrux). |
| [`sealing/`](sealing/) | The server-side primitives: libsodium **sealed boxes**, an **HMAC-SHA256 blind index**, **AES-256-GCM**, digest helpers, and **ML-DSA-87 signature verification** for post-quantum identity auth. Source-for-visibility — see [`sealing/README.md`](sealing/README.md); these files are **not** standalone-buildable. |

## Cryptography

Messaging uses the **fully post-quantum** MLS ciphersuite
**`MLS_256_MLKEM1024_AES256GCM_SHA384_MLDSA87`** — **ML-KEM-1024** key agreement, **ML-DSA-87**
signatures, AES-256-GCM AEAD, SHA-384. Both post-quantum threats are closed for the MLS leaf: the
harvest-now-decrypt-later risk (KEM) and future signature forgery (signatures).

**The identity layer is post-quantum too.** Since the 2026 identity migration, the root identity key
and the per-device certificates that bind each device's messaging key to a user are **ML-DSA-87**, as
is the login-challenge signature — so the whole trust chain, authentication *and* MLS-leaf
attribution, is PQ. (Pre-migration Ed25519 identity certificates are rejected outright rather than
accepted as a fallback.) The at-rest / PII layer adds libsodium sealed boxes and an HMAC blind index.

| Primitive | Where | Standard / publication |
|---|---|---|
| ML-KEM-1024 (KEM) | MLS messaging | [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final) (NIST PQC) |
| ML-DSA-87 (signatures) | MLS messaging · identity keys · device certs · login challenge | [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final) (NIST PQC) |
| AES-256-GCM | MLS AEAD · blob store | FIPS 197 / NIST SP 800-38D |
| SHA-384 / SHA-256 | MLS KDF · digests · device ids | FIPS 180-4 |
| MLS protocol | messaging | [RFC 9420](https://www.rfc-editor.org/rfc/rfc9420) |
| X25519 + XSalsa20-Poly1305 | `sealing/` sealed boxes | [RFC 7748](https://www.rfc-editor.org/rfc/rfc7748) + libsodium |
| HMAC-SHA256 | `sealing/` blind index | FIPS 198-1 / FIPS 180-4 |
| Ed25519 | verification of legacy pre-migration identity signatures only | [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032) |

All primitives are published, industry-standard algorithms. The ML-KEM-1024 + ML-DSA-87 MLS
ciphersuite is a draft ciphersuite pinned to the OpenMLS implementation.

## ⚠️ No secrets are in this repository

This is **algorithms, not keys.** Every secret — the blind-index HMAC key, the sealed-box private
key, session secrets — is supplied at runtime from the deployment environment and is **never** stored
in source. The security of the blind index rests on the secrecy of its key, not on the secrecy of the
method (which is standard HMAC). Publishing this code does not weaken any deployed Endiavo instance.

## Export compliance

This source is published as **publicly available encryption source code** under
[15 CFR §742.15(b)](https://www.ecfr.gov/current/title-15/subtitle-B/chapter-VII/subchapter-C/part-742/section-742.15)
and [§734.7](https://www.ecfr.gov/current/title-15/subtitle-B/chapter-VII/subchapter-C/part-734/section-734.7).
Per §742.15(b), the URL of this source is notified to BIS (`crypt@bis.doc.gov`) and the NSA ENC
Request Coordinator (`enc@nsa.gov`); the notification is re-sent when the cryptographic functionality
changes.

## License

[MIT](LICENSE). Upstream OpenMLS and libcrux carry their own licenses.
