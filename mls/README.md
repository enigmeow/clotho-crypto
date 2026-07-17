# clotho-mls

Post-quantum end-to-end encryption for the [Endiavo](https://endiavo.com) messenger (internal
codename *Clotho*). A thin Rust wrapper around [OpenMLS](https://github.com/openmls/openmls)
(RFC 9420 — Messaging Layer Security), compiled to **WebAssembly** so all encryption happens
**client-side in the browser / mobile webview**. The server only ever moves opaque ciphertext.

This crate is the **crypto layer** of the app, kept deliberately self-contained (pure crypto — no
network, no storage, no application logic) so it can be reviewed, tested, and published on its own.

## What it does

- **Fully post-quantum ciphersuite.** `MLS_256_MLKEM1024_AES256GCM_SHA384_MLDSA87`, via the
  **RustCrypto** (`openmls_rust_crypto`) provider — **ML-KEM-1024** (NIST FIPS 203) for key
  agreement and **ML-DSA-87** (NIST FIPS 204) for signatures, AES-256-GCM AEAD. Both the
  harvest-now-decrypt-later threat (KEM) and future signature forgery are closed for the MLS leaf.
  (The Clotho *identity* key that signs device certificates and auth challenges stays Ed25519 for
  now — see the crate's `CLAUDE.md`.)
- **Per-device identity.** The MLS signature key is a per-device **ML-DSA-87** key; a device
  certificate signed by the user's root Ed25519 identity key binds `device_pubkey → identity`, so
  one identity runs multiple device leaves and messages are spoof-proof-attributable to an identity
  key, never a self-asserted id.
- **Full group lifecycle** — create, staged add/remove commits (server-sequenced, fork-resistant),
  encrypt/decrypt, Welcome processing, per-device revocation, serialize/restore.
- **Panic-safe boundary.** Every method that touches attacker-controlled bytes returns `Result`
  rather than panicking, so a malformed peer message can't brick the client.

## Layout

- `src/lib.rs` — the entire crate. Each `#[wasm_bindgen]` method has a plain-Rust `*_native` twin;
  `cargo test` exercises the twins with no wasm, no JS, no browser.
- Builds to two wasm targets via [`wasm-pack`](https://github.com/rustwasm/wasm-pack): `--target web`
  (browser) and `--target nodejs` (test harness).

## Build & test

```bash
cargo test                                    # crypto correctness (native twins; fast, no wasm)
cargo build --target wasm32-unknown-unknown   # confirm it compiles to wasm
wasm-pack build --target web                  # → pkg/  (browser bundle)
wasm-pack build --target nodejs               # → pkg-node/  (node/test bundle)
```

Toolchain notes (getrandom wasm backends, the draft-ciphersuite feature flags, the OpenMLS pin) live
in [`CLAUDE.md`](CLAUDE.md) next to this file.

## Security posture

The server is **untrusted** by design: it sees rosters, timing, and message sizes, but never
plaintext. Confidentiality rests on the client-side MLS state and the ML-KEM-1024 KEM. Keys and
group state are persisted by the host app (out of scope for this crate); at-rest encryption of that
store is the host's responsibility.

## License

MIT (placeholder — see `LICENSE`). Upstream OpenMLS and the RustCrypto crates are separately
licensed and public.
