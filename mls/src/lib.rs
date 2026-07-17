use std::collections::HashMap;

use openmls::prelude::tls_codec::*;
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use wasm_bindgen::prelude::*;

const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_256_MLKEM1024_AES256GCM_SHA384_MLDSA87;

#[wasm_bindgen]
pub fn ping() -> String {
    "clotho-mls ok".to_string()
}

/// Sign a device cert with the identity seed (JS: `mint_device_cert(identity_seed, identity_uuid,
/// device_pubkey)`). The enrolling client holds the identity seed and authorizes a device key.
#[wasm_bindgen]
pub fn mint_device_cert(identity_seed: &[u8], identity_uuid: String, device_pubkey: &[u8]) -> Result<js_sys::Uint8Array, JsError> {
    // Validate untrusted lengths at the boundary (security-audit 2026-07-05 L-3) so a wrong-size seed
    // or device key is a JsError, never a panic across the wasm boundary — matching every sibling
    // seed export (they all go through `require_seed32`). The infallible `*_native` twin keeps its
    // 32-byte / non-empty-pubkey contract for the crate's own trusted callers.
    require_seed32(identity_seed)?;
    if device_pubkey.is_empty() || device_pubkey.len() > u16::MAX as usize {
        return Err(JsError::new("device_pubkey must be 1..=65535 bytes"));
    }
    Ok(js_sys::Uint8Array::from(&mint_device_cert_native(identity_seed, &identity_uuid, device_pubkey)[..]))
}

// The seed-derivation wasm exports below validate length and return a JS error (never panic) on a
// wrong-size seed. The `*_native` twins keep an infallible 32-byte contract for the crate's own
// trusted callers (new_native/restore_native, whose seed comes from secure storage); the wasm
// boundary is where a future (Slice B/C) or malformed caller could feed untrusted bytes, so it is
// hardened here — consistent with the crate's "no panics across the wasm boundary" invariant.
fn require_seed32(seed: &[u8]) -> Result<(), JsError> {
    if seed.len() == 32 { Ok(()) } else { Err(JsError::new("seed must be 32 bytes")) }
}

/// Derive a device's ML-DSA-87 verifying key from its 32-byte seed (JS: `mldsa87_public_from_seed(seed)`).
#[wasm_bindgen]
pub fn mldsa87_public_from_seed(seed: &[u8]) -> Result<Vec<u8>, JsError> {
    require_seed32(seed)?;
    Ok(mldsa87_public_from_seed_native(seed))
}

/// Derive a device's routing id (SHA-256 of its ML-DSA-87 leaf pubkey) from its seed alone — used by
/// the enrollment QR (JS: `device_id_from_seed(seed)`).
#[wasm_bindgen]
pub fn device_id_from_seed(seed: &[u8]) -> Result<Vec<u8>, JsError> {
    require_seed32(seed)?;
    Ok(device_id_from_seed_native(seed))
}

/// The ML-DSA-87 identity sign/verify surface the Slice-B/C identity-auth migration consumes
/// (JS: `mldsa87_sign(seed, msg)` / `mldsa87_verify(public_key, msg, sig)`). The 2026-07-05 audit's
/// L-4 had this export REMOVED "until Slice B/C needs it" — Slice B/C is now integrated and drives
/// identity auth from JS (`identity.ts`: auth-challenge + rekey signing), so the export is restored.
///
/// ⚠️ IDENTITY-SEED USE ONLY. `seed` MUST be the root identity seed, never a device seed: a device
/// seed is the live MLS leaf signer, and this function signs arbitrary caller-supplied bytes with no
/// domain separation from MLS leaf signing — feeding it the device seed turns it into an
/// arbitrary-bytes signing oracle over the group's leaf key (a cross-protocol forgery primitive).
/// The identity-auth layer supplies its own domain-separated framing at the caller (`clotho-auth:` /
/// `clotho-rekey:v1:`); this function adds none. (L-4 residual — accepted, documented tradeoff.)
#[wasm_bindgen]
pub fn mldsa87_sign(seed: &[u8], msg: &[u8]) -> Result<Vec<u8>, JsError> {
    require_seed32(seed)?;
    Ok(mldsa87_sign_native(seed, msg))
}

#[wasm_bindgen]
pub fn mldsa87_verify(public_key: &[u8], msg: &[u8], sig: &[u8]) -> bool { mldsa87_verify_native(public_key, msg, sig) }

/// The result of processing an incoming MLS message.
pub struct ProcessResult {
    pub kind: String,            // "application" | "commit" | "other"
    pub plaintext: Option<Vec<u8>>,
    // The cert's `identity_uuid` — CONVENIENCE only. It is self-asserted in the cert, so a malicious
    // member can claim any uuid; do NOT trust it for security-critical attribution.
    pub sender: Option<String>,
    // The cert's `identity_pubkey` (hex) — the SPOOF-PROOF sender identity. A member can only present
    // a cert self-signed by their own identity key, so this can't be forged to be another identity.
    // Attribution MUST key on this (the TS maps it to a known contact).
    pub sender_pubkey: Option<String>,
}

/// A per-identity MLS client. The MLS signature key is the user's existing Ed25519
/// identity key (so KeyPackages are self-authenticating against the registered key).
#[wasm_bindgen]
pub struct MlsClient {
    provider: OpenMlsRustCrypto,
    signer: SignatureKeyPair,
    credential: CredentialWithKey,
    groups: HashMap<Vec<u8>, MlsGroup>,
}

// ML-KEM-1024 + ML-DSA-87 is a draft ciphersuite, so we must explicitly advertise it in the leaf-node
// capabilities or add-member validation rejects our KeyPackages.
fn pq_capabilities() -> Capabilities {
    // Advertise the CIPHERSUITE (ValSem105, see CLAUDE.md) AND the last_resort KeyPackage extension —
    // without the latter, a last-resort KP fails add-validation with UnsupportedExtension.
    Capabilities::new(None, Some(&[CIPHERSUITE]), Some(&[ExtensionType::LastResort]), None, None)
}

// Self-contained Welcomes: include the ratchet tree so a joiner needs nothing out-of-band.
fn create_config() -> MlsGroupCreateConfig {
    MlsGroupCreateConfig::builder()
        .ciphersuite(CIPHERSUITE)   // else the group defaults to the classical MTI suite
        .use_ratchet_tree_extension(true)
        .capabilities(pq_capabilities())
        .build()
}

// Joiners must keep the ratchet-tree-extension ON too, so a Welcome THEY later send (e.g. a non-admin
// reconciling in a peer's new device) carries the tree — else the new joiner hits "No ratchet tree
// available". Default join config leaves it off, which only mattered once reconcile let non-creators add.
fn join_config() -> MlsGroupJoinConfig {
    MlsGroupJoinConfig::builder()
        .use_ratchet_tree_extension(true)
        .build()
}

impl MlsClient {
    /// Build a fresh client. Returns `Err` (NOT panic) on a storage failure so the wasm `new`
    /// constructor never unwinds across the boundary (security-audit 2026-07-05 L-2, paired with
    /// `restore`'s corrupt-blob handling). The seed is trusted (from secure storage), so its size is
    /// the caller's contract, exactly as for the other `*_native` twins.
    pub fn new_native(device_seed: &[u8], device_cert: &[u8]) -> Result<MlsClient, String> {
        let public = mldsa87_public_from_seed_native(device_seed);
        let signer = SignatureKeyPair::from_raw(SignatureScheme::MLDSA87, device_seed.to_vec(), public);
        let provider = OpenMlsRustCrypto::default();
        signer.store(provider.storage()).map_err(|e| format!("store signer: {e:?}"))?;
        let credential = CredentialWithKey {
            credential: BasicCredential::new(device_cert.to_vec()).into(),
            signature_key: signer.public().into(),
        };
        Ok(MlsClient { provider, signer, credential, groups: HashMap::new() })
    }

    pub fn key_packages_native(&self, n: usize) -> Vec<Vec<u8>> {
        (0..n)
            .map(|_| {
                let bundle = KeyPackage::builder()
                    .leaf_node_capabilities(pq_capabilities())
                    .build(CIPHERSUITE, &self.provider, &self.signer, self.credential.clone())
                    .expect("build key package");
                bundle.key_package().tls_serialize_detached().expect("serialize kp")
            })
            .collect()
    }

    // A REUSABLE last-resort KeyPackage (marked with the last_resort extension). The directory hands
    // this out when a device's one-time packages are exhausted, so reconciliation can always add a
    // live device even after its one-times are drained (accepting the standard last-resort forward-
    // secrecy tradeoff) instead of leaving it unreachable.
    pub fn last_resort_key_package_native(&self) -> Vec<u8> {
        let bundle = KeyPackage::builder()
            .leaf_node_capabilities(pq_capabilities())
            .mark_as_last_resort()
            .build(CIPHERSUITE, &self.provider, &self.signer, self.credential.clone())
            .expect("build last-resort key package");
        bundle.key_package().tls_serialize_detached().expect("serialize last-resort kp")
    }

    pub fn signature_public_key_native(&self) -> Vec<u8> {
        self.signer.to_public_vec()
    }

    /// This device's id (SHA-256 of its ML-DSA-87 leaf pubkey) — the per-device routing key.
    pub fn device_id_native(&self) -> Vec<u8> {
        device_id(&self.signer.to_public_vec())
    }

    pub fn create_group_native(&mut self) -> Vec<u8> {
        let group = MlsGroup::new(&self.provider, &self.signer, &create_config(), self.credential.clone())
            .expect("create group");
        let gid = group.group_id().as_slice().to_vec();
        self.groups.insert(gid.clone(), group);
        gid
    }

    /// Add a member from their serialized KeyPackage. Returns (commit, welcome) bytes, or an
    /// `Err(String)` on ANY malformed/invalid input — it must NOT panic. KeyPackage bytes are fully
    /// attacker-controlled (the directory stores opaque base64 with no MLS validation), and a panic
    /// unwinds through the wasm-bindgen `&mut self` borrow without releasing it, POISONING the whole
    /// client ("recursive use of an object … unsafe aliasing") so every later call fails — a remote,
    /// repeatable client-bricking DoS (security-audit 2026-06-27 #1). A returned error lets the TS
    /// caller skip one bad peer KeyPackage and keep the client alive. Mirrors process_*_native.
    pub fn add_member_native(&mut self, gid: &[u8], kp_bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
        let kp = Self::validate_joiner_kp(self, kp_bytes, None)?;
        let group = self.groups.get_mut(gid).ok_or_else(|| "unknown group".to_string())?;
        let (commit, welcome, _gi) = group
            .add_members(&self.provider, &self.signer, &[kp])
            .map_err(|e| format!("add member: {e:?}"))?;
        group.merge_pending_commit(&self.provider).map_err(|e| format!("merge commit: {e:?}"))?;
        Ok((
            commit.tls_serialize_detached().map_err(|e| format!("serialize commit: {e:?}"))?,
            welcome.tls_serialize_detached().map_err(|e| format!("serialize welcome: {e:?}"))?,
        ))
    }

    /// Deserialize + validate one joiner KeyPackage and its device cert (T10): well-formed cert that
    /// authorizes exactly the key this leaf signs with. When `expected_identity` is `Some`, ALSO require
    /// the cert's `identity_uuid` to equal it — the claimed KeyPackage must belong to the identity the
    /// caller intended to add. Without this, the UNTRUSTED delivery server can answer a claim for peer P
    /// with a different (attacker) identity's valid self-signed KeyPackage, silently injecting a reader
    /// into a private conversation (security review, confidentiality). Returns `Err` (never panics).
    fn validate_joiner_kp(&self, kp_bytes: &[u8], expected_identity: Option<&str>) -> Result<KeyPackage, String> {
        let kp_in = KeyPackageIn::tls_deserialize_exact(kp_bytes)
            .map_err(|e| format!("deserialize key package: {e:?}"))?;
        let kp = kp_in
            .validate(self.provider.crypto(), ProtocolVersion::Mls10)
            .map_err(|e| format!("validate key package: {e:?}"))?;
        let leaf = kp.leaf_node();
        let cert = verify_device_cert(leaf.credential().serialized_content())
            .ok_or_else(|| "joiner: invalid device cert".to_string())?;
        if cert.device_pubkey.as_slice() != leaf.signature_key().as_slice() {
            return Err("joiner: cert device_pubkey != leaf signature_key".into());
        }
        if let Some(expected) = expected_identity {
            if cert.identity_uuid != expected {
                return Err("joiner: key package identity != expected peer".into());
            }
        }
        Ok(kp)
    }

    /// Add SEVERAL members in ONE commit (multi-device fan-out, Phase 0a Part 2): a single epoch
    /// change and a single Welcome that every added leaf can join from. Lets a peer reach all of an
    /// identity's device-leaves at once — and keeps the joiners' read cursor correct (one commit, so
    /// no intermediate epoch a late sibling would miss). Returns (commit, welcome).
    pub fn add_members_native(&mut self, gid: &[u8], kp_blobs: Vec<Vec<u8>>)
        -> Result<(Vec<u8>, Vec<u8>), String> {
        // Like add_member_native, returns Err (never panics) on any bad/attacker-controlled KeyPackage
        // so one malformed blob can't poison the client (security-audit 2026-06-27 #1).
        let mut kps = Vec::with_capacity(kp_blobs.len());
        for kp_bytes in &kp_blobs {
            kps.push(self.validate_joiner_kp(kp_bytes, None)?);
        }
        let group = self.groups.get_mut(gid).ok_or_else(|| "unknown group".to_string())?;
        let (commit, welcome, _gi) = group
            .add_members(&self.provider, &self.signer, &kps)
            .map_err(|e| format!("add members: {e:?}"))?;
        group.merge_pending_commit(&self.provider).map_err(|e| format!("merge commit: {e:?}"))?;
        Ok((
            commit.tls_serialize_detached().map_err(|e| format!("serialize commit: {e:?}"))?,
            welcome.tls_serialize_detached().map_err(|e| format!("serialize welcome: {e:?}"))?,
        ))
    }

    /// Build an add-members commit but DO NOT merge it locally (invariant 1, server-sequenced commits).
    /// The caller posts the commit to the server's sequenced log FIRST; on accept it calls
    /// `merge_staged_native`, on reject/failure `discard_staged_native`. This is what prevents a
    /// local epoch advance that the server never accepted (fork/brick — review #3/#4). Never panics on
    /// attacker-controlled KeyPackage input (returns Err). Returns (commit, welcome).
    pub fn stage_add_members_native(&mut self, gid: &[u8], kp_blobs: Vec<Vec<u8>>, expected_identity: &str)
        -> Result<(Vec<u8>, Vec<u8>), String> {
        // SKIP invalid KeyPackages instead of aborting the whole batch. A multi-device fan-out claims
        // one KeyPackage per device of the peer; a single stale/wrong-ciphersuite one (e.g. an
        // un-reloaded old-suite tab still publishing during the PQ flag-day window) must NOT block the
        // peer's other, valid devices from being added — `?`-aborting here would persistently wedge the
        // add (the stale reusable last-resort KP is re-claimed every reconcile and re-fails). We still
        // enforce `expected_identity` per KP, so a foreign leaf the untrusted server tries to substitute
        // is dropped, not added. Err only when NOTHING valid remains (caller has nothing to stage).
        let mut kps = Vec::with_capacity(kp_blobs.len());
        for kp_bytes in &kp_blobs {
            match self.validate_joiner_kp(kp_bytes, Some(expected_identity)) {
                Ok(kp) => kps.push(kp),
                Err(_) => continue,
            }
        }
        if kps.is_empty() {
            return Err("stage add members: no valid key packages".into());
        }
        let group = self.groups.get_mut(gid).ok_or_else(|| "unknown group".to_string())?;
        let (commit, welcome, _gi) = group
            .add_members(&self.provider, &self.signer, &kps)
            .map_err(|e| format!("stage add members: {e:?}"))?;   // stages a pending commit; NOT merged
        Ok((
            commit.tls_serialize_detached().map_err(|e| format!("serialize commit: {e:?}"))?,
            welcome.tls_serialize_detached().map_err(|e| format!("serialize welcome: {e:?}"))?,
        ))
    }

    /// Merge the previously-staged pending commit — the server accepted it (invariant 1).
    pub fn merge_staged_native(&mut self, gid: &[u8]) -> Result<(), String> {
        let group = self.groups.get_mut(gid).ok_or_else(|| "unknown group".to_string())?;
        group.merge_pending_commit(&self.provider).map_err(|e| format!("merge staged: {e:?}"))
    }

    /// Discard the previously-staged pending commit — the server rejected it or the post failed
    /// (invariant 1). No local epoch change, so a lost race / network blip can't fork this client.
    pub fn discard_staged_native(&mut self, gid: &[u8]) -> Result<(), String> {
        let group = self.groups.get_mut(gid).ok_or_else(|| "unknown group".to_string())?;
        group.clear_pending_commit(self.provider.storage()).map_err(|e| format!("discard staged: {e:?}"))
    }

    /// Process a Welcome and join the group. Returns the group id, or an `Err(String)` on ANY
    /// malformed/invalid input — it must NOT panic: a panic unwinds through the wasm-bindgen `&mut
    /// self` borrow without releasing it, poisoning the whole client ("recursive use of an object …
    /// unsafe aliasing") so every later call fails. A peer can post arbitrary welcome bytes
    /// (security-audit M2), so a returned error here is what lets the TS layer skip a bad welcome and
    /// keep processing the rest of the batch.
    pub fn process_welcome_native(&mut self, welcome_bytes: &[u8]) -> Result<Vec<u8>, String> {
        let msg = MlsMessageIn::tls_deserialize_exact(welcome_bytes)
            .map_err(|e| format!("deserialize welcome: {e}"))?;
        let welcome = match msg.extract() {
            MlsMessageBodyIn::Welcome(w) => w,
            _ => return Err("not a welcome message".into()),
        };
        let staged =
            StagedWelcome::new_from_welcome(&self.provider, &join_config(), welcome, None)
                .map_err(|e| format!("staged welcome: {e}"))?;
        let group = staged.into_group(&self.provider).map_err(|e| format!("join group: {e}"))?;
        // Validate every existing member's device cert on join (T10): well-formed + the cert must
        // authorize exactly the key this leaf signs with.
        for m in group.members() {
            let cert = verify_device_cert(m.credential.serialized_content())
                .ok_or_else(|| "welcome: invalid member device cert".to_string())?;
            if cert.device_pubkey.as_slice() != m.signature_key.as_slice() {
                return Err("welcome: member cert device_pubkey != leaf signature_key".into());
            }
        }
        let gid = group.group_id().as_slice().to_vec();
        self.groups.insert(gid.clone(), group);
        Ok(gid)
    }

    /// Encrypt an application message. Returns `Err` (NOT panic) on an unknown group / encrypt /
    /// serialize failure: the `gid` can be desynced from the wasm `groups` map (e.g. a group present
    /// in the TS `convos` map but absent here after a partial restore), and a panic would unwind
    /// through the wasm-bindgen `&mut self` borrow without releasing it, POISONING the whole client
    /// for every conversation until reload (security-audit 2026-07-05 L-1). A returned error lets the
    /// TS `send()` caller surface/skip the one failed send and keep the client alive.
    pub fn encrypt_native(&mut self, gid: &[u8], pt: &[u8]) -> Result<Vec<u8>, String> {
        let group = self.groups.get_mut(gid).ok_or_else(|| "unknown group".to_string())?;
        let msg = group.create_message(&self.provider, &self.signer, pt).map_err(|e| format!("encrypt: {e:?}"))?;
        msg.tls_serialize_detached().map_err(|e| format!("serialize message: {e:?}"))
    }

    /// Decrypt/apply one incoming message. Returns `Err` (NOT panic) on ANY malformed/invalid input:
    /// a peer (or the untrusted server) can hand us arbitrary bytes, and a panic would unwind through
    /// the wasm-bindgen `&mut self` borrow without releasing it, POISONING the whole client so every
    /// later call fails ("recursive use of an object … unsafe aliasing"). A returned error lets the TS
    /// receive loop skip the one bad message and keep the client alive (security-audit M2-class DoS).
    pub fn process_native(&mut self, gid: &[u8], msg_bytes: &[u8]) -> Result<ProcessResult, String> {
        let msg = MlsMessageIn::tls_deserialize_exact(msg_bytes)
            .map_err(|e| format!("deserialize message: {e}"))?;
        let protocol = msg.try_into_protocol_message().map_err(|e| format!("protocol message: {e}"))?;
        let group = self.groups.get_mut(gid).ok_or_else(|| "unknown group".to_string())?;
        let processed = group.process_message(&self.provider, protocol)
            .map_err(|e| format!("process message: {e}"))?;
        // Verify the sender's device cert on every message and attribute. `sender_pubkey` (the cert's
        // identity_pubkey) is the spoof-proof identity; `sender` (uuid) is self-asserted convenience.
        let cert = verify_device_cert(processed.credential().serialized_content());
        // M3: bind the cert's `device_pubkey` to the sender's ACTUAL leaf signature key. OpenMLS does
        // not pin a member's credential across self-Updates, so a joined member could self-Update a
        // cert whose `device_pubkey` is forged (≠ their real leaf key) — corrupting the device list
        // used for per-device revocation. Reject any such mismatch (drop the message, don't panic).
        if let Some(c) = &cert {
            if let Sender::Member(leaf_idx) = processed.sender() {
                let idx = *leaf_idx;
                let leaf_ok = group.members().any(|m| m.index == idx
                    && m.signature_key.as_slice() == c.device_pubkey.as_slice());
                if !leaf_ok {
                    return Err("message: cert device_pubkey != sender leaf signature key".into());
                }
            }
        }
        let sender = cert.as_ref().map(|c| c.identity_uuid.clone());
        let sender_pubkey = cert.as_ref().map(|c| hex_encode(&c.identity_pubkey));
        match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(app) => {
                Ok(ProcessResult { kind: "application".into(), plaintext: Some(app.into_bytes()), sender, sender_pubkey })
            }
            ProcessedMessageContent::StagedCommitMessage(staged) => {
                group.merge_staged_commit(&self.provider, *staged)
                    .map_err(|e| format!("merge staged commit: {e}"))?;
                Ok(ProcessResult { kind: "commit".into(), plaintext: None, sender, sender_pubkey })
            }
            _ => Ok(ProcessResult { kind: "other".into(), plaintext: None, sender, sender_pubkey }),
        }
    }

    /// Immediate (merge-on-build) remove by identity_uuid — evicts EVERY leaf of an identity. Returns
    /// `Err` (never panics) on unknown group / member-not-found / any MLS error: a panic here would
    /// unwind through the wasm-bindgen `&mut self` borrow and poison the whole client (the panic-poison
    /// DoS class the 2026-06-27 audit closed everywhere else). The staged twin
    /// (`stage_remove_member_native`) is the server-sequenced path the app uses; this immediate form is
    /// kept for the native crypto tests + completeness.
    pub fn remove_member_native(&mut self, gid: &[u8], identity_uuid: &str) -> Result<Vec<u8>, String> {
        let group = self.groups.get_mut(gid).ok_or_else(|| "unknown group".to_string())?;
        let target = group
            .members()
            .find(|m| verify_device_cert(m.credential.serialized_content())
                .map(|c| c.identity_uuid).as_deref() == Some(identity_uuid))
            .map(|m| m.index)
            .ok_or_else(|| "member not found".to_string())?;
        let (commit, _welcome, _gi) = group
            .remove_members(&self.provider, &self.signer, &[target])
            .map_err(|e| format!("remove member: {e:?}"))?;
        group.merge_pending_commit(&self.provider).map_err(|e| format!("merge commit: {e:?}"))?;
        commit.tls_serialize_detached().map_err(|e| format!("serialize commit: {e:?}"))
    }

    /// Immediate (merge-on-build) remove of ONE leaf — the one whose device id (SHA-256 of the cert's
    /// `device_pubkey`) matches the given hex (Phase 0a Part 2 per-device revocation). Unlike
    /// `remove_member` (by identity_uuid, which evicts EVERY leaf of an identity), this cuts off a
    /// single device while the identity's other devices keep working. Returns `Err` (never panics) —
    /// same panic-poison rationale as `remove_member_native`; the staged twin is the app's live path.
    pub fn remove_device_leaf_native(&mut self, gid: &[u8], device_id_hex: &str) -> Result<Vec<u8>, String> {
        let group = self.groups.get_mut(gid).ok_or_else(|| "unknown group".to_string())?;
        let target = group
            .members()
            .find(|m| member_device_id_hex(m.credential.serialized_content()).as_deref() == Some(device_id_hex))
            .map(|m| m.index)
            .ok_or_else(|| "device leaf not found".to_string())?;
        let (commit, _welcome, _gi) = group
            .remove_members(&self.provider, &self.signer, &[target])
            .map_err(|e| format!("remove device leaf: {e:?}"))?;
        group.merge_pending_commit(&self.provider).map_err(|e| format!("merge commit: {e:?}"))?;
        commit.tls_serialize_detached().map_err(|e| format!("serialize commit: {e:?}"))
    }

    /// Staged variants of the removes (invariant 1, server-sequenced commits): build a remove commit
    /// but DO NOT merge locally — the caller posts it with the CAS and then `merge_staged`/`discard_staged`
    /// on accept/reject, exactly like `stage_add_members`. This is what brings kicks + per-device
    /// revocation under the same fork-proof serialization as adds (final-review #1). Returns `Err`
    /// (never panics) on unknown group / target so a caller can recover instead of poisoning the client.
    pub fn stage_remove_member_native(&mut self, gid: &[u8], identity_uuid: &str) -> Result<Vec<u8>, String> {
        let group = self.groups.get_mut(gid).ok_or_else(|| "unknown group".to_string())?;
        let target = group
            .members()
            .find(|m| verify_device_cert(m.credential.serialized_content())
                .map(|c| c.identity_uuid).as_deref() == Some(identity_uuid))
            .map(|m| m.index)
            .ok_or_else(|| "member not found".to_string())?;
        let (commit, _welcome, _gi) = group
            .remove_members(&self.provider, &self.signer, &[target])
            .map_err(|e| format!("stage remove member: {e:?}"))?;   // stages a pending commit; NOT merged
        commit.tls_serialize_detached().map_err(|e| format!("serialize commit: {e:?}"))
    }

    pub fn stage_remove_device_leaf_native(&mut self, gid: &[u8], device_id_hex: &str) -> Result<Vec<u8>, String> {
        let group = self.groups.get_mut(gid).ok_or_else(|| "unknown group".to_string())?;
        let target = group
            .members()
            .find(|m| member_device_id_hex(m.credential.serialized_content()).as_deref() == Some(device_id_hex))
            .map(|m| m.index)
            .ok_or_else(|| "device leaf not found".to_string())?;
        let (commit, _welcome, _gi) = group
            .remove_members(&self.provider, &self.signer, &[target])
            .map_err(|e| format!("stage remove device leaf: {e:?}"))?;
        commit.tls_serialize_detached().map_err(|e| format!("serialize commit: {e:?}"))
    }

    /// List a group's leaves as (identity_uuid, device_id_hex) pairs (Phase 0a Part 2). Drives the
    /// "My devices" view (filter to your own identity_uuid → your device-leaves + which groups each is
    /// in) and lets revoke target only groups a device is actually in.
    pub fn group_members_native(&self, gid: &[u8]) -> Result<Vec<(String, String)>, String> {
        // #14 (2026-07-13): return Err instead of `.expect`-panicking — this was the ONE exported
        // instance method the L-1 panic sweep missed. A panic here unwinds through the wasm-bindgen
        // borrow guard without releasing it, poisoning the whole MlsClient (every later call throws
        // until reload). An unknown group (a convos↔wasm-groups desync) is now a catchable JS error.
        let group = self.groups.get(gid).ok_or_else(|| "unknown group".to_string())?;
        Ok(group
            .members()
            .filter_map(|m| verify_device_cert(m.credential.serialized_content())
                .map(|c| (c.identity_uuid, hex_encode(&device_id(&c.device_pubkey)))))
            .collect())
        // (this site keeps the inline form: it also needs `identity_uuid` from the same cert, so the
        // one-field `member_device_id_hex` helper wouldn't cover it without re-verifying the cert twice.)
    }

    /// Serialize the whole client's MLS state. All group state + key material lives in the
    /// provider's `MemoryStorage` (a `HashMap<Vec<u8>, Vec<u8>>`); we frame both the group-id
    /// list and that map with length prefixes. (MemoryStorage's own serialize() is test-utils
    /// gated, so we serialize the public `values` map directly — no extra features.)
    /// Framing: [u32 group-count]{[u32 len][group_id]}* [u32 kv-count]{[u32 klen][k][u32 vlen][v]}*
    pub fn serialize_native(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&(self.groups.len() as u32).to_be_bytes());
        for id in self.groups.keys() {
            out.extend_from_slice(&(id.len() as u32).to_be_bytes());
            out.extend_from_slice(id);
        }
        let values = self.provider.storage().values.read().unwrap();
        out.extend_from_slice(&(values.len() as u32).to_be_bytes());
        for (k, v) in values.iter() {
            out.extend_from_slice(&(k.len() as u32).to_be_bytes());
            out.extend_from_slice(k);
            out.extend_from_slice(&(v.len() as u32).to_be_bytes());
            out.extend_from_slice(v);
        }
        out
    }

    /// Rebuild a client from a serialized blob. The signer/credential are deterministic from the
    /// seed; storage is repopulated and each group reloaded via `MlsGroup::load`.
    ///
    /// Returns `Err` (NOT panic) on ANY malformed/truncated blob (security-audit 2026-07-05 L-2): the
    /// blob is untrusted local input (a quota-evicted / partially-written IndexedDB value), and every
    /// length-prefixed read is bounds-checked. An out-of-range prefix would otherwise panic on a slice
    /// and brick client construction; the error lets the TS caller fall back to a fresh client. The
    /// group-count/kv-count are NOT used to pre-size allocations (a corrupt count could request a
    /// multi-GiB allocation → abort); we grow the collections as we validate each entry.
    pub fn restore_native(device_seed: &[u8], device_cert: &[u8], blob: &[u8]) -> Result<MlsClient, String> {
        let mut pos = 0usize;
        let n = read_u32(blob, &mut pos)?;
        let mut ids = Vec::new();
        for _ in 0..n {
            let len = read_u32(blob, &mut pos)?;
            ids.push(read_bytes(blob, &mut pos, len)?);
        }
        let provider = OpenMlsRustCrypto::default();
        {
            let cnt = read_u32(blob, &mut pos)?;
            let mut map = HashMap::new();
            for _ in 0..cnt {
                let klen = read_u32(blob, &mut pos)?;
                let k = read_bytes(blob, &mut pos, klen)?;
                let vlen = read_u32(blob, &mut pos)?;
                let v = read_bytes(blob, &mut pos, vlen)?;
                map.insert(k, v);
            }
            *provider.storage().values.write().unwrap() = map;
        }
        let public = mldsa87_public_from_seed_native(device_seed);
        let signer = SignatureKeyPair::from_raw(SignatureScheme::MLDSA87, device_seed.to_vec(), public);
        let credential = CredentialWithKey {
            credential: BasicCredential::new(device_cert.to_vec()).into(),
            signature_key: signer.public().into(),
        };
        let mut groups = HashMap::new();
        for id in ids {
            let gid = GroupId::from_slice(&id);
            if let Some(mut g) = MlsGroup::load(provider.storage(), &gid).map_err(|e| format!("load group: {e:?}"))? {
                // Retrofit: a group joined before use_ratchet_tree_extension(true) existed persisted it
                // OFF, so a Welcome THIS client later builds would omit the ratchet tree and the joiner
                // would fail "No ratchet tree available" (#2). Re-apply the current join config on every
                // restore. Also defensively discards any dangling pending commit (staged-but-unresolved
                // add from a crash mid-operation) so the group loads Operational.
                g.set_configuration(provider.storage(), &join_config()).map_err(|e| format!("retrofit join config: {e:?}"))?;
                let _ = g.clear_pending_commit(provider.storage());
                groups.insert(id, g);
            }
        }
        Ok(MlsClient { provider, signer, credential, groups })
    }
}

// ---- WASM boundary (Uint8Array in/out; structured results as plain JS objects) ----

#[wasm_bindgen]
impl MlsClient {
    #[wasm_bindgen(constructor)]
    pub fn new(device_seed: &[u8], device_cert: &[u8]) -> Result<MlsClient, JsError> {
        Self::new_native(device_seed, device_cert).map_err(|e| JsError::new(&e))
    }

    pub fn generate_key_packages(&self, n: usize) -> Vec<js_sys::Uint8Array> {
        self.key_packages_native(n).iter().map(|b| js_sys::Uint8Array::from(&b[..])).collect()
    }

    pub fn last_resort_key_package(&self) -> js_sys::Uint8Array {
        js_sys::Uint8Array::from(&self.last_resort_key_package_native()[..])
    }

    pub fn signature_public_key(&self) -> js_sys::Uint8Array {
        js_sys::Uint8Array::from(&self.signature_public_key_native()[..])
    }

    /// This device's id (SHA-256 of its ML-DSA-87 leaf pubkey) — the per-device routing key.
    pub fn device_id(&self) -> Vec<u8> { self.device_id_native() }

    pub fn create_group(&mut self) -> js_sys::Uint8Array {
        js_sys::Uint8Array::from(&self.create_group_native()[..])
    }

    pub fn add_member(&mut self, group_id: &[u8], key_package: &[u8]) -> Result<js_sys::Object, JsError> {
        // Return Err (NOT panic) on a bad/attacker-controlled KeyPackage so the borrow releases cleanly
        // and the client isn't poisoned — the TS caller catches this and skips the bad peer (#1).
        let (commit, welcome) = self.add_member_native(group_id, key_package).map_err(|e| JsError::new(&e))?;
        let obj = js_sys::Object::new();
        js_sys::Reflect::set(&obj, &"commit".into(), &js_sys::Uint8Array::from(&commit[..])).unwrap();
        js_sys::Reflect::set(&obj, &"welcome".into(), &js_sys::Uint8Array::from(&welcome[..])).unwrap();
        Ok(obj)
    }

    pub fn add_members(&mut self, group_id: &[u8], key_packages: js_sys::Array)
        -> Result<js_sys::Object, JsError> {
        let kps: Vec<Vec<u8>> = key_packages.iter().map(|v| js_sys::Uint8Array::new(&v).to_vec()).collect();
        let (commit, welcome) = self.add_members_native(group_id, kps).map_err(|e| JsError::new(&e))?;
        let obj = js_sys::Object::new();
        js_sys::Reflect::set(&obj, &"commit".into(), &js_sys::Uint8Array::from(&commit[..])).unwrap();
        js_sys::Reflect::set(&obj, &"welcome".into(), &js_sys::Uint8Array::from(&welcome[..])).unwrap();
        Ok(obj)
    }

    pub fn stage_add_members(&mut self, group_id: &[u8], key_packages: js_sys::Array, expected_identity: String)
        -> Result<js_sys::Object, JsError> {
        let kps: Vec<Vec<u8>> = key_packages.iter().map(|v| js_sys::Uint8Array::new(&v).to_vec()).collect();
        let (commit, welcome) = self.stage_add_members_native(group_id, kps, &expected_identity).map_err(|e| JsError::new(&e))?;
        let obj = js_sys::Object::new();
        js_sys::Reflect::set(&obj, &"commit".into(), &js_sys::Uint8Array::from(&commit[..])).unwrap();
        js_sys::Reflect::set(&obj, &"welcome".into(), &js_sys::Uint8Array::from(&welcome[..])).unwrap();
        Ok(obj)
    }

    pub fn merge_staged(&mut self, group_id: &[u8]) -> Result<(), JsError> {
        self.merge_staged_native(group_id).map_err(|e| JsError::new(&e))
    }

    pub fn discard_staged(&mut self, group_id: &[u8]) -> Result<(), JsError> {
        self.discard_staged_native(group_id).map_err(|e| JsError::new(&e))
    }

    pub fn process_welcome(&mut self, welcome: &[u8]) -> Result<js_sys::Uint8Array, JsError> {
        // Return Err (NOT panic) on bad input so the borrow releases cleanly and the client isn't
        // poisoned — the TS joinPending loop catches this and skips the one bad welcome.
        let gid = self.process_welcome_native(welcome).map_err(|e| JsError::new(&e))?;
        Ok(js_sys::Uint8Array::from(&gid[..]))
    }

    pub fn encrypt(&mut self, group_id: &[u8], plaintext: &[u8]) -> Result<js_sys::Uint8Array, JsError> {
        // Return Err (NOT panic) so the borrow releases cleanly and the client isn't poisoned; the TS
        // caller catches this and surfaces/skips the failed send (security-audit 2026-07-05 L-1).
        let ct = self.encrypt_native(group_id, plaintext).map_err(|e| JsError::new(&e))?;
        Ok(js_sys::Uint8Array::from(&ct[..]))
    }

    pub fn process(&mut self, group_id: &[u8], message: &[u8]) -> Result<js_sys::Object, JsError> {
        // Return Err (NOT panic) on bad input so the borrow releases and the client isn't poisoned;
        // the TS receive loop catches this and skips the one bad message.
        let r = self.process_native(group_id, message).map_err(|e| JsError::new(&e))?;
        let obj = js_sys::Object::new();
        js_sys::Reflect::set(&obj, &"kind".into(), &JsValue::from_str(&r.kind)).unwrap();
        let pt = match r.plaintext {
            Some(b) => js_sys::Uint8Array::from(&b[..]).into(),
            None => JsValue::NULL,
        };
        js_sys::Reflect::set(&obj, &"plaintext".into(), &pt).unwrap();
        let sender = match &r.sender {
            Some(s) => JsValue::from_str(s),
            None => JsValue::NULL,
        };
        js_sys::Reflect::set(&obj, &"sender".into(), &sender).unwrap();
        let sender_pubkey = match &r.sender_pubkey {
            Some(s) => JsValue::from_str(s),
            None => JsValue::NULL,
        };
        js_sys::Reflect::set(&obj, &"sender_pubkey".into(), &sender_pubkey).unwrap();
        Ok(obj)
    }

    pub fn remove_member(&mut self, group_id: &[u8], identity_uuid: String) -> Result<js_sys::Uint8Array, JsError> {
        let commit = self.remove_member_native(group_id, &identity_uuid).map_err(|e| JsError::new(&e))?;
        Ok(js_sys::Uint8Array::from(&commit[..]))
    }

    pub fn stage_remove_member(&mut self, group_id: &[u8], identity_uuid: String) -> Result<js_sys::Uint8Array, JsError> {
        let commit = self.stage_remove_member_native(group_id, &identity_uuid).map_err(|e| JsError::new(&e))?;
        Ok(js_sys::Uint8Array::from(&commit[..]))
    }

    pub fn stage_remove_device_leaf(&mut self, group_id: &[u8], device_id_hex: String) -> Result<js_sys::Uint8Array, JsError> {
        let commit = self.stage_remove_device_leaf_native(group_id, &device_id_hex).map_err(|e| JsError::new(&e))?;
        Ok(js_sys::Uint8Array::from(&commit[..]))
    }

    pub fn remove_device_leaf(&mut self, group_id: &[u8], device_id_hex: String) -> Result<js_sys::Uint8Array, JsError> {
        let commit = self.remove_device_leaf_native(group_id, &device_id_hex).map_err(|e| JsError::new(&e))?;
        Ok(js_sys::Uint8Array::from(&commit[..]))
    }

    pub fn group_members(&self, group_id: &[u8]) -> Result<js_sys::Array, JsError> {
        let out = js_sys::Array::new();
        for (uuid, dev) in self.group_members_native(group_id).map_err(|e| JsError::new(&e))? {
            let o = js_sys::Object::new();
            js_sys::Reflect::set(&o, &"identityUuid".into(), &JsValue::from_str(&uuid)).unwrap();
            js_sys::Reflect::set(&o, &"devicePubkey".into(), &JsValue::from_str(&dev)).unwrap();
            out.push(&o);
        }
        Ok(out)
    }

    pub fn serialize(&self) -> js_sys::Uint8Array {
        js_sys::Uint8Array::from(&self.serialize_native()[..])
    }

    /// Static: `MlsClient.restore(device_seed, device_cert, state)` in JS. Returns `Err` (throws in
    /// JS) on a corrupt/truncated blob so the TS caller can fall back to a fresh client instead of
    /// crashing (security-audit 2026-07-05 L-2).
    pub fn restore(device_seed: &[u8], device_cert: &[u8], state: &[u8]) -> Result<MlsClient, JsError> {
        Self::restore_native(device_seed, device_cert, state).map_err(|e| JsError::new(&e))
    }
}

// Bounds-checked read of a big-endian u32 length prefix (security-audit 2026-07-05 L-2). A
// truncated/corrupt local blob (quota-evicted IndexedDB, partial write) must yield an `Err`, never a
// slice-out-of-bounds panic that unwinds across the wasm boundary and bricks client construction.
fn read_u32(b: &[u8], pos: &mut usize) -> Result<usize, String> {
    let end = pos.checked_add(4).ok_or_else(|| "blob: length prefix overflow".to_string())?;
    let bytes: [u8; 4] = b.get(*pos..end).ok_or_else(|| "blob: truncated length prefix".to_string())?
        .try_into().map_err(|_| "blob: bad length prefix".to_string())?;
    *pos = end;
    Ok(u32::from_be_bytes(bytes) as usize)
}

// Bounds-checked read of `len` bytes at `*pos`, advancing `pos`. Returns `Err` on a length prefix
// that runs past the end of the blob (L-2) instead of panicking on an out-of-range slice.
fn read_bytes(b: &[u8], pos: &mut usize, len: usize) -> Result<Vec<u8>, String> {
    let end = pos.checked_add(len).ok_or_else(|| "blob: length overflow".to_string())?;
    let out = b.get(*pos..end).ok_or_else(|| "blob: length prefix exceeds remaining bytes".to_string())?.to_vec();
    *pos = end;
    Ok(out)
}

/// Deterministically derive the ML-DSA-87 verifying key from a 32-byte seed. FIPS 204 keygen is a
/// pure function of the seed, and BOTH the RustCrypto provider and openmls_basic_credential treat
/// the ML-DSA private key as this same 32-byte seed (`SigningKey::from_seed`) — so restore_native
/// can keep re-deriving the signer from the stored device seed exactly as it did for Ed25519.
fn mldsa87_public_from_seed_native(seed: &[u8]) -> Vec<u8> {
    use ml_dsa::Keypair;
    let seed: &ml_dsa::Seed = seed.try_into().expect("32-byte seed");
    ml_dsa::SigningKey::<ml_dsa::MlDsa87>::from_seed(seed).verifying_key().encode().to_vec()
}

/// The device id: SHA-256 of the leaf signature pubkey. ML-DSA-87 keys are 2592 bytes, so the raw
/// key can't be the routing handle any more (64-hex-char DB columns, QR payloads, URL params). The
/// id is the stable 32-byte handle used EVERYWHERE outside the crate — the server's KeyPackage/
/// Welcome/device-registry rows, group_members, per-device revocation, the pairing QR + SAS. The
/// full key still lives (and is verified) inside certs and KeyPackages.
fn device_id(pubkey: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    Sha256::digest(pubkey).to_vec()
}

pub fn device_id_from_seed_native(seed: &[u8]) -> Vec<u8> {
    device_id(&mldsa87_public_from_seed_native(seed))
}

/// Sign `msg` with the ML-DSA-87 key derived from `seed`. This is the "Slice A" surface the later
/// identity-auth migration consumes; unused by the app in this plan.
///
/// ⚠️ IDENTITY-SEED USE ONLY — MUST NOT be called with the DEVICE seed. The device seed is the live
/// MLS leaf signer; this function is a no-domain-separation raw-bytes signing oracle, so calling it
/// with the device seed would let a caller forge signatures indistinguishable from real MLS leaf
/// signing traffic (a cross-protocol forgery primitive). Domain separation for the identity-auth use
/// case is the CALLER's responsibility (see the identity-auth design spec); this function does not
/// add any itself.
pub fn mldsa87_sign_native(seed: &[u8], msg: &[u8]) -> Vec<u8> {
    use ml_dsa::Signer;
    let seed: &ml_dsa::Seed = seed.try_into().expect("32-byte seed");
    let k = ml_dsa::SigningKey::<ml_dsa::MlDsa87>::from_seed(seed);
    k.sign(msg).encode().to_vec()
}

/// Never panics on malformed input (attacker-suppliable) — returns false.
pub fn mldsa87_verify_native(public_key: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    use ml_dsa::Verifier;
    let Ok(ek) = <&ml_dsa::EncodedVerifyingKey<ml_dsa::MlDsa87>>::try_from(public_key) else { return false };
    let Ok(es) = <&ml_dsa::EncodedSignature<ml_dsa::MlDsa87>>::try_from(sig) else { return false };
    let key = ml_dsa::VerifyingKey::<ml_dsa::MlDsa87>::decode(ek);
    let Some(signature) = ml_dsa::Signature::<ml_dsa::MlDsa87>::decode(es) else { return false };
    key.verify(msg, &signature).is_ok()
}

fn hex_encode(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b { s.push_str(&format!("{:02x}", x)); }
    s
}

/// A group member's device-id hex (SHA-256 of the leaf key in its device cert), or `None` if the
/// member's credential isn't a valid device cert. The one place device-id derivation from a member
/// credential lives — the per-device revocation lookups (`remove_device_leaf`/`stage_…`) all match on
/// this, so the derivation rule can't drift between them.
fn member_device_id_hex(credential: &[u8]) -> Option<String> {
    verify_device_cert(credential).map(|c| hex_encode(&device_id(&c.device_pubkey)))
}

// ---- Device certificate (Phase 0a / T10) ----
// The identity key (root) signs a per-device cert binding a device's signing key to the identity, so
// each device runs its own MLS leaf under one identity. Domain-separated so this signature can't be
// confused with the `clotho-auth:` challenge the same identity key also signs.
const DEVCERT_DOMAIN: &[u8] = b"clotho-device-cert:v3";
const DEVCERT_VER: u8 = 3;
// v3 fixed-size header fields (bytes). The identity key + cert signature are now ML-DSA-87 (Slices
// B/C), so the whole trust chain — auth AND MLS-leaf attribution — is post-quantum. Naming the sizes
// keeps the parse/mint/tamper-test offsets in one place. A v2 cert (Ed25519 identity, 32/64) is
// rejected by verify_device_cert — this is a clean-break flag day (existing device certs re-mint).
const DEVCERT_ID_PUBKEY_LEN: usize = 2592;  // ML-DSA-87 identity pubkey
const DEVCERT_DEVLEN_PREFIX: usize = 2;     // u16 BE length prefix for the (variable) device key
const DEVCERT_SIG_LEN: usize = 4627;        // ML-DSA-87 signature
// Offset of the device key's length prefix / the device key itself (ver ‖ id_pubkey ‖ …).
const DEVCERT_DEVLEN_OFF: usize = 1 + DEVCERT_ID_PUBKEY_LEN;
const DEVCERT_DEVKEY_OFF: usize = DEVCERT_DEVLEN_OFF + DEVCERT_DEVLEN_PREFIX;

pub struct DeviceCert {
    pub identity_pubkey: Vec<u8>,   // ML-DSA-87 (2592 bytes)
    pub device_pubkey: Vec<u8>,
    pub identity_uuid: String,
}

// Length-delimited exactly like the cert body (v2): with device_pubkey now variable-length, an
// unframed concatenation would let one signature verify under two different field splits. The
// domain also bumps to v2 so v1 signatures can't be replayed into the new framing.
fn devcert_signed_message(id_pub: &[u8], dev_pub: &[u8], uuid: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(DEVCERT_DOMAIN.len() + id_pub.len() + 2 + dev_pub.len() + 1 + uuid.len());
    m.extend_from_slice(DEVCERT_DOMAIN);
    m.extend_from_slice(id_pub);
    m.extend_from_slice(&(dev_pub.len() as u16).to_be_bytes());
    m.extend_from_slice(dev_pub);
    m.push(uuid.len() as u8);
    m.extend_from_slice(uuid);
    m
}

/// Sign a device certificate with the identity seed: binds device_pubkey to this identity.
/// v3 layout: ver(1) ‖ identity_pubkey(2592) ‖ dev_pub_len(u16 BE) ‖ device_pubkey ‖ uuid_len(1) ‖ uuid ‖ sig(4627).
/// Both the identity key and the cert signature are ML-DSA-87 (Slices B/C) — the identity seed derives
/// the ML-DSA-87 key that both authenticates (auth challenge) and signs this cert.
pub fn mint_device_cert_native(identity_seed: &[u8], identity_uuid: &str, device_pubkey: &[u8]) -> Vec<u8> {
    assert!(!device_pubkey.is_empty() && device_pubkey.len() <= u16::MAX as usize, "device_pubkey length");
    let id_pub = mldsa87_public_from_seed_native(identity_seed);
    let uuid = identity_uuid.as_bytes();
    let sig = mldsa87_sign_native(identity_seed, &devcert_signed_message(&id_pub, device_pubkey, uuid));
    let mut cert = Vec::with_capacity(DEVCERT_DEVKEY_OFF + device_pubkey.len() + 1 + uuid.len() + DEVCERT_SIG_LEN);
    cert.push(DEVCERT_VER);
    cert.extend_from_slice(&id_pub);
    cert.extend_from_slice(&(device_pubkey.len() as u16).to_be_bytes());
    cert.extend_from_slice(device_pubkey);
    cert.push(uuid.len() as u8);
    cert.extend_from_slice(uuid);
    cert.extend_from_slice(&sig);
    cert
}

/// Parse + cryptographically verify a device cert. `None` on any malformed, forged, or pre-v3 input.
pub fn verify_device_cert(cert: &[u8]) -> Option<DeviceCert> {
    if cert.first().copied()? != DEVCERT_VER { return None; }
    let id_pub = cert.get(1..DEVCERT_DEVLEN_OFF)?.to_vec();   // ML-DSA-87 identity pubkey (2592)
    let dev_len = u16::from_be_bytes(cert.get(DEVCERT_DEVLEN_OFF..DEVCERT_DEVKEY_OFF)?.try_into().ok()?) as usize;
    let dev_pub = cert.get(DEVCERT_DEVKEY_OFF..DEVCERT_DEVKEY_OFF + dev_len)?.to_vec();
    let upos = DEVCERT_DEVKEY_OFF + dev_len;
    let uuid_len = *cert.get(upos)? as usize;
    let uuid = cert.get(upos + 1..upos + 1 + uuid_len)?;
    let sig = cert.get(upos + 1 + uuid_len..upos + 1 + uuid_len + DEVCERT_SIG_LEN)?;
    if !mldsa87_verify_native(&id_pub, &devcert_signed_message(&id_pub, &dev_pub, uuid), sig) {
        return None;
    }
    Some(DeviceCert { identity_pubkey: id_pub, device_pubkey: dev_pub, identity_uuid: String::from_utf8(uuid.to_vec()).ok()? })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_cert_roundtrip() {
        let id_seed = [9u8; 32];
        let id_pub = mldsa87_public_from_seed_native(&id_seed);
        assert_eq!(id_pub.len(), 2592, "identity pubkey is now ML-DSA-87");
        let dev_pub = mldsa87_public_from_seed_native(&[5u8; 32]);
        let uuid = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
        let cert = mint_device_cert_native(&id_seed, uuid, &dev_pub);
        let v = verify_device_cert(&cert).expect("valid cert verifies");
        assert_eq!(v.identity_pubkey, id_pub);
        assert_eq!(v.device_pubkey.to_vec(), dev_pub);
        assert_eq!(v.identity_uuid, uuid);
    }

    #[test]
    fn device_cert_rejects_forged_sig() {
        let id_seed = [9u8; 32];
        let dev_pub = mldsa87_public_from_seed_native(&[5u8; 32]);
        let mut cert = mint_device_cert_native(&id_seed, "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", &dev_pub);
        let n = cert.len();
        cert[n - 1] ^= 0xff; // corrupt the signature
        assert!(verify_device_cert(&cert).is_none());
    }

    #[test]
    fn device_cert_rejects_tampered_device_key() {
        let id_seed = [9u8; 32];
        let dev_pub = mldsa87_public_from_seed_native(&[5u8; 32]);
        let mut cert = mint_device_cert_native(&id_seed, "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", &dev_pub);
        cert[DEVCERT_DEVKEY_OFF] ^= 0x01; // flip the first byte of device_pubkey
        assert!(verify_device_cert(&cert).is_none());
    }

    #[test]
    fn device_cert_roundtrip_large_device_key() {
        // ML-DSA-87 public keys are 2592 bytes — the cert must carry variable-length device keys.
        let id_seed = [9u8; 32];
        let dev_pub = vec![0xabu8; 2592];
        let uuid = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
        let cert = mint_device_cert_native(&id_seed, uuid, &dev_pub);
        let v = verify_device_cert(&cert).expect("valid large-key cert verifies");
        assert_eq!(v.device_pubkey, dev_pub);
        assert_eq!(v.identity_uuid, uuid);
    }

    /// Build a client whose MLS signer is `dev_seed`, credentialed with a cert minted by `id_seed`.
    fn client_for(id_seed: [u8; 32], dev_seed: [u8; 32], uuid: &str) -> MlsClient {
        let dev_pub = mldsa87_public_from_seed_native(&dev_seed);
        let cert = mint_device_cert_native(&id_seed, uuid, &dev_pub);
        MlsClient::new_native(&dev_seed, &cert).expect("new client")
    }

    #[test]
    fn client_signs_with_device_key_credential_is_cert() {
        let dev_seed = [5u8; 32];
        let dev_pub = mldsa87_public_from_seed_native(&dev_seed);
        let cert = mint_device_cert_native(&[9u8; 32], "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", &dev_pub);
        let c = MlsClient::new_native(&dev_seed, &cert).unwrap();
        assert_eq!(c.signature_public_key_native(), dev_pub); // signs with the DEVICE key
    }

    #[test]
    fn add_rejects_non_cert_credential() {
        let mut a = client_for([1u8; 32], [11u8; 32], "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa");
        // A client whose credential is raw bytes (not a valid device cert) must not be addable.
        let dev_seed = [33u8; 32];
        let public = mldsa87_public_from_seed_native(&dev_seed);
        let signer = SignatureKeyPair::from_raw(SignatureScheme::MLDSA87, dev_seed.to_vec(), public.clone());
        let provider = OpenMlsRustCrypto::default();
        signer.store(provider.storage()).unwrap();
        let credential = CredentialWithKey {
            credential: BasicCredential::new(b"not-a-cert".to_vec()).into(),
            signature_key: signer.public().into(),
        };
        let bogus = MlsClient { provider, signer, credential, groups: HashMap::new() };
        let kp = bogus.key_packages_native(1).remove(0);
        let gid = a.create_group_native();
        // Must return Err, NOT panic (#1): a panic would poison the whole client via the leaked
        // wasm-bindgen borrow. An invalid-cert credential is exactly the attacker-controlled input.
        assert!(a.add_member_native(&gid, &kp).is_err());
    }

    #[test]
    fn add_member_returns_err_on_garbage_keypackage() {
        // A non-deserializable KeyPackage blob (the cheapest attack) must Err, not panic (#1).
        let mut a = client_for([1u8; 32], [11u8; 32], "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa");
        let gid = a.create_group_native();
        assert!(a.add_member_native(&gid, b"not a key package at all").is_err());
        // And the client is STILL usable afterwards (not poisoned): a real add succeeds.
        let mut b = client_for([2u8; 32], [21u8; 32], "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb");
        assert!(a.add_member_native(&gid, &b.key_packages_native(1).remove(0)).is_ok());
    }

    #[test]
    fn two_devices_one_identity_attribute_to_identity() {
        // Identity I authorizes two devices A and B; both join a group with friend F; F's message is
        // attributed to the single identity I on both devices.
        let i_seed = [7u8; 32];
        let i_uuid = "11111111-1111-1111-1111-111111111111";
        let mut dev_a = client_for(i_seed, [71u8; 32], i_uuid);
        let mut dev_b = client_for(i_seed, [72u8; 32], i_uuid);
        let mut f = client_for([8u8; 32], [81u8; 32], "ffffffff-ffff-ffff-ffff-ffffffffffff");
        let gid = f.create_group_native();
        let (_c1, wa) = f.add_member_native(&gid, &dev_a.key_packages_native(1).remove(0)).unwrap();
        let ag = dev_a.process_welcome_native(&wa).unwrap();
        let (c2, wb) = f.add_member_native(&gid, &dev_b.key_packages_native(1).remove(0)).unwrap();
        dev_a.process_native(&ag, &c2).unwrap(); // A applies F's add-B commit to stay in sync
        let bg = dev_b.process_welcome_native(&wb).unwrap();
        let ct = f.encrypt_native(&gid, b"hi devices").unwrap();
        assert_eq!(dev_a.process_native(&ag, &ct).unwrap().sender.as_deref(), Some("ffffffff-ffff-ffff-ffff-ffffffffffff"));
        assert_eq!(dev_b.process_native(&bg, &ct).unwrap().sender.as_deref(), Some("ffffffff-ffff-ffff-ffff-ffffffffffff"));
    }

    #[test]
    fn batch_add_then_revoke_one_device_leaf_keeps_the_other() {
        // Fan-out + per-device revocation (Phase 0a Part 2). F adds BOTH of identity I's devices in
        // ONE commit (a single Welcome serves both leaves), then revokes just device B's leaf by its
        // device id — device A (same identity) keeps decrypting. (remove_member, by uuid, would
        // instead have evicted BOTH of I's leaves.)
        let i_seed = [7u8; 32];
        let i_uuid = "11111111-1111-1111-1111-111111111111";
        let mut dev_a = client_for(i_seed, [71u8; 32], i_uuid);
        let dev_b_seed = [72u8; 32];
        let dev_b_id_hex = hex_encode(&device_id_from_seed_native(&dev_b_seed));
        let mut dev_b = client_for(i_seed, dev_b_seed, i_uuid);
        let mut f = client_for([8u8; 32], [81u8; 32], "ffffffff-ffff-ffff-ffff-ffffffffffff");

        let gid = f.create_group_native();
        let kps = vec![dev_a.key_packages_native(1).remove(0), dev_b.key_packages_native(1).remove(0)];
        let (_commit, welcome) = f.add_members_native(&gid, kps).unwrap();
        let ag = dev_a.process_welcome_native(&welcome).unwrap(); // the SAME welcome lets each device join
        let bg = dev_b.process_welcome_native(&welcome).unwrap();
        let ct = f.encrypt_native(&gid, b"hi both at once").unwrap();
        assert_eq!(dev_a.process_native(&ag, &ct).unwrap().plaintext.as_deref(), Some(&b"hi both at once"[..]));
        assert_eq!(dev_b.process_native(&bg, &ct).unwrap().plaintext.as_deref(), Some(&b"hi both at once"[..]));

        // Revoke device B's leaf; A applies the commit and keeps working.
        let rm = f.remove_device_leaf_native(&gid, &dev_b_id_hex).unwrap();
        dev_a.process_native(&ag, &rm).unwrap();
        let ct2 = f.encrypt_native(&gid, b"after revoke").unwrap();
        assert_eq!(dev_a.process_native(&ag, &ct2).unwrap().plaintext.as_deref(), Some(&b"after revoke"[..]));
    }

    #[test]
    fn sender_pubkey_is_unspoofable_even_when_uuid_is_claimed() {
        // An attacker (identity key i_att) mints a cert CLAIMING a victim's uuid — allowed, since the
        // cert is self-signed. They join a group with F and send a message.
        let i_att = [44u8; 32];
        let att_id_pub = mldsa87_public_from_seed_native(&i_att);
        let dev_seed = [45u8; 32];
        let dev_pub = mldsa87_public_from_seed_native(&dev_seed);
        let victim_uuid = "11111111-1111-1111-1111-111111111111";
        let spoof_cert = mint_device_cert_native(&i_att, victim_uuid, &dev_pub);
        let mut attacker = MlsClient::new_native(&dev_seed, &spoof_cert).unwrap();

        let mut f = client_for([8u8; 32], [81u8; 32], "ffffffff-ffff-ffff-ffff-ffffffffffff");
        let gid = f.create_group_native();
        let (_c, w) = f.add_member_native(&gid, &attacker.key_packages_native(1).remove(0)).unwrap();
        attacker.process_welcome_native(&w).unwrap();
        let ct = attacker.encrypt_native(&gid, b"i am the victim").unwrap();
        let res = f.process_native(&gid, &ct).unwrap();

        // The UUID IS spoofable (self-asserted) — F must NOT trust it for attribution:
        assert_eq!(res.sender.as_deref(), Some(victim_uuid));
        // The pubkey is the attacker's REAL identity key, not the victim's — F detects the spoof by
        // comparing sender_pubkey to the victim's known contact pubkey.
        assert_eq!(res.sender_pubkey.as_deref(), Some(hex_encode(&att_id_pub).as_str()));
    }

    #[test]
    fn init_and_generate_keypackages() {
        let client = client_for([7u8; 32], [17u8; 32], "11111111-1111-1111-1111-111111111111");
        let kps = client.key_packages_native(2);
        assert_eq!(kps.len(), 2);
        assert!(!kps[0].is_empty());
        assert_eq!(client.signature_public_key_native().len(), 2592); // ML-DSA-87 encoded verifying key
        // A last-resort KeyPackage builds, serializes, and is usable to add a member (reconciliation
        // fallback when one-times are drained).
        let lr = client.last_resort_key_package_native();
        assert!(!lr.is_empty());
        let mut adder = client_for([8u8; 32], [18u8; 32], "22222222-2222-2222-2222-222222222222");
        let gid = adder.create_group_native();
        adder.add_member_native(&gid, &lr).expect("add_member with a last-resort key package");
    }

    #[test]
    fn two_party_message_roundtrip() {
        let mut a = client_for([1u8; 32], [11u8; 32], "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa");
        let mut b = client_for([2u8; 32], [12u8; 32], "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb");
        let b_kp = b.key_packages_native(1).remove(0);

        let gid = a.create_group_native();
        let (_commit, welcome) = a.add_member_native(&gid, &b_kp).unwrap();
        let b_gid = b.process_welcome_native(&welcome).unwrap();
        assert_eq!(b_gid, gid);

        let ct = a.encrypt_native(&gid, b"hello bob").unwrap();
        let res = b.process_native(&b_gid, &ct).unwrap();
        assert_eq!(res.plaintext.as_deref(), Some(&b"hello bob"[..]));
        // attribution comes from the cryptographically-verified leaf credential (A's UUID),
        // never the transport — this is what the messaging client must trust.
        assert_eq!(res.sender.as_deref(), Some("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"));
    }

    #[test]
    fn three_party_and_removal() {
        let mut a = client_for([1u8; 32], [11u8; 32], "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa");
        let mut b = client_for([2u8; 32], [12u8; 32], "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb");
        let mut c = client_for([3u8; 32], [13u8; 32], "cccccccc-cccc-cccc-cccc-cccccccccccc");
        let gid = a.create_group_native();

        let (_c1, w_b) = a.add_member_native(&gid, &b.key_packages_native(1).remove(0)).unwrap();
        let bg = b.process_welcome_native(&w_b).unwrap();

        // add C: existing member B must process A's add-C commit to stay in sync
        let (c_commit, w_c) = a.add_member_native(&gid, &c.key_packages_native(1).remove(0)).unwrap();
        b.process_native(&bg, &c_commit).unwrap();
        let cg = c.process_welcome_native(&w_c).unwrap();

        let ct = a.encrypt_native(&gid, b"hi all").unwrap();
        assert_eq!(b.process_native(&bg, &ct).unwrap().plaintext.as_deref(), Some(&b"hi all"[..]));
        assert_eq!(c.process_native(&cg, &ct).unwrap().plaintext.as_deref(), Some(&b"hi all"[..]));

        // remove B; C applies the removal commit and can still decrypt; B is evicted
        let rm = a.remove_member_native(&gid, "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb").unwrap();
        c.process_native(&cg, &rm).unwrap();
        let ct2 = a.encrypt_native(&gid, b"after removal").unwrap();
        assert_eq!(c.process_native(&cg, &ct2).unwrap().plaintext.as_deref(), Some(&b"after removal"[..]));
    }

    #[test]
    fn stage_add_rejects_key_package_of_a_different_identity() {
        // Security: an untrusted server answers a claim for peer B with ATTACKER's valid, self-signed
        // KeyPackage. Staging an add "for B" must reject it because its cert identity != B (else the
        // attacker silently joins + decrypts the conversation).
        let mut a = client_for([1u8; 32], [11u8; 32], "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa");
        let attacker = client_for([9u8; 32], [99u8; 32], "99999999-9999-9999-9999-999999999999");
        let gid = a.create_group_native();
        let attacker_kp = attacker.key_packages_native(1).remove(0);
        let r = a.stage_add_members_native(&gid, vec![attacker_kp], "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb");
        assert!(r.is_err(), "a foreign-identity KeyPackage must be rejected");
        // Not wedged: a correct add for the attacker's OWN id still works afterwards.
        let ok = a.stage_add_members_native(&gid, vec![attacker.key_packages_native(1).remove(0)],
                                            "99999999-9999-9999-9999-999999999999");
        assert!(ok.is_ok());
    }

    #[test]
    fn stage_add_skips_a_bad_kp_and_adds_the_valid_ones() {
        // Multi-device fan-out: a peer (identity B) has two device-leaves; one KeyPackage is valid,
        // the other is garbage bytes (a stale/wrong-suite KP, as during the PQ flag-day window). The
        // whole batch must NOT abort — the valid device is still added (else one dead device-leaf
        // wedges the peer's real device out of the group forever).
        let mut a = client_for([1u8; 32], [11u8; 32], "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa");
        let mut b_dev = client_for([2u8; 32], [12u8; 32], "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb");
        let gid = a.create_group_native();
        let good_kp = b_dev.key_packages_native(1).remove(0); // KP private keys live in b_dev's storage
        let bad_kp = vec![0xabu8; 200]; // not a deserializable KeyPackage
        let (_c, w) = a.stage_add_members_native(
            &gid, vec![bad_kp, good_kp], "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb").unwrap();
        a.merge_staged_native(&gid).unwrap();
        // The valid leaf really joined and can decrypt (b_dev holds the KP's private keys).
        let bg = b_dev.process_welcome_native(&w).unwrap();
        let ct = a.encrypt_native(&gid, b"the valid device got in").unwrap();
        assert_eq!(b_dev.process_native(&bg, &ct).unwrap().plaintext.as_deref(), Some(&b"the valid device got in"[..]));
    }

    #[test]
    fn stage_then_merge_advances_epoch() {
        let mut a = client_for([1u8; 32], [11u8; 32], "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa");
        let mut b = client_for([2u8; 32], [12u8; 32], "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb");
        let gid = a.create_group_native();
        let (_c, w) = a.stage_add_members_native(&gid, vec![b.key_packages_native(1).remove(0)], "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb").unwrap();
        a.merge_staged_native(&gid).unwrap();           // commit is real only after merge
        let bg = b.process_welcome_native(&w).unwrap();
        let ct = a.encrypt_native(&gid, b"hi after staged merge").unwrap();
        assert_eq!(b.process_native(&bg, &ct).unwrap().plaintext.as_deref(), Some(&b"hi after staged merge"[..]));
    }

    #[test]
    fn stage_then_discard_leaves_epoch_unchanged_and_client_usable() {
        let mut a = client_for([1u8; 32], [11u8; 32], "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa");
        let mut b = client_for([2u8; 32], [12u8; 32], "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb");
        let mut c = client_for([3u8; 32], [13u8; 32], "cccccccc-cccc-cccc-cccc-cccccccccccc");
        let gid = a.create_group_native();
        let (_c1, wb) = a.add_member_native(&gid, &b.key_packages_native(1).remove(0)).unwrap();
        let bg = b.process_welcome_native(&wb).unwrap();

        // Stage adding C, then DISCARD (simulating a rejected/failed post) — no local epoch change.
        let _ = a.stage_add_members_native(&gid, vec![c.key_packages_native(1).remove(0)], "cccccccc-cccc-cccc-cccc-cccccccccccc").unwrap();
        a.discard_staged_native(&gid).unwrap();

        // A stayed in sync with B (no fork), and C was NOT added.
        let ct = a.encrypt_native(&gid, b"still in sync with B").unwrap();
        assert_eq!(b.process_native(&bg, &ct).unwrap().plaintext.as_deref(), Some(&b"still in sync with B"[..]));

        // A can still stage+merge a real add afterwards (client not wedged by the discard).
        let (c2, wc) = a.stage_add_members_native(&gid, vec![c.key_packages_native(1).remove(0)], "cccccccc-cccc-cccc-cccc-cccccccccccc").unwrap();
        a.merge_staged_native(&gid).unwrap();
        b.process_native(&bg, &c2).unwrap(); // B applies A's add-C commit to stay in sync
        assert!(c.process_welcome_native(&wc).is_ok());
    }

    #[test]
    fn stage_remove_then_merge_evicts_member() {
        let mut a = client_for([1u8; 32], [11u8; 32], "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa");
        let mut b = client_for([2u8; 32], [12u8; 32], "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb");
        let mut c = client_for([3u8; 32], [13u8; 32], "cccccccc-cccc-cccc-cccc-cccccccccccc");
        let gid = a.create_group_native();
        let (_c1, wb) = a.add_member_native(&gid, &b.key_packages_native(1).remove(0)).unwrap();
        let bg = b.process_welcome_native(&wb).unwrap();
        let (c_commit, wc) = a.add_member_native(&gid, &c.key_packages_native(1).remove(0)).unwrap();
        b.process_native(&bg, &c_commit).unwrap();
        let cg = c.process_welcome_native(&wc).unwrap();

        // Staged remove of B: build the commit but don't merge until "the server accepts".
        let rm = a.stage_remove_member_native(&gid, "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb").unwrap();
        a.merge_staged_native(&gid).unwrap();
        c.process_native(&cg, &rm).unwrap(); // C applies the eviction commit
        let ct = a.encrypt_native(&gid, b"after staged removal").unwrap();
        assert_eq!(c.process_native(&cg, &ct).unwrap().plaintext.as_deref(), Some(&b"after staged removal"[..]));
        // B was evicted: the post-removal message must NOT decrypt for B.
        assert!(b.process_native(&bg, &ct).is_err());
    }

    #[test]
    fn stage_remove_then_discard_leaves_epoch_unchanged() {
        let mut a = client_for([1u8; 32], [11u8; 32], "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa");
        let mut b = client_for([2u8; 32], [12u8; 32], "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb");
        let gid = a.create_group_native();
        let (_c1, wb) = a.add_member_native(&gid, &b.key_packages_native(1).remove(0)).unwrap();
        let bg = b.process_welcome_native(&wb).unwrap();

        // Stage removing B, then DISCARD (server rejected the commit) — B stays in, no epoch change.
        let _ = a.stage_remove_member_native(&gid, "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb").unwrap();
        a.discard_staged_native(&gid).unwrap();
        let ct = a.encrypt_native(&gid, b"B is still here").unwrap();
        assert_eq!(b.process_native(&bg, &ct).unwrap().plaintext.as_deref(), Some(&b"B is still here"[..]));
    }

    #[test]
    fn restore_retrofits_ratchet_tree_extension() {
        // A group JOINED with the ratchet-tree extension OFF (simulating pre-retrofit persisted state):
        // restore must flip it ON so a Welcome THIS client later builds is self-contained (#2).
        let off_cfg = MlsGroupJoinConfig::builder().use_ratchet_tree_extension(false).build();
        let creator_seed = [1u8; 32];
        let cert_c = mint_device_cert_native(&[9u8; 32], "cccccccc-cccc-cccc-cccc-cccccccccccc", &mldsa87_public_from_seed_native(&creator_seed));
        let mut creator = MlsClient::new_native(&creator_seed, &cert_c).unwrap();
        let joiner_seed = [2u8; 32];
        let cert_j = mint_device_cert_native(&[8u8; 32], "jjjjjjjj-jjjj-jjjj-jjjj-jjjjjjjjjjjj", &mldsa87_public_from_seed_native(&joiner_seed));
        let mut joiner = MlsClient::new_native(&joiner_seed, &cert_j).unwrap();

        let gid = creator.create_group_native();
        let (_c, w) = creator.add_member_native(&gid, &joiner.key_packages_native(1).remove(0)).unwrap();
        // Joiner joins with the OFF config (bypass process_welcome_native, which now uses join_config()).
        let msg = MlsMessageIn::tls_deserialize_exact(&w).unwrap();
        let welcome = match msg.extract() { MlsMessageBodyIn::Welcome(x) => x, _ => panic!("not a welcome") };
        let staged = StagedWelcome::new_from_welcome(&joiner.provider, &off_cfg, welcome, None).unwrap();
        let jg = staged.into_group(&joiner.provider).unwrap();
        let jgid = jg.group_id().as_slice().to_vec();
        joiner.groups.insert(jgid.clone(), jg);

        // Round-trip through serialize/restore — the retrofit must flip the extension ON.
        let blob = joiner.serialize_native();
        let mut joiner2 = MlsClient::restore_native(&joiner_seed, &cert_j, &blob).unwrap();

        // The retrofitted joiner adds a THIRD device; its Welcome must be self-contained (tree included).
        let third_seed = [3u8; 32];
        let cert_t = mint_device_cert_native(&[7u8; 32], "tttttttt-tttt-tttt-tttt-tttttttttttt", &mldsa87_public_from_seed_native(&third_seed));
        let mut third = MlsClient::new_native(&third_seed, &cert_t).unwrap();
        let (_c2, w2) = joiner2.add_member_native(&jgid, &third.key_packages_native(1).remove(0)).unwrap();
        // A fresh client joins from w2 with NO out-of-band tree — only works if the tree rode in the Welcome.
        assert!(third.process_welcome_native(&w2).is_ok());
    }

    #[test]
    fn serialize_restore_roundtrip() {
        let dev_a = [11u8; 32];
        let cert_a = mint_device_cert_native(&[1u8; 32], "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", &mldsa87_public_from_seed_native(&dev_a));
        let mut a = MlsClient::new_native(&dev_a, &cert_a).unwrap();
        let mut b = client_for([2u8; 32], [12u8; 32], "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb");
        let gid = a.create_group_native();
        let (_c, w) = a.add_member_native(&gid, &b.key_packages_native(1).remove(0)).unwrap();
        let bg = b.process_welcome_native(&w).unwrap();

        let blob = a.serialize_native();
        let mut a2 = MlsClient::restore_native(&dev_a, &cert_a, &blob).unwrap();

        // a2 (restored from storage) still owns the group and can message b
        let ct = a2.encrypt_native(&gid, b"after restore").unwrap();
        assert_eq!(b.process_native(&bg, &ct).unwrap().plaintext.as_deref(), Some(&b"after restore"[..]));
    }

    #[test]
    fn mldsa87_public_from_seed_is_deterministic_and_sized() {
        let a = mldsa87_public_from_seed_native(&[7u8; 32]);
        let b = mldsa87_public_from_seed_native(&[7u8; 32]);
        let c = mldsa87_public_from_seed_native(&[8u8; 32]);
        assert_eq!(a, b, "same seed must derive the same ML-DSA-87 key (restore depends on it)");
        assert_ne!(a, c);
        assert_eq!(a.len(), 2592, "ML-DSA-87 encoded verifying key size");
    }

    #[test]
    fn device_id_is_sha256_of_leaf_key_and_drives_removal() {
        let dev_seed = [5u8; 32];
        let c = client_for([9u8; 32], dev_seed, "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa");
        // id = SHA-256(leaf pubkey): 32 bytes, derivable from the seed alone (enrollment QR needs that).
        let id = c.device_id_native();
        assert_eq!(id.len(), 32);
        assert_eq!(id, device_id_from_seed_native(&dev_seed));
        // group_members reports ids (64 hex chars — fits the backend's String(64) columns unchanged)
        let mut a = client_for([1u8; 32], [11u8; 32], "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb");
        let gid = a.create_group_native();
        let kp = c.key_packages_native(1).remove(0);
        a.add_member_native(&gid, &kp).unwrap();
        let members = a.group_members_native(&gid).unwrap();
        let entry = members.iter().find(|(u, _)| u == "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa").unwrap();
        assert_eq!(entry.1, hex_encode(&id));
        // and removal by device-id hex evicts exactly that leaf
        let commit = a.stage_remove_device_leaf_native(&gid, &hex_encode(&id)).unwrap();
        assert!(!commit.is_empty());
    }

    #[test]
    fn mldsa87_sign_verify_roundtrip() {
        let seed = [3u8; 32];
        let pk = mldsa87_public_from_seed_native(&seed);
        let sig = mldsa87_sign_native(&seed, b"hello pq");
        assert_eq!(sig.len(), 4627, "ML-DSA-87 signature size");
        assert!(mldsa87_verify_native(&pk, b"hello pq", &sig));
        assert!(!mldsa87_verify_native(&pk, b"tampered", &sig));
        let mut bad = sig.clone();
        bad[0] ^= 0xff;
        assert!(!mldsa87_verify_native(&pk, b"hello pq", &bad));
        assert!(!mldsa87_verify_native(&pk[..31], b"hello pq", &sig), "malformed key must not panic");
    }

    #[test]
    fn pq_artifact_sizes_fit_backend_caps() {
        // The delivery backend caps payloads (backend/app/messaging/schemas.py): KeyPackage 36 KiB
        // decoded, message 196 KiB, welcome 1 MiB. PQ artifacts are much bigger than X-Wing's —
        // prove they still fit so no backend change is needed.
        let mut a = client_for([1u8; 32], [11u8; 32], "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa");
        let b = client_for([2u8; 32], [21u8; 32], "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb");
        let kp = b.key_packages_native(1).remove(0);
        assert!(kp.len() < 36_000, "KeyPackage {} must fit the 36 KiB directory cap", kp.len());
        let gid = a.create_group_native();
        let (commit, welcome) = a.add_member_native(&gid, &kp).unwrap();
        assert!(commit.len() < 196_000, "add-commit {} must fit the 196 KiB message cap", commit.len());
        assert!(welcome.len() < 1_000_000, "welcome {} must fit the 1 MiB welcome cap", welcome.len());
        let ct = a.encrypt_native(&gid, b"hi").unwrap();
        assert!(ct.len() < 196_000, "app message {} must fit the 196 KiB cap", ct.len());
    }
}
