// SPDX-License-Identifier:

//! Session management for the enclave protocol.

use crate::{crypto, nsm};
use anyhow::{Result, anyhow};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64URL};
use p256::{EncodedPoint, PublicKey, SecretKey, ecdh::diffie_hellman};
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

pub(crate) struct Session {
    pub session_id: String,

    /// Stored until `KeyExchange`, then consumed.
    pub enclave_priv: Option<SecretKey>,

    /// Uncompressed SEC1 public keys (65 bytes).
    pub enclave_pub: Vec<u8>,
    pub client_pub: Option<Vec<u8>>,

    /// 32-byte derived keys (we use first 16 bytes as AES-128 key).
    pub ck: Option<Vec<u8>>,
    pub mk: Option<Vec<u8>>,
    pub vk: Option<Vec<u8>>,
}

static SESSIONS: OnceLock<Mutex<HashMap<String, Session>>> = OnceLock::new();

fn sessions() -> &'static Mutex<HashMap<String, Session>> {
    SESSIONS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn nsm_random_bytes(len: usize) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(len);
    while out.len() < len {
        let rnd = nsm::get_random().map_err(|e| anyhow!("NSM random failed: {e}"))?;
        out.extend_from_slice(&rnd);
    }
    out.truncate(len);
    Ok(out)
}

pub(crate) fn new_session() -> Result<Session> {
    // session_id: 16 random bytes base64url(no-pad)
    let sid_raw = {
        let rnd = nsm::get_random().map_err(|e| anyhow!("NSM random failed: {e}"))?;
        if rnd.len() < 16 {
            return Err(anyhow!("NSM random too short"));
        }
        rnd[..16].to_vec()
    };
    let session_id = B64URL.encode(sid_raw);

    // ECDH P-256 keypair (entropy from NSM)
    let privkey = loop {
        let sk_bytes = nsm_random_bytes(32)?;
        match SecretKey::from_slice(&sk_bytes) {
            Ok(sk) => break sk,
            Err(_) => continue, // retry on invalid scalar (e.g., 0/out of range)
        }
    };
    let pubkey = privkey.public_key();
    let pubkey = EncodedPoint::from(pubkey).to_bytes().to_vec();

    Ok(Session {
        session_id,
        enclave_priv: Some(privkey),
        enclave_pub: pubkey,
        client_pub: None,
        ck: None,
        mk: None,
        vk: None,
    })
}

pub(crate) fn insert_session(sess: Session) -> Result<()> {
    let mut map = sessions()
        .lock()
        .map_err(|_| anyhow!("session mutex poisoned"))?;
    map.insert(sess.session_id.clone(), sess);
    Ok(())
}

pub(crate) fn take_session(session_id: &str) -> Result<Session> {
    let mut map = sessions()
        .lock()
        .map_err(|_| anyhow!("session mutex poisoned"))?;
    map.remove(session_id)
        .ok_or_else(|| anyhow!("unknown session_id"))
}

pub(crate) fn get_session(session_id: &str) -> Result<Session> {
    let map = sessions()
        .lock()
        .map_err(|_| anyhow!("session mutex poisoned"))?;
    map.get(session_id)
        .map(|s| Session {
            session_id: s.session_id.clone(),
            // not cloneable; keep in map only, so callers should use take_session when needed
            enclave_priv: None,
            enclave_pub: s.enclave_pub.clone(),
            client_pub: s.client_pub.clone(),
            ck: s.ck.clone(),
            mk: s.mk.clone(),
            vk: s.vk.clone(),
        })
        .ok_or_else(|| anyhow!("unknown session_id"))
}

pub(crate) fn put_session(sess: Session) -> Result<()> {
    let mut map = sessions()
        .lock()
        .map_err(|_| anyhow!("session mutex poisoned"))?;
    map.insert(sess.session_id.clone(), sess);
    Ok(())
}

pub(crate) fn delete_session(session_id: &str) -> Result<()> {
    let mut map = sessions()
        .lock()
        .map_err(|_| anyhow!("session mutex poisoned"))?;
    map.remove(session_id);
    Ok(())
}

/// Bind attestation to the session by computing user_data = SHA256(client_pub || enclave_pub || VK).
pub(crate) fn session_user_data(sess: &Session) -> Result<Vec<u8>> {
    let client_pub = sess
        .client_pub
        .as_ref()
        .ok_or_else(|| anyhow!("client_pub not set"))?;
    let vk = sess.vk.as_ref().ok_or_else(|| anyhow!("VK not set"))?;

    let mut buf = Vec::with_capacity(client_pub.len() + sess.enclave_pub.len() + vk.len());
    buf.extend_from_slice(client_pub);
    buf.extend_from_slice(&sess.enclave_pub);
    buf.extend_from_slice(vk);
    Ok(crypto::sha256(&buf))
}

pub(crate) fn ecdh_shared_secret(
    enclave_priv: SecretKey,
    client_pub_sec1: &[u8],
) -> Result<Vec<u8>> {
    let client_pub = PublicKey::from_sec1_bytes(client_pub_sec1)
        .map_err(|e| anyhow!("bad client pubkey: {e}"))?;
    let shared = diffie_hellman(enclave_priv.to_nonzero_scalar(), client_pub.as_affine());
    Ok(shared.raw_secret_bytes().to_vec())
}
