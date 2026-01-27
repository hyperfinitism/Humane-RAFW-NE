// SPDX-License-Identifier:

use anyhow::{Result, anyhow};
use aws_lc_rs::rand::SecureRandom;
use aws_lc_rs::{aead, digest, hmac, rand};
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};

pub(crate) fn sha256(data: &[u8]) -> Vec<u8> {
    digest::digest(&digest::SHA256, data).as_ref().to_vec()
}

pub(crate) fn derive_key(shared_secret: &[u8], label: &[u8]) -> Vec<u8> {
    let key = hmac::Key::new(hmac::HMAC_SHA256, shared_secret);
    hmac::sign(&key, label).as_ref().to_vec()
}

pub(crate) fn b64_encode(data: &[u8]) -> String {
    B64.encode(data)
}

pub(crate) fn b64_decode(s: &str) -> Result<Vec<u8>> {
    Ok(B64.decode(s)?)
}

pub(crate) fn aes128gcm_encrypt(
    key_16: &[u8],
    nonce_12: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    if key_16.len() != 16 {
        return Err(anyhow!("AES-128-GCM key must be 16 bytes"));
    }
    if nonce_12.len() != 12 {
        return Err(anyhow!("AES-128-GCM nonce must be 12 bytes"));
    }
    let unbound = aead::UnboundKey::new(&aead::AES_128_GCM, key_16)?;
    let less_safe = aead::LessSafeKey::new(unbound);
    let nonce = aead::Nonce::try_assume_unique_for_key(nonce_12)?;
    let mut in_out = plaintext.to_vec();
    less_safe.seal_in_place_append_tag(nonce, aead::Aad::empty(), &mut in_out)?;
    Ok(in_out)
}

pub(crate) fn aes128gcm_decrypt(
    key_16: &[u8],
    nonce_12: &[u8],
    ciphertext_and_tag: &[u8],
) -> Result<Vec<u8>> {
    if key_16.len() != 16 {
        return Err(anyhow!("AES-128-GCM key must be 16 bytes"));
    }
    if nonce_12.len() != 12 {
        return Err(anyhow!("AES-128-GCM nonce must be 12 bytes"));
    }
    let unbound = aead::UnboundKey::new(&aead::AES_128_GCM, key_16)?;
    let less_safe = aead::LessSafeKey::new(unbound);
    let nonce = aead::Nonce::try_assume_unique_for_key(nonce_12)?;
    let mut in_out = ciphertext_and_tag.to_vec();
    let pt = less_safe.open_in_place(nonce, aead::Aad::empty(), &mut in_out)?;
    Ok(pt.to_vec())
}

pub(crate) fn random_bytes(len: usize) -> Result<Vec<u8>> {
    let rng = rand::SystemRandom::new();
    let mut out = vec![0u8; len];
    rng.fill(&mut out)?;
    Ok(out)
}
