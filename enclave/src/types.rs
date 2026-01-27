// SPDX-License-Identifier:

//! This module provides public types.

use anyhow::Result;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum Request {
    /// Start a session. Enclave returns (session_id, enclave_pubkey).
    Init,

    /// Complete ECDH and request attestation bound to this session.
    ///
    /// - `client_pubkey_b64`: uncompressed SEC1 (65 bytes) base64.
    KeyExchange {
        session_id: String,
        client_pubkey_b64: String,
    },

    /// Encrypted add request.
    Add {
        session_id: String,
        x: EncryptedBlob,
        y: EncryptedBlob,
    },

    /// Close the session and wipe keys.
    Close { session_id: String },

    /// Request an attestation document anytime.
    ///
    /// - If `user_data_b64` or `nonce_b64` is omitted, enclave fills it.
    /// - If both are omitted, `session_id` must be provided and enclave uses
    ///   SHA256(client_pubkey || enclave_pubkey || VK) as user_data and NSM random as nonce.
    Attest {
        session_id: Option<String>,
        user_data_b64: Option<String>,
        nonce_b64: Option<String>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedBlob {
    pub nonce_b64: String,      // 12 bytes
    pub ciphertext_b64: String, // includes tag
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum Response {
    Init {
        session_id: String,
        enclave_pubkey_b64: String,
    },
    KeyExchange {
        attestation_document_b64: String,
    },
    Add {
        sum: EncryptedBlob,
    },
    CloseOk {},
    Attest {
        attestation_document_b64: String,
    },
    Error {
        error: String,
    },
}

impl Request {
    pub fn from_json(s: &str) -> Result<Self> {
        Ok(serde_json::from_str(s)?)
    }
}

impl Response {
    pub fn to_json(&self) -> Result<String> {
        Ok(serde_json::to_string(self)?)
    }
}
