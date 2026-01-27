// SPDX-License-Identifier:

use anyhow::Result;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedBlob {
    pub nonce_b64: String,
    pub ciphertext_b64: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum Request {
    Init,
    KeyExchange {
        session_id: String,
        client_pubkey_b64: String,
    },
    Add {
        session_id: String,
        x: EncryptedBlob,
        y: EncryptedBlob,
    },
    Close {
        session_id: String,
    },
    Attest {
        session_id: Option<String>,
        user_data_b64: Option<String>,
        nonce_b64: Option<String>,
    },
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
    pub fn to_json(&self) -> Result<String> {
        Ok(serde_json::to_string(self)?)
    }
}

impl Response {
    pub fn from_json(s: &str) -> Result<Self> {
        Ok(serde_json::from_str(s)?)
    }
}
