//! Trusted public keys and signed key-set updates.
//!
//! The app ships with an embedded key set (trusted because it's compiled in). It updates
//! it from `GET /v1/license/keys`, which returns a [`SignedKeySet`]: the full key list,
//! signed by every non-revoked server key that still has its private half. An update is
//! accepted only if at least one signature comes from a key the app already trusts and
//! the list isn't older than the one it has (no rollback). That is how a client that was
//! offline during a rotation learns the new key: the old key vouches for it.

use std::collections::BTreeMap;

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::compact::{b64, unb64, valid_kid};
use crate::{UnixTime, VerifyError};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KeyStatus {
    /// Signs new licenses.
    Active,
    /// No longer signs licenses; licenses it signed stay valid until refreshed.
    Retired,
    /// Compromised or withdrawn: nothing it signed is valid.
    Revoked,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyEntry {
    pub key: VerifyingKey,
    pub status: KeyStatus,
}

/// One key as it appears in JSON.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyInfo {
    pub kid: String,
    /// base64url of the 32-byte Ed25519 public key.
    pub public_key: String,
    pub status: KeyStatus,
}

/// The key list payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeySetPayload {
    pub typ: String,
    pub v: u32,
    /// When the server produced this list. Updates must not go backwards.
    pub iat: UnixTime,
    pub keys: Vec<KeyInfo>,
}

impl KeySetPayload {
    pub const TYP: &'static str = "keyset";
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeySignature {
    pub kid: String,
    pub sig: String,
}

/// `GET /v1/license/keys` response body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedKeySet {
    /// base64url of the JSON [`KeySetPayload`].
    pub keyset: String,
    pub signatures: Vec<KeySignature>,
}

const KEYSET_CONTEXT: &str = "kntr1-keyset.";

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KeySet {
    keys: BTreeMap<String, KeyEntry>,
    iat: UnixTime,
}

impl KeySet {
    /// Keys the caller trusts unconditionally (compiled into the app, or loaded by the
    /// server). JSON: `{"keys": [{"kid", "public_key", "status"}]}` or a full payload.
    pub fn from_trusted_json(json: &str) -> Result<Self, VerifyError> {
        #[derive(Deserialize)]
        struct Embedded {
            #[serde(default)]
            iat: UnixTime,
            keys: Vec<KeyInfo>,
        }
        let e: Embedded = serde_json::from_str(json).map_err(|_| VerifyError::Malformed)?;
        Self::from_infos(&e.keys, e.iat)
    }

    pub fn from_infos(infos: &[KeyInfo], iat: UnixTime) -> Result<Self, VerifyError> {
        let mut keys = BTreeMap::new();
        for info in infos {
            if !valid_kid(&info.kid) {
                return Err(VerifyError::Malformed);
            }
            let bytes: [u8; 32] = unb64(&info.public_key)?
                .try_into()
                .map_err(|_| VerifyError::Malformed)?;
            let key = VerifyingKey::from_bytes(&bytes).map_err(|_| VerifyError::Malformed)?;
            keys.insert(
                info.kid.clone(),
                KeyEntry {
                    key,
                    status: info.status,
                },
            );
        }
        Ok(Self { keys, iat })
    }

    pub fn get(&self, kid: &str) -> Option<&KeyEntry> {
        self.keys.get(kid)
    }

    pub fn iat(&self) -> UnixTime {
        self.iat
    }

    pub fn infos(&self) -> Vec<KeyInfo> {
        self.keys
            .iter()
            .map(|(kid, e)| KeyInfo {
                kid: kid.clone(),
                public_key: b64(e.key.as_bytes()),
                status: e.status,
            })
            .collect()
    }

    /// JSON for persisting the current set (e.g. in the app's settings).
    pub fn to_json(&self) -> String {
        serde_json::json!({"iat": self.iat, "keys": self.infos()}).to_string()
    }

    /// Verify a signed key set against the keys trusted now and, if valid, adopt it.
    ///
    /// Keys missing from the update are kept (a missing key is not a revocation); keys in
    /// the update are added or have their status replaced. A key once revoked stays
    /// revoked.
    pub fn apply_update(&mut self, update: &SignedKeySet) -> Result<(), VerifyError> {
        let payload_bytes = unb64(&update.keyset)?;
        let message = format!("{KEYSET_CONTEXT}{}", update.keyset);
        let vouched = update.signatures.iter().any(|s| {
            let Some(entry) = self.keys.get(&s.kid) else {
                return false;
            };
            if entry.status == KeyStatus::Revoked {
                return false;
            }
            let Ok(sig) = unb64(&s.sig).and_then(|b| {
                <[u8; 64]>::try_from(b.as_slice()).map_err(|_| VerifyError::Malformed)
            }) else {
                return false;
            };
            entry
                .key
                .verify(message.as_bytes(), &Signature::from_bytes(&sig))
                .is_ok()
        });
        if !vouched {
            return Err(
                if update
                    .signatures
                    .iter()
                    .any(|s| self.keys.contains_key(&s.kid))
                {
                    VerifyError::BadSignature
                } else {
                    VerifyError::UnknownKey
                },
            );
        }
        let payload: KeySetPayload =
            serde_json::from_slice(&payload_bytes).map_err(|_| VerifyError::Malformed)?;
        if payload.typ != KeySetPayload::TYP {
            return Err(VerifyError::WrongType);
        }
        if payload.v != 1 {
            return Err(VerifyError::UnsupportedVersion);
        }
        if payload.iat < self.iat {
            return Err(VerifyError::StaleKeySet);
        }
        let incoming = Self::from_infos(&payload.keys, payload.iat)?;
        for (kid, mut entry) in incoming.keys {
            if let Some(existing) = self.keys.get(&kid) {
                if existing.key != entry.key {
                    // Same kid, different key material: never silently replace.
                    return Err(VerifyError::Malformed);
                }
                if existing.status == KeyStatus::Revoked {
                    entry.status = KeyStatus::Revoked;
                }
            }
            self.keys.insert(kid, entry);
        }
        self.iat = payload.iat;
        Ok(())
    }
}

/// Sign a key list with every given key (server side).
#[cfg(feature = "sign")]
pub fn sign_keyset(
    keys: &[KeyInfo],
    iat: UnixTime,
    signers: &[(&str, &ed25519_dalek::SigningKey)],
) -> SignedKeySet {
    use ed25519_dalek::Signer;
    let payload = KeySetPayload {
        typ: KeySetPayload::TYP.to_owned(),
        v: 1,
        iat,
        keys: keys.to_vec(),
    };
    let keyset = b64(&serde_json::to_vec(&payload).expect("serializes"));
    let message = format!("{KEYSET_CONTEXT}{keyset}");
    let signatures = signers
        .iter()
        .map(|(kid, key)| KeySignature {
            kid: (*kid).to_owned(),
            sig: b64(&key.sign(message.as_bytes()).to_bytes()),
        })
        .collect();
    SignedKeySet { keyset, signatures }
}

/// `KeyInfo` for a signing key.
#[cfg(feature = "sign")]
pub fn key_info(kid: &str, key: &ed25519_dalek::SigningKey, status: KeyStatus) -> KeyInfo {
    KeyInfo {
        kid: kid.to_owned(),
        public_key: b64(key.verifying_key().as_bytes()),
        status,
    }
}
