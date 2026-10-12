//! Compact signed documents: `kntr1.<kid>.<payload>.<sig>`.
//!
//! - `payload` is base64url (no padding) of a JSON object with a `typ` field.
//! - `sig` is base64url of an Ed25519 signature over the ASCII bytes
//!   `kntr1.<kid>.<payload>`, so any change to version, kid or payload breaks it.
//! - Only Ed25519 exists; there is no algorithm field to confuse.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signature, Verifier};
use serde::de::DeserializeOwned;

use crate::VerifyError;
use crate::keys::{KeySet, KeyStatus};

pub(crate) const VERSION: &str = "kntr1";
/// Size caps, checked before any parsing. License tokens are well under 2 KiB; lists
/// (revocations, beta status) grow with use, e.g. every deactivation in the window.
pub(crate) const MAX_TOKEN_LEN: usize = 16 * 1024;
pub(crate) const MAX_LIST_LEN: usize = 8 * 1024 * 1024;

pub(crate) fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

pub(crate) fn unb64(s: &str) -> Result<Vec<u8>, VerifyError> {
    URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|_| VerifyError::Malformed)
}

pub(crate) fn valid_kid(kid: &str) -> bool {
    (1..=64).contains(&kid.len())
        && kid
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

pub(crate) struct Parsed<'a> {
    pub kid: &'a str,
    pub signed: &'a str,
    pub payload: Vec<u8>,
    pub signature: Signature,
}

pub(crate) fn parse(doc: &str, max_len: usize) -> Result<Parsed<'_>, VerifyError> {
    if doc.len() > max_len || !doc.is_ascii() {
        return Err(VerifyError::Malformed);
    }
    let (signed, sig_b64) = doc.rsplit_once('.').ok_or(VerifyError::Malformed)?;
    let mut parts = signed.splitn(3, '.');
    let (Some(version), Some(kid), Some(payload_b64)) = (parts.next(), parts.next(), parts.next())
    else {
        return Err(VerifyError::Malformed);
    };
    if version != VERSION {
        return Err(if version.starts_with("kntr") {
            VerifyError::UnsupportedVersion
        } else {
            VerifyError::Malformed
        });
    }
    if !valid_kid(kid) || payload_b64.contains('.') {
        return Err(VerifyError::Malformed);
    }
    let sig: [u8; 64] = unb64(sig_b64)?
        .try_into()
        .map_err(|_| VerifyError::Malformed)?;
    Ok(Parsed {
        kid,
        signed,
        payload: unb64(payload_b64)?,
        signature: Signature::from_bytes(&sig),
    })
}

/// Verify against the key set and decode the payload, checking its `typ`.
pub(crate) fn verify<T: DeserializeOwned>(
    doc: &str,
    keys: &KeySet,
    expected_typ: &str,
    max_len: usize,
) -> Result<(String, T), VerifyError> {
    let parsed = parse(doc, max_len)?;
    let entry = keys.get(parsed.kid).ok_or(VerifyError::UnknownKey)?;
    if entry.status == KeyStatus::Revoked {
        return Err(VerifyError::RevokedKey);
    }
    entry
        .key
        .verify(parsed.signed.as_bytes(), &parsed.signature)
        .map_err(|_| VerifyError::BadSignature)?;
    // Only parse JSON after the signature checked out.
    let value: serde_json::Value =
        serde_json::from_slice(&parsed.payload).map_err(|_| VerifyError::Malformed)?;
    if value.get("typ").and_then(|t| t.as_str()) != Some(expected_typ) {
        return Err(VerifyError::WrongType);
    }
    if value.get("v").and_then(serde_json::Value::as_u64) != Some(1) {
        return Err(VerifyError::UnsupportedVersion);
    }
    let payload = serde_json::from_value(value).map_err(|_| VerifyError::Malformed)?;
    Ok((parsed.kid.to_owned(), payload))
}

#[cfg(feature = "sign")]
pub(crate) fn sign<T: serde::Serialize>(
    payload: &T,
    kid: &str,
    key: &ed25519_dalek::SigningKey,
) -> String {
    use ed25519_dalek::Signer;
    assert!(valid_kid(kid), "invalid kid");
    let payload = serde_json::to_vec(payload).expect("payload serializes");
    let signed = format!("{VERSION}.{kid}.{}", b64(&payload));
    let sig = key.sign(signed.as_bytes());
    format!("{signed}.{}", b64(&sig.to_bytes()))
}
