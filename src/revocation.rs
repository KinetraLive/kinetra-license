//! Signed revocation list (`GET /v1/license/revocations`).
//!
//! Lists licenses and activations revoked or deactivated recently (long enough that any
//! token issued before the revocation has run out of offline grace). The app checks its
//! own `lid`/`aid` against it whenever it's online, even if refresh fails.

use serde::{Deserialize, Serialize};

use crate::keys::KeySet;
use crate::{UnixTime, VerifyError, compact};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevocationList {
    /// Always `"revocations"`.
    pub typ: String,
    pub v: u32,
    pub iat: UnixTime,
    /// Revoked license ids.
    pub licenses: Vec<String>,
    /// Deactivated or revoked activation ids.
    pub activations: Vec<String>,
}

impl RevocationList {
    pub const TYP: &'static str = "revocations";

    pub fn revokes(&self, lid: &str, aid: &str) -> bool {
        self.licenses.iter().any(|l| l == lid) || self.activations.iter().any(|a| a == aid)
    }
}

pub fn verify_revocations(doc: &str, keys: &KeySet) -> Result<RevocationList, VerifyError> {
    compact::verify(doc, keys, RevocationList::TYP, compact::MAX_LIST_LEN).map(|(_, list)| list)
}

#[cfg(feature = "sign")]
pub fn sign_revocations(
    list: &RevocationList,
    kid: &str,
    key: &ed25519_dalek::SigningKey,
) -> String {
    compact::sign(list, kid, key)
}
