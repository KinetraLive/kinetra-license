//! License tokens.
//!
//! A token is issued per activation (one license on one machine) by
//! `POST /v1/license/activate` and `/refresh`. Features are unlocked by the
//! entitlements in `ent`, never by the plan name.

use serde::{Deserialize, Serialize};

use crate::keys::KeySet;
use crate::{UnixTime, VerifyError, compact};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Slot {
    /// Uses a seat.
    Main,
    /// The one backup machine per license; doesn't use a seat.
    Backup,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LicenseClaims {
    /// Always `"license"`.
    pub typ: String,
    /// Format version, 1.
    pub v: u32,
    /// License id (uuid).
    pub lid: String,
    /// Activation id (uuid): this license on this machine.
    pub aid: String,
    /// Account id (uuid) of the license owner.
    pub sub: String,
    /// Plan, for display only (`pro_yearly`, `perpetual`, …). Never gate features on it.
    pub plan: String,
    /// Entitlements, e.g. `core.app`, `pro.ai` (see [`crate::entitlements`]).
    pub ent: Vec<String>,
    /// Machine fingerprint (see [`crate::machine`]).
    pub machine: String,
    pub slot: Slot,
    /// Server time when issued. The app keeps the latest one it has seen.
    pub iat: UnixTime,
    /// Full access offline until this time (`iat` + 30 days).
    pub grace: UnixTime,
    /// Reduced mode until this time (`grace` + 14 days), then Free.
    pub reduced: UnixTime,
    /// Subscriptions and day passes: the license ends here, online or not.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ends_at: Option<UnixTime>,
    /// Perpetual licenses: app versions released after this time aren't covered.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updates_until: Option<UnixTime>,
    /// Echo of the request nonce, so the app can match the response to its request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
}

impl LicenseClaims {
    pub const TYP: &'static str = "license";

    pub fn has(&self, entitlement: &str) -> bool {
        self.ent.iter().any(|e| e == entitlement)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedLicense {
    pub kid: String,
    pub claims: LicenseClaims,
}

/// Check signature, key status, type, version and machine binding.
///
/// Time-based rules (expiry, offline grace, clock tampering) are *not* errors here; run
/// [`crate::evaluate`] on the result.
pub fn verify_license(
    token: &str,
    keys: &KeySet,
    machine: &str,
) -> Result<VerifiedLicense, VerifyError> {
    let (kid, claims): (String, LicenseClaims) =
        compact::verify(token, keys, LicenseClaims::TYP, compact::MAX_TOKEN_LEN)?;
    // The fingerprint is not a secret, so a plain comparison is fine.
    if claims.machine != machine {
        return Err(VerifyError::WrongMachine);
    }
    Ok(VerifiedLicense { kid, claims })
}

#[cfg(feature = "sign")]
pub fn sign_license(claims: &LicenseClaims, kid: &str, key: &ed25519_dalek::SigningKey) -> String {
    compact::sign(claims, kid, key)
}
