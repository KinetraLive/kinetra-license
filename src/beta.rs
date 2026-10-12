//! Signed beta status (`GET /v1/beta/status`).
//!
//! Beta builds check it whenever they're online: when a program has ended, the app shows
//! `end_message` (lines separated by `\n`) once no show is on air. Beta licenses also
//! carry the program's hard end in `ends_at` and a short offline grace, so an offline
//! beta build stops on its own.

use serde::{Deserialize, Serialize};

use crate::keys::KeySet;
use crate::{UnixTime, VerifyError, compact};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BetaState {
    Upcoming,
    Active,
    Ended,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BetaProgram {
    pub id: String,
    pub slug: String,
    pub name: String,
    pub state: BetaState,
    pub starts_at: UnixTime,
    pub ends_at: UnixTime,
    pub end_message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BetaStatus {
    /// Always `"beta_status"`.
    pub typ: String,
    pub v: u32,
    pub iat: UnixTime,
    pub programs: Vec<BetaProgram>,
}

impl BetaStatus {
    pub const TYP: &'static str = "beta_status";

    pub fn program(&self, slug: &str) -> Option<&BetaProgram> {
        self.programs.iter().find(|p| p.slug == slug)
    }
}

pub fn verify_beta_status(doc: &str, keys: &KeySet) -> Result<BetaStatus, VerifyError> {
    compact::verify(doc, keys, BetaStatus::TYP, compact::MAX_LIST_LEN).map(|(_, s)| s)
}

#[cfg(feature = "sign")]
pub fn sign_beta_status(status: &BetaStatus, kid: &str, key: &ed25519_dalek::SigningKey) -> String {
    compact::sign(status, kid, key)
}
