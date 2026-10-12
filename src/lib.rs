//! Kinetra license tokens, shared by the server and the desktop app.
//!
//! Everything here is pure: no I/O, no clock, no randomness (callers pass them in), so
//! the app and the server evaluate licenses identically.
//!
//! - [`token`]: signed license tokens (`kntr1.<kid>.<payload>.<sig>`), claims, verify.
//! - [`keys`]: trusted public keys, signed key-set updates (rotation, revocation).
//! - [`revocation`]: signed revocation list.
//! - [`beta`]: signed beta-program status.
//! - [`entitlements`]: the entitlement catalog (`core.app`, `pro.*`, `business.*`).
//! - [`evaluate`]: offline policy (active, reduced, expired, clock tampering, …).
//! - [`key_format`]: `KNTR-XXXX-XXXX-XXXX` license keys (generate, normalize, auto-format).
//! - [`machine`]: machine fingerprint from the OS machine id.

pub mod beta;
pub mod entitlements;
pub mod evaluate;
pub mod key_format;
pub mod keys;
pub mod machine;
pub mod revocation;
pub mod token;

mod compact;

pub use evaluate::{Access, EvalInput, Evaluation, Status, evaluate};
pub use keys::{KeySet, KeyStatus, SignedKeySet};
pub use token::{LicenseClaims, Slot, VerifiedLicense, verify_license};

/// Why a token or signed document was rejected. Deliberately coarse: the app treats every
/// variant as "no valid license from this token".
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum VerifyError {
    #[error("malformed token")]
    Malformed,
    #[error("unsupported format version")]
    UnsupportedVersion,
    #[error("signed with an unknown key")]
    UnknownKey,
    #[error("signed with a revoked key")]
    RevokedKey,
    #[error("bad signature")]
    BadSignature,
    #[error("wrong document type")]
    WrongType,
    #[error("license is for another machine")]
    WrongMachine,
    #[error("key set is older than the one already trusted")]
    StaleKeySet,
}

/// Seconds since the Unix epoch, UTC. All times in tokens use this.
pub type UnixTime = i64;
