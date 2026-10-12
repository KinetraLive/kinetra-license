//! Offline license policy, evaluated identically by the app and the server's tests.
//!
//! Order of checks (first match wins):
//! 1. Revoked (seen on the revocation list): Free.
//! 2. Clock tampering: the local clock is earlier than the latest server time seen →
//!    offline time counts as used up → Free until the next successful refresh.
//! 3. Perpetual license and this app build was released after `updates_until` → Free
//!    for this version (older versions stay licensed).
//! 4. Subscription or day pass past `ends_at` → Free.
//! 5. Before `grace` → full access. Before `reduced` → reduced mode. After → Free.
//!
//! `core.app` (the whole local app) is in effect in every state: the local app is free.
//!
//! The app applies a change of access only when no show is on air; this function just
//! says what the license allows.

use crate::UnixTime;
use crate::entitlements::BASELINE;
use crate::token::LicenseClaims;

/// Clock differences smaller than this aren't treated as tampering (NTP jitter, the time
/// between the server signing and the app storing `iat`).
pub const CLOCK_TOLERANCE_SECS: i64 = 5 * 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EvalInput {
    /// Local clock now.
    pub now: UnixTime,
    /// Latest server time the app has seen (from any token or response). The token's own
    /// `iat` is taken into account automatically.
    pub last_server_time: UnixTime,
    /// Release date of the running app build.
    pub app_release_date: UnixTime,
    /// The license or activation is on the signed revocation list.
    pub revoked: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// Online-fresh or within offline grace: everything the entitlements allow.
    Active,
    /// Offline past the grace period: reduced mode.
    Reduced,
    /// Offline too long: Free until the next successful refresh.
    OfflineExpired,
    /// Subscription or day pass ended.
    Expired,
    /// Perpetual license that doesn't cover this app version.
    NotCovered,
    /// On the revocation list.
    Revoked,
    /// Local clock is behind the server time already seen.
    ClockTampered,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    Full,
    /// Existing work keeps running; no new Pro content.
    Reduced,
    Free,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Evaluation {
    pub status: Status,
    pub access: Access,
    /// Entitlements in effect: the baseline (`core.app`) always, plus the token's for
    /// Full/Reduced.
    pub entitlements: Vec<String>,
    /// For "valid for N more days without connection".
    pub full_until: UnixTime,
    pub reduced_until: UnixTime,
}

pub fn evaluate(claims: &LicenseClaims, input: &EvalInput) -> Evaluation {
    let last_server_time = input.last_server_time.max(claims.iat);
    let status = if input.revoked {
        Status::Revoked
    } else if input.now < last_server_time - CLOCK_TOLERANCE_SECS {
        Status::ClockTampered
    } else if claims
        .updates_until
        .is_some_and(|until| input.app_release_date > until)
    {
        Status::NotCovered
    } else if claims.ends_at.is_some_and(|end| input.now >= end) {
        Status::Expired
    } else if input.now < claims.grace {
        Status::Active
    } else if input.now < claims.reduced {
        Status::Reduced
    } else {
        Status::OfflineExpired
    };
    let access = match status {
        Status::Active => Access::Full,
        Status::Reduced => Access::Reduced,
        _ => Access::Free,
    };
    // Full access never extends past a subscription's end.
    let cap = |t: UnixTime| claims.ends_at.map_or(t, |end| t.min(end));
    Evaluation {
        status,
        access,
        entitlements: entitlements_for(access, &claims.ent),
        full_until: cap(claims.grace),
        reduced_until: cap(claims.reduced),
    }
}

/// The baseline, plus the token's entitlements unless access is Free. Sorted, unique.
fn entitlements_for(access: Access, token: &[String]) -> Vec<String> {
    let mut e: Vec<String> = BASELINE.iter().map(|s| (*s).to_owned()).collect();
    if access != Access::Free {
        e.extend(token.iter().cloned());
    }
    e.sort();
    e.dedup();
    e
}

/// What someone with no license (or no valid token) gets: the baseline.
pub fn no_license() -> Vec<String> {
    entitlements_for(Access::Free, &[])
}

/// Whole days of full access left offline, for the UI ("valid for 18 more days without
/// connection"). 0 when not in full access.
pub fn offline_days_left(eval: &Evaluation, now: UnixTime) -> i64 {
    if eval.access != Access::Full {
        return 0;
    }
    ((eval.full_until - now).max(0)) / 86_400
}
