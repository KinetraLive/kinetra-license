//! Fixed test keys. NEVER used outside tests: the seeds are public.

#![allow(dead_code)]

use ed25519_dalek::SigningKey;
use kinetra_license::keys::{KeyStatus, key_info};
use kinetra_license::{KeySet, LicenseClaims, Slot};

pub fn key(n: u8) -> SigningKey {
    SigningKey::from_bytes(&[n; 32])
}

pub fn keyset(entries: &[(&str, u8, KeyStatus)]) -> KeySet {
    let infos: Vec<_> = entries
        .iter()
        .map(|(kid, n, s)| key_info(kid, &key(*n), *s))
        .collect();
    KeySet::from_infos(&infos, 0).expect("keyset")
}

pub const MACHINE: &str = "857a78b7a23b14cd718a9cbf9b90b0577225543ddcce5ed21854a4985f25ee27";
pub const T0: i64 = 1_791_590_400; // 2026-10-10T00:00:00Z
pub const DAY: i64 = 86_400;

pub fn claims() -> LicenseClaims {
    LicenseClaims {
        typ: "license".into(),
        v: 1,
        lid: "01a12259-0000-7000-8000-000000000001".into(),
        aid: "01a12259-0000-7000-8000-000000000002".into(),
        sub: "01a12259-0000-7000-8000-000000000003".into(),
        plan: "pro_yearly".into(),
        ent: vec!["core.app".into(), "pro.ai".into(), "pro.polls".into()],
        machine: MACHINE.into(),
        slot: Slot::Main,
        iat: T0,
        grace: T0 + 30 * DAY,
        reduced: T0 + 44 * DAY,
        ends_at: Some(T0 + 365 * DAY),
        updates_until: None,
        nonce: Some("n0nce".into()),
    }
}
