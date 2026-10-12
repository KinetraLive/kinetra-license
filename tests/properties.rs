//! Property tests: no single-byte change to a valid token or signed document verifies.

mod common;

use common::*;
use kinetra_license::keys::KeyStatus;
use kinetra_license::revocation::{RevocationList, sign_revocations, verify_revocations};
use kinetra_license::token::sign_license;
use kinetra_license::verify_license;
use proptest::prelude::*;

fn mutate(s: &str, index: usize, byte: u8) -> Option<String> {
    let mut bytes = s.as_bytes().to_vec();
    let i = index % bytes.len();
    if bytes[i] == byte {
        return None;
    }
    bytes[i] = byte;
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1500))]

    #[test]
    fn any_single_byte_change_breaks_a_license(index in 0usize..10_000, byte in any::<u8>()) {
        let keys = keyset(&[("test-k1", 1, KeyStatus::Active), ("test-k2", 2, KeyStatus::Active)]);
        let token = sign_license(&claims(), "test-k1", &key(1));
        if let Some(bad) = mutate(&token, index, byte) {
            prop_assert!(verify_license(&bad, &keys, MACHINE).is_err(), "accepted: {bad}");
        }
    }

    #[test]
    fn any_single_byte_change_breaks_a_revocation_list(index in 0usize..10_000, byte in any::<u8>()) {
        let keys = keyset(&[("test-k1", 1, KeyStatus::Active)]);
        let list = RevocationList {
            typ: RevocationList::TYP.into(), v: 1, iat: T0,
            licenses: vec!["lic-1".into()], activations: vec!["act-1".into(), "act-2".into()],
        };
        let doc = sign_revocations(&list, "test-k1", &key(1));
        if let Some(bad) = mutate(&doc, index, byte) {
            prop_assert!(verify_revocations(&bad, &keys).is_err());
        }
    }
}

#[test]
fn exhaustive_single_character_substitutions() {
    // Every position with a spread of replacements, alongside the random cases.
    let keys = keyset(&[("test-k1", 1, KeyStatus::Active)]);
    let token = sign_license(&claims(), "test-k1", &key(1));
    for i in 0..token.len() {
        for byte in [b'A', b'B', b'z', b'0', b'_', b'-', b'.', 0u8, 0xff] {
            if let Some(bad) = mutate(&token, i, byte) {
                assert!(
                    verify_license(&bad, &keys, MACHINE).is_err(),
                    "pos {i} byte {byte}"
                );
            }
        }
    }
}

#[test]
fn beta_status_round_trips_and_is_typed() {
    use kinetra_license::beta::{
        BetaProgram, BetaState, BetaStatus, sign_beta_status, verify_beta_status,
    };
    let keys = keyset(&[("test-k1", 1, KeyStatus::Active)]);
    let status = BetaStatus {
        typ: BetaStatus::TYP.into(),
        v: 1,
        iat: T0,
        programs: vec![BetaProgram {
            id: "b1".into(),
            slug: "spring-2027".into(),
            name: "Spring beta".into(),
            state: BetaState::Ended,
            starts_at: T0,
            ends_at: T0 + DAY,
            end_message: "Beta Ended\nThanks for testing!".into(),
        }],
    };
    let doc = sign_beta_status(&status, "test-k1", &key(1));
    assert_eq!(verify_beta_status(&doc, &keys), Ok(status));
    assert_eq!(
        verify_license(&doc, &keys, MACHINE),
        Err(kinetra_license::VerifyError::WrongType)
    );
}

#[test]
fn documents_cant_be_used_as_each_other() {
    let keys = keyset(&[("test-k1", 1, KeyStatus::Active)]);
    let list = RevocationList {
        typ: RevocationList::TYP.into(),
        v: 1,
        iat: T0,
        licenses: vec![],
        activations: vec![],
    };
    let doc = sign_revocations(&list, "test-k1", &key(1));
    assert_eq!(
        verify_license(&doc, &keys, MACHINE),
        Err(kinetra_license::VerifyError::WrongType)
    );
    let token = sign_license(&claims(), "test-k1", &key(1));
    assert_eq!(
        verify_revocations(&token, &keys),
        Err(kinetra_license::VerifyError::WrongType)
    );
}

#[test]
fn large_revocation_lists_verify_but_huge_tokens_dont() {
    let keys = keyset(&[("test-k1", 1, KeyStatus::Active)]);
    // ~50,000 activations (about 2 MB): far beyond any token, still a valid list.
    let list = RevocationList {
        typ: RevocationList::TYP.into(),
        v: 1,
        iat: T0,
        licenses: vec![],
        activations: (0..50_000)
            .map(|i| format!("01a12259-0000-7000-8000-{i:012}"))
            .collect(),
    };
    let doc = sign_revocations(&list, "test-k1", &key(1));
    assert!(doc.len() > 1_000_000);
    assert!(
        verify_revocations(&doc, &keys)
            .expect("verifies")
            .revokes("x", "01a12259-0000-7000-8000-000000049999")
    );
    // A token that large is refused before parsing.
    let mut c = claims();
    c.ent = (0..2000).map(|i| format!("pro.feature_{i}")).collect();
    let token = sign_license(&c, "test-k1", &key(1));
    assert!(token.len() > 16 * 1024);
    assert_eq!(
        verify_license(&token, &keys, MACHINE),
        Err(kinetra_license::VerifyError::Malformed)
    );
}
