//! Committed test vectors. The desktop app runs the same file through its own copy of
//! this crate, so both sides provably agree on the format.
//!
//! Regenerate (only when the format changes on purpose):
//! `cargo test --all-features --test vectors -- --ignored regenerate`

mod common;

use common::*;
use kinetra_license::keys::KeyStatus;
use kinetra_license::token::sign_license;
use kinetra_license::{EvalInput, Status, VerifyError, evaluate, verify_license};
use serde_json::{Value, json};

const PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors/tokens.json");

fn tamper_payload(token: &str) -> String {
    // Flip one character in the middle of the payload segment.
    let parts: Vec<&str> = token.split('.').collect();
    let mut payload: Vec<u8> = parts[2].bytes().collect();
    let i = payload.len() / 2;
    payload[i] = if payload[i] == b'A' { b'B' } else { b'A' };
    format!(
        "{}.{}.{}.{}",
        parts[0],
        parts[1],
        String::from_utf8_lossy(&payload),
        parts[3]
    )
}

fn tamper_signature(token: &str) -> String {
    let (head, sig) = token.rsplit_once('.').expect("sig");
    let mut sig: Vec<u8> = sig.bytes().collect();
    sig[10] = if sig[10] == b'A' { b'B' } else { b'A' };
    format!("{head}.{}", String::from_utf8_lossy(&sig))
}

fn build() -> Value {
    let k1 = key(1);
    let valid = sign_license(&claims(), "test-k1", &k1);
    let mut expired = claims();
    expired.ends_at = Some(T0 + DAY);
    let mut perpetual = claims();
    perpetual.plan = "perpetual".into();
    perpetual.ends_at = None;
    perpetual.updates_until = Some(T0 + 365 * DAY);
    json!({
        "comment": "Test-only keys (seeds are public). Machine = fingerprint(\"00000000-0000-0000-0000-000000000000\").",
        "keyset": {"iat": 0, "keys": keyset(&[("test-k1", 1, KeyStatus::Active), ("test-revoked", 3, KeyStatus::Revoked)]).infos()},
        "machine": MACHINE,
        "now": T0 + DAY,
        "vectors": [
            {"name": "valid", "token": valid, "verify": "ok", "status": "active"},
            {"name": "expired", "token": sign_license(&expired, "test-k1", &k1), "verify": "ok", "status": "expired", "now": T0 + 2 * DAY},
            {"name": "perpetual_covered", "token": sign_license(&perpetual, "test-k1", &k1), "verify": "ok", "status": "active", "app_release_date": T0},
            {"name": "perpetual_newer_app", "token": sign_license(&perpetual, "test-k1", &k1), "verify": "ok", "status": "not_covered", "app_release_date": T0 + 400 * DAY},
            {"name": "wrong_kid", "token": sign_license(&claims(), "test-k2", &key(2)), "verify": "unknown_key"},
            {"name": "revoked_kid", "token": sign_license(&claims(), "test-revoked", &key(3)), "verify": "revoked_key"},
            {"name": "kid_swapped", "token": valid.replacen("test-k1", "test-revoked", 1), "verify": "revoked_key"},
            {"name": "tampered_payload", "token": tamper_payload(&valid), "verify": "bad_signature"},
            {"name": "tampered_signature", "token": tamper_signature(&valid), "verify": "bad_signature"},
            {"name": "wrong_machine", "token": valid, "machine": "0".repeat(64), "verify": "wrong_machine"},
            {"name": "other_version", "token": valid.replacen("kntr1.", "kntr2.", 1), "verify": "unsupported_version"},
            {"name": "garbage", "token": "not a token", "verify": "malformed"},
        ]
    })
}

fn err_name(e: &VerifyError) -> &'static str {
    match e {
        VerifyError::Malformed => "malformed",
        VerifyError::UnsupportedVersion => "unsupported_version",
        VerifyError::UnknownKey => "unknown_key",
        VerifyError::RevokedKey => "revoked_key",
        VerifyError::BadSignature => "bad_signature",
        VerifyError::WrongType => "wrong_type",
        VerifyError::WrongMachine => "wrong_machine",
        VerifyError::StaleKeySet => "stale_keyset",
    }
}

fn status_name(s: Status) -> &'static str {
    match s {
        Status::Active => "active",
        Status::Reduced => "reduced",
        Status::OfflineExpired => "offline_expired",
        Status::Expired => "expired",
        Status::NotCovered => "not_covered",
        Status::Revoked => "revoked",
        Status::ClockTampered => "clock_tampered",
    }
}

#[test]
#[ignore = "writes tests/vectors/tokens.json"]
fn regenerate() {
    let text = serde_json::to_string_pretty(&build()).expect("json");
    std::fs::write(PATH, text + "\n").expect("write vectors");
}

#[test]
fn committed_vectors_match_this_implementation() {
    let committed: Value =
        serde_json::from_str(&std::fs::read_to_string(PATH).expect("vectors file")).expect("json");
    // Ed25519 is deterministic: re-signing must give byte-identical tokens.
    assert_eq!(
        committed,
        build(),
        "format drifted; regenerate only if intended"
    );

    let keys = kinetra_license::KeySet::from_trusted_json(&committed["keyset"].to_string())
        .expect("keyset");
    for v in committed["vectors"].as_array().expect("vectors") {
        let name = v["name"].as_str().unwrap_or_default();
        let machine = v["machine"].as_str().unwrap_or(MACHINE);
        let result = verify_license(v["token"].as_str().unwrap_or_default(), &keys, machine);
        match (&result, v["verify"].as_str().unwrap_or_default()) {
            (Ok(_), "ok") => {}
            (Err(e), expected) => assert_eq!(err_name(e), expected, "{name}"),
            (Ok(_), expected) => panic!("{name}: verified but expected {expected}"),
        }
        if let (Ok(lic), Some(expected)) = (&result, v["status"].as_str()) {
            let now = v["now"]
                .as_i64()
                .or(committed["now"].as_i64())
                .unwrap_or(T0);
            let eval = evaluate(
                &lic.claims,
                &EvalInput {
                    now,
                    last_server_time: T0,
                    app_release_date: v["app_release_date"].as_i64().unwrap_or(T0),
                    revoked: false,
                },
            );
            assert_eq!(status_name(eval.status), expected, "{name}");
        }
    }
}
