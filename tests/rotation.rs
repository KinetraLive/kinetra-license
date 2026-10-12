//! Key rotation, including a client that was offline during the rotation.

mod common;

use common::*;
use kinetra_license::keys::{KeyStatus, key_info, sign_keyset};
use kinetra_license::token::sign_license;
use kinetra_license::{KeySet, VerifyError, verify_license};

#[test]
fn offline_client_learns_new_key_vouched_by_old_one() {
    // The app shipped trusting only K1.
    let mut client = keyset(&[("k1", 1, KeyStatus::Active)]);
    let old_token = sign_license(&claims(), "k1", &key(1));
    assert!(verify_license(&old_token, &client, MACHINE).is_ok());

    // While the client is offline the server rotates twice: K2, then K3. K1 and K2 are
    // retired, their private keys kept for signing key sets.
    let server_keys = [
        key_info("k1", &key(1), KeyStatus::Retired),
        key_info("k2", &key(2), KeyStatus::Retired),
        key_info("k3", &key(3), KeyStatus::Active),
    ];
    let (k1, k2, k3) = (key(1), key(2), key(3));
    let update = sign_keyset(
        &server_keys,
        T0 + 100,
        &[("k1", &k1), ("k2", &k2), ("k3", &k3)],
    );
    let new_token = sign_license(&claims(), "k3", &key(3));

    // Before updating, the new token isn't trusted.
    assert_eq!(
        verify_license(&new_token, &client, MACHINE),
        Err(VerifyError::UnknownKey)
    );
    // Back online: fetch keys, apply (vouched for by K1), refresh.
    client.apply_update(&update).expect("update vouched by k1");
    assert!(verify_license(&new_token, &client, MACHINE).is_ok());
    // The old token stays valid (K1 is retired, not revoked) until it's refreshed.
    assert!(verify_license(&old_token, &client, MACHINE).is_ok());
    assert_eq!(client.get("k1").map(|e| e.status), Some(KeyStatus::Retired));
}

#[test]
fn updates_need_a_trusted_signature() {
    let mut client = keyset(&[("k1", 1, KeyStatus::Active)]);
    let attacker = key(66);
    let forged = sign_keyset(
        &[key_info("evil", &attacker, KeyStatus::Active)],
        T0,
        &[("evil", &attacker)],
    );
    assert_eq!(client.apply_update(&forged), Err(VerifyError::UnknownKey));

    // Claiming to be k1 with the wrong key.
    let forged = sign_keyset(
        &[key_info("evil", &attacker, KeyStatus::Active)],
        T0,
        &[("k1", &attacker)],
    );
    assert_eq!(client.apply_update(&forged), Err(VerifyError::BadSignature));
    assert!(client.get("evil").is_none());
}

#[test]
fn revocation_sticks_and_rollback_is_refused() {
    let mut client = keyset(&[("k1", 1, KeyStatus::Active), ("k2", 2, KeyStatus::Active)]);
    let (k1, k2) = (key(1), key(2));
    let token_k1 = sign_license(&claims(), "k1", &k1);

    // K1 compromised: server revokes it, signs the new set with K2 only.
    let revoke = sign_keyset(
        &[
            key_info("k1", &k1, KeyStatus::Revoked),
            key_info("k2", &k2, KeyStatus::Active),
        ],
        T0 + 10,
        &[("k2", &k2)],
    );
    client.apply_update(&revoke).expect("apply");
    assert_eq!(
        verify_license(&token_k1, &client, MACHINE),
        Err(VerifyError::RevokedKey)
    );

    // An attacker holding K1 replays an older set, or signs a newer one un-revoking K1.
    let old = sign_keyset(
        &[key_info("k1", &k1, KeyStatus::Active)],
        T0,
        &[("k2", &k2)],
    );
    assert_eq!(client.apply_update(&old), Err(VerifyError::StaleKeySet));
    let unrevoke = sign_keyset(
        &[key_info("k1", &k1, KeyStatus::Active)],
        T0 + 20,
        &[("k1", &k1)],
    );
    assert!(client.apply_update(&unrevoke).is_err());
    let via_k2 = sign_keyset(
        &[key_info("k1", &k1, KeyStatus::Active)],
        T0 + 30,
        &[("k2", &k2)],
    );
    client.apply_update(&via_k2).expect("apply");
    assert_eq!(client.get("k1").map(|e| e.status), Some(KeyStatus::Revoked));
}

#[test]
fn same_kid_with_different_key_is_rejected() {
    let mut client = keyset(&[("k1", 1, KeyStatus::Active)]);
    let k1 = key(1);
    let swap = sign_keyset(
        &[key_info("k1", &key(9), KeyStatus::Active)],
        T0,
        &[("k1", &k1)],
    );
    assert_eq!(client.apply_update(&swap), Err(VerifyError::Malformed));
}

#[test]
fn key_sets_round_trip_through_json() {
    let client = keyset(&[("k1", 1, KeyStatus::Active), ("k2", 2, KeyStatus::Retired)]);
    let restored = KeySet::from_trusted_json(&client.to_json()).expect("json");
    assert_eq!(restored, client);
}
