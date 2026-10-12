//! Every license state and the transitions between them.

mod common;

use common::*;
use kinetra_license::evaluate::{CLOCK_TOLERANCE_SECS, offline_days_left};
use kinetra_license::{Access, EvalInput, Status, evaluate};

fn at(now: i64) -> EvalInput {
    EvalInput {
        now,
        last_server_time: T0,
        app_release_date: T0 - 30 * DAY,
        revoked: false,
    }
}

#[test]
fn offline_timeline_active_reduced_free() {
    let c = claims();
    let e = evaluate(&c, &at(T0 + DAY));
    assert_eq!((e.status, e.access), (Status::Active, Access::Full));
    assert_eq!(e.entitlements, ["core.app", "pro.ai", "pro.polls"]);
    assert_eq!(offline_days_left(&e, T0 + DAY), 29);

    let e = evaluate(&c, &at(c.grace - 1));
    assert_eq!(e.status, Status::Active);
    let e = evaluate(&c, &at(c.grace));
    assert_eq!((e.status, e.access), (Status::Reduced, Access::Reduced));
    assert_eq!(e.entitlements, ["core.app", "pro.ai", "pro.polls"]); // the app decides what reduced allows
    assert_eq!(offline_days_left(&e, c.grace), 0);
    let e = evaluate(&c, &at(c.reduced));
    assert_eq!((e.status, e.access), (Status::OfflineExpired, Access::Free));
    // The local app is free: core.app stays, Pro goes.
    assert_eq!(e.entitlements, ["core.app"]);
}

#[test]
fn free_licenses_never_lose_core_app() {
    let mut c = claims();
    c.plan = "free".into();
    c.ent = vec!["core.app".into()];
    c.ends_at = None;
    for now in [T0, T0 + 40 * DAY, T0 + 10 * 365 * DAY] {
        assert_eq!(evaluate(&c, &at(now)).entitlements, ["core.app"], "{now}");
    }
    assert_eq!(kinetra_license::evaluate::no_license(), ["core.app"]);
    // Even revoked or clock-tampered: the baseline remains.
    let mut input = at(T0);
    input.revoked = true;
    assert_eq!(evaluate(&c, &input).entitlements, ["core.app"]);
}

#[test]
fn subscription_end_beats_grace() {
    let mut c = claims();
    c.ends_at = Some(T0 + 10 * DAY);
    let e = evaluate(&c, &at(T0 + 9 * DAY));
    assert_eq!(e.status, Status::Active);
    assert_eq!(e.full_until, T0 + 10 * DAY);
    let e = evaluate(&c, &at(T0 + 10 * DAY));
    assert_eq!((e.status, e.access), (Status::Expired, Access::Free));
}

#[test]
fn day_pass() {
    let mut c = claims();
    c.plan = "day_pass".into();
    c.ends_at = Some(T0 + DAY);
    assert_eq!(evaluate(&c, &at(T0 + DAY - 1)).status, Status::Active);
    assert_eq!(evaluate(&c, &at(T0 + DAY)).status, Status::Expired);
}

#[test]
fn perpetual_covers_older_builds_forever() {
    let mut c = claims();
    c.ends_at = None;
    c.updates_until = Some(T0 + 365 * DAY);
    // A build from before updates_until: active while refreshed, years later.
    let mut input = at(T0 + 3 * 365 * DAY);
    input.last_server_time = input.now;
    let mut fresh = c.clone();
    fresh.iat = input.now;
    fresh.grace = input.now + 30 * DAY;
    fresh.reduced = input.now + 44 * DAY;
    input.app_release_date = T0 + 300 * DAY;
    assert_eq!(evaluate(&fresh, &input).status, Status::Active);
    // A build released after updates_until isn't covered.
    input.app_release_date = T0 + 366 * DAY;
    let e = evaluate(&fresh, &input);
    assert_eq!((e.status, e.access), (Status::NotCovered, Access::Free));
    // Perpetual still obeys the offline policy.
    let mut stale = at(c.reduced + 1);
    stale.app_release_date = T0;
    assert_eq!(evaluate(&c, &stale).status, Status::OfflineExpired);
}

#[test]
fn revoked_wins_over_everything() {
    let c = claims();
    let mut input = at(T0 + DAY);
    input.revoked = true;
    let e = evaluate(&c, &input);
    assert_eq!((e.status, e.access), (Status::Revoked, Access::Free));
    assert_eq!(e.entitlements, ["core.app"]);
}

#[test]
fn clock_set_back_counts_as_offline_expired() {
    let c = claims();
    // The app saw server time T0 + 20 days earlier; now the clock says T0 + 1 day.
    let mut input = at(T0 + DAY);
    input.last_server_time = T0 + 20 * DAY;
    let e = evaluate(&c, &input);
    assert_eq!((e.status, e.access), (Status::ClockTampered, Access::Free));
    // The token's own iat counts as server time seen.
    let mut input = at(T0 - DAY);
    input.last_server_time = 0;
    assert_eq!(evaluate(&c, &input).status, Status::ClockTampered);
    // Small drift is tolerated.
    let mut input = at(T0 - CLOCK_TOLERANCE_SECS + 1);
    input.last_server_time = T0;
    assert_eq!(evaluate(&c, &input).status, Status::Active);
}
