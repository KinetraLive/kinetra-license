//! The entitlement catalog, shared by the server and the app. Features are gated on
//! these names, never on plan names.
//!
//! | Entitlement | Granted by |
//! |---|---|
//! | `core.app` | everyone, always (also with no license and offline): the whole local app |
//! | `pro.ai`, `pro.cloud_sync`, `pro.polls`, `pro.team` | Pro plans, enterprise |
//! | `business.*` | enterprise |
//! | `pro.ndi`, `pro.sdi`, `pro.redundancy` | reserved: defined, not granted by any plan yet |
//!
//! Which plan grants what is server configuration; this module only defines the names.

pub const CORE_APP: &str = "core.app";

pub const PRO_AI: &str = "pro.ai";
pub const PRO_CLOUD_SYNC: &str = "pro.cloud_sync";
pub const PRO_POLLS: &str = "pro.polls";
pub const PRO_TEAM: &str = "pro.team";

pub const PRO_NDI: &str = "pro.ndi";
pub const PRO_SDI: &str = "pro.sdi";
pub const PRO_REDUNDANCY: &str = "pro.redundancy";

pub const BUSINESS_SSO: &str = "business.sso";
pub const BUSINESS_CENTRAL_MANAGEMENT: &str = "business.central_management";
pub const BUSINESS_OFFLINE_ACTIVATION: &str = "business.offline_activation";

/// Available to everyone, whatever the license state.
pub const BASELINE: &[&str] = &[CORE_APP];

/// Defined so the app can reference them, but no plan grants them yet.
pub const RESERVED: &[&str] = &[PRO_NDI, PRO_SDI, PRO_REDUNDANCY];

/// Every known entitlement.
pub const ALL: &[&str] = &[
    CORE_APP,
    PRO_AI,
    PRO_CLOUD_SYNC,
    PRO_POLLS,
    PRO_TEAM,
    PRO_NDI,
    PRO_SDI,
    PRO_REDUNDANCY,
    BUSINESS_SSO,
    BUSINESS_CENTRAL_MANAGEMENT,
    BUSINESS_OFFLINE_ACTIVATION,
];

pub fn is_known(e: &str) -> bool {
    ALL.contains(&e)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_is_consistent() {
        assert!(BASELINE.iter().all(|e| is_known(e)));
        assert!(RESERVED.iter().all(|e| is_known(e)));
        let mut sorted = ALL.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), ALL.len(), "duplicates in ALL");
        assert!(!is_known("pro.studio_mode"));
    }
}
