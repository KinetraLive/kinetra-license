//! Machine fingerprint.
//!
//! The app reads the OS machine id (Windows `MachineGuid`, macOS `IOPlatformUUID`,
//! Linux `/etc/machine-id`) and hashes it with an app-specific salt. Only the hash ever
//! leaves the machine. It survives OS updates, network changes and docking stations
//! because it uses neither MAC addresses nor disk serials.

use sha2::{Digest, Sha256};

const SALT: &str = "kinetra-machine-v1:";

/// 64 lowercase hex characters.
pub fn fingerprint(os_machine_id: &str) -> String {
    let normalized = os_machine_id.trim().to_ascii_lowercase();
    let digest = Sha256::digest(format!("{SALT}{normalized}").as_bytes());
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

/// Shape check for a fingerprint received from a client.
pub fn is_fingerprint(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stable_and_normalized() {
        let a = fingerprint("4C4C4544-0042-3510-8051-B4C04F4E4B32");
        assert_eq!(a, fingerprint(" 4c4c4544-0042-3510-8051-b4c04f4e4b32\n"));
        assert!(is_fingerprint(&a));
        assert_ne!(a, fingerprint("4C4C4544-0042-3510-8051-B4C04F4E4B33"));
        // Test vector: pinned so the app and server can't drift apart.
        assert_eq!(
            fingerprint("00000000-0000-0000-0000-000000000000"),
            "857a78b7a23b14cd718a9cbf9b90b0577225543ddcce5ed21854a4985f25ee27" // sha256("kinetra-machine-v1:" + id)
        );
    }

    #[test]
    fn shape() {
        assert!(!is_fingerprint("ABC"));
        assert!(!is_fingerprint(&"A".repeat(64)));
        assert!(is_fingerprint(&"a".repeat(64)));
    }
}
