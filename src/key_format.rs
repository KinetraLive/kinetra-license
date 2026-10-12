//! License keys: `KNTR-XXXX-XXXX-XXXX`.
//!
//! 12 characters from Crockford base32 without 0, 1 (and Crockford's own exclusions
//! I, L, O, U): `23456789ABCDEFGHJKMNPQRSTVWXYZ` (30 symbols). 11 are random
//! (~54 bits); the 12th is a check character (weighted sum mod 31, keys whose check
//! would be 30 are never generated), which catches every single-character typo and
//! every swap of two neighbouring characters before anything is sent to the server.

pub const PREFIX: &str = "KNTR";
pub const ALPHABET: &[u8; 30] = b"23456789ABCDEFGHJKMNPQRSTVWXYZ";
const BODY_LEN: usize = 12;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum KeyFormatError {
    #[error("a license key has 12 characters after KNTR-")]
    WrongLength,
    #[error("'{0}' can't appear in a license key")]
    InvalidChar(char),
    #[error("this key has a typo; check it against the original")]
    Checksum,
}

fn value(c: u8) -> Option<u32> {
    ALPHABET.iter().position(|&a| a == c).map(|p| p as u32)
}

/// Weighted sum mod 31 with weights 3^1..3^11 (3 is a primitive root mod 31, so the
/// weights are distinct and non-zero).
fn check_value(body: &[u8]) -> u32 {
    let mut weight = 1u32;
    body.iter().fold(0, |acc, &c| {
        weight = weight * 3 % 31;
        (acc + value(c).unwrap_or(0) * weight) % 31
    })
}

/// Generate a key from a source of random bytes (the server passes the OS CSPRNG).
pub fn generate(mut random_byte: impl FnMut() -> u8) -> String {
    loop {
        let mut body = Vec::with_capacity(BODY_LEN);
        while body.len() < BODY_LEN - 1 {
            let b = random_byte();
            // 240 = 8 * 30: rejection sampling keeps the distribution uniform.
            if b < 240 {
                body.push(ALPHABET[(b % 30) as usize]);
            }
        }
        let check = check_value(&body);
        if check < 30 {
            body.push(ALPHABET[check as usize]);
            return format_body(&body);
        }
    }
}

fn format_body(body: &[u8]) -> String {
    let s = String::from_utf8_lossy(body);
    format!("{PREFIX}-{}-{}-{}", &s[0..4], &s[4..8], &s[8..12])
}

/// The key characters typed so far: uppercased, without spaces, dashes or the `KNTR`
/// prefix.
fn clean(input: &str) -> String {
    let upper: String = input
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-' && *c != '–' && *c != '—')
        .flat_map(char::to_uppercase)
        .collect();
    match upper.strip_prefix(PREFIX) {
        // A bare 12-character key that happens to start with KNTR keeps it.
        Some(rest) if upper.len() != BODY_LEN => rest.to_owned(),
        _ => upper,
    }
}

/// Validate and canonicalize anything a user might paste: lowercase, spaces, missing or
/// extra dashes, with or without `KNTR-`.
pub fn normalize(input: &str) -> Result<String, KeyFormatError> {
    let body = clean(input);
    if let Some(bad) = body
        .chars()
        .find(|c| !c.is_ascii() || value(*c as u8).is_none())
    {
        return Err(KeyFormatError::InvalidChar(bad));
    }
    if body.len() != BODY_LEN {
        return Err(KeyFormatError::WrongLength);
    }
    let bytes = body.as_bytes();
    if check_value(&bytes[..BODY_LEN - 1]) != value(bytes[BODY_LEN - 1]).unwrap_or(99) {
        return Err(KeyFormatError::Checksum);
    }
    Ok(format_body(bytes))
}

/// Live formatting for a text field: `kntr4b7` → `KNTR-4B7`. Invalid characters are
/// dropped, input beyond 12 characters is cut.
pub fn format_partial(input: &str) -> String {
    let body: String = clean(input)
        .chars()
        .filter(|c| c.is_ascii() && value(*c as u8).is_some())
        .take(BODY_LEN)
        .collect();
    if body.is_empty() {
        return String::new();
    }
    let groups: Vec<&str> = body
        .as_bytes()
        .chunks(4)
        .map(|c| std::str::from_utf8(c).unwrap_or_default())
        .collect();
    format!("{PREFIX}-{}", groups.join("-"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn counter_rng(seed: u8) -> impl FnMut() -> u8 {
        let mut x = seed as u32;
        move || {
            x = x.wrapping_mul(1_103_515_245).wrapping_add(12_345);
            (x >> 16) as u8
        }
    }

    #[test]
    fn generated_keys_are_valid_and_canonical() {
        let mut rng = counter_rng(7);
        for _ in 0..1000 {
            let key = generate(&mut rng);
            assert_eq!(key.len(), 19);
            assert!(key.starts_with("KNTR-"));
            assert_eq!(normalize(&key).as_deref(), Ok(key.as_str()));
        }
    }

    #[test]
    fn paste_friendly() {
        let key = generate(counter_rng(1));
        let body = key.replace("KNTR-", "").replace('-', "");
        for variant in [
            key.to_lowercase(),
            body.clone(),
            body.to_lowercase(),
            format!("  {} ", key.replace('-', " ")),
            format!("kntr{body}"),
            key.replace('-', "–"),
        ] {
            assert_eq!(
                normalize(&variant).as_deref(),
                Ok(key.as_str()),
                "{variant}"
            );
        }
    }

    #[test]
    fn every_single_typo_and_neighbour_swap_is_caught() {
        let mut rng = counter_rng(3);
        for _ in 0..200 {
            let key = generate(&mut rng);
            let body: Vec<u8> = key.replace("KNTR-", "").replace('-', "").into_bytes();
            for i in 0..BODY_LEN {
                for &c in ALPHABET {
                    if c == body[i] {
                        continue;
                    }
                    let mut typo = body.clone();
                    typo[i] = c;
                    assert_eq!(
                        normalize(std::str::from_utf8(&typo).unwrap_or_default()),
                        Err(KeyFormatError::Checksum)
                    );
                }
                if i + 1 < BODY_LEN && body[i] != body[i + 1] {
                    let mut swapped = body.clone();
                    swapped.swap(i, i + 1);
                    assert_eq!(
                        normalize(std::str::from_utf8(&swapped).unwrap_or_default()),
                        Err(KeyFormatError::Checksum)
                    );
                }
            }
        }
    }

    #[test]
    fn helpful_errors() {
        assert_eq!(normalize("KNTR-ABCD"), Err(KeyFormatError::WrongLength));
        assert_eq!(
            normalize("KNTR-ABCD-EFGH-JK0M"),
            Err(KeyFormatError::InvalidChar('0'))
        );
        assert_eq!(
            normalize("KNTR-ABCD-EFGH-JKLM"),
            Err(KeyFormatError::InvalidChar('L'))
        );
        assert_eq!(
            normalize("KNTR-ABCD-EFGH-JKOM"),
            Err(KeyFormatError::InvalidChar('O'))
        );
    }

    #[test]
    fn partial_formatting() {
        assert_eq!(format_partial(""), "");
        assert_eq!(format_partial("k"), "KNTR-K");
        assert_eq!(format_partial("kntr"), "");
        assert_eq!(format_partial("4b7x"), "KNTR-4B7X");
        assert_eq!(format_partial("4b7x9"), "KNTR-4B7X-9");
        assert_eq!(
            format_partial("KNTR-4B7X-9Q2Z-HHHH-EXTRA"),
            "KNTR-4B7X-9Q2Z-HHHH"
        );
        assert_eq!(format_partial("4b0x"), "KNTR-4BX");
    }
}
