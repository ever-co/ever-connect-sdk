//! Connect and link codes (`EVC-XXXX-XXXX-XXXX`, `EVL-XXXX-XXXX-XXXX`): what an operator pastes
//! into the product. [`normalize`] accepts any case, spaces or missing dashes and answers the
//! canonical spelling Ever Platform expects, or `None` when the input is not a code.

const ALPHABET: &[u8] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// The canonical spelling of a connect or link code, or `None`.
#[must_use]
pub fn normalize(input: &str) -> Option<String> {
    let compact: String = input
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .collect::<String>()
        .to_ascii_uppercase();
    let (prefix, symbols) = compact.split_at_checked(3)?;
    if !matches!(prefix, "EVC" | "EVL")
        || symbols.len() != 12
        || !symbols.bytes().all(|b| ALPHABET.contains(&b))
    {
        return None;
    }
    Some(format!(
        "{prefix}-{}-{}-{}",
        &symbols[0..4],
        &symbols[4..8],
        &symbols[8..12]
    ))
}

/// Whether the input is a connect code (after normalisation).
#[must_use]
pub fn is_connect_code(input: &str) -> bool {
    normalize(input).is_some_and(|c| c.starts_with("EVC-"))
}

/// Whether the input is a link code (after normalisation).
#[must_use]
pub fn is_link_code(input: &str) -> bool {
    normalize(input).is_some_and(|c| c.starts_with("EVL-"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_normalise_to_the_canonical_spelling() {
        assert_eq!(
            normalize(" evc test 0000 0001 ").as_deref(),
            Some("EVC-TEST-0000-0001")
        );
        assert_eq!(
            normalize("EVL-TEST-0000-0002").as_deref(),
            Some("EVL-TEST-0000-0002")
        );
        assert!(is_connect_code("evctest00000001"));
        assert!(!is_connect_code("EVL-TEST-0000-0002"));
        assert!(is_link_code("evl-test-0000-0002"));
        assert_eq!(normalize("EVC-TEST-0000-000I"), None);
        assert_eq!(normalize("EVX-TEST-0000-0001"), None);
        assert_eq!(normalize("EVC-TEST-0000"), None);
    }
}
