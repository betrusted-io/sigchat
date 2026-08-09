//! Log-redaction helpers for account identifiers.
//!
//! Per-receive/send log lines used to emit full ACI UUIDs, e164
//! phone numbers, and contact labels — one boot's UART capture
//! reconstructed the contact graph. Call [`log_id`] at the emit
//! site: default builds get the redacted form from [`redact_id`];
//! the default-off `verbose-pii` feature restores full identifiers
//! for ops triage.

/// Redact an identifier to its last four characters (`..abcd`).
///
/// Four trailing characters are enough to correlate lines within
/// one capture (retries, receipt matching) without reconstructing
/// the contact graph from a UART log. Strings of four characters
/// or fewer pass through unchanged — at that length there is no
/// identifier left to protect (e.g. the `"all"` prekey-bundle key).
pub fn redact_id(s: &str) -> String {
    const KEEP: usize = 4;
    let n = s.chars().count();
    if n <= KEEP { s.to_string() } else { format!("..{}", s.chars().skip(n - KEEP).collect::<String>()) }
}

/// An identifier as it should appear in a log line: full under
/// `verbose-pii`, redacted otherwise.
#[cfg(feature = "verbose-pii")]
pub fn log_id(s: &str) -> String { s.to_string() }

/// An identifier as it should appear in a log line: full under
/// `verbose-pii`, redacted otherwise.
#[cfg(not(feature = "verbose-pii"))]
pub fn log_id(s: &str) -> String { redact_id(s) }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_uuid_to_last_four() {
        assert_eq!(redact_id("84e2d5a0-1b2c-4d3e-9f00-aabbccddeeff"), "..eeff");
    }

    #[test]
    fn redacts_e164_to_last_four() {
        assert_eq!(redact_id("+15551234567"), "..4567");
    }

    #[test]
    fn short_non_identifier_keys_pass_through() {
        assert_eq!(redact_id("all"), "all");
        assert_eq!(redact_id(""), "");
    }

    #[test]
    fn boundary_length_five_is_redacted() {
        assert_eq!(redact_id("abcde"), "..bcde");
    }

    #[cfg(not(feature = "verbose-pii"))]
    #[test]
    fn log_id_redacts_by_default() {
        assert_eq!(log_id("+15551234567"), "..4567");
    }
}
