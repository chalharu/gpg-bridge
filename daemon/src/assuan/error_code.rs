//! Unified GPG/Assuan error code constants for the daemon.
//!
//! Error codes follow the libgpg-error convention with source = 0 (raw codes).
//! GPG clients only inspect the lower 16 bits, so omitting the source field
//! avoids pretending to be the real gpg-agent.

/// General error for unclassified failures.
pub(crate) const GPG_ERR_GENERAL: u32 = 1;

/// No secret key available (HAVEKEY / KEYINFO / READKEY / PKSIGN).
pub(crate) const GPG_ERR_NO_SECKEY: u32 = 17;

/// No data available.
pub(crate) const GPG_ERR_NO_DATA: u32 = 58;

/// Timeout (SSE wait expiry, request JWT expiry).
pub(crate) const GPG_ERR_TIMEOUT: u32 = 62;

/// Command or feature not supported (PKDECRYPT, AUTH, GENKEY, etc.).
pub(crate) const GPG_ERR_NOT_SUPPORTED: u32 = 69;

/// Invalid length (e.g., SETHASH with wrong hash byte count).
pub(crate) const GPG_ERR_INV_LENGTH: u32 = 71;

/// Operation cancelled by the user or by CANCEL command.
pub(crate) const GPG_ERR_CANCELED: u32 = 99;

/// Syntax error in command arguments.
pub(crate) const GPG_ERR_SYNTAX: u32 = 147;

/// Missing value (e.g., SETHASH not called before PKSIGN).
pub(crate) const GPG_ERR_MISSING_VALUE: u32 = 178;

/// Unknown Assuan IPC command.
pub(crate) const GPG_ERR_ASS_UNKNOWN_CMD: u32 = 275;

/// Line exceeds Assuan protocol maximum length.
pub(crate) const GPG_ERR_ASS_LINE_TOO_LONG: u32 = 276;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_codes_are_raw_without_source_bits() {
        let codes = [
            GPG_ERR_GENERAL,
            GPG_ERR_NO_SECKEY,
            GPG_ERR_NO_DATA,
            GPG_ERR_TIMEOUT,
            GPG_ERR_NOT_SUPPORTED,
            GPG_ERR_INV_LENGTH,
            GPG_ERR_CANCELED,
            GPG_ERR_SYNTAX,
            GPG_ERR_MISSING_VALUE,
            GPG_ERR_ASS_UNKNOWN_CMD,
            GPG_ERR_ASS_LINE_TOO_LONG,
        ];
        for code in codes {
            assert!(code < 1 << 16, "code {code} has source bits set");
        }
    }

    #[test]
    fn error_codes_have_expected_values() {
        assert_eq!(GPG_ERR_GENERAL, 1);
        assert_eq!(GPG_ERR_NO_SECKEY, 17);
        assert_eq!(GPG_ERR_NO_DATA, 58);
        assert_eq!(GPG_ERR_TIMEOUT, 62);
        assert_eq!(GPG_ERR_NOT_SUPPORTED, 69);
        assert_eq!(GPG_ERR_INV_LENGTH, 71);
        assert_eq!(GPG_ERR_CANCELED, 99);
        assert_eq!(GPG_ERR_SYNTAX, 147);
        assert_eq!(GPG_ERR_MISSING_VALUE, 178);
        assert_eq!(GPG_ERR_ASS_UNKNOWN_CMD, 275);
        assert_eq!(GPG_ERR_ASS_LINE_TOO_LONG, 276);
    }
}
