use super::*;

/// Helper macro for tests that assert `Command::parse(input) == expected`.
macro_rules! parse_test {
    ($name:ident, $input:expr, $expected:expr) => {
        #[test]
        fn $name() {
            assert_eq!(Command::parse($input), $expected);
        }
    };
}

/// Helper macro for tests with multiple inputs that all parse to the same expected command.
macro_rules! parse_multi_test {
    ($name:ident, $expected:expr, $($input:expr),+ $(,)?) => {
        #[test]
        fn $name() {
            $(assert_eq!(Command::parse($input), $expected);)+
        }
    };
}

// --- Simple command parsing ---

parse_test!(parse_nop, "NOP", Command::Nop);
parse_multi_test!(parse_nop_case_insensitive, Command::Nop, "nop", "Nop");
parse_test!(parse_reset, "RESET", Command::Reset);
parse_test!(parse_end, "END", Command::End);
parse_test!(parse_bye, "BYE", Command::Bye);
parse_test!(parse_pkdecrypt, "PKDECRYPT", Command::PkDecrypt);
parse_test!(parse_auth, "AUTH", Command::Auth);
parse_test!(parse_leading_trailing_whitespace, "  NOP  ", Command::Nop);

// --- PKSIGN ---

parse_test!(parse_pksign, "PKSIGN", Command::Pksign);
parse_multi_test!(
    parse_pksign_case_insensitive,
    Command::Pksign,
    "pksign",
    "PkSign"
);
parse_test!(
    parse_pksign_with_options_ignored,
    "PKSIGN --something",
    Command::Pksign
);

// --- CANCEL ---

parse_test!(parse_cancel, "CANCEL", Command::Cancel);
parse_multi_test!(
    parse_cancel_case_insensitive,
    Command::Cancel,
    "cancel",
    "Cancel"
);

// --- GENKEY ---

parse_test!(parse_genkey, "GENKEY", Command::GenKey);
parse_multi_test!(
    parse_genkey_case_insensitive,
    Command::GenKey,
    "genkey",
    "GenKey"
);
parse_test!(
    parse_genkey_with_args_still_genkey,
    "GENKEY --something",
    Command::GenKey
);

// --- IMPORT_KEY ---

parse_test!(parse_import_key, "IMPORT_KEY", Command::ImportKey);
parse_test!(parse_import_keyfiles, "IMPORT_KEYFILES", Command::ImportKey);
parse_test!(
    parse_import_key_case_insensitive,
    "import_key",
    Command::ImportKey
);

// --- EXPORT_KEY ---

parse_test!(parse_export_key, "EXPORT_KEY", Command::ExportKey);
parse_test!(
    parse_export_key_case_insensitive,
    "export_key",
    Command::ExportKey
);

// --- DELETE_KEY ---

parse_test!(parse_delete_key, "DELETE_KEY", Command::DeleteKey);
parse_test!(
    parse_delete_key_case_insensitive,
    "delete_key",
    Command::DeleteKey
);

// --- GET_PASSPHRASE ---

parse_test!(
    parse_get_passphrase,
    "GET_PASSPHRASE",
    Command::GetPassphrase
);
parse_test!(
    parse_get_passphrase_case_insensitive,
    "get_passphrase",
    Command::GetPassphrase
);

// --- SCD ---

parse_test!(parse_scd, "SCD", Command::Scd);
parse_multi_test!(parse_scd_case_insensitive, Command::Scd, "scd", "Scd");
parse_test!(
    parse_scd_with_args_still_scd,
    "SCD GETATTR KEY-FPR",
    Command::Scd
);

// --- LEARN ---

parse_test!(parse_learn, "LEARN", Command::Learn);
parse_multi_test!(
    parse_learn_case_insensitive,
    Command::Learn,
    "learn",
    "Learn"
);

// --- OPTION ---

parse_test!(
    parse_option_with_value,
    "OPTION ttyname=/dev/pts/1",
    Command::Option {
        name: "ttyname".to_owned(),
        value: Some("/dev/pts/1".to_owned()),
    }
);
parse_test!(
    parse_option_without_value,
    "OPTION lc-messages",
    Command::Option {
        name: "lc-messages".to_owned(),
        value: None,
    }
);
parse_test!(
    parse_option_no_args,
    "OPTION",
    Command::Option {
        name: String::new(),
        value: None,
    }
);
parse_test!(
    parse_option_with_equals_in_value,
    "OPTION key=val=ue",
    Command::Option {
        name: "key".to_owned(),
        value: Some("val=ue".to_owned()),
    }
);
parse_test!(
    parse_option_trims_whitespace_around_equals,
    "OPTION name = value",
    Command::Option {
        name: "name".to_owned(),
        value: Some("value".to_owned()),
    }
);

// --- GETINFO ---

parse_test!(
    parse_getinfo_version,
    "GETINFO version",
    Command::GetInfo {
        subcommand: "version".to_owned(),
    }
);
parse_test!(
    parse_getinfo_pid,
    "GETINFO pid",
    Command::GetInfo {
        subcommand: "pid".to_owned(),
    }
);
parse_test!(
    parse_getinfo_socket_name,
    "GETINFO socket_name",
    Command::GetInfo {
        subcommand: "socket_name".to_owned(),
    }
);
parse_test!(
    parse_getinfo_no_subcommand,
    "GETINFO",
    Command::GetInfo {
        subcommand: String::new(),
    }
);
parse_test!(
    parse_mixed_case_command,
    "getinfo version",
    Command::GetInfo {
        subcommand: "version".to_owned(),
    }
);

// --- HAVEKEY ---

parse_test!(
    parse_havekey_single,
    "HAVEKEY ABCD1234",
    Command::Havekey {
        keygrips: vec!["ABCD1234".to_owned()],
    }
);
parse_test!(
    parse_havekey_multiple,
    "HAVEKEY AA BB CC",
    Command::Havekey {
        keygrips: vec!["AA".to_owned(), "BB".to_owned(), "CC".to_owned()],
    }
);
parse_test!(
    parse_havekey_no_args_is_unknown,
    "HAVEKEY",
    Command::Unknown {
        name: "HAVEKEY".to_owned(),
    }
);

// --- KEYINFO ---

parse_test!(
    parse_keyinfo_with_keygrip,
    "KEYINFO ABCD",
    Command::Keyinfo {
        keygrip: Some("ABCD".to_owned()),
        list: false,
        data: false,
        ssh_list: false,
    }
);
parse_test!(
    parse_keyinfo_list_mode,
    "KEYINFO --list",
    Command::Keyinfo {
        keygrip: None,
        list: true,
        data: false,
        ssh_list: false,
    }
);
parse_test!(
    parse_keyinfo_with_flags,
    "KEYINFO --data --ssh-list ABCD",
    Command::Keyinfo {
        keygrip: Some("ABCD".to_owned()),
        list: false,
        data: true,
        ssh_list: true,
    }
);

// --- READKEY ---

parse_test!(
    parse_readkey_basic,
    "READKEY ABCD",
    Command::Readkey {
        keygrip: "ABCD".to_owned(),
        no_data: false,
    }
);
parse_test!(
    parse_readkey_no_data_flag,
    "READKEY --no-data ABCD",
    Command::Readkey {
        keygrip: "ABCD".to_owned(),
        no_data: true,
    }
);
parse_test!(
    parse_readkey_no_args_is_unknown,
    "READKEY",
    Command::Unknown {
        name: "READKEY".to_owned(),
    }
);

// --- SIGKEY ---

parse_test!(
    parse_sigkey_basic,
    "SIGKEY ABCD",
    Command::Sigkey {
        keygrip: "ABCD".to_owned(),
    }
);
parse_test!(
    parse_sigkey_no_args_is_unknown,
    "SIGKEY",
    Command::Unknown {
        name: "SIGKEY".to_owned(),
    }
);

// --- SETKEYDESC ---

parse_test!(
    parse_setkeydesc_basic,
    "SETKEYDESC Please+enter+the+passphrase",
    Command::SetKeyDesc {
        description: "Please+enter+the+passphrase".to_owned(),
    }
);
parse_test!(
    parse_setkeydesc_no_text_is_unknown,
    "SETKEYDESC",
    Command::Unknown {
        name: "SETKEYDESC".to_owned(),
    }
);

// --- SETHASH ---

parse_test!(
    parse_sethash_named_algo,
    "SETHASH --hash=sha256 AABB",
    Command::SetHash {
        algorithm: 8,
        hash_hex: "AABB".to_owned(),
    }
);
parse_test!(
    parse_sethash_numeric_algo,
    "SETHASH 10 AABB",
    Command::SetHash {
        algorithm: 10,
        hash_hex: "AABB".to_owned(),
    }
);
parse_test!(
    parse_sethash_sha1,
    "SETHASH --hash=sha1 FF",
    Command::SetHash {
        algorithm: 2,
        hash_hex: "FF".to_owned(),
    }
);
parse_test!(
    parse_sethash_no_args_is_unknown,
    "SETHASH",
    Command::Unknown {
        name: "SETHASH".to_owned(),
    }
);
parse_test!(
    parse_sethash_unknown_named_algo_is_unknown,
    "SETHASH --hash=blake2 AABB",
    Command::Unknown {
        name: "SETHASH".to_owned(),
    }
);

// --- Unknown / edge cases ---

parse_test!(
    parse_unknown_command,
    "FOOBAR",
    Command::Unknown {
        name: "FOOBAR".to_owned(),
    }
);
parse_test!(
    parse_unknown_command_with_args,
    "FOOBAR some args",
    Command::Unknown {
        name: "FOOBAR".to_owned(),
    }
);
parse_test!(
    parse_empty_line,
    "",
    Command::Unknown {
        name: String::new(),
    }
);
parse_test!(
    parse_whitespace_only,
    "   ",
    Command::Unknown {
        name: String::new(),
    }
);
