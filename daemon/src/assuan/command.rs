/// Parsed Assuan protocol command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Command {
    Nop,
    Option {
        name: String,
        value: Option<String>,
    },
    Reset,
    GetInfo {
        subcommand: String,
    },
    End,
    Bye,
    PkDecrypt,
    Auth,
    Havekey {
        keygrips: Vec<String>,
    },
    Keyinfo {
        keygrip: Option<String>,
        list: bool,
        data: bool,
        ssh_list: bool,
    },
    Readkey {
        keygrip: String,
        no_data: bool,
    },
    Sigkey {
        keygrip: String,
    },
    SetKeyDesc {
        description: String,
    },
    SetHash {
        algorithm: u32,
        hash_hex: String,
    },
    Unknown {
        name: String,
    },
}

impl Command {
    /// Parse a trimmed (no trailing newline) line into a [`Command`].
    ///
    /// Command names are matched case-insensitively per the Assuan protocol spec.
    pub(super) fn parse(line: &str) -> Self {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            return Self::Unknown {
                name: String::new(),
            };
        }

        let (cmd, args) = match trimmed.split_once(' ') {
            Some((cmd, rest)) => (cmd, Some(rest)),
            None => (trimmed, None),
        };

        match cmd.to_ascii_uppercase().as_str() {
            "NOP" => Self::Nop,
            "OPTION" => parse_option(args),
            "RESET" => Self::Reset,
            "GETINFO" => Self::GetInfo {
                subcommand: args.unwrap_or("").to_owned(),
            },
            "END" => Self::End,
            "BYE" => Self::Bye,
            "PKDECRYPT" => Self::PkDecrypt,
            "AUTH" => Self::Auth,
            "HAVEKEY" => parse_havekey(args),
            "KEYINFO" => parse_keyinfo(args),
            "READKEY" => parse_readkey(args),
            "SIGKEY" => parse_sigkey(args),
            "SETKEYDESC" => parse_setkeydesc(args),
            "SETHASH" => parse_sethash(args),
            _ => Self::Unknown {
                name: cmd.to_owned(),
            },
        }
    }
}

fn parse_option(args: Option<&str>) -> Command {
    let Some(args) = args else {
        return Command::Option {
            name: String::new(),
            value: None,
        };
    };

    match args.split_once('=') {
        Some((name, value)) => Command::Option {
            name: name.trim().to_owned(),
            value: Some(value.trim().to_owned()),
        },
        None => Command::Option {
            name: args.trim().to_owned(),
            value: None,
        },
    }
}

fn parse_havekey(args: Option<&str>) -> Command {
    let keygrips: Vec<String> = args
        .unwrap_or("")
        .split_whitespace()
        .map(|s| s.to_owned())
        .collect();
    if keygrips.is_empty() {
        return Command::Unknown {
            name: "HAVEKEY".to_owned(),
        };
    }
    Command::Havekey { keygrips }
}

fn parse_keyinfo(args: Option<&str>) -> Command {
    let parts: Vec<&str> = args.unwrap_or("").split_whitespace().collect();
    let mut list = false;
    let mut data = false;
    let mut ssh_list = false;
    let mut keygrip = None;

    for part in &parts {
        match *part {
            "--list" => list = true,
            "--data" => data = true,
            "--ssh-list" => ssh_list = true,
            s if s.starts_with("--") => {}
            s => keygrip = Some(s.to_owned()),
        }
    }
    Command::Keyinfo {
        keygrip,
        list,
        data,
        ssh_list,
    }
}

fn parse_readkey(args: Option<&str>) -> Command {
    let parts: Vec<&str> = args.unwrap_or("").split_whitespace().collect();
    let mut no_data = false;
    let mut keygrip = None;

    for part in &parts {
        match *part {
            "--no-data" => no_data = true,
            s if s.starts_with("--") => {}
            s => keygrip = Some(s.to_owned()),
        }
    }
    match keygrip {
        Some(kg) => Command::Readkey {
            keygrip: kg,
            no_data,
        },
        None => Command::Unknown {
            name: "READKEY".to_owned(),
        },
    }
}

fn parse_sigkey(args: Option<&str>) -> Command {
    match args.and_then(|a| a.split_whitespace().next()) {
        Some(kg) => Command::Sigkey {
            keygrip: kg.to_owned(),
        },
        None => Command::Unknown {
            name: "SIGKEY".to_owned(),
        },
    }
}

fn parse_setkeydesc(args: Option<&str>) -> Command {
    match args {
        Some(text) if !text.trim().is_empty() => Command::SetKeyDesc {
            description: text.trim().to_owned(),
        },
        _ => Command::Unknown {
            name: "SETKEYDESC".to_owned(),
        },
    }
}

fn parse_sethash(args: Option<&str>) -> Command {
    let parts: Vec<&str> = args.unwrap_or("").split_whitespace().collect();
    if parts.len() != 2 {
        return Command::Unknown {
            name: "SETHASH".to_owned(),
        };
    }

    let (algo, hash_hex) = if let Some(name) = parts[0].strip_prefix("--hash=") {
        let algo = match name.to_ascii_lowercase().as_str() {
            "md5" => 1,
            "sha1" => 2,
            "rmd160" => 3,
            "sha256" => 8,
            "sha384" => 9,
            "sha512" => 10,
            "sha224" => 11,
            _ => {
                return Command::Unknown {
                    name: "SETHASH".to_owned(),
                };
            }
        };
        (algo, parts[1])
    } else {
        let Ok(algo) = parts[0].parse::<u32>() else {
            return Command::Unknown {
                name: "SETHASH".to_owned(),
            };
        };
        (algo, parts[1])
    };

    Command::SetHash {
        algorithm: algo,
        hash_hex: hash_hex.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_nop() {
        assert_eq!(Command::parse("NOP"), Command::Nop);
    }

    #[test]
    fn parse_nop_case_insensitive() {
        assert_eq!(Command::parse("nop"), Command::Nop);
        assert_eq!(Command::parse("Nop"), Command::Nop);
    }

    #[test]
    fn parse_option_with_value() {
        assert_eq!(
            Command::parse("OPTION ttyname=/dev/pts/1"),
            Command::Option {
                name: "ttyname".to_owned(),
                value: Some("/dev/pts/1".to_owned()),
            }
        );
    }

    #[test]
    fn parse_option_without_value() {
        assert_eq!(
            Command::parse("OPTION lc-messages"),
            Command::Option {
                name: "lc-messages".to_owned(),
                value: None,
            }
        );
    }

    #[test]
    fn parse_option_no_args() {
        assert_eq!(
            Command::parse("OPTION"),
            Command::Option {
                name: String::new(),
                value: None,
            }
        );
    }

    #[test]
    fn parse_option_with_equals_in_value() {
        assert_eq!(
            Command::parse("OPTION key=val=ue"),
            Command::Option {
                name: "key".to_owned(),
                value: Some("val=ue".to_owned()),
            }
        );
    }

    #[test]
    fn parse_option_trims_whitespace_around_equals() {
        assert_eq!(
            Command::parse("OPTION name = value"),
            Command::Option {
                name: "name".to_owned(),
                value: Some("value".to_owned()),
            }
        );
    }

    #[test]
    fn parse_reset() {
        assert_eq!(Command::parse("RESET"), Command::Reset);
    }

    #[test]
    fn parse_getinfo_version() {
        assert_eq!(
            Command::parse("GETINFO version"),
            Command::GetInfo {
                subcommand: "version".to_owned(),
            }
        );
    }

    #[test]
    fn parse_getinfo_pid() {
        assert_eq!(
            Command::parse("GETINFO pid"),
            Command::GetInfo {
                subcommand: "pid".to_owned(),
            }
        );
    }

    #[test]
    fn parse_getinfo_socket_name() {
        assert_eq!(
            Command::parse("GETINFO socket_name"),
            Command::GetInfo {
                subcommand: "socket_name".to_owned(),
            }
        );
    }

    #[test]
    fn parse_getinfo_no_subcommand() {
        assert_eq!(
            Command::parse("GETINFO"),
            Command::GetInfo {
                subcommand: String::new(),
            }
        );
    }

    #[test]
    fn parse_end() {
        assert_eq!(Command::parse("END"), Command::End);
    }

    #[test]
    fn parse_bye() {
        assert_eq!(Command::parse("BYE"), Command::Bye);
    }

    #[test]
    fn parse_pkdecrypt() {
        assert_eq!(Command::parse("PKDECRYPT"), Command::PkDecrypt);
    }

    #[test]
    fn parse_auth() {
        assert_eq!(Command::parse("AUTH"), Command::Auth);
    }

    #[test]
    fn parse_unknown_command() {
        assert_eq!(
            Command::parse("FOOBAR"),
            Command::Unknown {
                name: "FOOBAR".to_owned(),
            }
        );
    }

    #[test]
    fn parse_unknown_command_with_args() {
        assert_eq!(
            Command::parse("FOOBAR some args"),
            Command::Unknown {
                name: "FOOBAR".to_owned(),
            }
        );
    }

    #[test]
    fn parse_empty_line() {
        assert_eq!(
            Command::parse(""),
            Command::Unknown {
                name: String::new(),
            }
        );
    }

    #[test]
    fn parse_whitespace_only() {
        assert_eq!(
            Command::parse("   "),
            Command::Unknown {
                name: String::new(),
            }
        );
    }

    #[test]
    fn parse_leading_trailing_whitespace() {
        assert_eq!(Command::parse("  NOP  "), Command::Nop);
    }

    #[test]
    fn parse_mixed_case_command() {
        assert_eq!(
            Command::parse("getinfo version"),
            Command::GetInfo {
                subcommand: "version".to_owned(),
            }
        );
    }

    #[test]
    fn parse_havekey_single() {
        assert_eq!(
            Command::parse("HAVEKEY ABCD1234"),
            Command::Havekey {
                keygrips: vec!["ABCD1234".to_owned()],
            }
        );
    }

    #[test]
    fn parse_havekey_multiple() {
        assert_eq!(
            Command::parse("HAVEKEY AA BB CC"),
            Command::Havekey {
                keygrips: vec!["AA".to_owned(), "BB".to_owned(), "CC".to_owned()],
            }
        );
    }

    #[test]
    fn parse_havekey_no_args_is_unknown() {
        assert_eq!(
            Command::parse("HAVEKEY"),
            Command::Unknown {
                name: "HAVEKEY".to_owned(),
            }
        );
    }

    #[test]
    fn parse_keyinfo_with_keygrip() {
        assert_eq!(
            Command::parse("KEYINFO ABCD"),
            Command::Keyinfo {
                keygrip: Some("ABCD".to_owned()),
                list: false,
                data: false,
                ssh_list: false,
            }
        );
    }

    #[test]
    fn parse_keyinfo_list_mode() {
        assert_eq!(
            Command::parse("KEYINFO --list"),
            Command::Keyinfo {
                keygrip: None,
                list: true,
                data: false,
                ssh_list: false,
            }
        );
    }

    #[test]
    fn parse_keyinfo_with_flags() {
        assert_eq!(
            Command::parse("KEYINFO --data --ssh-list ABCD"),
            Command::Keyinfo {
                keygrip: Some("ABCD".to_owned()),
                list: false,
                data: true,
                ssh_list: true,
            }
        );
    }

    #[test]
    fn parse_readkey_basic() {
        assert_eq!(
            Command::parse("READKEY ABCD"),
            Command::Readkey {
                keygrip: "ABCD".to_owned(),
                no_data: false,
            }
        );
    }

    #[test]
    fn parse_readkey_no_data_flag() {
        assert_eq!(
            Command::parse("READKEY --no-data ABCD"),
            Command::Readkey {
                keygrip: "ABCD".to_owned(),
                no_data: true,
            }
        );
    }

    #[test]
    fn parse_readkey_no_args_is_unknown() {
        assert_eq!(
            Command::parse("READKEY"),
            Command::Unknown {
                name: "READKEY".to_owned(),
            }
        );
    }

    #[test]
    fn parse_sigkey_basic() {
        assert_eq!(
            Command::parse("SIGKEY ABCD"),
            Command::Sigkey {
                keygrip: "ABCD".to_owned(),
            }
        );
    }

    #[test]
    fn parse_sigkey_no_args_is_unknown() {
        assert_eq!(
            Command::parse("SIGKEY"),
            Command::Unknown {
                name: "SIGKEY".to_owned(),
            }
        );
    }

    #[test]
    fn parse_setkeydesc_basic() {
        assert_eq!(
            Command::parse("SETKEYDESC Please+enter+the+passphrase"),
            Command::SetKeyDesc {
                description: "Please+enter+the+passphrase".to_owned(),
            }
        );
    }

    #[test]
    fn parse_setkeydesc_no_text_is_unknown() {
        assert_eq!(
            Command::parse("SETKEYDESC"),
            Command::Unknown {
                name: "SETKEYDESC".to_owned(),
            }
        );
    }

    #[test]
    fn parse_sethash_named_algo() {
        assert_eq!(
            Command::parse("SETHASH --hash=sha256 AABB"),
            Command::SetHash {
                algorithm: 8,
                hash_hex: "AABB".to_owned(),
            }
        );
    }

    #[test]
    fn parse_sethash_numeric_algo() {
        assert_eq!(
            Command::parse("SETHASH 10 AABB"),
            Command::SetHash {
                algorithm: 10,
                hash_hex: "AABB".to_owned(),
            }
        );
    }

    #[test]
    fn parse_sethash_sha1() {
        assert_eq!(
            Command::parse("SETHASH --hash=sha1 FF"),
            Command::SetHash {
                algorithm: 2,
                hash_hex: "FF".to_owned(),
            }
        );
    }

    #[test]
    fn parse_sethash_no_args_is_unknown() {
        assert_eq!(
            Command::parse("SETHASH"),
            Command::Unknown {
                name: "SETHASH".to_owned(),
            }
        );
    }

    #[test]
    fn parse_sethash_unknown_named_algo_is_unknown() {
        assert_eq!(
            Command::parse("SETHASH --hash=blake2 AABB"),
            Command::Unknown {
                name: "SETHASH".to_owned(),
            }
        );
    }
}
