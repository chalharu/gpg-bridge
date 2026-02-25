/// Parsed Assuan protocol command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Command {
    Nop,
    Option { name: String, value: Option<String> },
    Reset,
    GetInfo { subcommand: String },
    End,
    Bye,
    PkDecrypt,
    Auth,
    Unknown { name: String },
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
}
