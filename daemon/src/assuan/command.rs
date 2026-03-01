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
    GenKey,
    ImportKey,
    ExportKey,
    DeleteKey,
    GetPassphrase,
    Scd,
    Learn,
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
    Pksign,
    Cancel,
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
            "GENKEY" => Self::GenKey,
            "IMPORT_KEY" | "IMPORT_KEYFILES" => Self::ImportKey,
            "EXPORT_KEY" => Self::ExportKey,
            "DELETE_KEY" => Self::DeleteKey,
            "GET_PASSPHRASE" => Self::GetPassphrase,
            "SCD" => Self::Scd,
            "LEARN" => Self::Learn,
            "HAVEKEY" => parse_havekey(args),
            "KEYINFO" => parse_keyinfo(args),
            "READKEY" => parse_readkey(args),
            "SIGKEY" => parse_sigkey(args),
            "SETKEYDESC" => parse_setkeydesc(args),
            "SETHASH" => parse_sethash(args),
            "PKSIGN" => Self::Pksign,
            "CANCEL" => Self::Cancel,
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
#[path = "command_tests.rs"]
mod tests;
