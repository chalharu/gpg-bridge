/// Assuan protocol response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Response {
    /// `OK [message]\n`
    Ok(Option<String>),
    /// `D <data>\nOK\n`
    DataThenOk(String),
    /// `ERR <code> <message>\n`
    Err { code: u32, message: String },
}

impl Response {
    /// Format the response as an Assuan protocol wire string.
    pub(crate) fn format(&self) -> String {
        match self {
            Self::Ok(None) => "OK\n".to_owned(),
            Self::Ok(Some(msg)) => format!("OK {msg}\n"),
            Self::DataThenOk(data) => format!("D {data}\nOK\n"),
            Self::Err { code, message } => format!("ERR {code} {message}\n"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_ok_no_message() {
        assert_eq!(Response::Ok(None).format(), "OK\n");
    }

    #[test]
    fn format_ok_with_message() {
        let r = Response::Ok(Some("Pleased to meet you".to_owned()));
        assert_eq!(r.format(), "OK Pleased to meet you\n");
    }

    #[test]
    fn format_data_then_ok() {
        let r = Response::DataThenOk("0.1.0".to_owned());
        assert_eq!(r.format(), "D 0.1.0\nOK\n");
    }

    #[test]
    fn format_err() {
        let r = Response::Err {
            code: 275,
            message: "unknown IPC command".to_owned(),
        };
        assert_eq!(r.format(), "ERR 275 unknown IPC command\n");
    }

    #[test]
    fn format_err_not_supported() {
        let r = Response::Err {
            code: 69,
            message: "Not supported".to_owned(),
        };
        assert_eq!(r.format(), "ERR 69 Not supported\n");
    }

    #[test]
    fn format_data_then_ok_with_spaces() {
        let r = Response::DataThenOk("/path/to my/socket".to_owned());
        assert_eq!(r.format(), "D /path/to my/socket\nOK\n");
    }
}
