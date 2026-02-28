/// Assuan protocol response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Response {
    /// `OK [message]\n`
    Ok(Option<String>),
    /// `D <data>\nOK\n`
    DataThenOk(String),
    /// One or more `S <line>\n` followed by `OK\n`.
    StatusThenOk(Vec<String>),
    /// `D <percent-encoded binary>\nOK\n` for canonical S-expressions.
    DataBinaryThenOk(Vec<u8>),
    /// `ERR <code> <message>\n`
    Err { code: u32, message: String },
}

impl Response {
    /// Format the response as Assuan protocol wire bytes.
    pub(super) fn format(&self) -> Vec<u8> {
        match self {
            Self::Ok(None) => b"OK\n".to_vec(),
            Self::Ok(Some(msg)) => format!("OK {msg}\n").into_bytes(),
            Self::DataThenOk(data) => format!("D {data}\nOK\n").into_bytes(),
            Self::StatusThenOk(lines) => {
                let mut buf = Vec::new();
                for line in lines {
                    buf.extend_from_slice(b"S ");
                    buf.extend_from_slice(line.as_bytes());
                    buf.push(b'\n');
                }
                buf.extend_from_slice(b"OK\n");
                buf
            }
            Self::DataBinaryThenOk(data) => {
                let mut buf = Vec::with_capacity(2 + data.len() * 2 + 5);
                buf.extend_from_slice(b"D ");
                percent_encode_assuan(data, &mut buf);
                buf.push(b'\n');
                buf.extend_from_slice(b"OK\n");
                buf
            }
            Self::Err { code, message } => format!("ERR {code} {message}\n").into_bytes(),
        }
    }
}

/// Percent-encode bytes for the Assuan D-line protocol.
///
/// Only CR (`%0D`), LF (`%0A`), and `%` (`%25`) need encoding; all other
/// bytes—including those above 0x7F—are sent verbatim.
fn percent_encode_assuan(data: &[u8], buf: &mut Vec<u8>) {
    for &byte in data {
        match byte {
            b'%' => buf.extend_from_slice(b"%25"),
            b'\r' => buf.extend_from_slice(b"%0D"),
            b'\n' => buf.extend_from_slice(b"%0A"),
            _ => buf.push(byte),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_ok_no_message() {
        assert_eq!(Response::Ok(None).format(), b"OK\n");
    }

    #[test]
    fn format_ok_with_message() {
        let r = Response::Ok(Some("Pleased to meet you".to_owned()));
        assert_eq!(r.format(), b"OK Pleased to meet you\n");
    }

    #[test]
    fn format_data_then_ok() {
        let r = Response::DataThenOk("0.1.0".to_owned());
        assert_eq!(r.format(), b"D 0.1.0\nOK\n");
    }

    #[test]
    fn format_err() {
        let r = Response::Err {
            code: 275,
            message: "unknown IPC command".to_owned(),
        };
        assert_eq!(r.format(), b"ERR 275 unknown IPC command\n");
    }

    #[test]
    fn format_err_not_supported() {
        let r = Response::Err {
            code: 69,
            message: "Not supported".to_owned(),
        };
        assert_eq!(r.format(), b"ERR 69 Not supported\n");
    }

    #[test]
    fn format_data_then_ok_with_spaces() {
        let r = Response::DataThenOk("/path/to my/socket".to_owned());
        assert_eq!(r.format(), b"D /path/to my/socket\nOK\n");
    }

    #[test]
    fn format_status_then_ok_single() {
        let r = Response::StatusThenOk(vec!["KEYINFO ABC D - - 1 P - 0 0 -".to_owned()]);
        assert_eq!(r.format(), b"S KEYINFO ABC D - - 1 P - 0 0 -\nOK\n");
    }

    #[test]
    fn format_status_then_ok_multiple() {
        let r = Response::StatusThenOk(vec!["LINE1".to_owned(), "LINE2".to_owned()]);
        assert_eq!(r.format(), b"S LINE1\nS LINE2\nOK\n");
    }

    #[test]
    fn format_data_binary_then_ok() {
        let r = Response::DataBinaryThenOk(vec![0x41, 0x0A, 0x25, 0x0D, 0x42]);
        assert_eq!(r.format(), b"D A%0A%25%0DB\nOK\n");
    }

    #[test]
    fn format_data_binary_then_ok_passthrough() {
        let r = Response::DataBinaryThenOk(vec![0x01, 0x80, 0xFF]);
        assert_eq!(r.format(), b"D \x01\x80\xFF\nOK\n");
    }
}
