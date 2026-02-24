use axum::{
    extract::Request,
    http::{
        HeaderMap, Method,
        header::{self, HeaderValue},
    },
    middleware::Next,
    response::Response,
};

use crate::error::AppError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ApiVersion {
    V1,
}

pub(crate) const ACCEPT_VERSION_V1: &str = "application/vnd.gpg-sign.v1+json";

fn parse_qvalue(raw: &str) -> Option<u16> {
    let raw = raw.trim();

    let (integer, fraction) = match raw.split_once('.') {
        Some((i, f)) => (i, f),
        None => {
            return match raw {
                "0" => Some(0),
                "1" => Some(1000),
                _ => None,
            };
        }
    };

    match integer {
        "1" if fraction.len() <= 3 && fraction.chars().all(|ch| ch == '0') => Some(1000),
        "0" if !fraction.is_empty()
            && fraction.len() <= 3
            && fraction.chars().all(|ch| ch.is_ascii_digit()) =>
        {
            let padded = format!("{fraction:0<3}");
            padded.parse::<u16>().ok()
        }
        _ => None,
    }
}

fn is_supported_media_type(media_type: &str) -> bool {
    media_type == "*/*"
        || media_type.eq_ignore_ascii_case("application/*")
        || media_type.eq_ignore_ascii_case("application/json")
        || media_type.eq_ignore_ascii_case(ACCEPT_VERSION_V1)
}

pub(crate) fn append_vary_accept(headers: &mut HeaderMap) {
    let Some(existing) = headers.get(header::VARY) else {
        headers.insert(header::VARY, HeaderValue::from_static("Accept"));
        return;
    };

    let Ok(existing) = existing.to_str() else {
        return;
    };

    let has_accept = existing
        .split(',')
        .any(|item| item.trim().eq_ignore_ascii_case("Accept"));

    if has_accept {
        return;
    }

    if let Ok(combined) = HeaderValue::from_str(&format!("{existing}, Accept")) {
        headers.insert(header::VARY, combined);
    }
}

pub(crate) fn apply_api_version_headers(headers: &mut HeaderMap, version: ApiVersion) {
    append_vary_accept(headers);

    let is_json_response = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.starts_with("application/json"));

    if !is_json_response {
        return;
    }

    match version {
        ApiVersion::V1 => {
            headers.insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static(ACCEPT_VERSION_V1),
            );
        }
    }
}

fn parse_accept_item(item: &str) -> Result<Option<ApiVersion>, AppError> {
    let mut parts = item.split(';').map(|part| part.trim());
    let media_type = parts.next().unwrap_or("");

    let mut quality = 1000u16;
    for parameter in parts {
        if let Some((name, value)) = parameter.split_once('=')
            && name.trim().eq_ignore_ascii_case("q")
        {
            let qvalue = value.trim();
            quality = parse_qvalue(qvalue).ok_or_else(|| {
                AppError::not_acceptable(format!("invalid q parameter in Accept header: {qvalue}"))
            })?;
        }
    }

    if quality == 0 || !is_supported_media_type(media_type) {
        return Ok(None);
    }

    Ok(Some(ApiVersion::V1))
}

pub(crate) fn parse_accept_version(headers: &HeaderMap) -> Result<ApiVersion, AppError> {
    let Some(accept) = headers.get(header::ACCEPT) else {
        return Ok(ApiVersion::V1);
    };

    let accept = accept
        .to_str()
        .map_err(|_| AppError::not_acceptable("Accept header contains invalid characters"))?;

    for item in accept
        .split(',')
        .map(|item| item.trim())
        .filter(|item| !item.is_empty())
    {
        if let Some(version) = parse_accept_item(item)? {
            return Ok(version);
        }
    }

    Err(AppError::not_acceptable(format!(
        "unsupported Accept header; use {ACCEPT_VERSION_V1}, application/json, or */*"
    )))
}

pub(crate) async fn accept_version_middleware(
    req: Request,
    next: Next,
) -> Result<Response, AppError> {
    if req.method() == Method::OPTIONS {
        return Ok(next.run(req).await);
    }

    let version = parse_accept_version(req.headers())?;
    let mut response = next.run(req).await;
    apply_api_version_headers(response.headers_mut(), version);

    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- parse_qvalue ----

    #[test]
    fn qvalue_integer_one() {
        assert_eq!(parse_qvalue("1"), Some(1000));
    }

    #[test]
    fn qvalue_integer_zero() {
        assert_eq!(parse_qvalue("0"), Some(0));
    }

    #[test]
    fn qvalue_one_with_zero_fraction() {
        assert_eq!(parse_qvalue("1.0"), Some(1000));
        assert_eq!(parse_qvalue("1.00"), Some(1000));
        assert_eq!(parse_qvalue("1.000"), Some(1000));
    }

    #[test]
    fn qvalue_one_with_non_zero_fraction_rejected() {
        assert_eq!(parse_qvalue("1.001"), None);
        assert_eq!(parse_qvalue("1.1"), None);
    }

    #[test]
    fn qvalue_zero_fractions() {
        assert_eq!(parse_qvalue("0.5"), Some(500));
        assert_eq!(parse_qvalue("0.01"), Some(10));
        assert_eq!(parse_qvalue("0.001"), Some(1));
        assert_eq!(parse_qvalue("0.999"), Some(999));
    }

    #[test]
    fn qvalue_rejects_four_digit_fraction() {
        assert_eq!(parse_qvalue("0.1234"), None);
        assert_eq!(parse_qvalue("1.0000"), None);
    }

    #[test]
    fn qvalue_rejects_non_numeric() {
        assert_eq!(parse_qvalue("abc"), None);
        assert_eq!(parse_qvalue("0.abc"), None);
    }

    #[test]
    fn qvalue_rejects_empty_fraction_after_zero_dot() {
        assert_eq!(parse_qvalue("0."), None);
    }

    #[test]
    fn qvalue_trims_whitespace() {
        assert_eq!(parse_qvalue("  1  "), Some(1000));
        assert_eq!(parse_qvalue(" 0.5 "), Some(500));
    }

    #[test]
    fn qvalue_rejects_integer_other_than_zero_or_one() {
        assert_eq!(parse_qvalue("2"), None);
        assert_eq!(parse_qvalue("9"), None);
    }

    // ---- is_supported_media_type ----

    #[test]
    fn supports_wildcard() {
        assert!(is_supported_media_type("*/*"));
    }

    #[test]
    fn supports_application_wildcard() {
        assert!(is_supported_media_type("application/*"));
        assert!(is_supported_media_type("APPLICATION/*"));
    }

    #[test]
    fn supports_application_json() {
        assert!(is_supported_media_type("application/json"));
        assert!(is_supported_media_type("APPLICATION/JSON"));
    }

    #[test]
    fn supports_vendor_type() {
        assert!(is_supported_media_type(ACCEPT_VERSION_V1));
    }

    #[test]
    fn rejects_unknown_media_type() {
        assert!(!is_supported_media_type("text/html"));
        assert!(!is_supported_media_type("application/xml"));
    }

    // ---- append_vary_accept ----

    #[test]
    fn appends_vary_when_absent() {
        let mut headers = HeaderMap::new();
        append_vary_accept(&mut headers);
        assert_eq!(headers.get(header::VARY).unwrap(), "Accept");
    }

    #[test]
    fn does_not_duplicate_accept_in_vary() {
        let mut headers = HeaderMap::new();
        headers.insert(header::VARY, HeaderValue::from_static("Accept"));
        append_vary_accept(&mut headers);
        assert_eq!(headers.get(header::VARY).unwrap(), "Accept");
    }

    #[test]
    fn appends_accept_to_existing_vary() {
        let mut headers = HeaderMap::new();
        headers.insert(header::VARY, HeaderValue::from_static("Origin"));
        append_vary_accept(&mut headers);
        assert_eq!(headers.get(header::VARY).unwrap(), "Origin, Accept");
    }

    #[test]
    fn does_not_duplicate_accept_case_insensitive() {
        let mut headers = HeaderMap::new();
        headers.insert(header::VARY, HeaderValue::from_static("accept"));
        append_vary_accept(&mut headers);
        assert_eq!(headers.get(header::VARY).unwrap(), "accept");
    }

    // ---- parse_accept_version ----

    #[test]
    fn missing_accept_defaults_to_v1() {
        let headers = HeaderMap::new();
        assert_eq!(parse_accept_version(&headers).unwrap(), ApiVersion::V1);
    }

    #[test]
    fn accept_wildcard_returns_v1() {
        let mut headers = HeaderMap::new();
        headers.insert(header::ACCEPT, HeaderValue::from_static("*/*"));
        assert_eq!(parse_accept_version(&headers).unwrap(), ApiVersion::V1);
    }

    #[test]
    fn accept_application_json_returns_v1() {
        let mut headers = HeaderMap::new();
        headers.insert(header::ACCEPT, HeaderValue::from_static("application/json"));
        assert_eq!(parse_accept_version(&headers).unwrap(), ApiVersion::V1);
    }

    #[test]
    fn accept_vendor_v1_returns_v1() {
        let mut headers = HeaderMap::new();
        headers.insert(header::ACCEPT, HeaderValue::from_static(ACCEPT_VERSION_V1));
        assert_eq!(parse_accept_version(&headers).unwrap(), ApiVersion::V1);
    }

    #[test]
    fn accept_unsupported_returns_error() {
        let mut headers = HeaderMap::new();
        headers.insert(header::ACCEPT, HeaderValue::from_static("text/html"));
        assert!(parse_accept_version(&headers).is_err());
    }

    #[test]
    fn accept_with_quality_zero_skips_entry() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::ACCEPT,
            HeaderValue::from_static("application/json;q=0, text/html"),
        );
        assert!(parse_accept_version(&headers).is_err());
    }

    #[test]
    fn accept_invalid_qvalue_returns_error() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::ACCEPT,
            HeaderValue::from_static("application/json;q=abc"),
        );
        assert!(parse_accept_version(&headers).is_err());
    }

    #[test]
    fn accept_multiple_with_supported_in_list() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::ACCEPT,
            HeaderValue::from_static("text/html, application/json, text/plain"),
        );
        assert_eq!(parse_accept_version(&headers).unwrap(), ApiVersion::V1);
    }
}
