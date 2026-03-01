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
