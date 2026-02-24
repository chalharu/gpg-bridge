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

    if raw == "1" {
        return Some(1000);
    }

    if let Some(frac) = raw.strip_prefix("1.") {
        if frac.len() <= 3 && frac.chars().all(|ch| ch == '0') {
            return Some(1000);
        }
        return None;
    }

    if raw == "0" {
        return Some(0);
    }

    if let Some(frac) = raw.strip_prefix("0.") {
        if frac.is_empty() || frac.len() > 3 || !frac.chars().all(|ch| ch.is_ascii_digit()) {
            return None;
        }

        let mut normalized = frac.to_owned();
        while normalized.len() < 3 {
            normalized.push('0');
        }
        return normalized.parse::<u16>().ok();
    }

    None
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
        let mut parts = item.split(';').map(|part| part.trim());
        let media_type = parts.next().unwrap_or("");

        let mut quality = 1000;
        for parameter in parts {
            if let Some((name, value)) = parameter.split_once('=')
                && name.trim().eq_ignore_ascii_case("q")
            {
                let qvalue = value.trim();
                quality = parse_qvalue(qvalue).ok_or_else(|| {
                    AppError::not_acceptable(format!(
                        "invalid q parameter in Accept header: {qvalue}"
                    ))
                })?;
            }
        }

        if quality == 0 {
            continue;
        }

        if is_supported_media_type(media_type) {
            return Ok(ApiVersion::V1);
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
