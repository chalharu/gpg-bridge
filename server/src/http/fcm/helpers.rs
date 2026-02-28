use anyhow::anyhow;

/// Convert a JSON value to a `Map<String, String>` (FCM data requires strings).
pub(super) fn convert_to_string_map(
    data: &serde_json::Value,
) -> anyhow::Result<serde_json::Map<String, serde_json::Value>> {
    let obj = data
        .as_object()
        .ok_or_else(|| anyhow!("FCM data must be a JSON object"))?;
    let mut map = serde_json::Map::new();
    for (k, v) in obj {
        let s = match v {
            serde_json::Value::String(s) => s.clone(),
            other => other.to_string(),
        };
        map.insert(k.clone(), serde_json::Value::String(s));
    }
    Ok(map)
}

/// Extract the FCM error code from an error response body.
///
/// Checks `error.details[].errorCode` first, then falls back to `error.status`.
pub(super) fn extract_fcm_error_code(body: &str) -> String {
    serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|v| {
            let error = v.get("error")?;
            // Primary: check details[].errorCode
            if let Some(code) = error
                .get("details")
                .and_then(|d| d.as_array())
                .and_then(|arr| {
                    arr.iter()
                        .find_map(|d| d.get("errorCode")?.as_str().map(String::from))
                })
            {
                return Some(code);
            }
            // Fallback: check error.status
            error.get("status")?.as_str().map(String::from)
        })
        .unwrap_or_else(|| "UNKNOWN".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn convert_to_string_map_converts_values() {
        let data = serde_json::json!({
            "type": "sign_request",
            "request_id": "abc-123",
            "count": 42
        });
        let map = convert_to_string_map(&data).unwrap();
        assert_eq!(map["type"], "sign_request");
        assert_eq!(map["request_id"], "abc-123");
        assert_eq!(map["count"], "42");
    }

    #[test]
    fn convert_to_string_map_rejects_non_object() {
        let data = serde_json::json!("not an object");
        assert!(convert_to_string_map(&data).is_err());
    }

    #[test]
    fn extract_fcm_error_code_parses_unregistered() {
        let body = r#"{"error":{"code":404,"details":[{"errorCode":"UNREGISTERED"}]}}"#;
        assert_eq!(extract_fcm_error_code(body), "UNREGISTERED");
    }

    #[test]
    fn extract_fcm_error_code_returns_unknown_for_bad_json() {
        assert_eq!(extract_fcm_error_code("not json"), "UNKNOWN");
    }

    #[test]
    fn extract_fcm_error_code_falls_back_to_status() {
        let body = r#"{"error":{"code":429,"status":"RESOURCE_EXHAUSTED"}}"#;
        assert_eq!(extract_fcm_error_code(body), "RESOURCE_EXHAUSTED");
    }

    #[test]
    fn extract_fcm_error_code_prefers_details_over_status() {
        let body = r#"{"error":{"code":404,"status":"NOT_FOUND","details":[{"errorCode":"UNREGISTERED"}]}}"#;
        assert_eq!(extract_fcm_error_code(body), "UNREGISTERED");
    }
}
