use super::*;

fn test_service_account() -> ServiceAccountKey {
    ServiceAccountKey {
        client_email: "test@example.iam.gserviceaccount.com".to_owned(),
        private_key: include_str!("../../../test_fixtures/fake_rsa_key.pem").to_owned(),
        token_uri: None,
    }
}

#[test]
fn create_signed_jwt_produces_valid_token() {
    let sa = test_service_account();
    let mgr = OAuth2TokenManager::new(sa.clone(), reqwest::Client::new());
    let jwt = mgr.create_signed_jwt().unwrap();

    let parts: Vec<&str> = jwt.split('.').collect();
    assert_eq!(parts.len(), 3, "JWT should have 3 parts");

    let payload_bytes =
        base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, parts[1])
            .unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();

    assert_eq!(payload["iss"], sa.client_email);
    assert_eq!(payload["scope"], FCM_SCOPE);
}

#[test]
fn service_account_key_deserialize() {
    let json = serde_json::json!({
        "client_email": "test@proj.iam.gserviceaccount.com",
        "private_key": "-----BEGIN RSA PRIVATE KEY-----\nfake\n-----END RSA PRIVATE KEY-----\n",
        "token_uri": "https://oauth2.googleapis.com/token"
    });
    let key: ServiceAccountKey = serde_json::from_value(json).unwrap();
    assert_eq!(key.client_email, "test@proj.iam.gserviceaccount.com");
    assert!(key.token_uri.is_some());
}

#[tokio::test]
async fn cached_token_is_reused() {
    let sa = test_service_account();
    let mgr = OAuth2TokenManager::new(sa, reqwest::Client::new());

    let cached = CachedToken {
        access_token: "cached-token".to_owned(),
        expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
    };
    *mgr.cache.write().await = Some(cached);

    let token = mgr.get_access_token().await.unwrap();
    assert_eq!(token, "cached-token");
}

#[tokio::test]
async fn expired_token_is_not_returned() {
    let sa = test_service_account();
    let mgr = OAuth2TokenManager::new(sa, reqwest::Client::new());

    let cached = CachedToken {
        access_token: "old-token".to_owned(),
        expires_at: chrono::Utc::now() - chrono::Duration::hours(1),
    };
    *mgr.cache.write().await = Some(cached);

    assert!(mgr.read_cached_token().await.is_none());
}

#[test]
fn service_account_key_debug_redacts_private_key() {
    let key = ServiceAccountKey {
        client_email: "test@example.com".to_owned(),
        private_key: "super-secret-key".to_owned(),
        token_uri: Some("https://example.com/token".to_owned()),
    };
    let debug_output = format!("{key:?}");
    assert!(
        !debug_output.contains("super-secret-key"),
        "Debug output must not contain private key"
    );
    assert!(
        debug_output.contains("[REDACTED]"),
        "Debug output must show [REDACTED]"
    );
    assert!(
        debug_output.contains("test@example.com"),
        "Debug output must still show client_email"
    );
}
