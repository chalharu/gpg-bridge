use std::sync::Arc;

use async_trait::async_trait;
use axum::Router;
use axum::body::{self, Body};
use axum::http::{Request, StatusCode};
use axum::routing::post;
use serde_json::json;
use tower::ServiceExt;

use crate::http::AppState;
use crate::http::fcm::NoopFcmValidator;
use crate::jwt::{
    ClientInnerClaims, ClientOuterClaims, PayloadType, encrypt_jwe_direct, encrypt_private_key,
    generate_signing_key_pair, jwk_to_json, sign_jws,
};
use crate::repository::{
    ClientPairingRow, ClientRow, RequestRow, SignatureRepository, SigningKeyRow,
};

use super::query_gpg_keys;

// ---------------------------------------------------------------------------
// Mock repository
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct PairingMockRepo {
    signing_key: Option<SigningKeyRow>,
    clients: Vec<ClientRow>,
    pairings: Vec<ClientPairingRow>,
}

#[async_trait]
impl SignatureRepository for PairingMockRepo {
    async fn run_migrations(&self) -> anyhow::Result<()> {
        Ok(())
    }
    async fn health_check(&self) -> anyhow::Result<()> {
        Ok(())
    }
    fn backend_name(&self) -> &'static str {
        "mock"
    }
    async fn store_signing_key(&self, _: &SigningKeyRow) -> anyhow::Result<()> {
        unimplemented!()
    }
    async fn get_active_signing_key(&self) -> anyhow::Result<Option<SigningKeyRow>> {
        Ok(self.signing_key.clone())
    }
    async fn get_signing_key_by_kid(&self, kid: &str) -> anyhow::Result<Option<SigningKeyRow>> {
        Ok(self.signing_key.as_ref().filter(|k| k.kid == kid).cloned())
    }
    async fn retire_signing_key(&self, _: &str) -> anyhow::Result<bool> {
        unimplemented!()
    }
    async fn delete_expired_signing_keys(&self, _: &str) -> anyhow::Result<u64> {
        unimplemented!()
    }
    async fn get_client_by_id(&self, client_id: &str) -> anyhow::Result<Option<ClientRow>> {
        Ok(self
            .clients
            .iter()
            .find(|c| c.client_id == client_id)
            .cloned())
    }
    async fn create_client(&self, _: &ClientRow) -> anyhow::Result<()> {
        unimplemented!()
    }
    async fn client_exists(&self, _: &str) -> anyhow::Result<bool> {
        unimplemented!()
    }
    async fn client_by_device_token(&self, _: &str) -> anyhow::Result<Option<ClientRow>> {
        unimplemented!()
    }
    async fn update_client_device_token(&self, _: &str, _: &str, _: &str) -> anyhow::Result<()> {
        unimplemented!()
    }
    async fn update_client_default_kid(&self, _: &str, _: &str, _: &str) -> anyhow::Result<()> {
        unimplemented!()
    }
    async fn delete_client(&self, _: &str) -> anyhow::Result<()> {
        unimplemented!()
    }
    async fn update_device_jwt_issued_at(&self, _: &str, _: &str, _: &str) -> anyhow::Result<()> {
        unimplemented!()
    }
    async fn get_client_pairings(&self, client_id: &str) -> anyhow::Result<Vec<ClientPairingRow>> {
        Ok(self
            .pairings
            .iter()
            .filter(|p| p.client_id == client_id)
            .cloned()
            .collect())
    }
    async fn get_request_by_id(&self, _: &str) -> anyhow::Result<Option<RequestRow>> {
        Ok(None)
    }
    async fn update_client_public_keys(
        &self,
        _: &str,
        _: &str,
        _: &str,
        _: &str,
        _: &str,
    ) -> anyhow::Result<bool> {
        unimplemented!()
    }
    async fn update_client_gpg_keys(
        &self,
        _: &str,
        _: &str,
        _: &str,
        _: &str,
    ) -> anyhow::Result<bool> {
        unimplemented!()
    }
    async fn is_kid_in_flight(&self, _: &str) -> anyhow::Result<bool> {
        unimplemented!()
    }
    async fn store_jti(&self, _: &str, _: &str) -> anyhow::Result<bool> {
        Ok(true)
    }
    async fn delete_expired_jtis(&self, _: &str) -> anyhow::Result<u64> {
        Ok(0)
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const TEST_SECRET: &str = "test-secret-key!";

fn make_signing_key_row(
    priv_jwk: &josekit::jwk::Jwk,
    pub_jwk: &josekit::jwk::Jwk,
    kid: &str,
) -> SigningKeyRow {
    let private_json = jwk_to_json(priv_jwk).unwrap();
    let encrypted = encrypt_private_key(&private_json, TEST_SECRET).unwrap();
    SigningKeyRow {
        kid: kid.to_owned(),
        private_key: encrypted,
        public_key: jwk_to_json(pub_jwk).unwrap(),
        created_at: "2026-01-01T00:00:00Z".into(),
        expires_at: "2027-01-01T00:00:00Z".into(),
        is_active: true,
    }
}

fn make_client_jwt(
    priv_jwk: &josekit::jwk::Jwk,
    pub_jwk: &josekit::jwk::Jwk,
    kid: &str,
    client_id: &str,
    pairing_id: &str,
) -> String {
    let inner_claims = ClientInnerClaims {
        sub: client_id.into(),
        pairing_id: pairing_id.into(),
    };
    let inner_bytes = serde_json::to_vec(&inner_claims).unwrap();
    let jwe = encrypt_jwe_direct(&inner_bytes, pub_jwk).unwrap();

    let outer = ClientOuterClaims {
        payload_type: PayloadType::Client,
        client_jwe: jwe,
        exp: 1_900_000_000,
    };
    sign_jws(&outer, priv_jwk, kid).unwrap()
}

fn make_client_row(client_id: &str, gpg_keys: &str) -> ClientRow {
    ClientRow {
        client_id: client_id.to_owned(),
        created_at: "2026-01-01T00:00:00+00:00".to_owned(),
        updated_at: "2026-01-01T00:00:00+00:00".to_owned(),
        device_token: "tok".to_owned(),
        device_jwt_issued_at: "2026-01-01T00:00:00+00:00".to_owned(),
        public_keys: "[]".to_owned(),
        default_kid: "".to_owned(),
        gpg_keys: gpg_keys.to_owned(),
    }
}

fn make_state(repo: PairingMockRepo) -> AppState {
    AppState {
        repository: Arc::new(repo),
        base_url: "https://api.example.com".to_owned(),
        signing_key_secret: TEST_SECRET.to_owned(),
        device_jwt_validity_seconds: 31_536_000,
        fcm_validator: Arc::new(NoopFcmValidator),
    }
}

fn build_app(state: AppState) -> Router {
    Router::new()
        .route("/pairing/gpg-keys", post(query_gpg_keys))
        .with_state(state)
}

fn json_body(tokens: &[String]) -> Body {
    let body = json!({ "client_jwts": tokens });
    Body::from(serde_json::to_vec(&body).unwrap())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn query_gpg_keys_returns_aggregated_keys() {
    let (priv_jwk, pub_jwk, kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_jwk, &pub_jwk, &kid);

    let gpg_keys_1 = json!([{
        "keygrip": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "key_id": "0xABCD1234",
        "public_key": { "kty": "EC", "crv": "P-256" }
    }]);
    let gpg_keys_2 = json!([{
        "keygrip": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
        "key_id": "0xEF567890",
        "public_key": { "kty": "EC", "crv": "P-384" }
    }]);

    let client1 = make_client_row("fid-1", &gpg_keys_1.to_string());
    let client2 = make_client_row("fid-2", &gpg_keys_2.to_string());

    let pairings = vec![
        ClientPairingRow {
            client_id: "fid-1".into(),
            pairing_id: "pair-1".into(),
            client_jwt_issued_at: "2026-01-01T00:00:00Z".into(),
        },
        ClientPairingRow {
            client_id: "fid-2".into(),
            pairing_id: "pair-2".into(),
            client_jwt_issued_at: "2026-01-01T00:00:00Z".into(),
        },
    ];

    let repo = PairingMockRepo {
        signing_key: Some(sk),
        clients: vec![client1, client2],
        pairings,
    };
    let app = build_app(make_state(repo));

    let t1 = make_client_jwt(&priv_jwk, &pub_jwk, &kid, "fid-1", "pair-1");
    let t2 = make_client_jwt(&priv_jwk, &pub_jwk, &kid, "fid-2", "pair-2");

    let response = app
        .oneshot(
            Request::post("/pairing/gpg-keys")
                .header("content-type", "application/json")
                .body(json_body(&[t1, t2]))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let resp_body = body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&resp_body).unwrap();
    let keys = json["gpg_keys"].as_array().unwrap();
    assert_eq!(keys.len(), 2);
    assert_eq!(keys[0]["client_id"], "fid-1");
    assert_eq!(keys[1]["client_id"], "fid-2");
}

#[tokio::test]
async fn query_gpg_keys_returns_empty_when_no_keys() {
    let (priv_jwk, pub_jwk, kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_jwk, &pub_jwk, &kid);

    let client = make_client_row("fid-1", "[]");
    let pairing = ClientPairingRow {
        client_id: "fid-1".into(),
        pairing_id: "pair-1".into(),
        client_jwt_issued_at: "2026-01-01T00:00:00Z".into(),
    };

    let repo = PairingMockRepo {
        signing_key: Some(sk),
        clients: vec![client],
        pairings: vec![pairing],
    };
    let app = build_app(make_state(repo));

    let token = make_client_jwt(&priv_jwk, &pub_jwk, &kid, "fid-1", "pair-1");
    let response = app
        .oneshot(
            Request::post("/pairing/gpg-keys")
                .header("content-type", "application/json")
                .body(json_body(&[token]))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let resp_body = body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&resp_body).unwrap();
    assert!(json["gpg_keys"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn query_gpg_keys_missing_client_returns_remaining_keys() {
    let (priv_jwk, pub_jwk, kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_jwk, &pub_jwk, &kid);

    let gpg_keys_1 = json!([{
        "keygrip": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "key_id": "0xABCD1234",
        "public_key": { "kty": "EC", "crv": "P-256" }
    }]);

    // Only client1 exists in the DB; client2 (fid-deleted) is missing
    let client1 = make_client_row("fid-1", &gpg_keys_1.to_string());

    let pairings = vec![
        ClientPairingRow {
            client_id: "fid-1".into(),
            pairing_id: "pair-1".into(),
            client_jwt_issued_at: "2026-01-01T00:00:00Z".into(),
        },
        ClientPairingRow {
            client_id: "fid-deleted".into(),
            pairing_id: "pair-deleted".into(),
            client_jwt_issued_at: "2026-01-01T00:00:00Z".into(),
        },
    ];

    let repo = PairingMockRepo {
        signing_key: Some(sk),
        clients: vec![client1],
        pairings,
    };
    let app = build_app(make_state(repo));

    let t1 = make_client_jwt(&priv_jwk, &pub_jwk, &kid, "fid-1", "pair-1");
    let t2 = make_client_jwt(&priv_jwk, &pub_jwk, &kid, "fid-deleted", "pair-deleted");

    let response = app
        .oneshot(
            Request::post("/pairing/gpg-keys")
                .header("content-type", "application/json")
                .body(json_body(&[t1, t2]))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let resp_body = body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&resp_body).unwrap();
    let keys = json["gpg_keys"].as_array().unwrap();
    // Only keys from existing client fid-1; deleted client contributes nothing
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0]["client_id"], "fid-1");
}
