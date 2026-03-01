use axum::Router;
use axum::body::{self, Body};
use axum::http::{Request, StatusCode, header};
use axum::routing::{delete, get, post};
use serde_json::json;
use tower::ServiceExt;

use crate::http::AppState;
use crate::jwt::{
    DeviceAssertionClaims, PairingClaims, PayloadType, encrypt_private_key,
    generate_signing_key_pair, jwk_to_json, sign_jws,
};
use crate::repository::{ClientPairingRow, ClientRow, PairingRow, SigningKeyRow};
use crate::test_support::{
    MockRepository, TEST_SECRET, make_client_jwt, make_signing_key_row, make_test_app_state,
};

use super::helpers::{
    build_client_jwt_token, remove_pairing_and_cleanup, verify_pairing_ownership,
};
use super::{
    delete_pairing_by_daemon, delete_pairing_by_phone, get_pairing_token, pair_device,
    query_gpg_keys, refresh_client_jwt,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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

fn build_app(state: AppState) -> Router {
    Router::new()
        .route("/pairing-token", get(get_pairing_token))
        .route("/pairing", post(pair_device))
        .route("/pairing", delete(delete_pairing_by_daemon))
        .route("/pairing/{pairing_id}", delete(delete_pairing_by_phone))
        .route("/pairing/refresh", post(refresh_client_jwt))
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

    let repo = MockRepository::new(sk);
    repo.clients.lock().unwrap().extend(vec![client1, client2]);
    repo.client_pairings_data.lock().unwrap().extend(pairings);
    let app = build_app(make_test_app_state(repo));

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

    let repo = MockRepository::new(sk);
    repo.clients.lock().unwrap().push(client);
    repo.client_pairings_data.lock().unwrap().push(pairing);
    let app = build_app(make_test_app_state(repo));

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

    let repo = MockRepository::new(sk);
    repo.clients.lock().unwrap().push(client1);
    repo.client_pairings_data.lock().unwrap().extend(pairings);
    let app = build_app(make_test_app_state(repo));

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

#[tokio::test]
async fn query_gpg_keys_malformed_json_returns_500() {
    let (priv_jwk, pub_jwk, kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_jwk, &pub_jwk, &kid);

    // Client with invalid gpg_keys JSON stored in DB
    let client = make_client_row("fid-bad", "not-valid-json");

    let pairings = vec![ClientPairingRow {
        client_id: "fid-bad".into(),
        pairing_id: "pair-bad".into(),
        client_jwt_issued_at: "2026-01-01T00:00:00Z".into(),
    }];

    let repo = MockRepository::new(sk);
    repo.clients.lock().unwrap().push(client);
    repo.client_pairings_data.lock().unwrap().extend(pairings);
    let app = build_app(make_test_app_state(repo));

    let token = make_client_jwt(&priv_jwk, &pub_jwk, &kid, "fid-bad", "pair-bad");

    let response = app
        .oneshot(
            Request::post("/pairing/gpg-keys")
                .header("content-type", "application/json")
                .body(json_body(&[token]))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

// ===========================================================================
// Endpoint test helpers
// ===========================================================================

fn make_device_assertion_token(
    priv_jwk: &josekit::jwk::Jwk,
    kid: &str,
    sub: &str,
    path: &str,
) -> String {
    let claims = DeviceAssertionClaims {
        iss: sub.to_owned(),
        sub: sub.to_owned(),
        aud: format!("https://api.example.com{path}"),
        exp: 1_900_000_000,
        iat: 1_900_000_000 - 30,
        jti: uuid::Uuid::new_v4().to_string(),
    };
    sign_jws(&claims, priv_jwk, kid).unwrap()
}

fn make_client_with_public_key(
    client_id: &str,
    pub_jwk: &josekit::jwk::Jwk,
    kid: &str,
) -> ClientRow {
    let pub_json = jwk_to_json(pub_jwk).unwrap();
    ClientRow {
        client_id: client_id.to_owned(),
        created_at: "2026-01-01T00:00:00+00:00".to_owned(),
        updated_at: "2026-01-01T00:00:00+00:00".to_owned(),
        device_token: "tok".to_owned(),
        device_jwt_issued_at: "2026-01-01T00:00:00+00:00".to_owned(),
        public_keys: format!("[{pub_json}]"),
        default_kid: kid.to_owned(),
        gpg_keys: "[]".to_owned(),
    }
}

fn make_pairing_token(priv_jwk: &josekit::jwk::Jwk, kid: &str, pairing_id: &str) -> String {
    let claims = PairingClaims {
        sub: pairing_id.to_owned(),
        payload_type: PayloadType::Pairing,
        exp: 1_900_000_000,
    };
    sign_jws(&claims, priv_jwk, kid).unwrap()
}

// ===========================================================================
// GET /pairing-token
// ===========================================================================

#[tokio::test]
async fn get_pairing_token_returns_200_with_token() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);
    let repo = MockRepository::new(sk);
    let state = make_test_app_state(repo);
    let app = build_app(state);

    let response = app
        .oneshot(Request::get("/pairing-token").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let resp_body = body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&resp_body).unwrap();
    assert!(json["pairing_token"].as_str().is_some());
    assert_eq!(json["expires_in"], 300);
}

#[tokio::test]
async fn get_pairing_token_returns_429_when_limit_reached() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);
    let mut repo = MockRepository::new(sk);
    repo.forced_unconsumed_count = Some(100); // matches unconsumed_pairing_limit
    let state = make_test_app_state(repo);
    let app = build_app(state);

    let response = app
        .oneshot(Request::get("/pairing-token").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
}

// ===========================================================================
// POST /pairing
// ===========================================================================

#[tokio::test]
async fn pair_device_returns_200_with_pairing_id() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);

    let (priv_client, pub_client, client_kid) = generate_signing_key_pair().unwrap();
    let client = make_client_with_public_key("fid-1", &pub_client, &client_kid);

    let pairing_id = "pair-test-1";
    let future_expired = "2099-01-01T00:00:00+00:00";

    let repo = MockRepository::new(sk);
    repo.clients.lock().unwrap().push(client);
    repo.pairings.lock().unwrap().push(PairingRow {
        pairing_id: pairing_id.to_owned(),
        expired: future_expired.to_owned(),
        client_id: None,
    });

    let state = make_test_app_state(repo);
    let app = build_app(state);

    let pairing_token = make_pairing_token(&priv_server, &server_kid, pairing_id);
    let device_assertion =
        make_device_assertion_token(&priv_client, &client_kid, "fid-1", "/pairing");
    let body_json = json!({ "pairing_jwt": pairing_token });

    let response = app
        .oneshot(
            Request::post("/pairing")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {device_assertion}"))
                .body(Body::from(serde_json::to_vec(&body_json).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let resp_body = body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&resp_body).unwrap();
    assert_eq!(json["pairing_id"], pairing_id);
    assert_eq!(json["ok"], true);
    assert_eq!(json["client_id"], "fid-1");
}

#[tokio::test]
async fn pair_device_expired_pairing_returns_410() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);

    let (priv_client, pub_client, client_kid) = generate_signing_key_pair().unwrap();
    let client = make_client_with_public_key("fid-1", &pub_client, &client_kid);

    let pairing_id = "pair-expired";
    let past_expired = "2020-01-01T00:00:00+00:00";

    let repo = MockRepository::new(sk);
    repo.clients.lock().unwrap().push(client);
    repo.pairings.lock().unwrap().push(PairingRow {
        pairing_id: pairing_id.to_owned(),
        expired: past_expired.to_owned(),
        client_id: None,
    });

    let state = make_test_app_state(repo);
    let app = build_app(state);

    let pairing_token = make_pairing_token(&priv_server, &server_kid, pairing_id);
    let device_assertion =
        make_device_assertion_token(&priv_client, &client_kid, "fid-1", "/pairing");
    let body_json = json!({ "pairing_jwt": pairing_token });

    let response = app
        .oneshot(
            Request::post("/pairing")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {device_assertion}"))
                .body(Body::from(serde_json::to_vec(&body_json).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::GONE);
}

#[tokio::test]
async fn pair_device_already_consumed_returns_409() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);

    let (priv_client, pub_client, client_kid) = generate_signing_key_pair().unwrap();
    let client = make_client_with_public_key("fid-1", &pub_client, &client_kid);

    let pairing_id = "pair-consumed";
    let future_expired = "2099-01-01T00:00:00+00:00";

    let repo = MockRepository::new(sk);
    repo.clients.lock().unwrap().push(client);
    repo.pairings.lock().unwrap().push(PairingRow {
        pairing_id: pairing_id.to_owned(),
        expired: future_expired.to_owned(),
        client_id: Some("other-client".to_owned()), // already consumed
    });

    let state = make_test_app_state(repo);
    let app = build_app(state);

    let pairing_token = make_pairing_token(&priv_server, &server_kid, pairing_id);
    let device_assertion =
        make_device_assertion_token(&priv_client, &client_kid, "fid-1", "/pairing");
    let body_json = json!({ "pairing_jwt": pairing_token });

    let response = app
        .oneshot(
            Request::post("/pairing")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {device_assertion}"))
                .body(Body::from(serde_json::to_vec(&body_json).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CONFLICT);
}

// ===========================================================================
// DELETE /pairing/{pairing_id}  (by phone)
// ===========================================================================

#[tokio::test]
async fn delete_by_phone_returns_204() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);

    let (priv_client, pub_client, client_kid) = generate_signing_key_pair().unwrap();
    let client = make_client_with_public_key("fid-1", &pub_client, &client_kid);

    let repo = MockRepository::new(sk);
    repo.clients.lock().unwrap().push(client);
    repo.client_pairings_data
        .lock()
        .unwrap()
        .push(ClientPairingRow {
            client_id: "fid-1".into(),
            pairing_id: "pair-del".into(),
            client_jwt_issued_at: "2026-01-01T00:00:00Z".into(),
        });

    let state = make_test_app_state(repo);
    let app = build_app(state);

    let device_assertion =
        make_device_assertion_token(&priv_client, &client_kid, "fid-1", "/pairing/pair-del");

    let response = app
        .oneshot(
            Request::delete("/pairing/pair-del")
                .header(header::AUTHORIZATION, format!("Bearer {device_assertion}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn delete_by_phone_not_found_returns_404() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);

    let (priv_client, pub_client, client_kid) = generate_signing_key_pair().unwrap();
    let client = make_client_with_public_key("fid-1", &pub_client, &client_kid);

    let repo = MockRepository::new(sk);
    repo.clients.lock().unwrap().push(client);
    // No client_pairings → not found

    let state = make_test_app_state(repo);
    let app = build_app(state);

    let device_assertion =
        make_device_assertion_token(&priv_client, &client_kid, "fid-1", "/pairing/nonexistent");

    let response = app
        .oneshot(
            Request::delete("/pairing/nonexistent")
                .header(header::AUTHORIZATION, format!("Bearer {device_assertion}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

// ===========================================================================
// DELETE /pairing  (by daemon)
// ===========================================================================

#[tokio::test]
async fn delete_by_daemon_returns_204() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);

    let repo = MockRepository::new(sk);
    repo.client_pairings_data
        .lock()
        .unwrap()
        .push(ClientPairingRow {
            client_id: "fid-1".into(),
            pairing_id: "pair-daemon-del".into(),
            client_jwt_issued_at: "2026-01-01T00:00:00Z".into(),
        });

    let state = make_test_app_state(repo);
    let app = build_app(state);

    let client_jwt = make_client_jwt(
        &priv_server,
        &pub_server,
        &server_kid,
        "fid-1",
        "pair-daemon-del",
    );
    let body_json = json!({ "client_jwt": client_jwt });

    let response = app
        .oneshot(
            Request::delete("/pairing")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&body_json).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

// ===========================================================================
// POST /pairing/refresh
// ===========================================================================

#[tokio::test]
async fn refresh_returns_200_with_new_jwt() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);

    let repo = MockRepository::new(sk);
    repo.client_pairings_data
        .lock()
        .unwrap()
        .push(ClientPairingRow {
            client_id: "fid-1".into(),
            pairing_id: "pair-refresh".into(),
            client_jwt_issued_at: "2026-01-01T00:00:00Z".into(),
        });

    let state = make_test_app_state(repo);
    let app = build_app(state);

    let client_jwt = make_client_jwt(
        &priv_server,
        &pub_server,
        &server_kid,
        "fid-1",
        "pair-refresh",
    );
    let body_json = json!({ "client_jwt": client_jwt });

    let response = app
        .oneshot(
            Request::post("/pairing/refresh")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&body_json).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let resp_body = body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&resp_body).unwrap();
    assert!(json["client_jwt"].as_str().is_some());
}

#[tokio::test]
async fn refresh_pairing_not_found_returns_404() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);

    let repo = MockRepository::new(sk);
    // No client_pairings → not found after JWT verification

    let state = make_test_app_state(repo);
    let app = build_app(state);

    let client_jwt = make_client_jwt(
        &priv_server,
        &pub_server,
        &server_kid,
        "fid-1",
        "pair-missing",
    );
    let body_json = json!({ "client_jwt": client_jwt });

    let response = app
        .oneshot(
            Request::post("/pairing/refresh")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&body_json).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

// ===========================================================================
// Additional coverage tests
// ===========================================================================

// -- GET /pairing-token: no active signing key --------------------------------

#[tokio::test]
async fn get_pairing_token_no_signing_key_returns_500() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);
    let mut repo = MockRepository::new(sk);
    repo.signing_key = None; // no active key
    let state = make_test_app_state(repo);
    let app = build_app(state);

    let response = app
        .oneshot(Request::get("/pairing-token").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

// -- POST /pairing: invalid pairing_token format ------------------------------

#[tokio::test]
async fn pair_device_invalid_token_format_returns_400() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);

    let (priv_client, pub_client, client_kid) = generate_signing_key_pair().unwrap();
    let client = make_client_with_public_key("fid-1", &pub_client, &client_kid);

    let repo = MockRepository::new(sk);
    repo.clients.lock().unwrap().push(client);

    let state = make_test_app_state(repo);
    let app = build_app(state);

    let device_assertion =
        make_device_assertion_token(&priv_client, &client_kid, "fid-1", "/pairing");
    let body_json = json!({ "pairing_jwt": "not-a-valid-jwt" });

    let response = app
        .oneshot(
            Request::post("/pairing")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {device_assertion}"))
                .body(Body::from(serde_json::to_vec(&body_json).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

// -- POST /pairing: unknown signing key in pairing_token ----------------------

#[tokio::test]
async fn pair_device_unknown_signing_key_returns_400() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);

    // Generate a DIFFERENT key pair to sign the pairing token
    let (priv_other, _pub_other, other_kid) = generate_signing_key_pair().unwrap();

    let (priv_client, pub_client, client_kid) = generate_signing_key_pair().unwrap();
    let client = make_client_with_public_key("fid-1", &pub_client, &client_kid);

    let repo = MockRepository::new(sk);
    repo.clients.lock().unwrap().push(client);

    let state = make_test_app_state(repo);
    let app = build_app(state);

    // Sign the pairing token with the OTHER key (kid won't match repo)
    let pairing_token = make_pairing_token(&priv_other, &other_kid, "pair-test");
    let device_assertion =
        make_device_assertion_token(&priv_client, &client_kid, "fid-1", "/pairing");
    let body_json = json!({ "pairing_jwt": pairing_token });

    let response = app
        .oneshot(
            Request::post("/pairing")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {device_assertion}"))
                .body(Body::from(serde_json::to_vec(&body_json).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

// -- POST /pairing: pairing not found in DB -----------------------------------

#[tokio::test]
async fn pair_device_pairing_not_found_returns_410() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);

    let (priv_client, pub_client, client_kid) = generate_signing_key_pair().unwrap();
    let client = make_client_with_public_key("fid-1", &pub_client, &client_kid);

    let repo = MockRepository::new(sk);
    repo.clients.lock().unwrap().push(client);
    // No pairing record in DB — pairing_id from JWT won't be found

    let state = make_test_app_state(repo);
    let app = build_app(state);

    let pairing_token = make_pairing_token(&priv_server, &server_kid, "pair-nonexistent");
    let device_assertion =
        make_device_assertion_token(&priv_client, &client_kid, "fid-1", "/pairing");
    let body_json = json!({ "pairing_jwt": pairing_token });

    let response = app
        .oneshot(
            Request::post("/pairing")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {device_assertion}"))
                .body(Body::from(serde_json::to_vec(&body_json).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::GONE);
}

// -- DELETE /pairing (daemon): invalid JWT format -----------------------------

#[tokio::test]
async fn delete_by_daemon_invalid_jwt_returns_401() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);
    let repo = MockRepository::new(sk);
    let state = make_test_app_state(repo);
    let app = build_app(state);

    let body_json = json!({ "client_jwt": "not-a-valid-jwt" });

    let response = app
        .oneshot(
            Request::delete("/pairing")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&body_json).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

// -- DELETE /pairing (daemon): pairing not found ------------------------------

#[tokio::test]
async fn delete_by_daemon_pairing_not_found_returns_404() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);
    let repo = MockRepository::new(sk);
    // No client_pairings → not found

    let state = make_test_app_state(repo);
    let app = build_app(state);

    let client_jwt = make_client_jwt(
        &priv_server,
        &pub_server,
        &server_kid,
        "fid-1",
        "pair-missing",
    );
    let body_json = json!({ "client_jwt": client_jwt });

    let response = app
        .oneshot(
            Request::delete("/pairing")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&body_json).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

// -- DELETE /pairing (daemon): last pairing triggers client cleanup -----------

#[tokio::test]
async fn delete_by_daemon_last_pairing_deletes_client() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);

    let repo = MockRepository::new(sk);
    repo.clients
        .lock()
        .unwrap()
        .push(make_client_row("fid-1", "[]"));
    repo.client_pairings_data
        .lock()
        .unwrap()
        .push(ClientPairingRow {
            client_id: "fid-1".into(),
            pairing_id: "pair-only".into(),
            client_jwt_issued_at: "2026-01-01T00:00:00Z".into(),
        });

    let state = make_test_app_state(repo);
    let app = build_app(state.clone());

    let client_jwt = make_client_jwt(&priv_server, &pub_server, &server_kid, "fid-1", "pair-only");
    let body_json = json!({ "client_jwt": client_jwt });

    let response = app
        .oneshot(
            Request::delete("/pairing")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&body_json).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    // Client should have been cleaned up
    let client = state.repository.get_client_by_id("fid-1").await.unwrap();
    assert!(client.is_none());
}

// -- DELETE /pairing/{pairing_id} (phone): last pairing triggers client cleanup

#[tokio::test]
async fn delete_by_phone_last_pairing_deletes_client() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);

    let (priv_client, pub_client, client_kid) = generate_signing_key_pair().unwrap();
    let client = make_client_with_public_key("fid-1", &pub_client, &client_kid);

    let repo = MockRepository::new(sk);
    repo.clients.lock().unwrap().push(client);
    repo.client_pairings_data
        .lock()
        .unwrap()
        .push(ClientPairingRow {
            client_id: "fid-1".into(),
            pairing_id: "pair-only".into(),
            client_jwt_issued_at: "2026-01-01T00:00:00Z".into(),
        });

    let state = make_test_app_state(repo);
    let app = build_app(state.clone());

    let device_assertion =
        make_device_assertion_token(&priv_client, &client_kid, "fid-1", "/pairing/pair-only");

    let response = app
        .oneshot(
            Request::delete("/pairing/pair-only")
                .header(header::AUTHORIZATION, format!("Bearer {device_assertion}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    // Client should have been cleaned up
    let client = state.repository.get_client_by_id("fid-1").await.unwrap();
    assert!(client.is_none());
}

// -- DELETE /pairing (daemon): multiple pairings, only one removed ------------

#[tokio::test]
async fn delete_by_daemon_preserves_client_with_remaining_pairings() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);

    let repo = MockRepository::new(sk);
    repo.clients
        .lock()
        .unwrap()
        .push(make_client_row("fid-1", "[]"));
    {
        let mut cp = repo.client_pairings_data.lock().unwrap();
        cp.push(ClientPairingRow {
            client_id: "fid-1".into(),
            pairing_id: "pair-a".into(),
            client_jwt_issued_at: "2026-01-01T00:00:00Z".into(),
        });
        cp.push(ClientPairingRow {
            client_id: "fid-1".into(),
            pairing_id: "pair-b".into(),
            client_jwt_issued_at: "2026-01-01T00:00:00Z".into(),
        });
    }

    let state = make_test_app_state(repo);
    let app = build_app(state.clone());

    let client_jwt = make_client_jwt(&priv_server, &pub_server, &server_kid, "fid-1", "pair-a");
    let body_json = json!({ "client_jwt": client_jwt });

    let response = app
        .oneshot(
            Request::delete("/pairing")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&body_json).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    // Client still exists because pair-b remains
    let client = state.repository.get_client_by_id("fid-1").await.unwrap();
    assert!(client.is_some());
}

// -- POST /pairing/refresh: invalid JWT format --------------------------------

#[tokio::test]
async fn refresh_invalid_jwt_returns_401() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);
    let repo = MockRepository::new(sk);
    let state = make_test_app_state(repo);
    let app = build_app(state);

    let body_json = json!({ "client_jwt": "garbage-token" });

    let response = app
        .oneshot(
            Request::post("/pairing/refresh")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&body_json).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

// -- DELETE /pairing/{pairing_id} (phone): multiple pairings, keep client -----

#[tokio::test]
async fn delete_by_phone_preserves_client_with_remaining_pairings() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);

    let (priv_client, pub_client, client_kid) = generate_signing_key_pair().unwrap();
    let client = make_client_with_public_key("fid-1", &pub_client, &client_kid);

    let repo = MockRepository::new(sk);
    repo.clients.lock().unwrap().push(client);
    {
        let mut cp = repo.client_pairings_data.lock().unwrap();
        cp.push(ClientPairingRow {
            client_id: "fid-1".into(),
            pairing_id: "pair-a".into(),
            client_jwt_issued_at: "2026-01-01T00:00:00Z".into(),
        });
        cp.push(ClientPairingRow {
            client_id: "fid-1".into(),
            pairing_id: "pair-b".into(),
            client_jwt_issued_at: "2026-01-01T00:00:00Z".into(),
        });
    }

    let state = make_test_app_state(repo);
    let app = build_app(state.clone());

    let device_assertion =
        make_device_assertion_token(&priv_client, &client_kid, "fid-1", "/pairing/pair-a");

    let response = app
        .oneshot(
            Request::delete("/pairing/pair-a")
                .header(header::AUTHORIZATION, format!("Bearer {device_assertion}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    // Client still exists because pair-b remains
    let client = state.repository.get_client_by_id("fid-1").await.unwrap();
    assert!(client.is_some());
}

// ===========================================================================
// helpers.rs – direct unit tests for error paths
// ===========================================================================

// -- build_client_jwt_token: decrypt_private_key fails -------------------------

#[tokio::test]
async fn build_client_jwt_decrypt_error_returns_500() {
    let (_, pub_jwk, kid) = generate_signing_key_pair().unwrap();
    let bad_sk = SigningKeyRow {
        kid: kid.clone(),
        private_key: "not-valid-encrypted-data".into(),
        public_key: jwk_to_json(&pub_jwk).unwrap(),
        created_at: "2026-01-01T00:00:00Z".into(),
        expires_at: "2027-01-01T00:00:00Z".into(),
        is_active: true,
    };
    let repo = MockRepository::new(bad_sk.clone());
    let state = make_test_app_state(repo);
    let result = build_client_jwt_token(&state, &bad_sk, "c1", "p1");
    assert!(result.is_err());
}

// -- build_client_jwt_token: private JWK parse fails ---------------------------

#[tokio::test]
async fn build_client_jwt_invalid_private_jwk_returns_500() {
    let (_, pub_jwk, kid) = generate_signing_key_pair().unwrap();
    // Encrypt a valid JSON that is NOT a JWK
    let encrypted = encrypt_private_key("{\"not\": \"a jwk\"}", TEST_SECRET).unwrap();
    let bad_sk = SigningKeyRow {
        kid: kid.clone(),
        private_key: encrypted,
        public_key: jwk_to_json(&pub_jwk).unwrap(),
        created_at: "2026-01-01T00:00:00Z".into(),
        expires_at: "2027-01-01T00:00:00Z".into(),
        is_active: true,
    };
    let repo = MockRepository::new(bad_sk.clone());
    let state = make_test_app_state(repo);
    let result = build_client_jwt_token(&state, &bad_sk, "c1", "p1");
    assert!(result.is_err());
}

// -- build_client_jwt_token: public JWK parse fails ----------------------------

#[tokio::test]
async fn build_client_jwt_invalid_public_key_returns_500() {
    let (priv_jwk, _, kid) = generate_signing_key_pair().unwrap();
    let private_json = jwk_to_json(&priv_jwk).unwrap();
    let encrypted = encrypt_private_key(&private_json, TEST_SECRET).unwrap();
    let bad_sk = SigningKeyRow {
        kid: kid.clone(),
        private_key: encrypted,
        public_key: "not-valid-json".into(),
        created_at: "2026-01-01T00:00:00Z".into(),
        expires_at: "2027-01-01T00:00:00Z".into(),
        is_active: true,
    };
    let repo = MockRepository::new(bad_sk.clone());
    let state = make_test_app_state(repo);
    let result = build_client_jwt_token(&state, &bad_sk, "c1", "p1");
    assert!(result.is_err());
}

// -- verify_pairing_ownership: DB error in get_client_pairings -----------------

#[tokio::test]
async fn verify_ownership_db_error_returns_500() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);
    let repo = MockRepository::new(sk);
    repo.force_error("get_client_pairings");
    repo.client_pairings_data
        .lock()
        .unwrap()
        .push(ClientPairingRow {
            client_id: "fid-1".into(),
            pairing_id: "pair-1".into(),
            client_jwt_issued_at: "2026-01-01T00:00:00Z".into(),
        });
    let state = make_test_app_state(repo);

    let result = verify_pairing_ownership(&state, "fid-1", "pair-1", "/pairing").await;
    assert!(result.is_err());
}

// -- remove_pairing_and_cleanup: DB error --------------------------------------

#[tokio::test]
async fn remove_cleanup_db_error_returns_500() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);
    let repo = MockRepository::new(sk);
    repo.force_error("delete_client_pairing_and_cleanup");
    let state = make_test_app_state(repo);

    let result = remove_pairing_and_cleanup(&state, "fid-1", "pair-1", "/pairing").await;
    assert!(result.is_err());
}

// -- verify_pairing_ownership DB error through DELETE /pairing endpoint --------

#[tokio::test]
async fn delete_by_daemon_ownership_db_error_returns_500() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);
    let repo = MockRepository::new(sk);
    repo.force_error("get_client_pairings");
    let state = make_test_app_state(repo);
    let app = build_app(state);

    let client_jwt = make_client_jwt(&priv_server, &pub_server, &server_kid, "fid-1", "pair-1");
    let body_json = json!({ "client_jwt": client_jwt });

    let response = app
        .oneshot(
            Request::delete("/pairing")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&body_json).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

// -- remove_pairing_and_cleanup DB error through DELETE /pairing endpoint ------

#[tokio::test]
async fn delete_by_daemon_cleanup_db_error_returns_500() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);
    let repo = MockRepository::new(sk);
    repo.force_error("delete_client_pairing_and_cleanup");
    repo.client_pairings_data
        .lock()
        .unwrap()
        .push(ClientPairingRow {
            client_id: "fid-1".into(),
            pairing_id: "pair-1".into(),
            client_jwt_issued_at: "2026-01-01T00:00:00Z".into(),
        });
    let state = make_test_app_state(repo);
    let app = build_app(state);

    let client_jwt = make_client_jwt(&priv_server, &pub_server, &server_kid, "fid-1", "pair-1");
    let body_json = json!({ "client_jwt": client_jwt });

    let response = app
        .oneshot(
            Request::delete("/pairing")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&body_json).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

// ===========================================================================
// pair.rs – additional error path tests
// ===========================================================================

// -- POST /pairing: malformed body (missing field) ----------------------------

#[tokio::test]
async fn pair_device_missing_field_returns_400() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);

    let (priv_client, pub_client, client_kid) = generate_signing_key_pair().unwrap();
    let client = make_client_with_public_key("fid-1", &pub_client, &client_kid);

    let repo = MockRepository::new(sk);
    repo.clients.lock().unwrap().push(client);
    let state = make_test_app_state(repo);
    let app = build_app(state);

    let device_assertion =
        make_device_assertion_token(&priv_client, &client_kid, "fid-1", "/pairing");
    // Body with wrong field name
    let body_json = json!({ "wrong_field": "value" });

    let response = app
        .oneshot(
            Request::post("/pairing")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {device_assertion}"))
                .body(Body::from(serde_json::to_vec(&body_json).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

// -- POST /pairing: invalid public JWK in signing key row ---------------------

#[tokio::test]
async fn pair_device_corrupt_public_key_returns_500() {
    let (priv_server, _, server_kid) = generate_signing_key_pair().unwrap();
    // Create a signing key row with valid private key but invalid public_key
    let private_json = jwk_to_json(&priv_server).unwrap();
    let encrypted = encrypt_private_key(&private_json, TEST_SECRET).unwrap();
    let bad_sk = SigningKeyRow {
        kid: server_kid.clone(),
        private_key: encrypted,
        public_key: "not-a-valid-jwk".into(),
        created_at: "2026-01-01T00:00:00Z".into(),
        expires_at: "2027-01-01T00:00:00Z".into(),
        is_active: true,
    };

    let (priv_client, pub_client, client_kid) = generate_signing_key_pair().unwrap();
    let client = make_client_with_public_key("fid-1", &pub_client, &client_kid);

    let repo = MockRepository::new(bad_sk);
    repo.clients.lock().unwrap().push(client);
    let state = make_test_app_state(repo);
    let app = build_app(state);

    // Sign pairing token with the REAL private key but repo returns bad public_key
    let pairing_token = make_pairing_token(&priv_server, &server_kid, "pair-test");
    let device_assertion =
        make_device_assertion_token(&priv_client, &client_kid, "fid-1", "/pairing");
    let body_json = json!({ "pairing_jwt": pairing_token });

    let response = app
        .oneshot(
            Request::post("/pairing")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {device_assertion}"))
                .body(Body::from(serde_json::to_vec(&body_json).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

// -- POST /pairing: invalid expired timestamp in pairing record ---------------

#[tokio::test]
async fn pair_device_invalid_expired_format_returns_500() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);

    let (priv_client, pub_client, client_kid) = generate_signing_key_pair().unwrap();
    let client = make_client_with_public_key("fid-1", &pub_client, &client_kid);

    let pairing_id = "pair-bad-ts";
    let repo = MockRepository::new(sk);
    repo.clients.lock().unwrap().push(client);
    repo.pairings.lock().unwrap().push(PairingRow {
        pairing_id: pairing_id.to_owned(),
        expired: "not-a-valid-timestamp".to_owned(),
        client_id: None,
    });

    let state = make_test_app_state(repo);
    let app = build_app(state);

    let pairing_token = make_pairing_token(&priv_server, &server_kid, pairing_id);
    let device_assertion =
        make_device_assertion_token(&priv_client, &client_kid, "fid-1", "/pairing");
    let body_json = json!({ "pairing_jwt": pairing_token });

    let response = app
        .oneshot(
            Request::post("/pairing")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {device_assertion}"))
                .body(Body::from(serde_json::to_vec(&body_json).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

// -- POST /pairing: consume_pairing DB error ----------------------------------

#[tokio::test]
async fn pair_device_consume_db_error_returns_500() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);

    let (priv_client, pub_client, client_kid) = generate_signing_key_pair().unwrap();
    let client = make_client_with_public_key("fid-1", &pub_client, &client_kid);

    let pairing_id = "pair-consume-err";
    let future_expired = "2099-01-01T00:00:00+00:00";

    let repo = MockRepository::new(sk);
    repo.clients.lock().unwrap().push(client);
    repo.pairings.lock().unwrap().push(PairingRow {
        pairing_id: pairing_id.to_owned(),
        expired: future_expired.to_owned(),
        client_id: None,
    });
    repo.force_error("consume_pairing");

    let state = make_test_app_state(repo);
    let app = build_app(state);

    let pairing_token = make_pairing_token(&priv_server, &server_kid, pairing_id);
    let device_assertion =
        make_device_assertion_token(&priv_client, &client_kid, "fid-1", "/pairing");
    let body_json = json!({ "pairing_jwt": pairing_token });

    let response = app
        .oneshot(
            Request::post("/pairing")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {device_assertion}"))
                .body(Body::from(serde_json::to_vec(&body_json).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

// -- POST /pairing: create_client_pairing DB error ----------------------------

#[tokio::test]
async fn pair_device_create_link_db_error_returns_500() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);

    let (priv_client, pub_client, client_kid) = generate_signing_key_pair().unwrap();
    let client = make_client_with_public_key("fid-1", &pub_client, &client_kid);

    let pairing_id = "pair-link-err";
    let future_expired = "2099-01-01T00:00:00+00:00";

    let repo = MockRepository::new(sk);
    repo.clients.lock().unwrap().push(client);
    repo.pairings.lock().unwrap().push(PairingRow {
        pairing_id: pairing_id.to_owned(),
        expired: future_expired.to_owned(),
        client_id: None,
    });
    repo.force_error("create_client_pairing");

    let state = make_test_app_state(repo);
    let app = build_app(state);

    let pairing_token = make_pairing_token(&priv_server, &server_kid, pairing_id);
    let device_assertion =
        make_device_assertion_token(&priv_client, &client_kid, "fid-1", "/pairing");
    let body_json = json!({ "pairing_jwt": pairing_token });

    let response = app
        .oneshot(
            Request::post("/pairing")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {device_assertion}"))
                .body(Body::from(serde_json::to_vec(&body_json).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

// -- POST /pairing: expired signing key returns 401 ---------------------------

#[tokio::test]
async fn pair_device_expired_signing_key_returns_401() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let private_json = jwk_to_json(&priv_server).unwrap();
    let encrypted = encrypt_private_key(&private_json, TEST_SECRET).unwrap();
    let expired_sk = SigningKeyRow {
        kid: server_kid.clone(),
        private_key: encrypted,
        public_key: jwk_to_json(&pub_server).unwrap(),
        created_at: "2020-01-01T00:00:00Z".into(),
        expires_at: "2020-06-01T00:00:00Z".into(), // already expired
        is_active: true,
    };

    let (priv_client, pub_client, client_kid) = generate_signing_key_pair().unwrap();
    let client = make_client_with_public_key("fid-1", &pub_client, &client_kid);

    let repo = MockRepository::new(expired_sk);
    repo.clients.lock().unwrap().push(client);
    let state = make_test_app_state(repo);
    let app = build_app(state);

    let pairing_token = make_pairing_token(&priv_server, &server_kid, "pair-test");
    let device_assertion =
        make_device_assertion_token(&priv_client, &client_kid, "fid-1", "/pairing");
    let body_json = json!({ "pairing_jwt": pairing_token });

    let response = app
        .oneshot(
            Request::post("/pairing")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {device_assertion}"))
                .body(Body::from(serde_json::to_vec(&body_json).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

// -- POST /pairing: get_signing_key_by_kid DB error ---------------------------

#[tokio::test]
async fn pair_device_signing_key_db_error_returns_500() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);

    let (priv_client, pub_client, client_kid) = generate_signing_key_pair().unwrap();
    let client = make_client_with_public_key("fid-1", &pub_client, &client_kid);

    let repo = MockRepository::new(sk);
    repo.clients.lock().unwrap().push(client);
    repo.force_error("get_signing_key_by_kid");
    let state = make_test_app_state(repo);
    let app = build_app(state);

    let pairing_token = make_pairing_token(&priv_server, &server_kid, "pair-test");
    let device_assertion =
        make_device_assertion_token(&priv_client, &client_kid, "fid-1", "/pairing");
    let body_json = json!({ "pairing_jwt": pairing_token });

    let response = app
        .oneshot(
            Request::post("/pairing")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {device_assertion}"))
                .body(Body::from(serde_json::to_vec(&body_json).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

// -- POST /pairing: get_pairing_by_id DB error --------------------------------

#[tokio::test]
async fn pair_device_get_pairing_db_error_returns_500() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);

    let (priv_client, pub_client, client_kid) = generate_signing_key_pair().unwrap();
    let client = make_client_with_public_key("fid-1", &pub_client, &client_kid);

    let repo = MockRepository::new(sk);
    repo.clients.lock().unwrap().push(client);
    repo.force_error("get_pairing_by_id");
    let state = make_test_app_state(repo);
    let app = build_app(state);

    let pairing_token = make_pairing_token(&priv_server, &server_kid, "pair-test");
    let device_assertion =
        make_device_assertion_token(&priv_client, &client_kid, "fid-1", "/pairing");
    let body_json = json!({ "pairing_jwt": pairing_token });

    let response = app
        .oneshot(
            Request::post("/pairing")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {device_assertion}"))
                .body(Body::from(serde_json::to_vec(&body_json).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

// ===========================================================================
// refresh.rs – additional error path tests
// ===========================================================================

// -- POST /pairing/refresh: malformed body ------------------------------------

#[tokio::test]
async fn refresh_missing_field_returns_400() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);
    let repo = MockRepository::new(sk);
    let state = make_test_app_state(repo);
    let app = build_app(state);

    let body_json = json!({ "wrong_field": "value" });

    let response = app
        .oneshot(
            Request::post("/pairing/refresh")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&body_json).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

// -- POST /pairing/refresh: signing key disappears between verify and fetch ---

#[tokio::test]
async fn refresh_signing_key_disappears_returns_500() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);

    let mut repo = MockRepository::new(sk);
    // First call to get_signing_key_by_kid succeeds (verify_one_token), second returns None
    repo.signing_key_by_kid_max_success = Some(1);
    repo.client_pairings_data
        .lock()
        .unwrap()
        .push(ClientPairingRow {
            client_id: "fid-1".into(),
            pairing_id: "pair-refresh".into(),
            client_jwt_issued_at: "2026-01-01T00:00:00Z".into(),
        });

    let state = make_test_app_state(repo);
    let app = build_app(state);

    let client_jwt = make_client_jwt(
        &priv_server,
        &pub_server,
        &server_kid,
        "fid-1",
        "pair-refresh",
    );
    let body_json = json!({ "client_jwt": client_jwt });

    let response = app
        .oneshot(
            Request::post("/pairing/refresh")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&body_json).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

// -- POST /pairing/refresh: update_client_jwt_issued_at returns false ---------

#[tokio::test]
async fn refresh_update_not_found_returns_404() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);

    let mut repo = MockRepository::new(sk);
    repo.force_update_false = true;
    repo.client_pairings_data
        .lock()
        .unwrap()
        .push(ClientPairingRow {
            client_id: "fid-1".into(),
            pairing_id: "pair-refresh".into(),
            client_jwt_issued_at: "2026-01-01T00:00:00Z".into(),
        });

    let state = make_test_app_state(repo);
    let app = build_app(state);

    let client_jwt = make_client_jwt(
        &priv_server,
        &pub_server,
        &server_kid,
        "fid-1",
        "pair-refresh",
    );
    let body_json = json!({ "client_jwt": client_jwt });

    let response = app
        .oneshot(
            Request::post("/pairing/refresh")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&body_json).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

// -- POST /pairing/refresh: update_client_jwt_issued_at DB error --------------

#[tokio::test]
async fn refresh_update_db_error_returns_500() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);

    let repo = MockRepository::new(sk);
    repo.force_error("update_client_jwt_issued_at");
    repo.client_pairings_data
        .lock()
        .unwrap()
        .push(ClientPairingRow {
            client_id: "fid-1".into(),
            pairing_id: "pair-refresh".into(),
            client_jwt_issued_at: "2026-01-01T00:00:00Z".into(),
        });

    let state = make_test_app_state(repo);
    let app = build_app(state);

    let client_jwt = make_client_jwt(
        &priv_server,
        &pub_server,
        &server_kid,
        "fid-1",
        "pair-refresh",
    );
    let body_json = json!({ "client_jwt": client_jwt });

    let response = app
        .oneshot(
            Request::post("/pairing/refresh")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&body_json).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

// -- POST /pairing/refresh: get_client_pairings DB error ----------------------

#[tokio::test]
async fn refresh_ownership_db_error_returns_500() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);

    let repo = MockRepository::new(sk);
    repo.force_error("get_client_pairings");

    let state = make_test_app_state(repo);
    let app = build_app(state);

    let client_jwt = make_client_jwt(
        &priv_server,
        &pub_server,
        &server_kid,
        "fid-1",
        "pair-refresh",
    );
    let body_json = json!({ "client_jwt": client_jwt });

    let response = app
        .oneshot(
            Request::post("/pairing/refresh")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&body_json).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

// ===========================================================================
// token.rs – additional error path tests
// ===========================================================================

// -- GET /pairing-token: count_unconsumed_pairings DB error -------------------

#[tokio::test]
async fn get_pairing_token_count_db_error_returns_500() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);
    let repo = MockRepository::new(sk);
    repo.force_error("count_unconsumed_pairings");
    let state = make_test_app_state(repo);
    let app = build_app(state);

    let response = app
        .oneshot(Request::get("/pairing-token").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

// -- GET /pairing-token: create_pairing DB error ------------------------------

#[tokio::test]
async fn get_pairing_token_create_pairing_db_error_returns_500() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);
    let repo = MockRepository::new(sk);
    repo.force_error("create_pairing");
    let state = make_test_app_state(repo);
    let app = build_app(state);

    let response = app
        .oneshot(Request::get("/pairing-token").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

// -- GET /pairing-token: bad encrypted private key ----------------------------

#[tokio::test]
async fn get_pairing_token_bad_private_key_returns_500() {
    let (_, pub_jwk, kid) = generate_signing_key_pair().unwrap();
    let bad_sk = SigningKeyRow {
        kid: kid.clone(),
        private_key: "bad-encrypted-data".into(),
        public_key: jwk_to_json(&pub_jwk).unwrap(),
        created_at: "2026-01-01T00:00:00Z".into(),
        expires_at: "2027-01-01T00:00:00Z".into(),
        is_active: true,
    };
    let repo = MockRepository::new(bad_sk);
    let state = make_test_app_state(repo);
    let app = build_app(state);

    let response = app
        .oneshot(Request::get("/pairing-token").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

// -- GET /pairing-token: invalid private JWK (decrypts to non-JWK) ------------

#[tokio::test]
async fn get_pairing_token_invalid_private_jwk_returns_500() {
    let (_, pub_jwk, kid) = generate_signing_key_pair().unwrap();
    let encrypted = encrypt_private_key("{\"not\": \"a jwk\"}", TEST_SECRET).unwrap();
    let bad_sk = SigningKeyRow {
        kid: kid.clone(),
        private_key: encrypted,
        public_key: jwk_to_json(&pub_jwk).unwrap(),
        created_at: "2026-01-01T00:00:00Z".into(),
        expires_at: "2027-01-01T00:00:00Z".into(),
        is_active: true,
    };
    let repo = MockRepository::new(bad_sk);
    let state = make_test_app_state(repo);
    let app = build_app(state);

    let response = app
        .oneshot(Request::get("/pairing-token").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

// -- DELETE /pairing: malformed body ------------------------------------------

#[tokio::test]
async fn delete_by_daemon_malformed_body_returns_400() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);
    let repo = MockRepository::new(sk);
    let state = make_test_app_state(repo);
    let app = build_app(state);

    let body_json = json!({ "wrong_field": "value" });

    let response = app
        .oneshot(
            Request::delete("/pairing")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&body_json).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

// -- DELETE /pairing/{pairing_id}: verify_pairing_ownership DB error ----------

#[tokio::test]
async fn delete_by_phone_ownership_db_error_returns_500() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);

    let (priv_client, pub_client, client_kid) = generate_signing_key_pair().unwrap();
    let client = make_client_with_public_key("fid-1", &pub_client, &client_kid);

    let repo = MockRepository::new(sk);
    repo.clients.lock().unwrap().push(client);
    repo.force_error("get_client_pairings");
    let state = make_test_app_state(repo);
    let app = build_app(state);

    let device_assertion =
        make_device_assertion_token(&priv_client, &client_kid, "fid-1", "/pairing/pair-1");

    let response = app
        .oneshot(
            Request::delete("/pairing/pair-1")
                .header(header::AUTHORIZATION, format!("Bearer {device_assertion}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

// -- DELETE /pairing/{pairing_id}: remove_pairing_and_cleanup DB error --------

#[tokio::test]
async fn delete_by_phone_cleanup_db_error_returns_500() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);

    let (priv_client, pub_client, client_kid) = generate_signing_key_pair().unwrap();
    let client = make_client_with_public_key("fid-1", &pub_client, &client_kid);

    let repo = MockRepository::new(sk);
    repo.clients.lock().unwrap().push(client);
    repo.client_pairings_data
        .lock()
        .unwrap()
        .push(ClientPairingRow {
            client_id: "fid-1".into(),
            pairing_id: "pair-del".into(),
            client_jwt_issued_at: "2026-01-01T00:00:00Z".into(),
        });
    repo.force_error("delete_client_pairing_and_cleanup");
    let state = make_test_app_state(repo);
    let app = build_app(state);

    let device_assertion =
        make_device_assertion_token(&priv_client, &client_kid, "fid-1", "/pairing/pair-del");

    let response = app
        .oneshot(
            Request::delete("/pairing/pair-del")
                .header(header::AUTHORIZATION, format!("Bearer {device_assertion}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

// ===========================================================================
// GET /pairing-session  (SSE)
// ===========================================================================

use super::get_pairing_session;

fn build_sse_app(state: AppState) -> Router {
    Router::new()
        .route("/pairing-session", get(get_pairing_session))
        .with_state(state)
}

#[tokio::test]
async fn session_missing_auth_returns_401() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);
    let repo = MockRepository::new(sk);
    let state = make_test_app_state(repo);
    let app = build_sse_app(state);

    let response = app
        .oneshot(
            Request::get("/pairing-session")
                .header("X-Forwarded-For", "10.0.0.1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn session_invalid_bearer_scheme_returns_401() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);
    let repo = MockRepository::new(sk);
    let state = make_test_app_state(repo);
    let app = build_sse_app(state);

    let response = app
        .oneshot(
            Request::get("/pairing-session")
                .header(header::AUTHORIZATION, "Basic abc123")
                .header("X-Forwarded-For", "10.0.0.1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn session_invalid_jwt_returns_401() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);
    let repo = MockRepository::new(sk);
    let state = make_test_app_state(repo);
    let app = build_sse_app(state);

    let response = app
        .oneshot(
            Request::get("/pairing-session")
                .header(header::AUTHORIZATION, "Bearer not-a-valid-jwt")
                .header("X-Forwarded-For", "10.0.0.1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn session_unknown_signing_key_returns_401() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);

    // Generate a different key pair to sign the token
    let (priv_other, _pub_other, other_kid) = generate_signing_key_pair().unwrap();
    let pairing_token = make_pairing_token(&priv_other, &other_kid, "pair-1");

    let repo = MockRepository::new(sk);
    let state = make_test_app_state(repo);
    let app = build_sse_app(state);

    let response = app
        .oneshot(
            Request::get("/pairing-session")
                .header(header::AUTHORIZATION, format!("Bearer {pairing_token}"))
                .header("X-Forwarded-For", "10.0.0.1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn session_pairing_not_found_returns_410() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);
    let pairing_token = make_pairing_token(&priv_server, &server_kid, "pair-nonexistent");

    let repo = MockRepository::new(sk);
    // No pairings in repo — get_pairing_by_id returns None
    let state = make_test_app_state(repo);
    let app = build_sse_app(state);

    let response = app
        .oneshot(
            Request::get("/pairing-session")
                .header(header::AUTHORIZATION, format!("Bearer {pairing_token}"))
                .header("X-Forwarded-For", "10.0.0.1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::GONE);
}

#[tokio::test]
async fn session_expired_pairing_returns_410() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);
    let pairing_token = make_pairing_token(&priv_server, &server_kid, "pair-expired");

    let repo = MockRepository::new(sk);
    repo.pairings.lock().unwrap().push(PairingRow {
        pairing_id: "pair-expired".to_owned(),
        expired: "2020-01-01T00:00:00+00:00".to_owned(), // past date
        client_id: None,
    });
    let state = make_test_app_state(repo);
    let app = build_sse_app(state);

    let response = app
        .oneshot(
            Request::get("/pairing-session")
                .header(header::AUTHORIZATION, format!("Bearer {pairing_token}"))
                .header("X-Forwarded-For", "10.0.0.1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::GONE);
}

#[tokio::test]
async fn session_already_paired_returns_sse_with_paired_event() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);
    let pairing_token = make_pairing_token(&priv_server, &server_kid, "pair-done");

    let repo = MockRepository::new(sk);
    repo.pairings.lock().unwrap().push(PairingRow {
        pairing_id: "pair-done".to_owned(),
        expired: "2099-01-01T00:00:00+00:00".to_owned(),
        client_id: Some("fid-1".to_owned()),
    });
    // Need a client that exists for the client_jwt build
    let (_, pub_client, client_kid) = generate_signing_key_pair().unwrap();
    let pub_json = jwk_to_json(&pub_client).unwrap();
    repo.clients.lock().unwrap().push(ClientRow {
        client_id: "fid-1".to_owned(),
        created_at: "2026-01-01T00:00:00+00:00".to_owned(),
        updated_at: "2026-01-01T00:00:00+00:00".to_owned(),
        device_token: "tok".to_owned(),
        device_jwt_issued_at: "2026-01-01T00:00:00+00:00".to_owned(),
        public_keys: format!("[{pub_json}]"),
        default_kid: client_kid.clone(),
        gpg_keys: "[]".to_owned(),
    });
    let state = make_test_app_state(repo);
    let app = build_sse_app(state);

    let response = app
        .oneshot(
            Request::get("/pairing-session")
                .header(header::AUTHORIZATION, format!("Bearer {pairing_token}"))
                .header("X-Forwarded-For", "10.0.0.1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body_bytes = body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body_str = String::from_utf8(body_bytes.to_vec()).unwrap();
    assert!(
        body_str.contains("event: paired"),
        "expected paired event in body: {body_str}"
    );
    assert!(
        body_str.contains("\"client_jwt\""),
        "expected client_jwt in body: {body_str}"
    );
    assert!(
        body_str.contains("\"client_id\""),
        "expected client_id in body: {body_str}"
    );
}

#[tokio::test]
async fn session_pending_pairing_returns_200_sse_stream() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);
    let pairing_token = make_pairing_token(&priv_server, &server_kid, "pair-pending");

    let repo = MockRepository::new(sk);
    repo.pairings.lock().unwrap().push(PairingRow {
        pairing_id: "pair-pending".to_owned(),
        expired: "2099-01-01T00:00:00+00:00".to_owned(),
        client_id: None,
    });
    let state = make_test_app_state(repo);
    let app = build_sse_app(state);

    let response = app
        .oneshot(
            Request::get("/pairing-session")
                .header(header::AUTHORIZATION, format!("Bearer {pairing_token}"))
                .header("X-Forwarded-For", "10.0.0.1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // SSE stream starts with 200
    assert_eq!(response.status(), StatusCode::OK);
    let content_type = response
        .headers()
        .get(header::CONTENT_TYPE)
        .unwrap()
        .to_str()
        .unwrap();
    assert!(
        content_type.contains("text/event-stream"),
        "expected text/event-stream but got: {content_type}"
    );
}

#[tokio::test]
async fn session_signing_key_db_error_returns_500() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);
    let pairing_token = make_pairing_token(&priv_server, &server_kid, "pair-1");

    let repo = MockRepository::new(sk);
    repo.force_error("get_signing_key_by_kid");
    let state = make_test_app_state(repo);
    let app = build_sse_app(state);

    let response = app
        .oneshot(
            Request::get("/pairing-session")
                .header(header::AUTHORIZATION, format!("Bearer {pairing_token}"))
                .header("X-Forwarded-For", "10.0.0.1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn session_get_pairing_db_error_returns_500() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);
    let pairing_token = make_pairing_token(&priv_server, &server_kid, "pair-1");

    let repo = MockRepository::new(sk);
    repo.pairings.lock().unwrap().push(PairingRow {
        pairing_id: "pair-1".to_owned(),
        expired: "2099-01-01T00:00:00+00:00".to_owned(),
        client_id: None,
    });
    repo.force_error("get_pairing_by_id");
    let state = make_test_app_state(repo);
    let app = build_sse_app(state);

    let response = app
        .oneshot(
            Request::get("/pairing-session")
                .header(header::AUTHORIZATION, format!("Bearer {pairing_token}"))
                .header("X-Forwarded-For", "10.0.0.1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn session_notify_delivers_paired_event_on_waiting_stream() {
    let (priv_server, pub_server, server_kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_server, &pub_server, &server_kid);
    let pairing_token = make_pairing_token(&priv_server, &server_kid, "pair-wait");

    let repo = MockRepository::new(sk);
    repo.pairings.lock().unwrap().push(PairingRow {
        pairing_id: "pair-wait".to_owned(),
        expired: "2099-01-01T00:00:00+00:00".to_owned(),
        client_id: None,
    });
    let (_, pub_client, client_kid) = generate_signing_key_pair().unwrap();
    let pub_json = jwk_to_json(&pub_client).unwrap();
    repo.clients.lock().unwrap().push(ClientRow {
        client_id: "fid-w".to_owned(),
        created_at: "2026-01-01T00:00:00+00:00".to_owned(),
        updated_at: "2026-01-01T00:00:00+00:00".to_owned(),
        device_token: "tok".to_owned(),
        device_jwt_issued_at: "2026-01-01T00:00:00+00:00".to_owned(),
        public_keys: format!("[{pub_json}]"),
        default_kid: client_kid.clone(),
        gpg_keys: "[]".to_owned(),
    });
    let state = make_test_app_state(repo);
    let notifier = state.pairing_notifier.clone();

    let app = build_sse_app(state);
    let request = Request::get("/pairing-session")
        .header(header::AUTHORIZATION, format!("Bearer {pairing_token}"))
        .header("X-Forwarded-For", "10.0.0.1")
        .body(Body::empty())
        .unwrap();

    // Send SSE request — spawns the stream.
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Send the paired notification.
    use super::notifier::PairedEventData;
    notifier.notify(
        "pair-wait",
        PairedEventData {
            client_jwt: "jwt-val".to_owned(),
            client_id: "fid-w".to_owned(),
        },
    );

    let body_bytes = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        body::to_bytes(response.into_body(), usize::MAX),
    )
    .await
    .expect("timed out reading SSE body")
    .unwrap();
    let body_str = String::from_utf8(body_bytes.to_vec()).unwrap();

    assert!(
        body_str.contains("event: paired"),
        "expected paired event: {body_str}"
    );
}
