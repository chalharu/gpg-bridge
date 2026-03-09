use std::sync::Arc;

use axum::body::{self, Body};
use axum::http::{Request, StatusCode};
use serde_json::json;
use tower::ServiceExt;

use crate::jwt::generate_signing_key_pair;
use crate::repository::ClientPairingRow;
use crate::test_support::{
    MockRepository, make_client_jwt, make_signing_key_row, make_test_app_state,
    make_test_app_state_arc,
};

use super::{
    VALID_COORD, body_json, build_app, make_client_row_no_enc_key, make_client_row_with_enc_key,
    post_json, response_status, setup_happy_path, valid_request_body,
};

#[tokio::test]
async fn happy_path_returns_201_with_request_jwt_and_e2e_keys() {
    let (priv_jwk, pub_jwk, kid, repo) = setup_happy_path();
    let state = make_test_app_state(repo);
    let app = build_app(state);

    let token = make_client_jwt(&priv_jwk, &pub_jwk, &kid, "client-1", "pair-1");
    let body = valid_request_body(vec![token]);
    let resp = app.oneshot(post_json(&body)).await.unwrap();

    assert_eq!(resp.status(), StatusCode::CREATED);

    let bytes = body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert!(json.get("request_jwt").is_some());
    assert!(json.get("e2e_keys").is_some());

    let e2e_keys = json["e2e_keys"].as_array().unwrap();
    assert_eq!(e2e_keys.len(), 1);
    assert_eq!(e2e_keys[0]["client_id"], "client-1");
}

#[tokio::test]
async fn happy_path_persists_request_and_audit_log() {
    let (priv_jwk, pub_jwk, kid, repo) = setup_happy_path();
    let repo_arc: Arc<MockRepository> = Arc::new(repo);
    let state = make_test_app_state_arc(repo_arc.clone());
    let app = build_app(state);

    let token = make_client_jwt(&priv_jwk, &pub_jwk, &kid, "client-1", "pair-1");
    let body = valid_request_body(vec![token]);
    let status = response_status(app, post_json(&body)).await;
    assert_eq!(status, StatusCode::CREATED);

    assert_eq!(repo_arc.requests.lock().unwrap().len(), 1);
    assert_eq!(repo_arc.audit_logs.lock().unwrap().len(), 1);

    let req_row = &repo_arc.requests.lock().unwrap()[0];
    assert_eq!(req_row.status, "created");
    assert!(!req_row.request_id.is_empty());

    let log_row = &repo_arc.audit_logs.lock().unwrap()[0];
    assert_eq!(log_row.event_type, "sign_request_created");
}

#[tokio::test]
async fn empty_client_jwts_returns_401() {
    let (_, _, _, repo) = setup_happy_path();
    let app = build_app(make_test_app_state(repo));

    let body = valid_request_body(vec![]);
    let status = response_status(app, post_json(&body)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn invalid_daemon_public_key_returns_400() {
    let (priv_jwk, pub_jwk, kid, repo) = setup_happy_path();
    let app = build_app(make_test_app_state(repo));

    let token = make_client_jwt(&priv_jwk, &pub_jwk, &kid, "client-1", "pair-1");
    let body = json!({
        "client_jwts": [token],
        "daemon_public_key": {
            "kty": "RSA",
            "crv": "P-256",
            "x": VALID_COORD,
            "y": VALID_COORD,
            "alg": "ES256"
        },
        "daemon_enc_public_key": {
            "kty": "EC",
            "crv": "P-256",
            "x": VALID_COORD,
            "y": VALID_COORD,
            "alg": "ECDH-ES+A256KW"
        }
    });
    let status = response_status(app, post_json(&body)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn invalid_daemon_enc_public_key_returns_400() {
    let (priv_jwk, pub_jwk, kid, repo) = setup_happy_path();
    let app = build_app(make_test_app_state(repo));

    let token = make_client_jwt(&priv_jwk, &pub_jwk, &kid, "client-1", "pair-1");
    let body = json!({
        "client_jwts": [token],
        "daemon_public_key": {
            "kty": "EC",
            "crv": "P-256",
            "x": VALID_COORD,
            "y": VALID_COORD,
            "alg": "ES256"
        },
        "daemon_enc_public_key": {
            "kty": "EC",
            "crv": "P-384",
            "x": VALID_COORD,
            "y": VALID_COORD,
            "alg": "ECDH-ES+A256KW"
        }
    });
    let status = response_status(app, post_json(&body)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn rate_limit_exceeded_returns_429() {
    let (priv_jwk, pub_jwk, kid, repo) = setup_happy_path();
    let repo = MockRepository {
        pending_count: 5,
        ..repo
    };
    let app = build_app(make_test_app_state(repo));

    let token = make_client_jwt(&priv_jwk, &pub_jwk, &kid, "client-1", "pair-1");
    let body = valid_request_body(vec![token]);
    let status = response_status(app, post_json(&body)).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn no_active_signing_key_returns_500() {
    let (priv_jwk, pub_jwk, kid, mut repo) = setup_happy_path();
    repo.active_signing_key_override = Some(None);
    let app = build_app(make_test_app_state(repo));

    let token = make_client_jwt(&priv_jwk, &pub_jwk, &kid, "client-1", "pair-1");
    let body = valid_request_body(vec![token]);
    let status = response_status(app, post_json(&body)).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn invalid_active_signing_key_returns_500() {
    let (priv_jwk, pub_jwk, kid, mut repo) = setup_happy_path();
    let mut bad_signing_key = repo.signing_key.clone().unwrap();
    bad_signing_key.private_key = "not-an-encrypted-jwk".into();
    repo.active_signing_key_override = Some(Some(bad_signing_key));
    let app = build_app(make_test_app_state(repo));

    let token = make_client_jwt(&priv_jwk, &pub_jwk, &kid, "client-1", "pair-1");
    let body = valid_request_body(vec![token]);
    let response = app.oneshot(post_json(&body)).await.unwrap();
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let body = body_json(response).await;
    assert!(
        body["detail"]
            .as_str()
            .unwrap()
            .contains("key decrypt failed")
    );
}

#[tokio::test]
async fn client_not_in_db_returns_500() {
    let (priv_jwk, pub_jwk, kid, repo) = setup_happy_path();
    // Remove client row so lookup_enc_key returns None → empty e2e_keys → 500.
    repo.clients.lock().unwrap().clear();
    let app = build_app(make_test_app_state(repo));

    let token = make_client_jwt(&priv_jwk, &pub_jwk, &kid, "client-1", "pair-1");
    let body = valid_request_body(vec![token]);
    let status = response_status(app, post_json(&body)).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn client_without_enc_key_returns_500() {
    let (priv_jwk, pub_jwk, kid, repo) = setup_happy_path();
    // Replace client with one that has no enc key → empty e2e_keys → 500.
    repo.clients.lock().unwrap().clear();
    repo.clients
        .lock()
        .unwrap()
        .push(make_client_row_no_enc_key("client-1"));
    let app = build_app(make_test_app_state(repo));

    let token = make_client_jwt(&priv_jwk, &pub_jwk, &kid, "client-1", "pair-1");
    let body = valid_request_body(vec![token]);
    let status = response_status(app, post_json(&body)).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn multiple_clients_happy_path() {
    let (priv_jwk, pub_jwk, kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_jwk, &pub_jwk, &kid);
    let repo = MockRepository::new(sk);

    for (cid, pid) in &[("c1", "p1"), ("c2", "p2")] {
        repo.client_pairings_data
            .lock()
            .unwrap()
            .push(ClientPairingRow {
                client_id: cid.to_string(),
                pairing_id: pid.to_string(),
                client_jwt_issued_at: "2026-01-01T00:00:00Z".into(),
            });
        repo.clients
            .lock()
            .unwrap()
            .push(make_client_row_with_enc_key(cid, &format!("ek-{cid}")));
    }

    let app = build_app(make_test_app_state(repo));

    let t1 = make_client_jwt(&priv_jwk, &pub_jwk, &kid, "c1", "p1");
    let t2 = make_client_jwt(&priv_jwk, &pub_jwk, &kid, "c2", "p2");
    let body = valid_request_body(vec![t1, t2]);
    let resp = app.oneshot(post_json(&body)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    let json = body_json(resp).await;
    let e2e_keys = json["e2e_keys"].as_array().unwrap();
    assert_eq!(e2e_keys.len(), 2);
}

#[tokio::test]
async fn create_request_error_returns_500() {
    let (priv_jwk, pub_jwk, kid, repo) = setup_happy_path();
    let repo = MockRepository {
        force_create_request_error: true,
        ..repo
    };
    let app = build_app(make_test_app_state(repo));

    let token = make_client_jwt(&priv_jwk, &pub_jwk, &kid, "client-1", "pair-1");
    let body = valid_request_body(vec![token]);
    let status = response_status(app, post_json(&body)).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn audit_log_error_returns_500() {
    let (priv_jwk, pub_jwk, kid, repo) = setup_happy_path();
    let repo = MockRepository {
        force_audit_log_error: true,
        ..repo
    };
    let app = build_app(make_test_app_state(repo));

    let token = make_client_jwt(&priv_jwk, &pub_jwk, &kid, "client-1", "pair-1");
    let body = valid_request_body(vec![token]);
    let status = response_status(app, post_json(&body)).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn invalid_jwt_token_returns_401() {
    let (_, _, _, repo) = setup_happy_path();
    let app = build_app(make_test_app_state(repo));

    let body = valid_request_body(vec!["not.a.valid.jwt".to_owned()]);
    let status = response_status(app, post_json(&body)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn pairing_not_in_db_returns_401() {
    let (priv_jwk, pub_jwk, kid, repo) = setup_happy_path();
    // Remove pairings so filter_valid_pairings filters all out.
    repo.client_pairings_data.lock().unwrap().clear();
    let app = build_app(make_test_app_state(repo));

    let token = make_client_jwt(&priv_jwk, &pub_jwk, &kid, "client-1", "pair-1");
    let body = valid_request_body(vec![token]);
    let status = response_status(app, post_json(&body)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn rate_limit_below_threshold_passes() {
    let (priv_jwk, pub_jwk, kid, repo) = setup_happy_path();
    let repo = MockRepository {
        pending_count: 4, // below MAX_PENDING_REQUESTS_PER_PAIRING (5)
        ..repo
    };
    let app = build_app(make_test_app_state(repo));

    let token = make_client_jwt(&priv_jwk, &pub_jwk, &kid, "client-1", "pair-1");
    let body = valid_request_body(vec![token]);
    let status = response_status(app, post_json(&body)).await;
    assert_eq!(status, StatusCode::CREATED);
}

#[tokio::test]
async fn malformed_json_returns_400() {
    let (_, _, _, repo) = setup_happy_path();
    let app = build_app(make_test_app_state(repo));

    let req = Request::builder()
        .method("POST")
        .uri("/sign-request")
        .header("content-type", "application/json")
        .body(Body::from(b"not json".to_vec()))
        .unwrap();
    let status = response_status(app, req).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn missing_daemon_enc_public_key_returns_422() {
    let (priv_jwk, pub_jwk, kid, repo) = setup_happy_path();
    let app = build_app(make_test_app_state(repo));

    let token = make_client_jwt(&priv_jwk, &pub_jwk, &kid, "client-1", "pair-1");
    let body = json!({
        "client_jwts": [token],
        "daemon_public_key": {
            "kty": "EC",
            "crv": "P-256",
            "x": VALID_COORD,
            "y": VALID_COORD,
            "alg": "ES256"
        }
    });
    let status = response_status(app, post_json(&body)).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
}
