use axum::body::{self};
use axum::http::{Request, StatusCode};
use serde_json::json;
use tower::ServiceExt;

use crate::jwt::generate_signing_key_pair;
use crate::repository::ClientPairingRow;
use crate::test_support::{
    MockRepository, make_client_jwt, make_signing_key_row, make_test_app_state,
};

use super::{build_app, json_body, make_client_row};

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
