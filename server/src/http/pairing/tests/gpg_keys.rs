use axum::body::{self};
use axum::http::StatusCode;
use serde_json::json;
use tower::ServiceExt;

use crate::jwt::generate_signing_key_pair;
use crate::test_support::{MockRepository, make_client_jwt, make_signing_key_row};

use super::{add_client_pairings, build_test_app, make_client_row, query_gpg_keys_request};

fn gpg_key_value(keygrip: &str, key_id: &str, crv: &str) -> serde_json::Value {
    json!({
        "keygrip": keygrip,
        "key_id": key_id,
        "public_key": { "kty": "EC", "crv": crv }
    })
}

fn build_query_gpg_keys_app(
    clients: Vec<crate::repository::ClientRow>,
    pairings: &[(&str, &str)],
) -> (axum::Router, josekit::jwk::Jwk, josekit::jwk::Jwk, String) {
    let (priv_jwk, pub_jwk, kid) = generate_signing_key_pair().unwrap();
    let sk = make_signing_key_row(&priv_jwk, &pub_jwk, &kid);
    let repo = MockRepository::new(sk);
    repo.clients.lock().unwrap().extend(clients);
    add_client_pairings(&repo, pairings);
    (build_test_app(repo), priv_jwk, pub_jwk, kid)
}

#[tokio::test]
async fn query_gpg_keys_returns_aggregated_keys() {
    let client1 = make_client_row(
        "fid-1",
        &json!([gpg_key_value(
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "0xABCD1234",
            "P-256",
        )])
        .to_string(),
    );
    let client2 = make_client_row(
        "fid-2",
        &json!([gpg_key_value(
            "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
            "0xEF567890",
            "P-384",
        )])
        .to_string(),
    );
    let (app, priv_jwk, pub_jwk, kid) = build_query_gpg_keys_app(
        vec![client1, client2],
        &[("fid-1", "pair-1"), ("fid-2", "pair-2")],
    );

    let t1 = make_client_jwt(&priv_jwk, &pub_jwk, &kid, "fid-1", "pair-1");
    let t2 = make_client_jwt(&priv_jwk, &pub_jwk, &kid, "fid-2", "pair-2");

    let response = app
        .oneshot(query_gpg_keys_request(&[t1, t2]))
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
    let repo = MockRepository::new(sk);
    repo.clients.lock().unwrap().push(client);
    add_client_pairings(&repo, &[("fid-1", "pair-1")]);
    let app = build_test_app(repo);

    let token = make_client_jwt(&priv_jwk, &pub_jwk, &kid, "fid-1", "pair-1");
    let response = app.oneshot(query_gpg_keys_request(&[token])).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let resp_body = body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&resp_body).unwrap();
    assert!(json["gpg_keys"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn query_gpg_keys_missing_client_returns_remaining_keys() {
    // Only client1 exists in the DB; client2 (fid-deleted) is missing
    let client1 = make_client_row(
        "fid-1",
        &json!([gpg_key_value(
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "0xABCD1234",
            "P-256",
        )])
        .to_string(),
    );
    let (app, priv_jwk, pub_jwk, kid) = build_query_gpg_keys_app(
        vec![client1],
        &[("fid-1", "pair-1"), ("fid-deleted", "pair-deleted")],
    );

    let t1 = make_client_jwt(&priv_jwk, &pub_jwk, &kid, "fid-1", "pair-1");
    let t2 = make_client_jwt(&priv_jwk, &pub_jwk, &kid, "fid-deleted", "pair-deleted");

    let response = app
        .oneshot(query_gpg_keys_request(&[t1, t2]))
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

    let repo = MockRepository::new(sk);
    repo.clients.lock().unwrap().push(client);
    add_client_pairings(&repo, &[("fid-bad", "pair-bad")]);
    let app = build_test_app(repo);

    let token = make_client_jwt(&priv_jwk, &pub_jwk, &kid, "fid-bad", "pair-bad");

    let response = app.oneshot(query_gpg_keys_request(&[token])).await.unwrap();

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}
