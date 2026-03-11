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

async fn query_gpg_keys_client_ids(
    clients: Vec<crate::repository::ClientRow>,
    pairings: &[(&str, &str)],
    request_clients: &[(&str, &str)],
) -> Vec<String> {
    let (app, priv_jwk, pub_jwk, kid) = build_query_gpg_keys_app(clients, pairings);
    let tokens: Vec<String> = request_clients
        .iter()
        .map(|(client_id, pairing_id)| {
            make_client_jwt(&priv_jwk, &pub_jwk, &kid, client_id, pairing_id)
        })
        .collect();

    let response = app.oneshot(query_gpg_keys_request(&tokens)).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let resp_body = body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&resp_body).unwrap();

    json["gpg_keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|key| key["client_id"].as_str().unwrap().to_owned())
        .collect()
}

#[tokio::test]
async fn query_gpg_keys_returns_aggregated_keys() {
    let client_ids = query_gpg_keys_client_ids(
        vec![
            make_client_row(
                "fid-1",
                &json!([gpg_key_value(
                    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                    "0xABCD1234",
                    "P-256",
                )])
                .to_string(),
            ),
            make_client_row(
                "fid-2",
                &json!([gpg_key_value(
                    "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
                    "0xEF567890",
                    "P-384",
                )])
                .to_string(),
            ),
        ],
        &[("fid-1", "pair-1"), ("fid-2", "pair-2")],
        &[("fid-1", "pair-1"), ("fid-2", "pair-2")],
    )
    .await;

    assert_eq!(client_ids, vec!["fid-1".to_owned(), "fid-2".to_owned()]);
}

#[tokio::test]
async fn query_gpg_keys_missing_client_returns_remaining_keys() {
    let client_ids = query_gpg_keys_client_ids(
        vec![make_client_row(
            "fid-1",
            &json!([gpg_key_value(
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "0xABCD1234",
                "P-256",
            )])
            .to_string(),
        )],
        &[("fid-1", "pair-1"), ("fid-deleted", "pair-deleted")],
        &[("fid-1", "pair-1"), ("fid-deleted", "pair-deleted")],
    )
    .await;

    assert_eq!(client_ids, vec!["fid-1".to_owned()]);
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
