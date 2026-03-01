use crate::http::signing::handler::{build_e2e_kids_map, build_pairing_ids_map, compute_expiry};
use crate::http::signing::types::E2eKeyItem;

// ---------------------------------------------------------------------------
// Unit tests for pure helpers (moved from handler.rs)
// ---------------------------------------------------------------------------

#[test]
fn e2e_kids_map_built_correctly() {
    let items = vec![
        E2eKeyItem {
            client_id: "c1".into(),
            public_key: serde_json::json!({"kid": "k1", "use": "enc"}),
        },
        E2eKeyItem {
            client_id: "c2".into(),
            public_key: serde_json::json!({"kid": "k2", "use": "enc"}),
        },
    ];
    let map = build_e2e_kids_map(&items);
    assert_eq!(map.get("c1").unwrap().as_str().unwrap(), "k1");
    assert_eq!(map.get("c2").unwrap().as_str().unwrap(), "k2");
}

#[test]
fn e2e_kids_map_skips_missing_kid() {
    let items = vec![E2eKeyItem {
        client_id: "c1".into(),
        public_key: serde_json::json!({"use": "enc"}),
    }];
    let map = build_e2e_kids_map(&items);
    assert!(map.as_object().unwrap().is_empty());
}

#[test]
fn pairing_ids_map_built_correctly() {
    use crate::http::auth::ClientInfo;

    let clients = vec![
        ClientInfo {
            client_id: "c1".into(),
            pairing_id: "p1".into(),
        },
        ClientInfo {
            client_id: "c2".into(),
            pairing_id: "p2".into(),
        },
    ];
    let map = build_pairing_ids_map(&clients);
    assert_eq!(map.get("c1").unwrap().as_str().unwrap(), "p1");
    assert_eq!(map.get("c2").unwrap().as_str().unwrap(), "p2");
}

#[test]
fn compute_expiry_returns_rfc3339() {
    let exp = compute_expiry(300);
    chrono::DateTime::parse_from_rfc3339(&exp).expect("should be valid RFC 3339");
}
