use super::*;
use crate::http::fcm::oauth2::ServiceAccountKey;

#[test]
fn send_url_format() {
    let sa = ServiceAccountKey {
        client_email: "x@y.iam.gserviceaccount.com".to_owned(),
        private_key: String::new(),
        token_uri: None,
    };
    let client = FcmClient::new("my-project".to_owned(), sa).unwrap();
    assert_eq!(
        client.send_url(),
        "https://fcm.googleapis.com/v1/projects/my-project/messages:send"
    );
}

#[test]
fn with_urls_overrides() {
    let sa = ServiceAccountKey {
        client_email: "x@y.iam.gserviceaccount.com".to_owned(),
        private_key: String::new(),
        token_uri: None,
    };
    let client = FcmClient::new("proj".to_owned(), sa).unwrap().with_urls(
        "http://localhost:9999".to_owned(),
        "http://localhost:9999/token".to_owned(),
    );
    assert_eq!(
        client.send_url(),
        "http://localhost:9999/v1/projects/proj/messages:send"
    );
}
