use axum::{
    extract::Request,
    http::header::{self, HeaderName, HeaderValue},
    middleware::Next,
    response::Response,
};

pub(crate) async fn security_headers_middleware(req: Request, next: Next) -> Response {
    let mut response = next.run(req).await;

    response.headers_mut().insert(
        HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));

    response
}
