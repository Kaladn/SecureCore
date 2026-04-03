use axum::{
    body::{Body, Bytes},
    extract::{OriginalUri, Path, State},
    http::{HeaderMap, Method, Response, StatusCode},
    response::{Html, IntoResponse},
    routing::{any, get},
    Router,
};
use reqwest::Client;
use std::{env, net::SocketAddr};
use tower_http::services::ServeDir;

#[derive(Clone)]
struct AppState {
    client: Client,
    backend_base: String,
}

#[tokio::main]
async fn main() {
    let frontend_host = env::var("FRONTDOOR_HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
    let frontend_port = env::var("FRONTDOOR_PORT")
        .ok()
        .and_then(|value| value.parse::<u16>().ok())
        .unwrap_or(5050);
    let backend_base =
        env::var("SECURECORE_BACKEND").unwrap_or_else(|_| "http://127.0.0.1:5057".to_string());

    let state = AppState {
        client: Client::new(),
        backend_base,
    };

    let app = Router::new()
        .route("/", get(index))
        .route("/healthz", get(healthz))
        .route("/api/*path", any(proxy_api))
        .nest_service("/assets", ServeDir::new("static"))
        .with_state(state);

    let bind = format!("{frontend_host}:{frontend_port}");
    let address: SocketAddr = bind
        .parse()
        .unwrap_or_else(|_| SocketAddr::from(([127, 0, 0, 1], frontend_port)));
    let listener = tokio::net::TcpListener::bind(address)
        .await
        .expect("frontdoor bind failed");

    println!(
        "SecureCore front door listening on http://{} -> {}",
        listener.local_addr().unwrap(),
        env::var("SECURECORE_BACKEND").unwrap_or_else(|_| "http://127.0.0.1:5057".to_string())
    );

    axum::serve(listener, app)
        .await
        .expect("frontdoor server failed");
}

async fn index() -> Html<&'static str> {
    Html(include_str!("../static/index.html"))
}

async fn healthz() -> &'static str {
    "ok"
}

async fn proxy_api(
    State(state): State<AppState>,
    Path(path): Path<String>,
    method: Method,
    headers: HeaderMap,
    OriginalUri(uri): OriginalUri,
    body: Bytes,
) -> impl IntoResponse {
    let query = uri.query().map(|value| format!("?{value}")).unwrap_or_default();
    let target = format!(
        "{}/api/{}{}",
        state.backend_base.trim_end_matches('/'),
        path,
        query
    );

    let reqwest_method =
        reqwest::Method::from_bytes(method.as_str().as_bytes()).unwrap_or(reqwest::Method::GET);
    let mut builder = state.client.request(reqwest_method, target).body(body.to_vec());

    for (name, value) in headers.iter() {
        if name.as_str().eq_ignore_ascii_case("host")
            || name.as_str().eq_ignore_ascii_case("content-length")
        {
            continue;
        }
        builder = builder.header(name, value);
    }

    let upstream = match builder.send().await {
        Ok(response) => response,
        Err(error) => {
            return (
                StatusCode::BAD_GATEWAY,
                format!("SecureCore backend unavailable: {error}"),
            )
                .into_response();
        }
    };

    let status =
        StatusCode::from_u16(upstream.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    let content_type = upstream.headers().get(reqwest::header::CONTENT_TYPE).cloned();
    let payload = match upstream.bytes().await {
        Ok(bytes) => bytes,
        Err(error) => {
            return (
                StatusCode::BAD_GATEWAY,
                format!("SecureCore backend returned an unreadable response: {error}"),
            )
                .into_response();
        }
    };

    let mut response = Response::builder().status(status);
    if let Some(content_type) = content_type {
        response = response.header(axum::http::header::CONTENT_TYPE, content_type);
    }
    response
        .body(Body::from(payload))
        .unwrap_or_else(|_| Response::new(Body::from("frontdoor response build failed")))
}
