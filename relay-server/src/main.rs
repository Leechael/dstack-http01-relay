mod dns;
mod metrics;
mod target;

use axum::{
    body::Body,
    extract::{OriginalUri, Path, State},
    http::{uri::Authority, HeaderMap, Method, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use futures_util::StreamExt;
use std::{sync::Arc, time::Instant};
use tower_http::trace::TraceLayer;
use tracing::{error, info};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Clone)]
struct AppState {
    dns_resolver: Arc<dns::DnsResolver>,
    http_client: reqwest::Client,
}

#[tokio::main]
async fn main() {
    let _ = dotenvy::dotenv();
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "relay_server=info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();
    metrics::init_metrics();
    // A narrowly scoped HTTP-01 bridge, not a general transparent proxy/redirector.
    if std::env::var("RELAY_MODE").is_ok_and(|mode| mode != "proxy") {
        error!("Only RELAY_MODE=proxy is supported by the hardened challenge-only relay");
        std::process::exit(1);
    }
    let dns_resolver = Arc::new(dns::DnsResolver::new().expect("Invalid relay DNS policy"));
    let http_client = dns::http_client(dns_resolver.clone()).expect("Failed to create HTTP client");
    let state = AppState {
        dns_resolver,
        http_client,
    };
    let app = router(state);
    let port = std::env::var("PORT")
        .unwrap_or_else(|_| "8081".into())
        .parse::<u16>()
        .expect("Invalid PORT");
    let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::UNSPECIFIED, port))
        .await
        .expect("Failed to bind relay");
    info!("Challenge-only relay listening on port {}", port);
    axum::serve(listener, app)
        .await
        .expect("Relay server failed");
}

fn router(state: AppState) -> Router {
    Router::new()
        .route(
            "/.well-known/acme-challenge/:token",
            get(acme_challenge_handler),
        )
        .route(
            "/metrics",
            get(|| async {
                (
                    [("content-type", "text/plain; version=0.0.4")],
                    metrics::gather_metrics(),
                )
            }),
        )
        .route("/health", get(|| async { "OK" }))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

async fn acme_challenge_handler(
    headers: HeaderMap,
    OriginalUri(uri): OriginalUri,
    Path(token): Path<String>,
    State(state): State<AppState>,
    method: Method,
) -> Response {
    let start = Instant::now();
    let path = format!("/.well-known/acme-challenge/{token}");
    // Path extraction percent-decodes. Do not accept an encoded/noncanonical variant.
    if target::validate_path(&path).is_err() || uri.path() != path || uri.query().is_some() {
        return (StatusCode::BAD_REQUEST, "Invalid challenge path").into_response();
    }
    // Axum's Host extractor trusts Forwarded/X-Forwarded-Host. This listener may
    // be reached directly: select only one literal Host header instead.
    let mut hosts = headers.get_all("host").iter();
    let hostname = match (hosts.next().and_then(|h| h.to_str().ok()), hosts.next()) {
        (Some(hostname), None) => hostname,
        _ => return (StatusCode::BAD_REQUEST, "Invalid Host").into_response(),
    };
    let authority = match hostname.parse::<Authority>() {
        Ok(a) if !hostname.contains('@') && (a.port().is_none() || a.port_u16() == Some(80)) => a,
        _ => return (StatusCode::BAD_REQUEST, "Invalid Host").into_response(),
    };
    let domain = authority.host().to_ascii_lowercase();
    let url = match state.dns_resolver.resolve_app_url(&domain, &path).await {
        Ok(url) => {
            metrics::inc_dns_lookups("combined", "success");
            url
        }
        Err(e) => {
            metrics::inc_dns_lookups("combined", "failure");
            error!("Challenge destination rejected: {}", e);
            return (StatusCode::BAD_GATEWAY, "Invalid challenge destination").into_response();
        }
    };
    // Preserve ONLY the validated custom Host for tenant virtual hosting.
    // No caller credentials, cookies, body, forwarding headers or connection headers.
    let method_label = if method == Method::HEAD {
        "HEAD"
    } else {
        "GET"
    };
    let response = proxy_challenge(&state.http_client, url, method, &domain).await;
    metrics::inc_requests(
        method_label,
        "/.well-known/acme-challenge/*",
        response.status().as_u16(),
    );
    metrics::observe_request_duration(
        method_label,
        "/.well-known/acme-challenge/*",
        start.elapsed().as_secs_f64(),
    );
    response
}

async fn proxy_challenge(
    client: &reqwest::Client,
    url: reqwest::Url,
    method: Method,
    domain: &str,
) -> Response {
    match fetch_challenge(client, url, method, domain).await {
        Ok(response) => {
            // Retain the legacy counter name, which also counted proxy attempts.
            metrics::inc_redirects("success");
            response
        }
        Err(e) => {
            metrics::inc_redirects("failure");
            error!("Challenge proxy failed: {}", e);
            (StatusCode::BAD_GATEWAY, "Challenge upstream failed").into_response()
        }
    }
}

async fn fetch_challenge(
    client: &reqwest::Client,
    url: reqwest::Url,
    method: Method,
    domain: &str,
) -> Result<Response, String> {
    if method != Method::GET && method != Method::HEAD {
        return Err("unsupported challenge method".into());
    }
    let response = client
        .request(method, url)
        .header("host", domain)
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if response.status() != StatusCode::OK {
        // Including 3xx: never follow it and never relay Location to the ACME validator.
        return Err(format!(
            "upstream status {} is not a challenge response",
            response.status()
        ));
    }
    let mut data = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| e.to_string())?;
        if data.len() + chunk.len() > 8192 {
            return Err("challenge response too large".into());
        }
        data.extend_from_slice(&chunk);
    }
    Ok((
        StatusCode::OK,
        [
            ("content-type", "text/plain"),
            ("cache-control", "no-store"),
        ],
        Body::from(data),
    )
        .into_response())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tower::ServiceExt;

    // invariant: public entry points cannot relay arbitrary paths/methods or decoded delimiters.
    #[tokio::test]
    async fn router_rejects_non_challenge_requests_before_dns() {
        let resolver = Arc::new(dns::tests::resolver());
        let client = dns::http_client(resolver.clone()).unwrap();
        let app = router(AppState {
            dns_resolver: resolver,
            http_client: client,
        });
        let cases = [
            (
                Method::GET,
                "/logs/foo",
                "tenant.example",
                StatusCode::NOT_FOUND,
            ),
            (
                Method::POST,
                "/.well-known/acme-challenge/abcdefghijklmnopqrstuvwxyz",
                "tenant.example",
                StatusCode::METHOD_NOT_ALLOWED,
            ),
            (
                Method::GET,
                "/.well-known/acme-challenge/abcdefghijklmnopqrstuvwxyz%2Fsecret",
                "tenant.example",
                StatusCode::BAD_REQUEST,
            ),
            (
                Method::GET,
                "/.well-known/acme-challenge/abcdefghijklmnopqrstuvwxyz?url=http://localhost",
                "tenant.example",
                StatusCode::BAD_REQUEST,
            ),
            (
                Method::GET,
                "/.well-known/acme-challenge/short",
                "tenant.example",
                StatusCode::BAD_REQUEST,
            ),
            (
                Method::GET,
                "/.well-known/acme-challenge/abcdefghijklmnopqrstuvwxyz",
                "user@tenant.example",
                StatusCode::BAD_REQUEST,
            ),
            (
                Method::GET,
                "/.well-known/acme-challenge/abcdefghijklmnopqrstuvwxyz",
                "tenant.example:443",
                StatusCode::BAD_REQUEST,
            ),
        ];
        for (method, uri, host, status) in cases {
            let request = axum::http::Request::builder()
                .method(method)
                .uri(uri)
                .header("host", host)
                .body(Body::empty())
                .unwrap();
            assert_eq!(
                app.clone().oneshot(request).await.unwrap().status(),
                status,
                "{uri} {host}"
            );
        }
    }

    // regression: actual transport must not make a request to an upstream redirect target.
    #[tokio::test]
    async fn upstream_redirect_is_not_followed_or_returned() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let hits = Arc::new(AtomicUsize::new(0));
        let h = hits.clone();
        let app = Router::new()
            .route(
                "/first",
                get(|| async { (StatusCode::FOUND, [("location", "/second")], "") }),
            )
            .route(
                "/second",
                get(move || {
                    let h = h.clone();
                    async move {
                        h.fetch_add(1, Ordering::SeqCst);
                        "secret"
                    }
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        // Loopback is test-only here: isolate redirect transport behavior from destination policy.
        let client = dns::http_client_builder()
            .https_only(false)
            .build()
            .unwrap();
        let response = proxy_challenge(
            &client,
            format!("http://{address}/first").parse().unwrap(),
            Method::GET,
            "test.example",
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        assert!(!response.headers().contains_key("location"));
        assert_eq!(hits.load(Ordering::SeqCst), 0);
        server.abort();
    }
}
