//! Agent observability endpoint (M14.2, ADR-0016).
//!
//! Serves the Agent's [`TunnelMetrics`] over HTTP in the Prometheus text
//! exposition format so a scraper (compose target) can read `/metrics`. The
//! metrics themselves are populated on the data path (M14.1b); this module only
//! exposes the already-shared `Arc<TunnelMetrics>`.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::State;
use axum::http::header::CONTENT_TYPE;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;

use ct_common::metrics::TunnelMetrics;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Build the metrics router: `GET /metrics` renders the current counters.
pub fn metrics_router(metrics: Arc<TunnelMetrics>) -> Router {
    Router::new()
        .route("/metrics", get(render))
        .with_state(metrics)
}

/// Render the counters in the Prometheus text exposition format, with the
/// content type Prometheus expects (`text/plain; version=0.0.4`).
async fn render(State(metrics): State<Arc<TunnelMetrics>>) -> impl IntoResponse {
    (
        [(CONTENT_TYPE, "text/plain; version=0.0.4")],
        metrics.render_prometheus(),
    )
}

/// Bind `listen` and serve the metrics endpoint until the process exits.
pub async fn serve_metrics(listen: SocketAddr, metrics: Arc<TunnelMetrics>) -> Result<(), BoxError> {
    let listener = tokio::net::TcpListener::bind(listen).await?;
    serve_metrics_on(listener, metrics).await
}

/// Serve the metrics scrape on an ALREADY-bound listener. Lets a caller (e.g. a test) bind the port
/// itself and keep the binding, avoiding the bind-`:0` → drop → re-bind TOCTOU race that made the
/// scrape test flaky under parallel load.
pub async fn serve_metrics_on(
    listener: tokio::net::TcpListener,
    metrics: Arc<TunnelMetrics>,
) -> Result<(), BoxError> {
    axum::serve(listener, metrics_router(metrics)).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    #[tokio::test]
    async fn metrics_endpoint_renders_current_counters() {
        let metrics = Arc::new(TunnelMetrics::new());
        metrics.tunnels_opened.inc();
        metrics.bytes_to_origin.add(2048);
        metrics.observe_handshake(std::time::Duration::from_millis(9));

        let app = metrics_router(Arc::clone(&metrics));
        let resp = app
            .oneshot(Request::get("/metrics").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let ct = resp
            .headers()
            .get(CONTENT_TYPE)
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        assert!(ct.starts_with("text/plain"), "Prometheus content type, got {ct}");

        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let text = String::from_utf8(body.to_vec()).unwrap();
        assert!(text.contains("# TYPE ct_tunnels_opened_total counter"), "exposition header present");
        assert!(text.contains("\nct_tunnels_opened_total 1\n"), "counter value exposed");
        assert!(text.contains("\nct_bytes_to_origin_total 2048\n"));
        assert!(text.contains("\nct_handshake_millis_total 9\n"));
    }

    #[tokio::test]
    async fn serve_metrics_is_scrapable_over_a_real_socket() {
        // Bind on an ephemeral port and scrape it over TCP with a raw HTTP/1.0
        // request — proves the endpoint serves off a real listener (no reqwest
        // dependency needed for a bare GET).
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let metrics = Arc::new(TunnelMetrics::new());
        metrics.tunnels_opened.add(3);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = metrics_router(Arc::clone(&metrics));
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let mut sock = tokio::net::TcpStream::connect(addr).await.unwrap();
        sock.write_all(b"GET /metrics HTTP/1.0\r\nHost: x\r\n\r\n").await.unwrap();
        let mut resp = String::new();
        sock.read_to_string(&mut resp).await.unwrap();

        assert!(resp.starts_with("HTTP/1.0 200") || resp.starts_with("HTTP/1.1 200"), "200 OK: {resp:.40}");
        assert!(resp.contains("ct_tunnels_opened_total 3"), "scraped counter value");
    }

    #[tokio::test]
    async fn serve_metrics_binds_its_own_listener_and_serves() {
        // Exercises serve_metrics() itself (the bind + serve wrapper), not just
        // metrics_router: reserve an ephemeral port, hand it to serve_metrics,
        // scrape once, then stop the (otherwise endless) server.
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let metrics = Arc::new(TunnelMetrics::new());
        metrics.tunnels_opened.add(5);
        // Bind the listener ONCE and hand it to serve_metrics_on — no drop-then-rebind, so there's no
        // TOCTOU window for another process to grab the port (the source of this test's flakiness).
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let m = Arc::clone(&metrics);
        let server = tokio::spawn(async move { serve_metrics_on(listener, m).await });

        // serve_metrics binds asynchronously; retry briefly until it answers.
        let mut resp = String::new();
        for _ in 0..50 {
            if let Ok(mut sock) = tokio::net::TcpStream::connect(addr).await {
                sock.write_all(b"GET /metrics HTTP/1.0\r\nHost: x\r\n\r\n")
                    .await
                    .unwrap();
                let _ = sock.read_to_string(&mut resp).await;
                if !resp.is_empty() {
                    break;
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        server.abort();
        assert!(
            resp.contains("ct_tunnels_opened_total 5"),
            "serve_metrics served the scrape: {resp:.60}"
        );
    }
}
