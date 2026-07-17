//! The relay itself: a non-blocking pass-through proxy.
//!
//! Each accepted connection is served as HTTP/1. A plain request (absolute-form,
//! sent by a client configured with an HTTP proxy) is forwarded straight to its
//! destination. A `CONNECT` is answered `200`, the tunnel is TLS-terminated with a
//! per-host leaf certificate from the [`CertAuthority`], and the decrypted requests
//! are forwarded the same way — so HTTPS content is observable.
//!
//! The destination's response is returned to the client **without waiting on
//! capture**: a clone of the exchange is handed to the async [`CaptureSink`]
//! (which never blocks), and neither request nor response is altered in flight
//! (beyond the connection-level hop-by-hop headers no proxy forwards).

use std::convert::Infallible;
use std::sync::Arc;
use std::time::Instant;

use bytes::Bytes;
use chrono::Utc;
use http::header::{self, HeaderMap, HeaderName};
use http::{Method, Request, Response, StatusCode, Uri};
use http_body_util::{BodyExt, Empty, Full, combinators::BoxBody};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::upgrade::Upgraded;
use hyper_util::rt::TokioIo;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;

use crate::ca::CertAuthority;
use crate::error::{Error, Result};
use crate::store::{CaptureSink, CapturedExchange};

/// The response body type the service produces (boxed so the plain, tunnel-error,
/// and forwarded paths share one type). Bodies are fully buffered, never streamed.
type ProxyBody = BoxBody<Bytes, Infallible>;

/// The relay. Holds the CA (for TLS termination), the outbound HTTP client, the
/// capture sink, and the body-capture size limit. Cheap to wrap in an `Arc` and
/// share across connections.
pub struct ProxyServer {
    ca: Arc<CertAuthority>,
    client: reqwest::Client,
    sink: CaptureSink,
    body_limit: usize,
}

impl ProxyServer {
    /// Build the relay. `body_limit` is the maximum number of bytes of each body
    /// retained by capture (`0` means no limit); `insecure_upstream` disables TLS
    /// verification on the outbound leg (useful against targets with broken certs,
    /// and required by the self-signed destinations in tests).
    pub fn new(
        ca: Arc<CertAuthority>,
        sink: CaptureSink,
        body_limit: usize,
        insecure_upstream: bool,
    ) -> Result<Self> {
        let client = reqwest::Client::builder()
            // Do not follow redirects — the client must observe them unmodified.
            .redirect(reqwest::redirect::Policy::none())
            // Never chain through an env-configured proxy of our own.
            .no_proxy()
            .danger_accept_invalid_certs(insecure_upstream)
            .build()
            .map_err(|e| Error::Upstream(e.to_string()))?;
        Ok(Self {
            ca,
            client,
            sink,
            body_limit,
        })
    }

    /// Accept connections on `listener` forever, serving each concurrently. Returns
    /// only on an accept error.
    pub async fn serve(self: Arc<Self>, listener: TcpListener) -> Result<()> {
        loop {
            let (stream, _peer) = listener.accept().await?;
            let me = self.clone();
            tokio::spawn(async move { me.serve_conn(stream).await });
        }
    }

    /// Serve one accepted TCP connection as HTTP/1, with CONNECT upgrades enabled.
    async fn serve_conn(self: Arc<Self>, stream: TcpStream) {
        let io = TokioIo::new(stream);
        let me = self.clone();
        let service = service_fn(move |req| {
            let me = me.clone();
            async move { me.handle(req).await }
        });
        if let Err(e) = http1::Builder::new()
            .serve_connection(io, service)
            .with_upgrades()
            .await
        {
            tracing::debug!(error = %e, "proxy connection ended with error");
        }
    }

    /// Route one request: `CONNECT` opens a TLS-terminated tunnel; anything else is
    /// forwarded directly. Never returns `Err` — failures become status responses.
    async fn handle(
        self: Arc<Self>,
        req: Request<Incoming>,
    ) -> std::result::Result<Response<ProxyBody>, Infallible> {
        if req.method() == Method::CONNECT {
            Ok(self.handle_connect(req))
        } else {
            let url = match absolute_http_url(&req) {
                Some(url) => url,
                None => {
                    return Ok(text_response(
                        StatusCode::BAD_REQUEST,
                        "expected an absolute-form request URI or a Host header",
                    ));
                }
            };
            Ok(self.forward(req, url).await)
        }
    }

    /// Answer a `CONNECT` with `200` and spawn the MITM tunnel. The tunnel runs off
    /// this response so the `200` reaches the client, which then begins its TLS
    /// handshake against the per-host leaf certificate.
    fn handle_connect(self: Arc<Self>, req: Request<Incoming>) -> Response<ProxyBody> {
        let Some(authority) = req.uri().authority().cloned() else {
            return text_response(StatusCode::BAD_REQUEST, "CONNECT requires an authority");
        };
        let host = authority.host().to_string();
        let me = self.clone();
        tokio::spawn(async move {
            match hyper::upgrade::on(req).await {
                Ok(upgraded) => {
                    if let Err(e) = me.tunnel(upgraded, host, authority.to_string()).await {
                        tracing::debug!(error = %e, "MITM tunnel ended with error");
                    }
                }
                Err(e) => tracing::debug!(error = %e, "CONNECT upgrade failed"),
            }
        });
        Response::new(empty_body())
    }

    /// TLS-terminate an upgraded CONNECT tunnel and serve the decrypted HTTP/1
    /// requests, forwarding each to `https://{authority}{path}`.
    async fn tunnel(
        self: Arc<Self>,
        upgraded: Upgraded,
        host: String,
        authority: String,
    ) -> Result<()> {
        let server_config = self.ca.server_config_for(&host)?;
        let acceptor = TlsAcceptor::from(server_config);
        let tls_stream = acceptor.accept(TokioIo::new(upgraded)).await?;

        let authority = Arc::new(authority);
        let me = self.clone();
        let service = service_fn(move |req: Request<Incoming>| {
            let me = me.clone();
            let authority = authority.clone();
            async move {
                let url = https_url(&authority, req.uri());
                Ok::<_, Infallible>(me.forward(req, url).await)
            }
        });

        http1::Builder::new()
            .serve_connection(TokioIo::new(tls_stream), service)
            .await
            .map_err(|e| Error::Upstream(e.to_string()))
    }

    /// Forward one request to `url`, return the destination's response unmodified,
    /// and hand a captured copy to the async writer. The response is returned as
    /// soon as it is read from the destination — capture does not gate it.
    async fn forward(self: Arc<Self>, req: Request<Incoming>, url: String) -> Response<ProxyBody> {
        let uri: Uri = match url.parse() {
            Ok(uri) => uri,
            Err(_) => return text_response(StatusCode::BAD_REQUEST, "invalid target URL"),
        };
        let method = req.method().clone();
        let (parts, body) = req.into_parts();

        let req_bytes = match body.collect().await {
            Ok(collected) => collected.to_bytes(),
            Err(e) => {
                tracing::debug!(error = %e, "failed reading request body");
                return text_response(StatusCode::BAD_REQUEST, "failed reading request body");
            }
        };

        let started_at = Utc::now();
        let t0 = Instant::now();
        let sent = self
            .client
            .request(method.clone(), url.clone())
            .headers(forwardable_request_headers(&parts.headers))
            .body(req_bytes.clone())
            .send()
            .await;
        let resp = match sent {
            Ok(resp) => resp,
            Err(e) => {
                tracing::debug!(error = %e, url = %url, "upstream request failed");
                return text_response(StatusCode::BAD_GATEWAY, "upstream request failed");
            }
        };

        let status = resp.status();
        let resp_headers = resp.headers().clone();
        let resp_bytes = match resp.bytes().await {
            Ok(bytes) => bytes,
            Err(e) => {
                tracing::debug!(error = %e, "failed reading upstream response");
                return text_response(StatusCode::BAD_GATEWAY, "failed reading upstream response");
            }
        };
        let duration_ms = i64::try_from(t0.elapsed().as_millis()).unwrap_or(i64::MAX);

        // Hand a capped copy to the async writer — this never blocks.
        let query = uri.query().map(str::to_string);
        let (req_body, req_truncated) = cap(&req_bytes, self.body_limit);
        let (resp_body, resp_truncated) = cap(&resp_bytes, self.body_limit);
        self.sink.capture(CapturedExchange {
            method: method.to_string(),
            url: url.clone(),
            host: uri.host().unwrap_or_default().to_string(),
            endpoint: uri.path().to_string(),
            params: param_names(query.as_deref()),
            query,
            req_headers: header_pairs(&parts.headers),
            req_body,
            req_body_truncated: req_truncated,
            status: status.as_u16(),
            resp_headers: header_pairs(&resp_headers),
            resp_body,
            resp_body_truncated: resp_truncated,
            started_at,
            duration_ms,
        });

        build_client_response(status, &resp_headers, resp_bytes)
    }
}

/// Resolve the absolute target URL for a non-CONNECT request: use the absolute-form
/// request URI if present, else reconstruct `http://{Host}{path}` from the Host
/// header. Returns `None` if neither is available.
fn absolute_http_url(req: &Request<Incoming>) -> Option<String> {
    if req.uri().authority().is_some() {
        return Some(req.uri().to_string());
    }
    let host = req.headers().get(header::HOST)?.to_str().ok()?;
    let path = req
        .uri()
        .path_and_query()
        .map(|p| p.as_str())
        .unwrap_or("/");
    Some(format!("http://{host}{path}"))
}

/// The HTTPS URL for a decrypted tunnel request: the CONNECT authority (host:port)
/// plus the request's path and query.
fn https_url(authority: &str, uri: &Uri) -> String {
    let path = uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");
    format!("https://{authority}{path}")
}

/// Copy the end-to-end request headers to forward upstream, dropping the
/// connection-level hop-by-hop headers plus `Host`/`Content-Length` (the client
/// sets those from the target URL and body).
fn forwardable_request_headers(headers: &HeaderMap) -> HeaderMap {
    let mut out = HeaderMap::new();
    for (name, value) in headers.iter() {
        if is_hop_by_hop(name) || name.as_str() == "host" || name.as_str() == "content-length" {
            continue;
        }
        out.append(name.clone(), value.clone());
    }
    out
}

/// Build the response returned to the client: the destination's status and body,
/// verbatim, with only hop-by-hop and length/framing headers dropped (hyper
/// re-derives `Content-Length` from the buffered body).
fn build_client_response(
    status: StatusCode,
    headers: &HeaderMap,
    body: Bytes,
) -> Response<ProxyBody> {
    let mut builder = Response::builder().status(status);
    for (name, value) in headers.iter() {
        if is_hop_by_hop(name) || name.as_str() == "content-length" {
            continue;
        }
        builder = builder.header(name, value);
    }
    builder
        .body(full_body(body))
        .unwrap_or_else(|_| Response::new(empty_body()))
}

/// Connection-level headers a conforming proxy never forwards end-to-end. Removing
/// these is correct proxy behaviour, not "altering" the request/response.
fn is_hop_by_hop(name: &HeaderName) -> bool {
    matches!(
        name.as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "proxy-connection"
            | "te"
            | "trailer"
            | "trailers"
            | "transfer-encoding"
            | "upgrade"
    )
}

/// Header name/value pairs, in wire order, for capture (values are lossily decoded).
fn header_pairs(headers: &HeaderMap) -> Vec<(String, String)> {
    headers
        .iter()
        .map(|(name, value)| {
            (
                name.as_str().to_string(),
                String::from_utf8_lossy(value.as_bytes()).into_owned(),
            )
        })
        .collect()
}

/// The distinct query-parameter names in `query`, in first-seen order.
fn param_names(query: Option<&str>) -> Vec<String> {
    let Some(query) = query else {
        return Vec::new();
    };
    let mut names = Vec::new();
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let name = pair.split('=').next().unwrap_or(pair).to_string();
        if !name.is_empty() && !names.contains(&name) {
            names.push(name);
        }
    }
    names
}

/// Truncate `bytes` to `limit` for capture, reporting whether truncation happened.
/// A `limit` of `0` means "keep everything".
fn cap(bytes: &Bytes, limit: usize) -> (Vec<u8>, bool) {
    if limit == 0 || bytes.len() <= limit {
        (bytes.to_vec(), false)
    } else {
        (bytes[..limit].to_vec(), true)
    }
}

/// An empty boxed body (for the CONNECT `200` and error fallbacks).
fn empty_body() -> ProxyBody {
    Empty::<Bytes>::new().boxed()
}

/// A fully-buffered boxed body.
fn full_body(bytes: Bytes) -> ProxyBody {
    Full::new(bytes).boxed()
}

/// A small `text/plain` status response (proxy-generated errors like `502`).
fn text_response(status: StatusCode, message: &str) -> Response<ProxyBody> {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(full_body(Bytes::from(message.to_string())))
        .unwrap_or_else(|_| Response::new(empty_body()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn param_names_are_distinct_and_ordered() {
        assert_eq!(
            param_names(Some("id=1&sort=asc&id=2&flag")),
            vec!["id".to_string(), "sort".to_string(), "flag".to_string()]
        );
        assert!(param_names(None).is_empty());
        assert!(param_names(Some("")).is_empty());
    }

    #[test]
    fn cap_truncates_only_past_the_limit() {
        assert_eq!(
            cap(&Bytes::from_static(b"abc"), 5),
            (b"abc".to_vec(), false)
        );
        assert_eq!(
            cap(&Bytes::from_static(b"abcdef"), 3),
            (b"abc".to_vec(), true)
        );
        // Zero means keep everything.
        assert_eq!(
            cap(&Bytes::from_static(b"abcdef"), 0),
            (b"abcdef".to_vec(), false)
        );
    }

    #[test]
    fn hop_by_hop_headers_are_recognised() {
        assert!(is_hop_by_hop(&header::CONNECTION));
        assert!(is_hop_by_hop(&HeaderName::from_static("transfer-encoding")));
        assert!(!is_hop_by_hop(&header::CONTENT_TYPE));
        assert!(!is_hop_by_hop(&header::AUTHORIZATION));
    }
}
