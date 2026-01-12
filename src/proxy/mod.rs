use auth::Auth;
use base64::engine::general_purpose;
use base64::Engine;
use color_eyre::eyre::{eyre, Result};

pub mod auth;

use hyper::header::{HeaderValue, PROXY_AUTHENTICATE, PROXY_AUTHORIZATION};
use hyper::service::service_fn;
use tokio::net::TcpStream;
use tokio_socks::tcp::Socks5Stream;
use tracing::{debug, warn};

use std::net::SocketAddr;
use std::str;

use bytes::Bytes;
use http_body_util::{combinators::BoxBody, BodyExt, Empty, Full};

use hyper::upgrade::Upgraded;
use hyper::{Method, Request, Response};

use hyper_util::rt::TokioIo;

use hyper::client::conn::http1::Builder;
use hyper::server::conn::http1;

async fn proxy(
    req: Request<hyper::body::Incoming>,
    client_addr: SocketAddr,
    socks_addr: SocketAddr,
    auth: Option<&'static Auth>,
    allowed_domains: Option<&'static Vec<String>>,
    basic_http_header: Option<&HeaderValue>,
    forward_basic_auth: bool,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>> {
    let mut authenticated = false;
    let hm = req.headers();
    let proxy_auth_header = hm.get(PROXY_AUTHORIZATION);

    if let Some(basic_http_header) = basic_http_header {
        let Some(http_auth) = proxy_auth_header else {
            // When the request does not contain a Proxy-Authorization header,
            // send a 407 response code and a Proxy-Authenticate header
            return Ok(proxy_auth_required_response());
        };
        if http_auth == basic_http_header {
            authenticated = true;
        }
    } else {
        authenticated = true;
    }

    if !authenticated {
        warn!("Failed auth attempt from: {}", client_addr);
        // http response code reference taken from tinyproxy
        let mut resp = Response::new(full("Unauthorized"));
        *resp.status_mut() = hyper::StatusCode::UNAUTHORIZED;
        return Ok(resp);
    }

    let mut forwarded_auth = None;
    if forward_basic_auth {
        if let Some(header_value) = proxy_auth_header {
            match parse_basic_proxy_credentials(header_value) {
                Ok(auth) => forwarded_auth = Some(auth),
                Err(err) => {
                    warn!(
                        "Invalid Proxy-Authorization header from {}: {}",
                        client_addr, err
                    );
                    let mut resp = Response::new(full("Invalid Proxy-Authorization header"));
                    *resp.status_mut() = hyper::StatusCode::BAD_REQUEST;
                    return Ok(resp);
                }
            }
        } else if let None = auth {
            // No static credentials configured, so request them from the client.
            return Ok(proxy_auth_required_response());
        }
    }

    let uri = req.uri();
    let method = req.method();
    debug!("Proxying request: {} {}", method, uri);
    if let (Some(allowed_domains), Some(request_domain)) = (allowed_domains, req.uri().host()) {
        let domain = request_domain.to_owned();
        if !allowed_domains.contains(&domain) {
            warn!(
                "Access to domain {} is not allowed through the proxy.",
                domain
            );
            let mut resp = Response::new(full(
                "Access to this domain is not allowed through the proxy.",
            ));
            *resp.status_mut() = hyper::StatusCode::FORBIDDEN;
            return Ok(resp);
        }
    }

    if Method::CONNECT == req.method() {
        if let Some(addr) = host_addr(req.uri()) {
            let tunnel_auth = forwarded_auth.or_else(|| auth.cloned());
            tokio::task::spawn(async move {
                match hyper::upgrade::on(req).await {
                    Ok(upgraded) => {
                        if let Err(e) = tunnel(upgraded, addr, socks_addr, tunnel_auth).await {
                            warn!("server io error: {}", e);
                        };
                    }
                    Err(e) => warn!("upgrade error: {}", e),
                }
            });

            Ok(Response::new(empty()))
        } else {
            warn!("CONNECT host is not socket addr: {:?}", req.uri());
            let mut resp = Response::new(full("CONNECT must be to a socket address"));
            *resp.status_mut() = hyper::StatusCode::BAD_REQUEST;

            Ok(resp)
        }
    } else {
        let host = req.uri().host().expect("uri has no host");
        let port = req.uri().port_u16().unwrap_or(80);
        let addr = format!("{}:{}", host, port);

        let stream = if let Some(auth) = forwarded_auth.as_ref() {
            Socks5Stream::connect_with_password(socks_addr, addr, &auth.username, &auth.password)
                .await?
        } else if let Some(auth) = auth {
            Socks5Stream::connect_with_password(socks_addr, addr, &auth.username, &auth.password)
                .await?
        } else {
            Socks5Stream::connect(socks_addr, addr).await?
        };
        let io = TokioIo::new(stream);

        let (mut sender, conn) = Builder::new()
            .preserve_header_case(true)
            .title_case_headers(true)
            .handshake(io)
            .await?;
        tokio::task::spawn(async move {
            if let Err(err) = conn.await {
                warn!("Connection failed: {:?}", err);
            }
        });

        let resp = sender.send_request(req).await?;
        Ok(resp.map(|b| b.boxed()))
    }
}

fn host_addr(uri: &hyper::Uri) -> Option<String> {
    uri.authority().map(|auth| auth.to_string())
}

fn empty() -> BoxBody<Bytes, hyper::Error> {
    Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed()
}

fn full<T: Into<Bytes>>(chunk: T) -> BoxBody<Bytes, hyper::Error> {
    Full::new(chunk.into())
        .map_err(|never| match never {})
        .boxed()
}

fn proxy_auth_required_response() -> Response<BoxBody<Bytes, hyper::Error>> {
    let mut response = Response::new(full("Proxy Authentication Required"));
    *response.status_mut() = hyper::StatusCode::PROXY_AUTHENTICATION_REQUIRED;
    response.headers_mut().insert(
        PROXY_AUTHENTICATE,
        HeaderValue::from_static("Basic realm=\"proxy\""),
    );
    response
}

fn parse_basic_proxy_credentials(header_value: &HeaderValue) -> Result<Auth> {
    let header_str = header_value.to_str()?;
    let encoded = header_str
        .strip_prefix("Basic ")
        .ok_or_else(|| eyre!("Proxy-Authorization header must use Basic scheme"))?;
    let decoded = general_purpose::STANDARD
        .decode(encoded)
        .map_err(|e| eyre!("Failed to decode Basic credentials: {}", e))?;
    let decoded_str = str::from_utf8(&decoded)?;
    let (username, password) = decoded_str
        .split_once(':')
        .ok_or_else(|| eyre!("Basic credentials must follow the user:password format"))?;
    Ok(Auth::new(username.to_string(), password.to_string()))
}

async fn tunnel(
    upgraded: Upgraded,
    addr: String,
    socks_addr: SocketAddr,
    auth: Option<Auth>,
) -> Result<()> {
    let mut stream = match auth {
        Some(auth) => {
            Socks5Stream::connect_with_password(socks_addr, addr, &auth.username, &auth.password)
                .await?
        }
        None => Socks5Stream::connect(socks_addr, addr).await?,
    };

    let mut upgraded = TokioIo::new(upgraded);

    // Proxying data
    let (from_client, from_server) =
        tokio::io::copy_bidirectional(&mut upgraded, &mut stream).await?;

    // Print message when done
    debug!(
        "client wrote {} bytes and received {} bytes",
        from_client, from_server
    );
    Ok(())
}

pub async fn proxy_request(
    stream: TcpStream,
    client_addr: SocketAddr,
    socks_addr: SocketAddr,
    auth_details: Option<&'static Auth>,
    allowed_domains: Option<&'static Vec<String>>,
    basic_http_header: Option<&'static HeaderValue>,
    forward_basic_auth: bool,
) -> color_eyre::Result<()> {
    let io = TokioIo::new(stream);

    let serve_connection = service_fn(move |req| {
        proxy(
            req,
            client_addr,
            socks_addr,
            auth_details,
            allowed_domains,
            basic_http_header,
            forward_basic_auth,
        )
    });

    tokio::task::spawn(async move {
        if let Err(err) = http1::Builder::new()
            .preserve_header_case(true)
            .title_case_headers(true)
            .serve_connection(io, serve_connection)
            .with_upgrades()
            .await
        {
            warn!("Failed to serve connection: {:?}", err);
        }
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_basic_proxy_credentials() {
        let header = HeaderValue::from_static("Basic dXNlcjpwYXNz");
        let auth = parse_basic_proxy_credentials(&header).expect("failed to parse credentials");
        assert_eq!(auth.username, "user");
        assert_eq!(auth.password, "pass");
    }

    #[test]
    fn rejects_non_basic_scheme() {
        let header = HeaderValue::from_static("Digest abc");
        assert!(parse_basic_proxy_credentials(&header).is_err());
    }
}
