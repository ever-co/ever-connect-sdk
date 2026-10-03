//! The one place the Rust client hands a request to `reqwest`. It holds no path of its own: the
//! client passes a path from the generated operation table, and the guard joins it to the base URL.
//!
//! * The base URL is `https://`, or `http://` on a local host only (`insecure_base_url`).
//! * A URL outside the base URL's origin and path prefix is refused before any I/O
//!   (`absolute_url`).
//! * Redirects are never followed (a 3xx answer is refused with `redirect`, no second request), no
//!   cookie store exists, and every request has a deadline.

use std::time::Duration;

use super::error::Error;

/// A checked base URL: its origin and its path prefix (without a trailing slash).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Base {
    pub(crate) origin: String,
    pub(crate) prefix: String,
    pub(crate) local: bool,
}

fn ipv4(host: &str) -> Option<u32> {
    let mut n: u32 = 0;
    let mut parts = 0;
    for p in host.split('.') {
        if p.is_empty()
            || p.len() > 3
            || !p.bytes().all(|b| b.is_ascii_digit())
            || (p.len() > 1 && p.starts_with('0'))
        {
            return None;
        }
        let v: u32 = p.parse().ok()?;
        if v > 255 {
            return None;
        }
        n = n.checked_mul(256)?.checked_add(v)?;
        parts += 1;
    }
    (parts == 4).then_some(n)
}

/// Whether `host` (lower case, IPv6 without brackets) is a local host (the constants'
/// `root_keys_file_hosts`).
pub(crate) fn is_local_host(host: &str) -> bool {
    let host = host
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_ascii_lowercase();
    let list = ever_connect_contracts::constants()
        .get("root_keys_file_hosts")
        .and_then(serde_json::Value::as_array)
        .map(|v| {
            v.iter()
                .filter_map(serde_json::Value::as_str)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let address = ipv4(&host);
    list.iter().any(|entry| {
        if let Some(suffix) = entry.strip_prefix('*') {
            host.ends_with(suffix) && host.len() > suffix.len()
        } else if let Some((base, bits)) = entry.split_once('/') {
            match (address, ipv4(base), bits.parse::<u32>()) {
                (Some(a), Some(b), Ok(bits)) if bits <= 32 => {
                    let size = 1_u64 << (32 - bits);
                    u64::from(a) >= u64::from(b) && u64::from(a) < u64::from(b) + size
                }
                _ => false,
            }
        } else {
            host == *entry
        }
    })
}

/// Checks a base URL: http(s), no credentials, query or fragment; `http://` on a local host only.
pub(crate) fn check_base_url(base_url: &str) -> Result<Base, Error> {
    let url = reqwest::Url::parse(base_url)
        .map_err(|_| Error::InvalidOptions("base_url is not a URL"))?;
    if url.scheme() != "https" && url.scheme() != "http" {
        return Err(Error::InvalidOptions("base_url is http or https"));
    }
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(Error::InvalidOptions(
            "base_url has no credentials, query or fragment",
        ));
    }
    let host = url
        .host_str()
        .ok_or(Error::InvalidOptions("base_url has no host"))?;
    let local = is_local_host(host);
    if url.scheme() == "http" && !local {
        return Err(Error::EgressRefused {
            code: "insecure_base_url",
        });
    }
    Ok(Base {
        origin: url.origin().ascii_serialization(),
        prefix: url.path().trim_end_matches('/').to_owned(),
        local,
    })
}

/// The URL of `path` under the base; refuses anything that would leave its origin or prefix.
pub(crate) fn url_for(
    base: &Base,
    path: &str,
    query: &[(String, String)],
) -> Result<reqwest::Url, Error> {
    let refused = Error::EgressRefused {
        code: "absolute_url",
    };
    if !path.starts_with('/') || path.starts_with("//") || path.contains('\\') {
        return Err(refused);
    }
    let text = format!("{}{}{path}", base.origin, base.prefix);
    let mut url = reqwest::Url::parse(&text).map_err(|_| refused.clone())?;
    if url.origin().ascii_serialization() != base.origin
        || url.path() != format!("{}{path}", base.prefix)
    {
        return Err(refused);
    }
    if !query.is_empty() {
        url.query_pairs_mut()
            .extend_pairs(query.iter().map(|(k, v)| (k.as_str(), v.as_str())));
    }
    Ok(url)
}

/// An answer, read in full.
pub(crate) struct WireResponse {
    pub(crate) status: u16,
    pub(crate) headers: reqwest::header::HeaderMap,
    pub(crate) body: Vec<u8>,
}

/// The HTTP client type.
pub(crate) type Http = reqwest::Client;

/// The HTTP client: no redirect is followed, no cookie is kept.
pub(crate) fn http_client(user_agent: &str) -> Result<reqwest::Client, Error> {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .user_agent(user_agent)
        .https_only(false)
        .build()
        .map_err(|_| Error::InvalidOptions("the HTTP client cannot be built"))
}

/// Sends one request.
pub(crate) async fn send(
    http: &reqwest::Client,
    method: &str,
    url: reqwest::Url,
    headers: Vec<(String, String)>,
    body: Option<Vec<u8>>,
    timeout: Duration,
) -> Result<WireResponse, Error> {
    let method = reqwest::Method::from_bytes(method.as_bytes())
        .map_err(|_| Error::InvalidOptions("method"))?;
    let mut request = http.request(method, url).timeout(timeout);
    for (name, value) in headers {
        request = request.header(name, value);
    }
    if let Some(body) = body {
        request = request.body(body);
    }
    let timeout_ms = u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX);
    let failed = |e: reqwest::Error| {
        if e.is_timeout() {
            Error::Timeout { timeout_ms }
        } else if e.is_connect() {
            Error::Transport("no connection".into())
        } else {
            Error::Transport("the exchange failed".into())
        }
    };
    let response = request.send().await.map_err(failed)?;
    let status = response.status().as_u16();
    if (300..400).contains(&status) && status != 304 {
        return Err(Error::EgressRefused { code: "redirect" });
    }
    let headers = response.headers().clone();
    let body = response.bytes().await.map_err(failed)?.to_vec();
    Ok(WireResponse {
        status,
        headers,
        body,
    })
}
