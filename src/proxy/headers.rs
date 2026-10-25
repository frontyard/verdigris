//! Header policy for forwarded requests and their responses: hop-by-hop
//! stripping, `Forwarded`/`X-Forwarded-*` fields, and upgrade detection.

use std::net::IpAddr;

use http::header::{
    CONNECTION, FORWARDED, HOST, PROXY_AUTHENTICATE, PROXY_AUTHORIZATION, TE, TRAILER,
    TRANSFER_ENCODING, UPGRADE,
};
use http::{HeaderMap, HeaderName, HeaderValue};

/// `X-Forwarded-*` header names (not exported by the `http` crate).
const XFF: HeaderName = HeaderName::from_static("x-forwarded-for");
const XFP: HeaderName = HeaderName::from_static("x-forwarded-proto");
const XFH: HeaderName = HeaderName::from_static("x-forwarded-host");
const XRI: HeaderName = HeaderName::from_static("x-real-ip");

/// Whether the request asks for a protocol upgrade (e.g. WebSocket):
/// `Connection: upgrade` + an `Upgrade` token.
pub fn wants_upgrade(headers: &HeaderMap) -> bool {
    headers.contains_key(UPGRADE) && connection_tokens(headers).any(|t| t == UPGRADE)
}

/// Iterate over header names listed in `Connection` values.
fn connection_tokens(headers: &HeaderMap) -> impl Iterator<Item = HeaderName> + '_ {
    headers
        .get_all(CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .filter_map(|t| HeaderName::from_bytes(t.trim().as_bytes()).ok())
}

/// Remove hop-by-hop headers per RFC 9110 §7.6.1: the fixed set plus every
/// name the `Connection` header advertises. When `upgrading` is true the
/// upgrade machinery itself (`connection`, `upgrade`) is preserved — it is
/// what the client and upstream are negotiating over.
pub fn strip_hop_by_hop(headers: &mut HeaderMap, upgrading: bool) {
    let tokens: Vec<HeaderName> = connection_tokens(headers).collect();
    for name in tokens {
        if upgrading && name == UPGRADE {
            continue;
        }
        headers.remove(&name);
    }
    for name in [
        PROXY_AUTHENTICATE,
        PROXY_AUTHORIZATION,
        TE,
        TRAILER,
        TRANSFER_ENCODING,
        // RFC 9110 fixed hop-by-hop names the `http` crate has no
        // constants for
        HeaderName::from_static("keep-alive"),
        // non-standard but widely sent; hop-by-hop all the same
        HeaderName::from_static("proxy-connection"),
    ] {
        headers.remove(name);
    }
    if !upgrading {
        headers.remove(CONNECTION);
        headers.remove(UPGRADE);
    }
}

/// Re-add `te: trailers` for h2 upstreams — required by gRPC backends.
pub fn preserve_te_trailers(outbound: &mut HeaderMap, inbound: &HeaderMap, h2: bool) {
    if !h2 {
        return;
    }
    for v in inbound.get_all(TE) {
        if v.to_str().is_ok_and(|s| s.eq_ignore_ascii_case("trailers")) {
            outbound.insert(TE, v.clone());
        }
    }
}

/// Concatenate all values of a comma-list header (`X-Forwarded-For`,
/// `Forwarded`) — a proxy chain may send several headers, and only
/// reading the first silently drops hops.
fn joined(headers: &HeaderMap, name: &HeaderName) -> Option<String> {
    let mut it = headers.get_all(name).iter().filter_map(|v| v.to_str().ok());
    let first = it.next()?;
    Some(it.fold(first.to_string(), |a, v| format!("{a}, {v}")))
}

/// Whether `host` is safe to forward verbatim in a list-ish header:
/// printable ASCII, no field separators or quoting chars.
fn host_clean(host: &str) -> bool {
    !host.is_empty()
        && host
            .chars()
            .all(|c| c.is_ascii_graphic() && !matches!(c, ',' | ';' | '"'))
}

/// RFC 7239 `host=` value: bare when the host is a clean token (the `:`
/// keeps `host:port` readable), otherwise a quoted-string with `"` and
/// `\` escaped — a client-controlled Host can otherwise smuggle extra
/// forwarded-pairs (`host=evil";for="spoof`).
fn rfc7239_value(host: &str) -> String {
    fn token_char(c: char) -> bool {
        c.is_ascii_alphanumeric()
            || matches!(
                c,
                '!' | '#'
                    | '$'
                    | '%'
                    | '&'
                    | '\''
                    | '*'
                    | '+'
                    | '-'
                    | '.'
                    | '^'
                    | '_'
                    | '`'
                    | '|'
                    | '~'
                    | ':'
            )
    }
    if host_clean(host) && host.chars().all(token_char) {
        host.to_string()
    } else {
        let escaped: String = host
            .chars()
            .flat_map(|c| match c {
                '"' | '\\' => vec!['\\', c],
                c if c.is_ascii_graphic() || c == ' ' => vec![c],
                _ => vec![],
            })
            .collect();
        format!("\"{escaped}\"")
    }
}

/// Set the `Forwarded` and `X-Forwarded-*` fields. Incoming values are only
/// honoured when the direct peer is a trusted proxy — otherwise the client
/// could spoof its apparent address.
pub fn set_forwarded(
    headers: &mut HeaderMap,
    peer_ip: IpAddr,
    peer_trusted: bool,
    client_ip: IpAddr,
    scheme: &str,
    host: &str,
) {
    // X-Forwarded-For: append the direct peer when the chain is trusted,
    // replace entirely when it is not.
    let xff = if peer_trusted {
        joined(headers, &XFF)
            .map(|v| format!("{v}, {peer_ip}"))
            .unwrap_or_else(|| peer_ip.to_string())
    } else {
        peer_ip.to_string()
    };
    if let Ok(v) = HeaderValue::from_str(&xff) {
        headers.insert(XFF, v);
    }
    // trusted peers' X-Forwarded-Proto/-Host describe the client-facing
    // side (e.g. a TLS terminator's `https`) — keep them; untrusted or
    // absent values get our own observation
    if !(peer_trusted && headers.contains_key(&XFP))
        && let Ok(v) = HeaderValue::from_str(scheme)
    {
        headers.insert(XFP, v);
    }
    // XFH: trusted peers' value is preserved; otherwise we emit our own
    // — and when our host isn't clean we must still REMOVE the client's
    // spoofed inbound value rather than let it pass through verbatim
    if peer_trusted && headers.contains_key(&XFH) {
        // preserved
    } else if host_clean(host)
        && let Ok(v) = HeaderValue::from_str(host)
    {
        headers.insert(XFH, v);
    } else {
        headers.remove(&XFH);
    }
    if let Ok(v) = HeaderValue::from_str(&client_ip.to_string()) {
        headers.insert(XRI, v);
    }

    // RFC 7239 Forwarded: for=peer;proto=scheme;host=host (IPv6 quoted,
    // host quoted when it isn't a bare token).
    let for_part = match peer_ip {
        IpAddr::V4(ip) => ip.to_string(),
        IpAddr::V6(ip) => format!("\"[{ip}]\""),
    };
    let entry = format!("for={for_part};proto={scheme};host={}", rfc7239_value(host));
    let fwd = if peer_trusted {
        joined(headers, &FORWARDED)
            .map(|v| format!("{v}, {entry}"))
            .unwrap_or(entry)
    } else {
        entry
    };
    if let Ok(v) = HeaderValue::from_str(&fwd) {
        headers.insert(FORWARDED, v);
    }
}

/// Re-encode a decoded normalized path for the upstream request-target:
/// everything outside the `pchar` set (plus `/`) is percent-encoded.
pub fn encode_path(path: &str) -> String {
    const PATH_SET: &percent_encoding::AsciiSet = &percent_encoding::CONTROLS
        .add(b' ')
        .add(b'"')
        .add(b'#')
        .add(b'<')
        .add(b'>')
        .add(b'?')
        .add(b'`')
        .add(b'{')
        .add(b'}')
        .add(b'%')
        .add(b'^');
    percent_encoding::utf8_percent_encode(path, PATH_SET).to_string()
}

/// The client's original `Host` value for `X-Forwarded-Host`.
pub fn original_host(parts: &http::request::Parts) -> String {
    parts
        .headers
        .get(HOST)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
        .or_else(|| parts.uri.authority().map(|a| a.to_string()))
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map(items: &[(&str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in items {
            h.insert(
                HeaderName::from_bytes(k.as_bytes()).unwrap(),
                HeaderValue::from_str(v).unwrap(),
            );
        }
        h
    }

    #[test]
    fn upgrade_detection() {
        assert!(wants_upgrade(&map(&[
            ("connection", "keep-alive, Upgrade"),
            ("upgrade", "websocket"),
        ])));
        assert!(!wants_upgrade(&map(&[("upgrade", "websocket")])));
        assert!(!wants_upgrade(&map(&[("connection", "upgrade")])));
    }

    #[test]
    fn hop_by_hop_stripped_with_connection_tokens() {
        let mut h = map(&[
            ("connection", "x-foo, keep-alive"),
            ("x-foo", "1"),
            ("keep-alive", "timeout=5"),
            ("te", "trailers"),
            ("transfer-encoding", "chunked"),
            ("content-type", "text/plain"),
        ]);
        strip_hop_by_hop(&mut h, false);
        assert!(!h.contains_key("x-foo"));
        assert!(!h.contains_key(CONNECTION));
        assert!(!h.contains_key(TE));
        assert!(!h.contains_key(TRANSFER_ENCODING));
        assert!(h.contains_key("content-type"));
    }

    #[test]
    fn upgrade_keeps_connection_and_upgrade() {
        let mut h = map(&[
            ("connection", "upgrade, x-foo"),
            ("x-foo", "1"),
            ("upgrade", "websocket"),
        ]);
        strip_hop_by_hop(&mut h, true);
        assert!(h.contains_key(CONNECTION));
        assert!(h.contains_key(UPGRADE));
        assert!(!h.contains_key("x-foo"));
    }

    #[test]
    fn forwarded_headers_untrusted_peer_replaces() {
        let mut h = map(&[("x-forwarded-for", "198.51.100.9")]);
        set_forwarded(
            &mut h,
            "203.0.113.5".parse().unwrap(),
            false,
            "203.0.113.5".parse().unwrap(),
            "https",
            "api.example.com",
        );
        assert_eq!(h.get(&XFF).unwrap(), "203.0.113.5");
        assert_eq!(h.get(&XRI).unwrap(), "203.0.113.5");
        assert_eq!(h.get(&XFP).unwrap(), "https");
        assert_eq!(h.get(&XFH).unwrap(), "api.example.com");
        assert_eq!(
            h.get(FORWARDED).unwrap(),
            "for=203.0.113.5;proto=https;host=api.example.com"
        );
    }

    #[test]
    fn forwarded_headers_trusted_peer_appends() {
        let mut h = map(&[
            ("x-forwarded-for", "198.51.100.9"),
            ("forwarded", "for=198.51.100.9"),
        ]);
        set_forwarded(
            &mut h,
            "10.0.0.1".parse().unwrap(),
            true,
            "198.51.100.9".parse().unwrap(),
            "http",
            "x.test",
        );
        assert_eq!(h.get(&XFF).unwrap(), "198.51.100.9, 10.0.0.1");
        assert_eq!(
            h.get(FORWARDED).unwrap(),
            "for=198.51.100.9, for=10.0.0.1;proto=http;host=x.test"
        );
    }

    #[test]
    fn host_injection_quoted_and_xfh_dropped() {
        let mut h = map(&[]);
        set_forwarded(
            &mut h,
            "203.0.113.5".parse().unwrap(),
            false,
            "203.0.113.5".parse().unwrap(),
            "http",
            "evil.com\";for=\"spoof",
        );
        // the host must be a quoted-string — injected pairs stay literal
        assert_eq!(
            h.get(FORWARDED).unwrap(),
            "for=203.0.113.5;proto=http;host=\"evil.com\\\";for=\\\"spoof\""
        );
        assert!(h.get(&XFH).is_none(), "dirty host not forwarded as XFH");
    }

    #[test]
    fn untrusted_dirty_host_drops_inbound_xfh() {
        // the spoofed client XFH must not survive when our own host is
        // unfit to forward
        let mut h = map(&[("x-forwarded-host", "attacker.example")]);
        set_forwarded(
            &mut h,
            "203.0.113.5".parse().unwrap(),
            false,
            "203.0.113.5".parse().unwrap(),
            "http",
            "dirty\";for=\"x",
        );
        assert!(h.get(&XFH).is_none());
    }

    #[test]
    fn trusted_peer_proto_and_host_preserved() {
        let mut h = map(&[
            ("x-forwarded-proto", "https"),
            ("x-forwarded-host", "original.example"),
        ]);
        set_forwarded(
            &mut h,
            "10.0.0.1".parse().unwrap(),
            true,
            "198.51.100.9".parse().unwrap(),
            "http",
            "inner.test",
        );
        assert_eq!(h.get(&XFP).unwrap(), "https");
        assert_eq!(h.get(&XFH).unwrap(), "original.example");
    }

    #[test]
    fn untrusted_peer_xfp_overwritten() {
        let mut h = map(&[("x-forwarded-proto", "https")]);
        set_forwarded(
            &mut h,
            "203.0.113.5".parse().unwrap(),
            false,
            "203.0.113.5".parse().unwrap(),
            "http",
            "x.test",
        );
        assert_eq!(h.get(&XFP).unwrap(), "http");
    }

    #[test]
    fn multi_value_xff_headers_merge() {
        let mut h = HeaderMap::new();
        h.append(&XFF, HeaderValue::from_static("198.51.100.1"));
        h.append(&XFF, HeaderValue::from_static("198.51.100.2"));
        set_forwarded(
            &mut h,
            "10.0.0.1".parse().unwrap(),
            true,
            "198.51.100.1".parse().unwrap(),
            "http",
            "x.test",
        );
        assert_eq!(h.get(&XFF).unwrap(), "198.51.100.1, 198.51.100.2, 10.0.0.1");
    }

    #[test]
    fn path_encoding() {
        assert_eq!(encode_path("/a b/%e7"), "/a%20b/%25e7");
        assert_eq!(encode_path("/a?b"), "/a%3Fb");
        assert_eq!(encode_path("/normal-1/x_y.z~"), "/normal-1/x_y.z~");
    }
}
