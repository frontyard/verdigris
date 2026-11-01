#![no_main]
use libfuzzer_sys::fuzz_target;

use http::{HeaderMap, HeaderName, HeaderValue};
use verd::proxy::headers;

// header-block interpretation shared with http_semantics: one
// `Name: value` pair per line; invalid pairs are skipped
fn parse_headers(data: &[u8]) -> HeaderMap {
    let mut headers = HeaderMap::new();
    for line in data.split(|b| *b == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let Some(colon) = line.iter().position(|b| *b == b':') else {
            continue;
        };
        let (Ok(name), Ok(value)) = (
            HeaderName::from_bytes(&line[..colon]),
            HeaderValue::from_bytes(&line[colon + 1..]),
        ) else {
            continue;
        };
        headers.append(name, value);
    }
    headers
}

// names the Connection header advertises on `h`
fn connection_tokens(h: &HeaderMap) -> Vec<HeaderName> {
    h.get_all(http::header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .filter_map(|t| HeaderName::from_bytes(t.trim().as_bytes()).ok())
        .collect()
}

fuzz_target!(|data: &[u8]| {
    let inbound = parse_headers(data);
    let upgrading = headers::wants_upgrade(&inbound);

    let mut out = inbound.clone();
    headers::strip_hop_by_hop(&mut out, upgrading);

    // invariants: no Connection-advertised name may survive; without an
    // upgrade neither `connection` nor `upgrade` may survive either
    for name in connection_tokens(&inbound) {
        if !(upgrading && name == http::header::UPGRADE) {
            assert!(
                !out.contains_key(&name),
                "connection-advertised {name} survived stripping"
            );
        }
    }
    if !upgrading {
        assert!(!out.contains_key(http::header::CONNECTION));
        assert!(!out.contains_key(http::header::UPGRADE));
    }
    for fixed in [
        http::header::TRANSFER_ENCODING,
        HeaderName::from_static("keep-alive"),
        HeaderName::from_static("proxy-connection"),
        http::header::PROXY_AUTHENTICATE,
        http::header::PROXY_AUTHORIZATION,
    ] {
        assert!(!out.contains_key(&fixed), "hop-by-hop {fixed} survived");
    }

    // set_forwarded must always leave exactly ONE value for each header
    // it owns — and must never panic on arbitrary header material
    let host = inbound
        .get(http::header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
        .unwrap_or_else(|| String::from_utf8_lossy(&data[..data.len().min(128)]).into_owned());
    for trusted in [false, true] {
        let mut h = inbound.clone();
        headers::set_forwarded(
            &mut h,
            "10.0.0.1".parse().unwrap(),
            trusted,
            "198.51.100.7".parse().unwrap(),
            "https",
            &host,
        );
        for name in [
            "x-forwarded-for",
            "x-real-ip",
            "x-forwarded-proto",
            "forwarded",
        ] {
            let name = HeaderName::from_static(name);
            assert_eq!(
                h.get_all(&name).iter().count(),
                1,
                "{name} must be single-valued (trusted={trusted})"
            );
        }
    }

    // encode_path output must be a legal header/request-target byte
    // string: no spaces, no raw controls, no `?`/`#` fragment break
    let text = String::from_utf8_lossy(data);
    for line in text.lines().take(16) {
        let enc = headers::encode_path(line);
        assert!(enc.bytes().all(|b| b.is_ascii_graphic() || b == b'%'));
        assert!(!enc.contains(['?', '#', ' ']));
    }
});
