#![no_main]
use libfuzzer_sys::fuzz_target;

use http::{HeaderMap, HeaderName, HeaderValue};
use verd::cache::semantics;
use verd::config::{ByteSize, RateSpec};
use verd::router::condition::Pattern;

fuzz_target!(|data: &[u8]| {
    // interpret the input as an HTTP header block: one `Name: value`
    // pair per line (CRLF or LF), skip anything that isn't a valid pair
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

    // cache-semantics interpretation must never panic on arbitrary headers
    let _ = semantics::request_directives(&headers);
    let _ = semantics::response_directives(&headers);
    let vary = semantics::response_vary(&headers);
    // feed the resolved vary names back as a stored variant's pairs
    let pairs: Vec<(String, Option<String>)> = vary
        .iter()
        .map(|n| {
            (
                n.clone(),
                headers
                    .get(n)
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_string),
            )
        })
        .collect();
    let _ = semantics::vary_matches(&pairs, &headers);

    // config-side string parsers on bounded chunks of the same input
    let text = String::from_utf8_lossy(data);
    for line in text.lines() {
        let short: String = line.chars().take(128).collect();
        let _ = Pattern::compile(&short);
        let _ = ByteSize::parse(&short);
        let _ = RateSpec::parse(&short);
    }
});
