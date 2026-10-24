//! Request IDs: propagated from `X-Request-Id` when sane, generated
//! otherwise.

/// A request identifier safe to echo into a response header and logs.
#[derive(Debug, Clone)]
pub struct RequestId(String);

impl RequestId {
    /// Extract a client-supplied `X-Request-Id` (≤128 bytes of printable,
    /// non-whitespace-free ASCII) or generate a UUIDv4.
    pub fn extract(headers: &http::HeaderMap) -> Self {
        let incoming = headers
            .get("x-request-id")
            .and_then(|v| v.to_str().ok())
            .filter(|v| is_usable(v));
        Self(
            incoming
                .map(str::to_string)
                .unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
        )
    }

    /// The id as a string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn is_usable(v: &str) -> bool {
    !v.is_empty() && v.len() <= 128 && v.bytes().all(|b| (0x21..=0x7e).contains(&b))
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderValue;

    #[test]
    fn propagates_valid_id() {
        let mut h = http::HeaderMap::new();
        h.insert("x-request-id", HeaderValue::from_static("abc-123"));
        assert_eq!(RequestId::extract(&h).as_str(), "abc-123");
    }

    #[test]
    fn rejects_bad_and_generates() {
        let mut h = http::HeaderMap::new();
        h.insert("x-request-id", HeaderValue::from_static("with space"));
        assert_ne!(RequestId::extract(&h).as_str(), "with space");
        // uuid shape
        assert_eq!(RequestId::extract(&h).as_str().len(), 36);
    }
}
