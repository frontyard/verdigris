//! Cache keys: canonical form `method␟host␟path␟query␟vary` plus a
//! stable (FNV-1a) hash — stable across restarts so the disk index stays
//! meaningful between process generations.

/// Separator byte inside the canonical key string: never legal in any
/// component, so the layout is unambiguous for prefix-purge scans.
const FS: char = '\u{1f}';

/// A request's cache key: the canonical string (kept for purge scans and
/// disk-object verification) and its stable hash.
#[derive(Debug, Clone)]
pub struct Key {
    /// Canonical string form.
    pub raw: String,
    /// FNV-1a hash of `raw`.
    pub hash: u64,
}

/// Authority for the key: lowercase + trailing-dot trimmed, but the port
/// is KEPT — upstreams see the forwarded `Host` verbatim, so
/// `example.com` and `example.com:8443` are different resources.
/// (Routing's `normalize_host` strips ports; that is deliberately not
/// reused here.)
pub fn key_authority(raw: &str) -> String {
    raw.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// Build the primary key for a request. `target` is the raw request
/// target (`path_and_query` verbatim, still percent-encoded and in the
/// client's parameter order) and `authority` is the request's host:port
/// after [`key_authority`]. `vary` holds the request's values for
/// config-forced vary headers (name, value-or-absent); response-driven
/// `Vary` is handled separately via variant buckets.
///
/// The raw target is used on purpose — the shape nginx's default
/// `proxy_cache_key` (`$scheme$proxy_host$request_uri`) has. The
/// percent-decoded normalized path is only a *routing* concern: two
/// spellings like `/group%2Fproject` and `/group/project` are different
/// upstream request targets and must not share an entry. Ditto query
/// order — `?a=1&a=2` vs `?a=2&a=1` can differ upstream. And keeping the
/// encoding raw means `%1F` stays three harmless characters instead of
/// decoding into the `FS` separator byte.
pub fn primary(
    method: &http::Method,
    scheme: &str,
    authority: &str,
    target: &str,
    vary: &[(String, Option<String>)],
) -> Key {
    // HEAD shares GET's slot: a HEAD hit serves GET headers, and a HEAD
    // response may update the stored GET representation.
    let method = if method == http::Method::HEAD {
        "GET"
    } else {
        method.as_str()
    };
    let mut raw = String::with_capacity(96);
    raw.push_str(method);
    raw.push(FS);
    raw.push_str(scheme);
    raw.push(FS);
    raw.push_str(&key_authority(authority));
    raw.push(FS);
    raw.push_str(target);
    for (name, value) in vary {
        raw.push(FS);
        raw.push_str(name);
        raw.push('=');
        if let Some(v) = value {
            raw.push_str(v);
        }
    }
    let hash = fnv1a(&raw);
    Key { raw, hash }
}

/// Remove `name=` pairs from a request target's query — used to keep
/// credentials carried in a query parameter (ApiKey auth with
/// `location = "query"`) out of persisted cache keys. The comparison
/// percent-decodes the pair's key, so `api_%6bey=x` cannot smuggle the
/// credential into the key under an encoded name. Returns the target
/// unchanged when nothing matched.
pub fn strip_query_param<'a>(target: &'a str, name: &str) -> std::borrow::Cow<'a, str> {
    use std::borrow::Cow;
    let Some(q) = target.find('?') else {
        return Cow::Borrowed(target);
    };
    let query = &target[q + 1..];
    let n_pairs = query.split('&').count();
    let kept: Vec<&str> = query
        .split('&')
        .filter(|pair| {
            let k = pair.split('=').next().unwrap_or("");
            percent_encoding::percent_decode_str(k).decode_utf8_lossy() != name
        })
        .collect();
    if kept.len() == n_pairs {
        return Cow::Borrowed(target);
    }
    let mut out = String::with_capacity(target.len());
    out.push_str(&target[..q]);
    if !kept.is_empty() {
        out.push('?');
        out.push_str(&kept.join("&"));
    }
    Cow::Owned(out)
}

/// FNV-1a 64 — deterministic across builds, unlike `DefaultHasher`.
pub fn fnv1a(s: &str) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in s.as_bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_is_stable_and_method_normalized() {
        let get = http::Method::GET;
        let k1 = primary(&get, "https", "h", "/p?a=1", &[]);
        let k2 = primary(&get, "https", "h", "/p?a=1", &[]);
        let kh = primary(&http::Method::HEAD, "https", "h", "/p?a=1", &[]);
        assert_eq!(k1.raw, k2.raw);
        assert_eq!(k1.hash, k2.hash);
        assert_eq!(k1.hash, kh.hash);
        let kv = primary(
            &get,
            "https",
            "h",
            "/p",
            &[("accept-language".into(), Some("en".into()))],
        );
        assert_ne!(k1.hash, kv.hash);
    }

    #[test]
    fn encoded_and_decoded_paths_do_not_share() {
        // `%2F` in the target is a different upstream request than a
        // literal slash — the key must reflect the raw target.
        let a = primary(&http::Method::GET, "https", "h", "/group%2Fproject", &[]);
        let b = primary(&http::Method::GET, "https", "h", "/group/project", &[]);
        assert_ne!(a.hash, b.hash);
    }

    #[test]
    fn percent_1f_stays_literal_in_key() {
        // The raw target keeps `%1F` as three characters — it must never
        // decode into the field separator.
        let k = primary(&http::Method::GET, "https", "h", "/a%1Fb", &[]);
        assert!(k.raw.contains("/a%1Fb"));
        // exactly the three field separators — a decoded 0x1F inside the
        // target would show up as a fourth
        assert_eq!(k.raw.matches(FS).count(), 3);
    }

    #[test]
    fn scheme_port_and_query_order_distinguish() {
        let get = http::Method::GET;
        let base = primary(&get, "https", "h", "/p", &[]);
        assert_ne!(base.hash, primary(&get, "http", "h", "/p", &[]).hash);
        assert_ne!(base.hash, primary(&get, "https", "h:8443", "/p", &[]).hash);
        assert_ne!(
            primary(&get, "https", "h", "/p?a=1&a=2", &[]).hash,
            primary(&get, "https", "h", "/p?a=2&a=1", &[]).hash
        );
        // cosmetic differences still fold: case and trailing dot
        assert_eq!(base.hash, primary(&get, "https", "H.", "/p", &[]).hash);
    }

    #[test]
    fn strip_query_param_removes_secret_even_encoded() {
        assert_eq!(strip_query_param("/p?a=1&k=s3kret&b=2", "k"), "/p?a=1&b=2");
        assert_eq!(strip_query_param("/p?a=1&k=s3kret", "k"), "/p?a=1");
        assert_eq!(strip_query_param("/p?k=s3kret", "k"), "/p");
        assert_eq!(strip_query_param("/p?a=1", "k"), "/p?a=1");
        // percent-encoded param name still matches (decoded compare)
        assert_eq!(strip_query_param("/p?%6b=s3kret", "k"), "/p");
        // bare ? with nothing after also collapses
        assert_eq!(strip_query_param("/p?", "k"), "/p?");
    }
}
