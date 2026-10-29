//! Authentication middleware: HTTP Basic (argon2 inline hashes, bcrypt
//! `$2y$` htpasswd files), Bearer tokens, and API keys. Credentials are
//! compared in constant time where the underlying format allows it; a
//! successful check produces an [`Identity`] used by rate limiting and the
//! access log.

use std::collections::BTreeMap;

use argon2::{PasswordHash, PasswordVerifier};
use http::header::{AUTHORIZATION, WWW_AUTHENTICATE};
use http::{HeaderMap, HeaderValue, StatusCode};
use subtle::ConstantTimeEq;

use crate::body::{self, BoxBody};
use crate::config::model as cfg;

/// Identity of an authenticated caller, attached to the request
/// extensions and the access log.
#[derive(Debug, Clone)]
pub struct Identity(pub String);

/// The result of an authentication check.
pub enum Outcome {
    /// Credentials accepted; carries the caller identity.
    Authenticated(Identity),
    /// Rejected; the response to return (401 + challenge headers).
    Rejected(http::Response<BoxBody>),
}

/// A compiled auth method.
pub enum Auth {
    /// HTTP Basic with hashed-password users.
    Basic(Basic),
    /// Bearer token list.
    Bearer(Bearer),
    /// API key in a header or query parameter.
    ApiKey(ApiKey),
}

/// Compiled Basic auth.
pub struct Basic {
    users: BTreeMap<String, Hash>,
    /// Dummy hash matching the table's scheme — unknown users pay the
    /// same verification family so the failure path isn't a user-
    /// existence timing oracle.
    dummy: Hash,
    realm: String,
}

#[derive(Clone)]
enum Hash {
    Argon2(String),
    Bcrypt(String),
}

/// Compiled Bearer auth.
pub struct Bearer {
    tokens: Vec<Vec<u8>>,
}

/// Compiled API-key auth.
pub struct ApiKey {
    location: cfg::ApiKeyLocation,
    name: String,
    header: Option<http::HeaderName>,
    keys: Vec<Vec<u8>>,
}

impl Auth {
    /// Compile from config. The validator guarantees exactly one method.
    pub fn build(c: &cfg::AuthConfig) -> Result<Self, String> {
        if let Some(b) = &c.basic {
            let mut users: BTreeMap<String, Hash> = BTreeMap::new();
            for (u, h) in &b.users {
                users.insert(u.clone(), classify_hash(h)?);
            }
            if let Some(file) = &b.htpasswd {
                let text = std::fs::read_to_string(file)
                    .map_err(|e| format!("cannot read htpasswd {}: {e}", file.display()))?;
                for (lineno, line) in text.lines().enumerate() {
                    let line = line.trim();
                    if line.is_empty() {
                        continue;
                    }
                    let (u, h) = line.split_once(':').ok_or_else(|| {
                        format!("{} line {}: expected user:hash", file.display(), lineno + 1)
                    })?;
                    users.insert(
                        u.to_string(),
                        classify_hash(h)
                            .map_err(|e| format!("{} line {}: {e}", file.display(), lineno + 1))?,
                    );
                }
            }
            // dummy matches the table's scheme so unknown users pay the
            // same verification family (no user-existence timing oracle)
            let dummy = users
                .values()
                .next()
                .cloned()
                .unwrap_or_else(|| Hash::Bcrypt(DUMMY_BCRYPT.to_string()));
            return Ok(Auth::Basic(Basic {
                users,
                dummy,
                realm: b.realm.clone().unwrap_or_else(|| "verd".into()),
            }));
        }
        if let Some(t) = &c.bearer {
            return Ok(Auth::Bearer(Bearer {
                tokens: t.tokens.iter().map(|s| s.as_bytes().to_vec()).collect(),
            }));
        }
        if let Some(k) = &c.api_key {
            let header = match k.location {
                cfg::ApiKeyLocation::Header => Some(
                    http::HeaderName::from_bytes(k.name.as_bytes())
                        .map_err(|_| format!("invalid api key header name {:?}", k.name))?,
                ),
                cfg::ApiKeyLocation::Query => None,
            };
            return Ok(Auth::ApiKey(ApiKey {
                location: k.location,
                name: k.name.clone(),
                header,
                keys: k.keys.iter().map(|s| s.as_bytes().to_vec()).collect(),
            }));
        }
        Err("auth block has no method".into())
    }

    /// Name of the query parameter carrying the credential — `Some`
    /// only for ApiKey auth in the `query` location. The cache layer
    /// strips it from cache keys so secrets never persist to disk.
    pub fn credential_query_param(&self) -> Option<&str> {
        match self {
            Auth::ApiKey(k) if k.location == cfg::ApiKeyLocation::Query => Some(&k.name),
            _ => None,
        }
    }

    /// Verify the request's credentials.
    pub fn check(&self, parts: &http::request::Parts) -> Outcome {
        match self {
            Auth::Basic(b) => b.check(parts),
            Auth::Bearer(b) => b.check(parts),
            Auth::ApiKey(k) => k.check(parts),
        }
    }

    /// Async check for the request path: Basic's password verification
    /// (~50-100ms of pure CPU) runs on the blocking pool so credential
    /// sprays can't pin reactor workers. Cheap methods stay inline.
    pub async fn check_throttled(&self, parts: &http::request::Parts) -> Outcome {
        match self {
            Auth::Basic(b) => b.check_throttled(parts).await,
            Auth::Bearer(b) => b.check(parts),
            Auth::ApiKey(k) => k.check(parts),
        }
    }
}

fn classify_hash(h: &str) -> Result<Hash, String> {
    if h.starts_with("$argon2") {
        PasswordHash::new(h)
            .map_err(|_| "password value is not a valid argon2 hash".to_string())?;
        return Ok(Hash::Argon2(h.to_string()));
    }
    if h.starts_with("$2a$") || h.starts_with("$2b$") || h.starts_with("$2y$") {
        h.parse::<bcrypt::HashParts>()
            .map_err(|_| "password value is not a valid bcrypt hash".to_string())?;
        return Ok(Hash::Bcrypt(h.to_string()));
    }
    Err("password value is not an argon2 or bcrypt hash".into())
}

impl Basic {
    fn check(&self, parts: &http::request::Parts) -> Outcome {
        let Some((user, password)) = creds(parts) else {
            return Outcome::Rejected(self.challenge());
        };
        let attempt = self.prepare(&user, &password);
        let ok = verify(&attempt.hash, &attempt.password);
        self.decide(ok, attempt.known, &user)
    }

    /// Async variant for the request path — the ~50-100ms hash verify
    /// runs on the blocking pool (see [`Auth::check_throttled`]).
    async fn check_throttled(&self, parts: &http::request::Parts) -> Outcome {
        let Some((user, password)) = creds(parts) else {
            return Outcome::Rejected(self.challenge());
        };
        let attempt = self.prepare(&user, &password);
        let ok = tokio::task::spawn_blocking(move || verify(&attempt.hash, &attempt.password))
            .await
            .unwrap_or(false);
        self.decide(ok, attempt.known, &user)
    }

    /// Select the hash to verify against — the user's own, or a scheme-
    /// matching dummy so unknown users cost the same verification family.
    fn prepare(&self, user: &str, password: &str) -> Attempt {
        let (hash, known) = self
            .users
            .get(user)
            .map(|h| (h.clone(), true))
            .unwrap_or_else(|| (self.dummy.clone(), false));
        Attempt {
            hash,
            known,
            password: password.as_bytes().to_vec(),
        }
    }

    fn decide(&self, ok: bool, known: bool, user: &str) -> Outcome {
        if ok && known {
            Outcome::Authenticated(Identity(format!("user:{user}")))
        } else {
            Outcome::Rejected(self.challenge())
        }
    }

    fn challenge(&self) -> http::Response<BoxBody> {
        unauthorized(&format!("Basic realm=\"{}\"", self.realm))
    }
}

/// A prepared verification: moved onto the blocking pool wholesale.
struct Attempt {
    hash: Hash,
    password: Vec<u8>,
    known: bool,
}

/// Parse `Authorization: Basic …` credentials out of the request.
fn creds(parts: &http::request::Parts) -> Option<(String, String)> {
    parts
        .headers
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| {
            // RFC 9110 §11: auth-scheme is case-insensitive
            let (scheme, b64) = v.split_once(' ')?;
            scheme.eq_ignore_ascii_case("basic").then_some(b64)
        })
        .and_then(|b64| {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD.decode(b64).ok()
        })
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .and_then(|s| {
            s.split_once(':')
                .map(|(u, p)| (u.to_string(), p.to_string()))
        })
}

/// A fixed bcrypt hash used for dummy verification on unknown users
/// (cost 10 hash of "dummy").
const DUMMY_BCRYPT: &str = "$2y$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy";

fn verify(hash: &Hash, password: &[u8]) -> bool {
    match hash {
        Hash::Bcrypt(h) => bcrypt::verify(password, h).unwrap_or(false),
        Hash::Argon2(h) => PasswordHash::new(h)
            .ok()
            .map(|ph| {
                argon2::Argon2::default()
                    .verify_password(password, &ph)
                    .is_ok()
            })
            .unwrap_or(false),
    }
}

impl Bearer {
    fn check(&self, parts: &http::request::Parts) -> Outcome {
        let token = parts
            .headers
            .get(AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| {
                // RFC 9110 §11: auth-scheme is case-insensitive
                let (scheme, tok) = v.split_once(' ')?;
                scheme.eq_ignore_ascii_case("bearer").then_some(tok)
            })
            .map(|t| t.trim());
        let Some(token) = token else {
            return Outcome::Rejected(unauthorized("Bearer"));
        };
        // fold, not .any(): scanning every token avoids leaking the
        // matching token's position in the list via early-exit timing
        let ok = self
            .tokens
            .iter()
            .fold(false, |acc, t| acc | ct_eq(t, token.as_bytes()));
        if ok {
            Outcome::Authenticated(Identity(format!("token:{}", fingerprint(token))))
        } else {
            Outcome::Rejected(unauthorized("Bearer"))
        }
    }
}

impl ApiKey {
    fn check(&self, parts: &http::request::Parts) -> Outcome {
        let presented: Option<String> = match self.location {
            cfg::ApiKeyLocation::Header => self
                .header
                .as_ref()
                .and_then(|h| parts.headers.get(h))
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string()),
            cfg::ApiKeyLocation::Query => parts.uri.query().and_then(|q| {
                form_urlencoded::parse(q.as_bytes())
                    .find(|(k, _)| k == &self.name)
                    .map(|(_, v)| v.into_owned())
            }),
        };
        let ok = self.keys.iter().fold(false, |acc, v| {
            acc | ct_eq(v, presented.as_deref().unwrap_or("").as_bytes())
        });
        match presented {
            Some(ref k) if ok => {
                Outcome::Authenticated(Identity(format!("key:{}", fingerprint(k))))
            }
            Some(_) => {
                Outcome::Rejected(unauthorized_msg(StatusCode::FORBIDDEN, "invalid api key"))
            }
            None => Outcome::Rejected(unauthorized_msg(
                StatusCode::UNAUTHORIZED,
                "missing api key",
            )),
        }
    }
}

/// Constant-time byte comparison (length leaks only, which is inherent).
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}

/// A short non-reversible tag for a secret — used as the log/rate-limit
/// identity instead of the secret itself. Keyed with a per-process
/// random seed so tags can't be precomputed offline to correlate a
/// leaked log back to a token.
fn fingerprint(secret: &str) -> String {
    static SEED: std::sync::LazyLock<ahash::RandomState> =
        std::sync::LazyLock::new(ahash::RandomState::new);
    format!("{:016x}", SEED.hash_one(secret))
}

fn unauthorized(challenge: &str) -> http::Response<BoxBody> {
    let mut resp = unauthorized_msg(StatusCode::UNAUTHORIZED, "authentication required");
    if let Ok(v) = HeaderValue::from_str(challenge) {
        resp.headers_mut().insert(WWW_AUTHENTICATE, v);
    }
    resp
}

fn unauthorized_msg(status: StatusCode, msg: &str) -> http::Response<BoxBody> {
    let mut resp = http::Response::new(body::full(format!("{status} {msg}\n")));
    *resp.status_mut() = status;
    resp.headers_mut().insert(
        http::header::CONTENT_TYPE,
        http::HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    resp
}

/// Insert the `WWW-Authenticate`-less plain 401 — kept for other users.
#[allow(dead_code)]
fn headers(_: &HeaderMap) {}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(auth_header: Option<(&'static str, &str)>) -> http::request::Parts {
        let mut b = http::Request::builder().uri("http://x/");
        if let Some((k, v)) = auth_header {
            b = b.header(k, v);
        }
        b.body(()).unwrap().into_parts().0
    }

    #[test]
    fn basic_argon2_roundtrip() {
        let hash = argon2::PasswordHasher::hash_password(&argon2::Argon2::default(), b"s3cret")
            .unwrap()
            .to_string();
        let mut users = BTreeMap::new();
        users.insert("alice".to_string(), hash);
        let a = Auth::build(&cfg::AuthConfig {
            basic: Some(cfg::BasicAuth {
                users,
                htpasswd: None,
                realm: Some("t".into()),
            }),
            ..Default::default()
        })
        .unwrap();
        let good = req(Some((
            "authorization",
            &format!(
                "Basic {}",
                base64::Engine::encode(&base64::engine::general_purpose::STANDARD, "alice:s3cret")
            ),
        )));
        assert!(matches!(a.check(&good), Outcome::Authenticated(_)));
        let bad = req(Some((
            "authorization",
            &format!(
                "Basic {}",
                base64::Engine::encode(&base64::engine::general_purpose::STANDARD, "alice:wrong")
            ),
        )));
        assert!(matches!(a.check(&bad), Outcome::Rejected(_)));
        let none = req(None);
        assert!(matches!(a.check(&none), Outcome::Rejected(_)));
    }

    #[test]
    fn basic_bcrypt_2y_accepted() {
        // htpasswd emits $2y$ (crypt_blowfish == the fixed $2b$ algorithm);
        // if bcrypt::verify rejected it, verify() would fail *instantly*
        // instead of paying the cost factor — a user-existence oracle.
        let h = bcrypt::hash_with_result(b"pw", 8)
            .unwrap()
            .format_for_version(bcrypt::Version::TwoY);
        assert!(h.starts_with("$2y$"));
        assert!(verify(&Hash::Bcrypt(h.clone()), b"pw"));
        assert!(!verify(&Hash::Bcrypt(h), b"nope"));
        // DUMMY_BCRYPT must be a *valid* $2y$ hash: is_ok means it parsed
        // and the full expansion ran even for a wrong password.
        assert!(bcrypt::verify(b"unknown-user-probe", DUMMY_BCRYPT).is_ok());
    }

    #[test]
    fn bearer_constant_time() {
        let a = Auth::build(&cfg::AuthConfig {
            bearer: Some(cfg::BearerAuth {
                tokens: vec!["abc123".into()],
            }),
            ..Default::default()
        })
        .unwrap();
        let ok = req(Some(("authorization", "Bearer abc123")));
        assert!(matches!(a.check(&ok), Outcome::Authenticated(_)));
        let no = req(Some(("authorization", "Bearer abc124")));
        assert!(matches!(a.check(&no), Outcome::Rejected(_)));
    }

    #[test]
    fn api_key_query() {
        let a = Auth::build(&cfg::AuthConfig {
            api_key: Some(cfg::ApiKeyAuth {
                location: cfg::ApiKeyLocation::Query,
                name: "k".into(),
                keys: vec!["s3kret".into()],
            }),
            ..Default::default()
        })
        .unwrap();
        let ok = http::Request::builder()
            .uri("http://x/?k=s3kret&x=1")
            .body(())
            .unwrap()
            .into_parts()
            .0;
        assert!(matches!(a.check(&ok), Outcome::Authenticated(_)));
        let bad = http::Request::builder()
            .uri("http://x/?k=nope")
            .body(())
            .unwrap()
            .into_parts()
            .0;
        assert!(matches!(a.check(&bad), Outcome::Rejected(_)));
    }

    #[test]
    fn ct_eq_works() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"abcd"));
    }

    #[test]
    fn classify_hash_covers_argon2_and_every_bcrypt_ident() {
        let argon = argon2::PasswordHasher::hash_password(&argon2::Argon2::default(), b"p")
            .unwrap()
            .to_string();
        assert!(matches!(classify_hash(&argon), Ok(Hash::Argon2(_))));
        for v in [
            bcrypt::Version::TwoA,
            bcrypt::Version::TwoB,
            bcrypt::Version::TwoY,
        ] {
            let h = bcrypt::hash_with_result(b"p", 4)
                .unwrap()
                .format_for_version(v);
            assert!(matches!(classify_hash(&h), Ok(Hash::Bcrypt(_))), "{h}");
        }
        // well-formed prefix but truncated body → parse fails → Err
        let mut bad = bcrypt::hash_with_result(b"p", 4)
            .unwrap()
            .format_for_version(bcrypt::Version::TwoB);
        bad.truncate(20);
        assert!(classify_hash(&bad).is_err());
        assert!(classify_hash("plaintext").is_err());
        assert!(classify_hash("$2x$bogus").is_err());
    }
}
