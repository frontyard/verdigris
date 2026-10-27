//! Verdigris is a web server and reverse proxy designed to be simple to run and
//! fast. One TOML file, sane defaults, batteries included: TLS, caching,
//! compression, load balancing, rate limiting and metrics are built in.
//!
//! The module layout mirrors the request lifecycle: [`config`] is parsed once,
//! [`server`] accepts connections, [`router`] picks a route, [`middleware`]
//! stages run in a fixed order, and a [`handler`] produces the response.

#![deny(unsafe_code)]
// deny, not forbid: the only sanctioned unsafe is body::mmap's read-only
// MAP_POPULATE file mapping — documented there.
#![warn(missing_docs)]

pub mod acme;
pub mod admin;
pub mod body;
pub mod cache;
pub mod cli;
pub mod config;
pub mod errors;
mod fsperm;
pub mod handler;
pub mod middleware;
pub mod observe;
pub mod proxy;
pub mod router;
pub mod server;
pub mod tls;

/// Whether a runtime build may touch the filesystem. `verd run` builds
/// [`BuildMode::Live`] — log files are opened and cache directories
/// created. `verd validate` builds [`BuildMode::Check`]: every
/// compile-time check runs (URLs, headers, auth files, filters, TLS
/// material) but nothing is created or written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuildMode {
    /// A real generation — filesystem side effects allowed.
    Live,
    /// A `verd validate` dry run — read-only.
    Check,
}

impl BuildMode {
    /// Filesystem writes permitted?
    pub fn live(self) -> bool {
        matches!(self, Self::Live)
    }
}
