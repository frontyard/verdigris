//! `respond` handler: fixed status, body template and headers.

use http::{HeaderName, HeaderValue, StatusCode};

use super::{BuildError, RequestCtx};
use crate::body::BoxBody;
use crate::config::model as cfg;

/// Compiled `respond` handler.
#[derive(Debug)]
pub struct Respond {
    status: StatusCode,
    body: String,
    headers: Vec<(HeaderName, HeaderValue)>,
}

impl Respond {
    /// Build from config.
    pub fn build(c: &cfg::RespondHandler, _site: &str) -> Result<Self, BuildError> {
        Ok(Self {
            status: super::compile_status(c.status)?,
            body: c.body.clone(),
            headers: super::compile_headers(&c.headers)?,
        })
    }

    /// Produce the fixed response; `{path}`, `{host}`, `{method}`,
    /// `{scheme}` placeholders substitute from the request.
    pub fn handle(
        &self,
        req: &http::Request<BoxBody>,
        ctx: &RequestCtx,
    ) -> http::Response<BoxBody> {
        let body = super::substitute(&self.body, req, ctx);
        super::response(self.status, self.headers.clone(), body, req.method())
    }
}
