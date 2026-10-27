//! Shared error types.

/// A boxed error usable across the async data plane.
pub type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;
