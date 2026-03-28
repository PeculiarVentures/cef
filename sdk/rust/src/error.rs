//! CEF error types.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum CefError {
    #[error("cef: {0}")]
    General(String),

    #[error("cef: crypto: {0}")]
    Crypto(String),

    #[error("cef: COSE: {0}")]
    Cose(String),

    #[error("cef: container: {0}")]
    Container(String),

    #[error("cef: manifest: {0}")]
    Manifest(String),

    #[error("cef: {0}")]
    Io(#[from] std::io::Error),
}
