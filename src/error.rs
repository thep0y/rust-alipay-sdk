use std::{fmt::Display, string, time::SystemTimeError};

#[derive(Debug)]
pub struct HttpError {
    result: String,
    msg: String,
}

impl HttpError {
    pub(crate) fn new(result: &str, msg: &str) -> Self {
        Self {
            result: result.to_owned(),
            msg: msg.to_owned(),
        }
    }
}

impl Display for HttpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{{result: {}, msg: {}}}", self.result, self.msg)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("{0}")]
    X509(String),
    #[error(transparent)]
    FromUtf8(#[from] string::FromUtf8Error),
    #[error("{0}")]
    Config(String),
    #[error(transparent)]
    Ureq(#[from] ureq::Error),
    #[error("{0}")]
    Params(String),
    #[error(transparent)]
    Base64(#[from] base64ct::Error),
    #[error(transparent)]
    Time(#[from] SystemTimeError),
    #[error("sign failed: {0}")]
    Sign(String),
    #[error("http error: {0}")]
    Http(HttpError),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

pub type AlipayResult<T> = std::result::Result<T, Error>;
