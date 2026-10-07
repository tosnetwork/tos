use reqwest::header::InvalidHeaderValue;
use reqwest::Error as ReqwestError;
use serde_json::Error as SerdeError;
use std::error::Error;
use std::fmt;
use url::ParseError as UrlParseError;

#[derive(Debug)]
pub enum ToscenterError {
    InvalidInput(InvalidInput),
    ProcessingError(ProcessingError),
    RateLimitExceeded,
    HttpClientError {
        code: u32,
        message: String,
    },
    HttpServerError {
        code: u32,
        message: String,
    },
    /// The configured server returned a syntactically valid HTTP response
    /// whose JSON-RPC envelope cannot be associated with the request.
    ProtocolError {
        message: String,
    },
    /// The response body exceeded the client's transport limit. It is refused
    /// whole: nothing of it is read or returned.
    ResponseTooLarge {
        limit: usize,
    },
    /// A non-success HTTP status whose body was not read (it exceeded the
    /// transport limit). Only the status is kept.
    HttpStatus {
        code: u16,
    },
}

#[derive(Debug)]
pub enum InvalidInput {
    HeaderValue(InvalidHeaderValue),
    UrlParse(UrlParseError),
}

#[derive(Debug)]
pub enum ProcessingError {
    Network(ReqwestError),
    Deserialization(SerdeError),
}

impl fmt::Display for ToscenterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ToscenterError::InvalidInput(err) => write!(f, "Invalid input: {}", err),
            ToscenterError::ProcessingError(err) => write!(f, "Processing error: {}", err),
            ToscenterError::RateLimitExceeded => write!(f, "Rate limit exceeded"),
            ToscenterError::HttpClientError { code, message } => {
                write!(f, "Client error {}: {}", code, message)
            }
            ToscenterError::HttpServerError { code, message } => {
                write!(f, "Server error {}: {}", code, message)
            }
            ToscenterError::ProtocolError { message } => {
                write!(f, "JSON-RPC protocol error: {}", message)
            }
            ToscenterError::HttpStatus { code } => {
                write!(f, "HTTP status {code} with an oversized body")
            }
            ToscenterError::ResponseTooLarge { limit } => write!(
                f,
                "Server error 502: configured endpoint response exceeds the one-megabyte limit \
                 ({limit} bytes)"
            ),
        }
    }
}

impl fmt::Display for InvalidInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InvalidInput::HeaderValue(err) => write!(f, "Invalid header value: {}", err),
            InvalidInput::UrlParse(err) => write!(f, "URL parse error: {}", err),
        }
    }
}

impl fmt::Display for ProcessingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProcessingError::Network(err) => write!(f, "Network error: {}", err),
            ProcessingError::Deserialization(err) => write!(f, "Deserialization error: {}", err),
        }
    }
}

impl Error for ToscenterError {}

impl From<InvalidHeaderValue> for ToscenterError {
    fn from(err: InvalidHeaderValue) -> ToscenterError {
        ToscenterError::InvalidInput(InvalidInput::HeaderValue(err))
    }
}

impl From<UrlParseError> for ToscenterError {
    fn from(err: UrlParseError) -> ToscenterError {
        ToscenterError::InvalidInput(InvalidInput::UrlParse(err))
    }
}

impl From<ReqwestError> for ToscenterError {
    fn from(err: ReqwestError) -> ToscenterError {
        ToscenterError::ProcessingError(ProcessingError::Network(err))
    }
}

impl From<SerdeError> for ToscenterError {
    fn from(err: SerdeError) -> ToscenterError {
        ToscenterError::ProcessingError(ProcessingError::Deserialization(err))
    }
}
