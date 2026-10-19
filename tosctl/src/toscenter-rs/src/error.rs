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
    /// The server answered with a well-formed JSON-RPC error object. A
    /// `RATE_LIMITED` refusal is reported as [`ToscenterError::RateLimitExceeded`]
    /// instead; every other reason arrives here.
    Rpc(RpcError),
}

/// A JSON-RPC error object as the server sent it, after validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpcError {
    /// The HTTP status the error arrived with: 200 for every method-level
    /// error, 401/404/405/415/429 for refusals made before a method runs.
    pub http_status: u16,
    /// The JSON-RPC error code.
    pub code: i64,
    /// The server's message, truncated to a bounded length.
    pub message: String,
    /// The typed reason from `error.data.reason`.
    pub reason: RpcErrorReason,
    /// Whether the same request may succeed when repeated later.
    pub retryable: bool,
}

/// The `error.data.reason` values the server defines. A reason this client
/// does not know is kept verbatim in [`RpcErrorReason::Unrecognized`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RpcErrorReason {
    ParseError,
    InvalidRequest,
    MethodNotFound,
    WriteDisabled,
    InvalidArgument,
    InternalError,
    Unauthorized,
    RateLimited,
    NotFound,
    ConfigParamAbsent,
    BlockUnavailable,
    PermissionSourceUnsupported,
    PermissionSourceDeferred,
    IndexedStateStale,
    LifecycleImmutable,
    ContractKindUnsupported,
    UpstreamUnavailable,
    UnsignedBlock,
    BlockIdMismatch,
    EvidenceInvalid,
    UnsupportedCarrier,
    StateInvalid,
    ResourceLimit,
    VerificationBackendFailure,
    Unrecognized(String),
}

/// Every known reason with its wire name, JSON-RPC code and retryability.
const KNOWN_REASONS: &[(RpcErrorReason, &str, i64, bool)] = &[
    (RpcErrorReason::ParseError, "PARSE_ERROR", -32700, false),
    (RpcErrorReason::InvalidRequest, "INVALID_REQUEST", -32600, false),
    (RpcErrorReason::MethodNotFound, "METHOD_NOT_FOUND", -32601, false),
    (RpcErrorReason::WriteDisabled, "WRITE_DISABLED", -32601, false),
    (RpcErrorReason::InvalidArgument, "INVALID_ARGUMENT", -32602, false),
    (RpcErrorReason::InternalError, "INTERNAL_ERROR", -32603, false),
    (RpcErrorReason::Unauthorized, "UNAUTHORIZED", -32000, false),
    (RpcErrorReason::RateLimited, "RATE_LIMITED", -32005, true),
    (RpcErrorReason::NotFound, "NOT_FOUND", -32004, false),
    (RpcErrorReason::ConfigParamAbsent, "CONFIG_PARAM_ABSENT", -32004, false),
    (RpcErrorReason::BlockUnavailable, "BLOCK_UNAVAILABLE", -32004, false),
    (RpcErrorReason::PermissionSourceUnsupported, "PERMISSION_SOURCE_UNSUPPORTED", -32006, false),
    (RpcErrorReason::PermissionSourceDeferred, "PERMISSION_SOURCE_DEFERRED", -32006, false),
    (RpcErrorReason::IndexedStateStale, "INDEXED_STATE_STALE", -32006, false),
    (RpcErrorReason::LifecycleImmutable, "LIFECYCLE_IMMUTABLE", -32006, false),
    (RpcErrorReason::ContractKindUnsupported, "CONTRACT_KIND_UNSUPPORTED", -32006, false),
    (RpcErrorReason::UpstreamUnavailable, "UPSTREAM_UNAVAILABLE", -32603, true),
    (RpcErrorReason::UnsignedBlock, "UNSIGNED_BLOCK", -32602, false),
    (RpcErrorReason::BlockIdMismatch, "BLOCK_ID_MISMATCH", -32009, false),
    (RpcErrorReason::EvidenceInvalid, "EVIDENCE_INVALID", -32603, false),
    (RpcErrorReason::UnsupportedCarrier, "UNSUPPORTED_CARRIER", -32603, false),
    (RpcErrorReason::StateInvalid, "STATE_INVALID", -32603, false),
    (RpcErrorReason::ResourceLimit, "RESOURCE_LIMIT", -32603, false),
    (RpcErrorReason::VerificationBackendFailure, "VERIFICATION_BACKEND_FAILURE", -32603, true),
];

impl RpcErrorReason {
    /// The reason for a wire name; an unknown name is kept as
    /// [`RpcErrorReason::Unrecognized`].
    pub fn from_wire(name: &str) -> RpcErrorReason {
        KNOWN_REASONS
            .iter()
            .find(|(_, wire, _, _)| *wire == name)
            .map(|(reason, _, _, _)| reason.clone())
            .unwrap_or_else(|| RpcErrorReason::Unrecognized(name.to_string()))
    }

    /// The wire name, as `error.data.reason` carries it.
    pub fn as_str(&self) -> &str {
        match self {
            RpcErrorReason::Unrecognized(name) => name,
            known => KNOWN_REASONS
                .iter()
                .find(|(reason, _, _, _)| reason == known)
                .map(|(_, wire, _, _)| *wire)
                .unwrap_or("UNRECOGNIZED"),
        }
    }

    /// The code and retryability the server pairs with a known reason; `None`
    /// for an unrecognized one.
    pub fn expected_code_and_retryable(&self) -> Option<(i64, bool)> {
        KNOWN_REASONS
            .iter()
            .find(|(reason, _, _, _)| reason == self)
            .map(|(_, _, code, retryable)| (*code, *retryable))
    }
}

impl fmt::Display for RpcErrorReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl fmt::Display for RpcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "JSON-RPC error {} {} (retryable: {}): {}",
            self.code, self.reason, self.retryable, self.message
        )
    }
}

#[derive(Debug)]
pub enum InvalidInput {
    HeaderValue(InvalidHeaderValue),
    UrlParse(UrlParseError),
    /// A request parameter the server would refuse, caught before sending.
    Parameter(String),
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
            ToscenterError::Rpc(error) => write!(f, "{error}"),
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
            InvalidInput::Parameter(message) => write!(f, "Invalid parameter: {}", message),
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
