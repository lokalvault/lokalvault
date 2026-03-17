use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AppError {
    WrongPassword,
    VaultNotFound,
    VaultCorrupted(String),
    UnsupportedVaultVersion(u8),
    ProjectNotFound(String),
    SecretNotFound(String),
    ProjectAlreadyExists(String),
    SecretAlreadyExists(String),
    InvalidProjectName(String),
    InvalidSecretKey(String),
    ValidationError(String),
    DaemonNotRunning,
    TokenInvalid,
    TokenExpired,
    PidMismatch,
    UidMismatch,
    ApprovalDenied(String),
    RateLimited(Option<u64>),
    InvalidResponse(String),
    ClipboardError(String),
    ProcessError(String),
    ConfigError(String),
    CryptoError(String),
    IoError(String),
    SerdeError(String),
    IpcError(String),
}

impl AppError {
    pub fn message(&self) -> String {
        match self {
            Self::WrongPassword => "wrong password".to_string(),
            Self::VaultNotFound => "vault not found".to_string(),
            Self::VaultCorrupted(message) => message.clone(),
            Self::UnsupportedVaultVersion(version) => {
                format!("unsupported vault version: {version}")
            }
            Self::ProjectNotFound(name) => format!("project not found: {name}"),
            Self::SecretNotFound(name) => format!("secret not found: {name}"),
            Self::ProjectAlreadyExists(name) => format!("project already exists: {name}"),
            Self::SecretAlreadyExists(name) => format!("secret already exists: {name}"),
            Self::InvalidProjectName(message) => message.clone(),
            Self::InvalidSecretKey(message) => message.clone(),
            Self::ValidationError(message) => message.clone(),
            Self::DaemonNotRunning => "daemon not running".to_string(),
            Self::TokenInvalid => "token invalid".to_string(),
            Self::TokenExpired => "token expired".to_string(),
            Self::PidMismatch => "client-reported pid mismatch".to_string(),
            Self::UidMismatch => "client-reported uid mismatch".to_string(),
            Self::ApprovalDenied(message) => message.clone(),
            Self::RateLimited(Some(retry_after_ms)) => {
                format!("rate limit exceeded — retry after {retry_after_ms}ms")
            }
            Self::RateLimited(None) => "rate limit exceeded".to_string(),
            Self::InvalidResponse(message) => message.clone(),
            Self::ClipboardError(message) => message.clone(),
            Self::ProcessError(message) => message.clone(),
            Self::ConfigError(message) => message.clone(),
            Self::CryptoError(message) => message.clone(),
            Self::IoError(message) => message.clone(),
            Self::SerdeError(message) => message.clone(),
            Self::IpcError(message) => message.clone(),
        }
    }

    pub fn from_daemon_message(message: &str) -> Self {
        match message {
            "daemon not running" => Self::DaemonNotRunning,
            "token invalid" | "action token invalid" => Self::TokenInvalid,
            "token expired" | "action token expired" => Self::TokenExpired,
            "client-reported pid mismatch" | "action token pid mismatch" => Self::PidMismatch,
            "client-reported uid mismatch" | "action token uid mismatch" => Self::UidMismatch,
            "approval denied" => Self::ApprovalDenied("approval denied".to_string()),
            "daemon returned empty response" => {
                Self::InvalidResponse("daemon returned empty response".to_string())
            }
            _ if message.starts_with("rate limit exceeded") => {
                let retry_after_ms = message
                    .split("retry after ")
                    .nth(1)
                    .and_then(|value| value.strip_suffix("ms"))
                    .and_then(|value| value.parse::<u64>().ok());
                Self::RateLimited(retry_after_ms)
            }
            _ => Self::IpcError(message.to_string()),
        }
    }

    pub fn from_daemon_response(response: &serde_json::Value) -> Self {
        response
            .get("error")
            .and_then(serde_json::Value::as_str)
            .map(Self::from_daemon_message)
            .unwrap_or_else(|| Self::InvalidResponse("unknown daemon error".to_string()))
    }
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message())
    }
}

impl std::error::Error for AppError {}

impl From<std::io::Error> for AppError {
    fn from(error: std::io::Error) -> Self {
        Self::IoError(error.to_string())
    }
}

impl From<serde_json::Error> for AppError {
    fn from(error: serde_json::Error) -> Self {
        Self::SerdeError(error.to_string())
    }
}

impl From<String> for AppError {
    fn from(error: String) -> Self {
        Self::IoError(error)
    }
}

impl From<toml::de::Error> for AppError {
    fn from(error: toml::de::Error) -> Self {
        Self::ConfigError(error.to_string())
    }
}

impl From<toml::ser::Error> for AppError {
    fn from(error: toml::ser::Error) -> Self {
        Self::ConfigError(error.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_display_for_domain_errors() {
        assert_eq!(AppError::WrongPassword.to_string(), "wrong password");
        assert_eq!(
            AppError::ProjectNotFound("my-app".to_string()).to_string(),
            "project not found: my-app"
        );
        assert_eq!(
            AppError::SecretAlreadyExists("OPENAI_KEY".to_string()).to_string(),
            "secret already exists: OPENAI_KEY"
        );
    }

    #[test]
    fn test_display_for_validation_errors() {
        assert_eq!(
            AppError::InvalidProjectName("bad project name".to_string()).to_string(),
            "bad project name"
        );
        assert_eq!(
            AppError::InvalidSecretKey("bad secret key".to_string()).to_string(),
            "bad secret key"
        );
    }

    #[test]
    fn test_error_conversions_preserve_messages() {
        let io_error = AppError::from(std::io::Error::other("disk full"));
        let serde_error =
            AppError::from(serde_json::from_str::<serde_json::Value>("{").unwrap_err());

        assert_eq!(io_error.to_string(), "disk full");
        assert!(serde_error.to_string().contains("EOF while parsing"));
    }

    #[test]
    fn test_from_daemon_message_parses_rate_limit_retry_after() {
        assert_eq!(
            AppError::from_daemon_message("rate limit exceeded — retry after 250ms"),
            AppError::RateLimited(Some(250))
        );
    }

    #[test]
    fn test_from_daemon_response_maps_known_error() {
        let response = serde_json::json!({ "ok": false, "error": "token invalid" });
        assert_eq!(
            AppError::from_daemon_response(&response),
            AppError::TokenInvalid
        );
    }

    #[test]
    fn test_from_daemon_response_maps_unknown_error_to_ipc_error() {
        let response = serde_json::json!({ "ok": false, "error": "unexpected boom" });
        assert_eq!(
            AppError::from_daemon_response(&response),
            AppError::IpcError("unexpected boom".to_string())
        );
    }
}
