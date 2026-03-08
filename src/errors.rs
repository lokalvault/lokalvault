use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AppError {
    WrongPassword,
    VaultNotFound,
    VaultCorrupted,
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
    RateLimited,
    IoError(String),
    SerdeError(String),
    IpcError(String),
}

impl AppError {
    pub fn message(&self) -> String {
        match self {
            Self::WrongPassword => "wrong password".to_string(),
            Self::VaultNotFound => "vault not found".to_string(),
            Self::VaultCorrupted => "vault corrupted".to_string(),
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
            Self::RateLimited => "rate limited".to_string(),
            Self::IoError(message) => message.clone(),
            Self::SerdeError(message) => message.clone(),
            Self::IpcError(message) => message.clone(),
        }
    }
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message())
    }
}

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
}
