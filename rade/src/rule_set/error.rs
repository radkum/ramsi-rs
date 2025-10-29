use thiserror_no_std::Error;

use crate::utils;

pub type RuleSetResult<T> = core::result::Result<T, RuleSetError>;
pub type RuleResult<T> = core::result::Result<T, RuleError>;

#[derive(Error, Debug)]
pub enum RuleSetError {
    #[error("Bincode deserialize error: {0}")]
    BincodeDeserializeError(#[from] bincode::error::DecodeError),
    #[error("Bincode serialize error: {0}")]
    BincodeSerializeError(#[from] bincode::error::EncodeError),
    #[error("Incorrect magic. Found '{current}'")]
    IncorrectMagicError { current: String },
    #[error("Incorrect checksum. Expected '{expected}' but found '{current}'")]
    IncorrectChecksumError { current: String, expected: String },
    #[error("Incorrect file size. Size: '{size}'")]
    IncorrectFileSizeError { size: u64 },
    #[error("Incorrect signature size. Size: '{size}'")]
    IncorrectSignatureSizeError { size: u32 },
    #[error("Incorrect signature. Info: '{info}'")]
    IncorrectSignatureError { info: String },
    #[error("IoError: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Given property doesn't exist in map: {0}")]
    NoSuchPropertyError(String),
    #[error("Can't convert OsString to String. After to_string_lossy(): {0}")]
    OsStringError(String),
    #[error("Serde yaml error: {0}")]
    SerdeYamlError(#[from] serde_yaml_bw::Error),
    #[error("Sha Error: {0}")]
    ShaError(#[from] utils::ShaError),
}

impl core::error::Error for RuleSetError {}

#[derive(Error, Debug)]
pub enum RuleError {
    #[error("Serde yaml error: {0}")]
    SerdeYaml(#[from] serde_yaml_bw::Error),
    #[error("Failed to read rule: {0}")]
    Io(#[from] std::io::Error),
}
impl core::error::Error for RuleError {}
