pub mod constants;
pub mod ffi_string;

pub use ffi_string::{FfiString, PipeName};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RamsiMessage {
    message: String,
}

impl RamsiMessage {
    pub fn new(msg: &str) -> Self {
        RamsiMessage {
            message: msg.to_string(),
        }
    }
}

impl std::fmt::Display for RamsiMessage {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(fmt, "{}", self.message)
    }
}
