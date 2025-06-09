pub mod constants;

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
