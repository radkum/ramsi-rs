mod fat_string;
use alloc::{string::String, vec::Vec};
use core::fmt;

use bincode::config::{Configuration, Fixint, LittleEndian, NoLimit};
pub use fat_string::{FatString, InsensitiveFlag};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use thiserror_no_std::Error;

pub type Result<T> = core::result::Result<T, Box<dyn core::error::Error>>;
pub type ShaResult<T> = core::result::Result<T, ShaError>;
pub(crate) const BIN_CONFIG: Configuration<LittleEndian, Fixint, NoLimit> =
    bincode::config::legacy();

#[derive(Error, Debug)]
pub enum ShaError {
    #[error("Sha string must have 32 chars not {string_len}")]
    IncorrectStringLen { string_len: usize },
    #[error("ToHex error: {0}")]
    ToHexError(#[from] hex::FromHexError),
}

pub const SHA256_LEN: usize = 32;

#[derive(Default, Serialize, Deserialize)]
pub struct Sha256Buff([u8; SHA256_LEN]);

impl Sha256Buff {
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    pub fn from_vec(v: Vec<u8>) -> Self {
        let mut hasher = sha2::Sha256::new();
        hasher.update(v);

        let mut checksum_buf = Sha256Buff::default();
        checksum_buf.0.copy_from_slice(&hasher.finalize()[..]);
        checksum_buf
    }

    pub fn from_bytes(v: &[u8]) -> Self {
        Self::from_vec(v.to_vec())
    }

    pub fn from_string(s: String) -> Self {
        let mut hasher = sha2::Sha256::new();
        hasher.update(s.as_bytes());

        let mut checksum_buf = Sha256Buff::default();
        checksum_buf.0.copy_from_slice(&hasher.finalize()[..]);
        checksum_buf
    }

    pub fn from_sha_string(s: &str) -> ShaResult<Self> {
        let mut sha = Sha256Buff::default();
        let v = hex::decode(s)?;

        if v.len() != SHA256_LEN {
            return Err(ShaError::IncorrectStringLen {
                string_len: v.len(),
            });
        }
        sha.0.copy_from_slice(&v);
        Ok(sha)
    }

    pub fn from_vec_of_vec(vec: Vec<Vec<u8>>) -> Sha256Buff {
        let mut hasher = sha2::Sha256::new();

        for v in vec {
            hasher.update(v);
        }

        let mut checksum_buf = Sha256Buff::default();
        checksum_buf.0.copy_from_slice(&hasher.finalize()[..]);
        checksum_buf
    }
}

impl fmt::Display for Sha256Buff {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode_upper(self.as_slice()))
    }
}
