mod error;
mod rule;
mod rules;

use core::mem::size_of;

pub use error::*;
pub use rule::*;
pub use rules::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::utils::{BIN_CONFIG, Sha256Buff};

#[derive(Deserialize, Serialize, Default)]
pub struct RuleSetHeader {
    magic: u32,
    checksum: Sha256Buff,
    //elem_count: u32,
}

impl RuleSetHeader {
    const HEADER_SIZE: usize = size_of::<Self>();
    const MAGIC: u32 = 0x45444152; // "RADE"

    pub fn verify_magic(&self) -> Result<(), RuleSetError> {
        if Self::MAGIC != self.magic {
            return Err(RuleSetError::IncorrectMagicError {
                current: String::from_utf8_lossy(&self.magic.to_le_bytes()).into(),
            });
        }
        Ok(())
    }

    pub fn verify_sha256(&self, calculated_checksum: Sha256Buff) -> Result<(), RuleSetError> {
        if calculated_checksum.as_slice() != self.checksum.as_slice() {
            return Err(RuleSetError::IncorrectChecksumError {
                current: String::from_utf8_lossy(self.checksum.as_slice()).into(),
                expected: hex::encode(calculated_checksum.as_slice()),
            });
        }
        Ok(())
    }
}

#[derive(Deserialize, Serialize)]
pub struct RuleSet {
    header: RuleSetHeader,
    rules: Rules,
}

impl RuleSet {
    pub fn new(header: RuleSetHeader, rules: Rules) -> Self {
        Self { header, rules }
    }

    #[cfg(feature = "std")]
    pub fn serialize<W: std::io::Write>(&self, out: &mut W) -> Result<(), RuleSetError> {
        let data = self.serialize_to_bytes()?;
        out.write_all(&data)?;
        Ok(())
    }

    pub(crate) fn serialize_to_bytes(&self) -> Result<Vec<u8>, RuleSetError> {
        let mut data = Vec::new();

        let rules_data = bincode::serde::encode_to_vec(&self.rules, BIN_CONFIG)?;

        let header = RuleSetHeader {
            magic: RuleSetHeader::MAGIC,
            checksum: Self::calc_checksum(&rules_data),
        };
        let header_data = bincode::serde::encode_to_vec(header, BIN_CONFIG)?;

        data.extend(header_data);
        data.extend(rules_data);

        Ok(data)
    }

    #[cfg(feature = "std")]
    pub fn deserialize<R: std::io::Read>(mut io_reader: R) -> Result<Self, RuleSetError> {
        let mut data = vec![];
        let _size = io_reader.read_to_end(&mut data)?;
        Self::deserialize_from_bytes(&mut data)
    }

    pub(crate) fn deserialize_from_bytes(data: &mut Vec<u8>) -> Result<Self, RuleSetError> {
        if data.len() < RuleSetHeader::HEADER_SIZE {
            return Err(RuleSetError::IncorrectFileSizeError {
                size: data.len() as u64,
            });
        }

        let header_data = data
            .drain(..RuleSetHeader::HEADER_SIZE)
            .collect::<Vec<u8>>();
        let header: RuleSetHeader = bincode::serde::decode_from_slice(&header_data, BIN_CONFIG)?.0;

        header.verify_magic()?;
        header.verify_sha256(Self::calc_checksum(data))?;

        println!("before deserializing rules");
        let rules: Rules = bincode::serde::decode_from_slice(data, BIN_CONFIG)?.0;
        println!("AFTER deserializing rules");
        Ok(Self::new(header, rules))
    }

    fn calc_checksum(data: &[u8]) -> Sha256Buff {
        let mut hasher = Sha256::new();
        hasher.update(data);
        Sha256Buff::from_vec(hasher.finalize().to_vec())
    }

    pub fn retain_rules(self) -> Rules {
        self.rules
    }

    pub fn rules(&self) -> &Rules {
        &self.rules
    }
}

impl From<Rules> for RuleSet {
    fn from(rules: Rules) -> Self {
        let header = RuleSetHeader::default();
        Self::new(header, rules)
    }
}

impl From<Rule> for RuleSet {
    fn from(rule: Rule) -> Self {
        let rules = vec![rule];
        Self::from(Rules::from(rules))
    }
}
