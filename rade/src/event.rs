mod serializer;

use serde::{Deserialize, Serialize};

use crate::FatString;

type Result<T> = core::result::Result<T, Box<dyn core::error::Error>>;

#[derive(Debug, Serialize, Deserialize)]
pub struct Events(Vec<Event>);
impl Events {
    pub fn iter(&self) -> core::slice::Iter<Event> {
        self.0.iter()
    }
}

impl Events {
    pub fn new(events: Vec<Event>) -> Self {
        Self(events)
    }

    #[cfg(feature = "std")]
    pub fn serialize<W: std::io::Write>(&self, out: W) -> Result<()> {
        // let data = self.serialize_to_bytes()?;
        // out.write_all(&data)?;
        Ok(serde_yaml_bw::to_writer(out, self)?)
    }

    // pub(crate) fn serialize_to_bytes(&self) -> Result<Vec<u8>> {
    //     Ok(bincode::serde::encode_to_vec(&self.0, BIN_CONFIG)?)
    // }

    #[cfg(feature = "std")]
    pub fn deserialize<R: std::io::Read>(io_reader: R) -> Result<Self> {
        // let mut data = vec![];
        // let _size = io_reader.read_to_end(&mut data)?;
        // Self::deserialize_from_bytes(&mut data)
        Ok(serde_yaml_bw::from_reader(io_reader)?)
    }

    // pub(crate) fn deserialize_from_bytes(data: &mut Vec<u8>) -> Result<Self> {
    //     let events: Events =
    //         bincode::serde::decode_from_slice(&data, BIN_CONFIG)?.0;
    //     Ok(events)
    // }
}

#[derive(Debug, Clone)]
pub struct Event {
    pub pid: Option<u64>,
    pub tid: Option<u64>,
    pub file_name: Option<FatString>,
    pub app_name: Option<FatString>,
    pub content_name: Option<FatString>,
    pub content: Option<FatString>,
    pub content_tokens: Option<Vec<FatString>>,
    pub session: Option<u64>,
    pub request_number: Option<u64>,
}

impl Event {
    pub fn new(
        pid: Option<u64>,
        tid: Option<u64>,
        file_name: Option<FatString>,
        app_name: Option<FatString>,
        content_name: Option<FatString>,
        content: Option<FatString>,
        session: Option<u64>,
        request_number: Option<u64>,
    ) -> Self {
        Self {
            pid,
            tid,
            file_name,
            app_name,
            content_name,
            content_tokens: content.as_ref().map(|s| {
                s.plain
                    .split_ascii_whitespace()
                    .filter_map(|token| {
                        if !token.is_empty() {
                            Some(FatString::from(token.to_string()))
                        } else {
                            None
                        }
                    })
                    .collect::<Vec<FatString>>()
            }),
            content,
            session,
            request_number,
        }
    }
}
