mod serializer;

use std::fs::read_to_string;

use anyhow::anyhow;
use serde::{Deserialize, Serialize};

use crate::{FatString, Result};

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct Events(Vec<Event>);
impl Events {
    pub fn iter(&self) -> core::slice::Iter<'_, Event> {
        self.0.iter()
    }

    fn add_event(&mut self, event: Event) {
        self.0.push(event);
    }

    #[cfg(feature = "std")]
    pub fn from_dir(path: &std::path::Path) -> Result<Self> {
        fn imp_from_dir(path: &std::path::Path, events: &mut Events) -> Result<()> {
            if path.is_file() {
                let content = read_to_string(path)
                    .map_err(|err| anyhow!("Failed to read file {}: {:?}", path.display(), err))?;
                let event = serde_yaml_bw::from_str::<Event>(&content)?;
                events.add_event(event);
            } else if path.is_dir() {
                let events_dir = std::fs::read_dir(path)?;
                for event_dir_entry in events_dir {
                    let Ok(event) = event_dir_entry else {
                        log::warn!("Failed to read dir entry from path",);
                        continue;
                    };

                    if let Err(err) = imp_from_dir(&event.path(), events) {
                        println!(
                            "Failed to read event from path: {:?}, error: {:?}",
                            event.path(),
                            err
                        );
                    }
                }
            } else {
                Err(anyhow::anyhow!(
                    "Path {} is neither file nor directory",
                    path.display()
                ))?;
            }
            Ok(())
        }
        let mut events = Events::default();
        imp_from_dir(path, &mut events)?;
        Ok(events)
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
