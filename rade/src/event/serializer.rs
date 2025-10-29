use serde::Serialize;

use super::{Event, FatString};

#[derive(serde::Deserialize, Serialize)]
struct EventSerialized {
    pid: Option<u64>,
    tid: Option<u64>,
    file_name: Option<String>,
    app_name: Option<String>,
    content_name: Option<String>,
    content: Option<String>,
    session: Option<u64>,
    request_number: Option<u64>,
}

impl<'de> serde::Deserialize<'de> for Event {
    fn deserialize<D>(deserializer: D) -> core::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let helper = EventSerialized::deserialize(deserializer)?;
        Ok(Event {
            pid: helper.pid,
            tid: helper.tid,
            file_name: helper.file_name.map(FatString::from),
            app_name: helper.app_name.map(FatString::from),
            content_name: helper.content_name.map(FatString::from),
            content: helper.content.clone().map(FatString::from),
            content_tokens: helper.content.map(|s| {
                s.split_ascii_whitespace()
                    .filter_map(|token| {
                        if !token.is_empty() {
                            Some(FatString::from(token.to_string()))
                        } else {
                            None
                        }
                    })
                    .collect::<Vec<FatString>>()
            }),
            session: helper.session,
            request_number: helper.request_number,
        })
    }
}

impl From<&Event> for EventSerialized {
    fn from(event: &Event) -> Self {
        EventSerialized {
            pid: event.pid,
            tid: event.tid,
            file_name: event.file_name.as_ref().map(|s| s.plain.clone()),
            app_name: event.app_name.as_ref().map(|s| s.plain.clone()),
            content_name: event.content_name.as_ref().map(|s| s.plain.clone()),
            content: event.content.as_ref().map(|s| s.plain.clone()),
            session: event.session,
            request_number: event.request_number,
        }
    }
}
impl From<&EventSerialized> for Event {
    fn from(event: &EventSerialized) -> Self {
        Event {
            pid: event.pid,
            tid: event.tid,
            file_name: event.file_name.as_ref().map(FatString::from),
            app_name: event.app_name.as_ref().map(FatString::from),
            content_name: event.content_name.as_ref().map(FatString::from),
            content: event.content.as_ref().map(FatString::from),
            content_tokens: event.content.as_ref().map(|s| {
                s.split_ascii_whitespace()
                    .filter_map(|token| {
                        if !token.is_empty() {
                            Some(FatString::from(token.to_string()))
                        } else {
                            None
                        }
                    })
                    .collect::<Vec<FatString>>()
            }),
            session: event.session,
            request_number: event.request_number,
        }
    }
}

impl serde::Serialize for Event {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let val_ser = EventSerialized::from(self);
        val_ser.serialize(serializer)
    }
}
