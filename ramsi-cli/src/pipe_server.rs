use std::{
    ffi::CString,
    mem::zeroed,
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
    time::Duration,
};

use serde::de::DeserializeOwned;
use serde_json::from_slice;
use shared::{
    ScanEvent,
    constants::{MAX_MESSAGE_LEN, PIPE_SDDL},
};
use thiserror::Error;
use tokio::{
    io::AsyncReadExt,
    net::windows::named_pipe::{NamedPipeServer, ServerOptions},
    time::timeout,
};
use windows::Win32::{
    Foundation::{FILETIME, HANDLE, HLOCAL, LocalFree},
    Security::{
        Authorization::ConvertSidToStringSidW, GetTokenInformation, SECURITY_ATTRIBUTES,
        TOKEN_QUERY, TOKEN_USER, TokenUser,
    },
    System::{
        Pipes::GetNamedPipeClientProcessId,
        Threading::{
            GetProcessTimes, OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
        },
    },
};
use windows_core::{PCSTR, PWSTR};

#[derive(Error, Debug)]
pub enum PipeError {
    #[error("Io error: {0}")]
    IoError(std::io::Error),

    #[error("Timeout")]
    Timeout,

    #[error("UnexpectedEof")]
    UnexpectedEof,
}

impl From<std::io::Error> for PipeError {
    fn from(err: std::io::Error) -> Self {
        if err.kind() == std::io::ErrorKind::TimedOut {
            Self::Timeout
        } else if err.kind() == std::io::ErrorKind::UnexpectedEof {
            Self::UnexpectedEof
        } else {
            Self::IoError(err)
        }
    }
}

pub async fn message<M: DeserializeOwned>(
    pipe: &mut NamedPipeServer,
) -> core::result::Result<M, PipeError> {
    Ok(read::<M, _>(pipe, BODY_TIMEOUT).await?)
}

// once the length arrived, the rest of the message must follow within this time
const BODY_TIMEOUT: Duration = Duration::from_secs(5);

pub async fn read<M: DeserializeOwned, R: AsyncReadExt + std::marker::Unpin>(
    pipe: &mut R,
    body_timeout: Duration,
) -> std::io::Result<M> {
    // no timeout here: read_u64 is not cancel-safe and an idle client is fine
    let message_length = pipe.read_u64().await?;
    if message_length > MAX_MESSAGE_LEN {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("Message too long: {message_length} bytes"),
        ));
    }
    // grows with the data instead of allocating the claimed length up front
    let mut buffer = Vec::new();
    let mut body = AsyncReadExt::take(&mut *pipe, message_length);
    timeout(body_timeout, body.read_to_end(&mut buffer)).await??;
    if buffer.len() as u64 != message_length {
        return Err(std::io::ErrorKind::UnexpectedEof.into());
    }
    Ok(from_slice::<M>(&buffer)?)
}

pub fn create_first_server(pipe_name: &str) -> std::io::Result<NamedPipeServer> {
    create_writer_with_security_attrs(pipe_name, true)
}

pub fn create_server(pipe_name: &str) -> std::io::Result<NamedPipeServer> {
    create_writer_with_security_attrs(pipe_name, false)
}

pub fn create_writer_with_security_attrs(
    pipe_name: &str,
    first: bool,
) -> std::io::Result<NamedPipeServer> {
    use windows::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorA, SDDL_REVISION_1,
    };

    let input = CString::new(PIPE_SDDL)?;

    let mut attributes: SECURITY_ATTRIBUTES = unsafe { zeroed() };

    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorA(
            PCSTR::from_raw(input.as_ptr() as *const _),
            SDDL_REVISION_1,
            &mut attributes.lpSecurityDescriptor as *mut _ as _,
            None,
        )?;
    }

    let server = unsafe {
        ServerOptions::new()
            .first_pipe_instance(first)
            .create_with_security_attributes_raw(pipe_name, &mut attributes as *mut _ as _)
    };
    unsafe { LocalFree(Some(HLOCAL(attributes.lpSecurityDescriptor))) };
    server
}

// the client process as the kernel sees it, any process may write to the pipe
pub struct ClientIdentity {
    pid: u32,
    process_created: Option<String>,
    user_sid: Option<String>,
}

impl ClientIdentity {
    pub fn of(pipe: &NamedPipeServer) -> std::io::Result<Self> {
        let mut pid = 0;
        unsafe { GetNamedPipeClientProcessId(HANDLE(pipe.as_raw_handle()), &mut pid)? };
        let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }
            .ok()
            .map(|h| unsafe { OwnedHandle::from_raw_handle(h.0) });
        let handle = process.as_ref().map(|p| HANDLE(p.as_raw_handle()));
        Ok(Self {
            pid,
            process_created: handle.and_then(process_created),
            user_sid: handle.and_then(user_sid),
        })
    }

    pub fn apply(&self, event: &mut ScanEvent) {
        if event.pid != self.pid {
            log::warn!("Client {} sent an event for pid {}", self.pid, event.pid);
            event.pid = self.pid;
        }
        event.process_created = self.process_created.clone();
        event.user_sid = self.user_sid.clone();
    }
}

// with the pid, it tells the process apart from a later one reusing the pid
fn process_created(process: HANDLE) -> Option<String> {
    let mut times = [FILETIME::default(); 4];
    let [created, exited, kernel, user] = &mut times;
    unsafe { GetProcessTimes(process, created, exited, kernel, user) }.ok()?;
    let ticks = (u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime);
    // FILETIME counts 100 ns since 1601-01-01
    let unix_nanos = (ticks as i64 - 116_444_736_000_000_000) * 100;
    Some(
        chrono::DateTime::from_timestamp_nanos(unix_nanos)
            .to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true),
    )
}

fn user_sid(process: HANDLE) -> Option<String> {
    let mut token = HANDLE::default();
    unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) }.ok()?;
    let token = unsafe { OwnedHandle::from_raw_handle(token.0) };
    // u64 keeps TOKEN_USER aligned
    let mut buf = [0u64; 64];
    let mut size = 0;
    unsafe {
        GetTokenInformation(
            HANDLE(token.as_raw_handle()),
            TokenUser,
            Some(buf.as_mut_ptr() as _),
            size_of_val(&buf) as u32,
            &mut size,
        )
    }
    .ok()?;
    let user = unsafe { &*(buf.as_ptr() as *const TOKEN_USER) };
    let mut text = PWSTR::null();
    unsafe { ConvertSidToStringSidW(user.User.Sid, &mut text) }.ok()?;
    let sid = unsafe { text.to_string() }.ok();
    unsafe { LocalFree(Some(HLOCAL(text.0 as _))) };
    sid
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn first_server_fails_when_pipe_exists() {
        let name = format!(r"\\.\pipe\ramsi-cli-test-{}", std::process::id());
        let _server = create_first_server(&name).unwrap();
        let _next = create_server(&name).unwrap();
        assert!(create_first_server(&name).is_err());
    }

    #[tokio::test]
    async fn identity_comes_from_the_client_process() {
        use tokio::net::windows::named_pipe::ClientOptions;

        let name =
            shared::PipeName::from_suffix(&format!("ramsi-cli-identity-{}", std::process::id()))
                .to_string();
        let server = create_first_server(&name).unwrap();
        let _client = ClientOptions::new().open(&name).unwrap();
        server.connect().await.unwrap();

        let identity = ClientIdentity::of(&server).unwrap();
        let mut event: ScanEvent = serde_json::from_str(&format!(
            r#"{{"time":"","pid":{},"tid":0,"process":"","cmd_line":"","app_name":"",
            "content_name":"","session":0,"request_number":0,"status":"detected",
            "reason":null,"blocked":false,"content":"","content_truncated":false,
            "process_created":"forged","user_sid":"S-1-5-18"}}"#,
            std::process::id() + 4
        ))
        .unwrap();
        identity.apply(&mut event);

        assert_eq!(event.pid, std::process::id());
        let created = event.process_created.unwrap();
        assert!(created.starts_with("20"), "{created}");
        let sid = event.user_sid.unwrap();
        assert!(sid.starts_with("S-1-5-") && sid != "S-1-5-18", "{sid}");
    }

    #[tokio::test]
    async fn rejects_oversized_message_length() {
        let mut input: &[u8] = &u64::MAX.to_be_bytes();
        let err = read::<String, _>(&mut input, Duration::from_secs(1))
            .await
            .unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn reads_length_prefixed_json() {
        let json = br#""hello""#;
        let mut input = (json.len() as u64).to_be_bytes().to_vec();
        input.extend_from_slice(json);
        let msg: String = read(&mut input.as_slice(), Duration::from_secs(1))
            .await
            .unwrap();
        assert_eq!(msg, "hello");
    }

    #[tokio::test]
    async fn stalled_body_times_out() {
        use tokio::io::AsyncWriteExt;

        let (mut client, mut server) = tokio::io::duplex(64);
        client.write_u64(10).await.unwrap();
        client.write_all(b"abc").await.unwrap();

        let err = read::<String, _>(&mut server, Duration::from_millis(100))
            .await
            .unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
    }

    #[tokio::test]
    async fn waits_for_a_slow_length_prefix() {
        use tokio::io::AsyncWriteExt;

        let (mut client, mut server) = tokio::io::duplex(64);
        let reader =
            tokio::spawn(
                async move { read::<String, _>(&mut server, Duration::from_secs(1)).await },
            );
        let json = br#""hi""#;
        client
            .write_all(&(json.len() as u64).to_be_bytes()[..3])
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(1500)).await;
        client
            .write_all(&(json.len() as u64).to_be_bytes()[3..])
            .await
            .unwrap();
        client.write_all(json).await.unwrap();

        assert_eq!(reader.await.unwrap().unwrap(), "hi");
    }
}
