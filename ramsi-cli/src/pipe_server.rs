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
use windows::{
    Wdk::System::Threading::{NtQueryInformationProcess, ProcessBasicInformation},
    Win32::{
        Foundation::{FILETIME, HANDLE, HLOCAL, LocalFree},
        Security::{
            Authorization::ConvertSidToStringSidW, GetTokenInformation, SECURITY_ATTRIBUTES,
            TOKEN_QUERY, TOKEN_USER, TokenUser,
        },
        System::{
            Pipes::{GetNamedPipeClientProcessId, GetNamedPipeClientSessionId},
            Threading::{
                GetProcessTimes, OpenProcess, OpenProcessToken, PROCESS_BASIC_INFORMATION,
                PROCESS_QUERY_LIMITED_INFORMATION,
            },
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
    parent_pid: Option<u32>,
    session_id: Option<u32>,
}

impl ClientIdentity {
    pub fn of(pipe: &NamedPipeServer) -> std::io::Result<Self> {
        let pipe = HANDLE(pipe.as_raw_handle());
        let mut pid = 0;
        unsafe { GetNamedPipeClientProcessId(pipe, &mut pid)? };
        let process = open_process(pid);
        let handle = process.as_ref().map(|p| HANDLE(p.as_raw_handle()));
        let mut session_id = 0;
        let session_id = unsafe { GetNamedPipeClientSessionId(pipe, &mut session_id) }
            .ok()
            .map(|()| session_id);
        let ticks = handle.and_then(creation_ticks);
        Ok(Self {
            pid,
            process_created: ticks.map(process_created),
            user_sid: handle.and_then(user_sid),
            parent_pid: handle.zip(ticks).and_then(|(h, t)| parent_pid(h, t)),
            session_id,
        })
    }

    // false when the event claims another pid, it cannot be trusted
    #[must_use]
    pub fn apply(&self, event: &mut ScanEvent) -> bool {
        if event.pid != self.pid {
            log::warn!("Client {} sent an event for pid {}", self.pid, event.pid);
            return false;
        }
        event.process_created = self.process_created.clone();
        event.user_sid = self.user_sid.clone();
        event.parent_pid = self.parent_pid;
        event.session_id = self.session_id;
        true
    }
}

fn open_process(pid: u32) -> Option<OwnedHandle> {
    unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }
        .ok()
        .map(|h| unsafe { OwnedHandle::from_raw_handle(h.0) })
}

// FILETIME ticks, 100 ns since 1601-01-01
fn creation_ticks(process: HANDLE) -> Option<u64> {
    let mut times = [FILETIME::default(); 4];
    let [created, exited, kernel, user] = &mut times;
    unsafe { GetProcessTimes(process, created, exited, kernel, user) }.ok()?;
    Some((u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime))
}

// with the pid, it tells the process apart from a later one reusing the pid
fn process_created(ticks: u64) -> String {
    let unix_nanos = (ticks as i64 - 116_444_736_000_000_000) * 100;
    chrono::DateTime::from_timestamp_nanos(unix_nanos)
        .to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true)
}

// None if the parent is gone: a process newer than the child reused its pid
fn parent_pid(process: HANDLE, child_ticks: u64) -> Option<u32> {
    let mut info = PROCESS_BASIC_INFORMATION::default();
    unsafe {
        NtQueryInformationProcess(
            process,
            ProcessBasicInformation,
            &mut info as *mut _ as _,
            size_of_val(&info) as u32,
            &mut 0,
        )
    }
    .ok()
    .ok()?;
    let parent_pid = info.InheritedFromUniqueProcessId as u32;
    let parent = open_process(parent_pid)?;
    (creation_ticks(HANDLE(parent.as_raw_handle()))? <= child_ticks).then_some(parent_pid)
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
        let event = |pid: u32| -> ScanEvent {
            serde_json::from_str(&format!(
                r#"{{"time":"","pid":{pid},"tid":0,"process":"","cmd_line":"","app_name":"",
                "content_name":"","session":0,"request_number":0,"status":"detected",
                "reason":null,"blocked":false,"content":"","content_truncated":false,
                "process_created":"forged","user_sid":"S-1-5-18"}}"#
            ))
            .unwrap()
        };
        assert!(!identity.apply(&mut event(std::process::id() + 4)));

        let mut event = event(std::process::id());
        assert!(identity.apply(&mut event));
        assert!(
            event
                .parent_pid
                .is_some_and(|p| p != 0 && p != std::process::id())
        );
        assert!(event.session_id.is_some());
        let created = event.process_created.unwrap();
        assert!(created.starts_with("20"), "{created}");
        let sid = event.user_sid.unwrap();
        assert!(sid.starts_with("S-1-5-") && sid != "S-1-5-18", "{sid}");
    }

    #[test]
    fn parent_pid_of_a_child_is_this_process() {
        let mut child = std::process::Command::new("cmd")
            .args(["/c", "pause"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let child_handle = HANDLE(child.as_raw_handle());
        let ticks = creation_ticks(child_handle).unwrap();
        let parent = parent_pid(child_handle, ticks);
        // a parent created after the child only reuses the pid
        let reused = parent_pid(child_handle, 0);
        child.kill().unwrap();
        assert_eq!(parent, Some(std::process::id()));
        assert_eq!(reused, None);
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
