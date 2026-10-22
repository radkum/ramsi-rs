use std::{
    os::windows::io::AsRawHandle,
    time::{Duration, Instant},
};

use serde::Serialize;
use serde_json::to_vec;
use thiserror::Error;
use tokio::{
    io::AsyncWriteExt,
    net::windows::named_pipe::{ClientOptions, NamedPipeClient},
    time,
};
use windows::Win32::Foundation::HANDLE;

use crate::winapi::pipe_server_is_elevated;

#[derive(Error, Debug)]
pub enum PipeClientError {
    #[error("Failed to connect pipe \"{1}\": {0}")]
    FailedToConnect(std::io::Error, String),

    #[error("Io error: {0}")]
    IoError(std::io::Error),

    #[error("Timeout")]
    Timeout,

    #[error("Pipe not active")]
    NotActive,

    #[error("Reconnect postponed after a timeout")]
    Backoff,

    #[error("Pipe \"{0}\" is not served by an elevated process")]
    UntrustedServer(String),
}
pub type PipeClientResult<T> = Result<T, PipeClientError>;

impl From<std::io::Error> for PipeClientError {
    fn from(err: std::io::Error) -> Self {
        if err.kind() == std::io::ErrorKind::TimedOut {
            Self::Timeout
        } else {
            Self::IoError(err)
        }
    }
}

impl From<time::error::Elapsed> for PipeClientError {
    fn from(_elapsed: time::error::Elapsed) -> Self {
        Self::Timeout
    }
}

const SEND_TIMEOUT: Duration = Duration::from_millis(500);
// a stalled server would otherwise cost SEND_TIMEOUT on every scan
const RECONNECT_BACKOFF: Duration = Duration::from_secs(30);

pub struct PipeClient {
    pub pipe: Option<NamedPipeClient>,
    pub pipe_name: String,
    retry_at: Option<Instant>,
}

impl PipeClient {
    pub fn new(pipe_name: &str) -> Self {
        Self {
            pipe: None,
            pipe_name: pipe_name.to_string(),
            retry_at: None,
        }
    }

    pub fn connect(&mut self) -> PipeClientResult<()> {
        if self.retry_at.is_some_and(|t| Instant::now() < t) {
            return Err(PipeClientError::Backoff);
        }
        let pipe = ClientOptions::new()
            .open(&self.pipe_name)
            .map_err(|err| PipeClientError::FailedToConnect(err, self.pipe_name.clone()))?;
        if !pipe_server_is_elevated(HANDLE(pipe.as_raw_handle())).unwrap_or(false) {
            self.retry_at = Some(Instant::now() + RECONNECT_BACKOFF);
            return Err(PipeClientError::UntrustedServer(self.pipe_name.clone()));
        }
        self.pipe = Some(pipe);
        Ok(())
    }

    pub fn active(&self) -> bool {
        self.pipe.is_some()
    }

    pub async fn send<M: Serialize + Clone + std::fmt::Debug>(
        &mut self,
        message: M,
    ) -> Result<(), PipeClientError> {
        if let Some(ref mut pipe) = self.pipe {
            let res = time::timeout(SEND_TIMEOUT, Self::send_internal(pipe, message.clone())).await;
            if !matches!(res, Ok(Ok(()))) {
                // broken or stalled pipe, reconnect on next send
                self.pipe = None;
            }
            if res.is_err() {
                self.retry_at = Some(Instant::now() + RECONNECT_BACKOFF);
            }
            res??;
            Ok(())
        } else {
            Err(PipeClientError::NotActive)
        }
    }

    pub async fn send_internal<
        M: Serialize + Clone + std::fmt::Debug,
        W: AsyncWriteExt + std::marker::Unpin,
    >(
        pipe: &mut W,
        message: M,
    ) -> std::io::Result<()> {
        let buffer = to_vec(&message)?;
        pipe.write_u64(buffer.len() as _).await?;
        pipe.write_all(&buffer).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use tokio::net::windows::named_pipe::ServerOptions;

    use super::*;

    fn pipe_name(test: &str) -> String {
        shared::PipeName::from_suffix(&format!("ramsi-test-{test}-{}", std::process::id()))
            .to_string()
    }

    // the runtime may buffer a few writes before one has to wait on the pipe
    async fn send_until_error(client: &mut PipeClient) -> PipeClientResult<()> {
        for _ in 0..8 {
            client.send("x".repeat(1 << 20)).await?;
        }
        Ok(())
    }

    #[tokio::test]
    async fn send_times_out_and_resets_when_server_does_not_read() {
        let name = pipe_name("stalled");
        let _server = ServerOptions::new().create(&name).unwrap();
        let mut client = PipeClient::new(&name);
        client.connect().unwrap();

        let res = send_until_error(&mut client).await;

        assert!(matches!(res, Err(PipeClientError::Timeout)), "{res:?}");
        assert!(!client.active());
        assert!(matches!(client.connect(), Err(PipeClientError::Backoff)));
    }

    #[tokio::test]
    async fn send_resets_when_server_is_gone() {
        let name = pipe_name("gone");
        let server = ServerOptions::new().create(&name).unwrap();
        let mut client = PipeClient::new(&name);
        client.connect().unwrap();
        drop(server);

        assert!(send_until_error(&mut client).await.is_err());
        assert!(!client.active());
    }

    // a pipe server started with a non-elevated (LUA) copy of our token
    #[test]
    fn rejects_server_that_is_not_elevated() {
        use windows::{
            Win32::{
                Foundation::{CloseHandle, HANDLE},
                Security::{
                    CreateRestrictedToken, LUA_TOKEN, TOKEN_ADJUST_DEFAULT, TOKEN_ADJUST_SESSIONID,
                    TOKEN_ASSIGN_PRIMARY, TOKEN_DUPLICATE, TOKEN_QUERY,
                },
                System::{
                    Pipes::WaitNamedPipeW,
                    Threading::{
                        CREATE_NO_WINDOW, CreateProcessAsUserW, GetCurrentProcess,
                        OpenProcessToken, PROCESS_INFORMATION, STARTUPINFOW, TerminateProcess,
                    },
                },
            },
            core::{HSTRING, PWSTR},
        };

        let name = pipe_name("untrusted");
        let script = format!(
            "$p = New-Object IO.Pipes.NamedPipeServerStream('{}'); $p.WaitForConnection(); \
             Start-Sleep 30",
            name.trim_start_matches(r"\\.\pipe\")
        );
        let mut cmd: Vec<u16> =
            format!("powershell.exe -NoProfile -NonInteractive -Command \"{script}\"\0")
                .encode_utf16()
                .collect();

        let process = unsafe {
            let mut token = HANDLE::default();
            OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_QUERY
                    | TOKEN_DUPLICATE
                    | TOKEN_ASSIGN_PRIMARY
                    | TOKEN_ADJUST_DEFAULT
                    | TOKEN_ADJUST_SESSIONID,
                &mut token,
            )
            .unwrap();
            let mut lua = HANDLE::default();
            CreateRestrictedToken(token, LUA_TOKEN, None, None, None, &mut lua).unwrap();
            let startup = STARTUPINFOW {
                cb: size_of::<STARTUPINFOW>() as u32,
                ..Default::default()
            };
            let mut info = PROCESS_INFORMATION::default();
            CreateProcessAsUserW(
                Some(lua),
                None,
                Some(PWSTR(cmd.as_mut_ptr())),
                None,
                None,
                false,
                CREATE_NO_WINDOW,
                None,
                None,
                &startup,
                &mut info,
            )
            .unwrap();
            let _ = CloseHandle(info.hThread);
            let _ = CloseHandle(lua);
            let _ = CloseHandle(token);
            info.hProcess
        };

        let pipe = HSTRING::from(name.as_str());
        let ready = (0..300).any(|_| {
            std::thread::sleep(std::time::Duration::from_millis(100));
            unsafe { WaitNamedPipeW(&pipe, 0) }.as_bool()
        });

        let res = ready.then(|| {
            let rt = tokio::runtime::Runtime::new().unwrap();
            let _guard = rt.enter();
            let mut client = PipeClient::new(&name);
            let res = client.connect();
            (res, client.active())
        });
        unsafe {
            let _ = TerminateProcess(process, 1);
            let _ = CloseHandle(process);
        }

        let (res, active) = res.expect("pipe server did not start");
        assert!(
            matches!(res, Err(PipeClientError::UntrustedServer(_))),
            "{res:?}"
        );
        assert!(!active);
    }

    #[tokio::test]
    async fn reconnects_without_backoff_after_broken_pipe() {
        let name = pipe_name("broken");
        let server = ServerOptions::new().create(&name).unwrap();
        let mut client = PipeClient::new(&name);
        client.connect().unwrap();
        drop(server);
        assert!(send_until_error(&mut client).await.is_err());

        let _server = ServerOptions::new().create(&name).unwrap();
        client.connect().unwrap();
    }
}
