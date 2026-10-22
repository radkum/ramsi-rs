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

use crate::winapi::pipe_owner_is_admin;

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

    #[error("Pipe \"{0}\" is not owned by Administrators or SYSTEM")]
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
        if !pipe_owner_is_admin(HANDLE(pipe.as_raw_handle())).unwrap_or(false) {
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
    use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};

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
        let _server = admin_server(&name);
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
        let server = admin_server(&name);
        let mut client = PipeClient::new(&name);
        client.connect().unwrap();
        drop(server);

        assert!(send_until_error(&mut client).await.is_err());
        assert!(!client.active());
    }

    // the security descriptor ramsi-cli uses
    fn admin_server(name: &str) -> NamedPipeServer {
        server_with_sddl(name, shared::constants::PIPE_SDDL)
    }

    fn server_with_sddl(name: &str, sddl: &str) -> NamedPipeServer {
        use windows::Win32::Security::{
            Authorization::{
                ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
            },
            SECURITY_ATTRIBUTES,
        };

        let mut attributes = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            ..Default::default()
        };
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                &windows_core::HSTRING::from(sddl),
                SDDL_REVISION_1,
                &mut attributes.lpSecurityDescriptor as *mut _ as _,
                None,
            )
            .unwrap();
            ServerOptions::new()
                .create_with_security_attributes_raw(name, &mut attributes as *mut _ as _)
                .unwrap()
        }
    }

    // an elevated server seen by a client impersonating `token`
    fn connect_impersonating(token: windows::Win32::Foundation::HANDLE) -> PipeClientResult<()> {
        use windows::Win32::Security::{ImpersonateLoggedOnUser, RevertToSelf};

        let rt = tokio::runtime::Runtime::new().unwrap();
        let _guard = rt.enter();
        let name = pipe_name(&format!("client-{}", token.0 as usize));
        let _server = admin_server(&name);
        unsafe {
            ImpersonateLoggedOnUser(token).unwrap();
            let res = PipeClient::new(&name).connect();
            RevertToSelf().unwrap();
            res
        }
    }

    #[test]
    fn accepts_elevated_server_from_lua_client() {
        use windows::Win32::{
            Foundation::{CloseHandle, HANDLE},
            Security::{
                CreateRestrictedToken, LUA_TOKEN, TOKEN_ASSIGN_PRIMARY, TOKEN_DUPLICATE,
                TOKEN_IMPERSONATE, TOKEN_QUERY,
            },
            System::Threading::{GetCurrentProcess, OpenProcessToken},
        };

        let res = unsafe {
            let mut token = HANDLE::default();
            OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_IMPERSONATE,
                &mut token,
            )
            .unwrap();
            let mut lua = HANDLE::default();
            CreateRestrictedToken(token, LUA_TOKEN, None, None, None, &mut lua).unwrap();
            let res = connect_impersonating(lua);
            let _ = CloseHandle(lua);
            let _ = CloseHandle(token);
            res
        };
        assert!(res.is_ok(), "{res:?}");
    }

    // needs a standard local account: RAMSI_TEST_USER, RAMSI_TEST_PASSWORD
    #[test]
    fn accepts_elevated_server_from_other_user() {
        use windows::Win32::{
            Foundation::{CloseHandle, HANDLE},
            Security::{LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, LogonUserW},
        };

        let (Ok(user), Ok(password)) = (
            std::env::var("RAMSI_TEST_USER"),
            std::env::var("RAMSI_TEST_PASSWORD"),
        ) else {
            eprintln!("SKIPPED: RAMSI_TEST_USER and RAMSI_TEST_PASSWORD not set");
            return;
        };
        let res = unsafe {
            let mut token = HANDLE::default();
            LogonUserW(
                &windows_core::HSTRING::from(user),
                windows_core::w!("."),
                &windows_core::HSTRING::from(password),
                LOGON32_LOGON_INTERACTIVE,
                LOGON32_PROVIDER_DEFAULT,
                &mut token,
            )
            .unwrap();
            let res = connect_impersonating(token);
            let _ = CloseHandle(token);
            res
        };
        assert!(res.is_ok(), "{res:?}");
    }

    // a user can create the pipe first, but cannot make Administrators its owner
    #[tokio::test]
    async fn rejects_server_not_owned_by_admins() {
        let name = pipe_name("untrusted");
        let sddl = format!(
            "O:{}D:(A;;GA;;;BA)(A;;GRGWGX;;;AU)",
            crate::winapi::current_user_sid()
        );
        let _server = server_with_sddl(&name, &sddl);
        let mut client = PipeClient::new(&name);

        let res = client.connect();

        assert!(
            matches!(res, Err(PipeClientError::UntrustedServer(_))),
            "{res:?}"
        );
        assert!(!client.active());
    }

    #[tokio::test]
    async fn reconnects_without_backoff_after_broken_pipe() {
        let name = pipe_name("broken");
        let server = admin_server(&name);
        let mut client = PipeClient::new(&name);
        client.connect().unwrap();
        drop(server);
        assert!(send_until_error(&mut client).await.is_err());

        let _server = admin_server(&name);
        client.connect().unwrap();
    }
}
