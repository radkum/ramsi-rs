use std::{ffi::CString, mem::zeroed, time::Duration};

use serde::de::DeserializeOwned;
use serde_json::from_slice;
use shared::constants::MAX_MESSAGE_LEN;
use thiserror::Error;
use tokio::{
    io::AsyncReadExt,
    net::windows::named_pipe::{NamedPipeServer, ServerOptions},
    time::timeout,
};
use windows::Win32::{
    Foundation::{HLOCAL, LocalFree},
    Security::SECURITY_ATTRIBUTES,
};
use windows_core::PCSTR;

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

impl From<tokio::time::error::Elapsed> for PipeError {
    fn from(_elapsed: tokio::time::error::Elapsed) -> Self {
        Self::Timeout
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

    // owner BA can only be set by an elevated process, providers check it
    let input =
        CString::new("O:BAD:(D;OICI;GA;;;BG)(D;OICI;GA;;;AN)(A;OICI;GRGWGX;;;AU)(A;OICI;GA;;;BA)")?;

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
