use std::{ffi::CString, mem::zeroed, time::Duration};

use serde::de::DeserializeOwned;
use serde_json::from_slice;
use thiserror::Error;
use tokio::{
    io::AsyncReadExt,
    net::windows::named_pipe::{NamedPipeServer, ServerOptions},
    time::timeout,
};
use windows::Win32::Security::SECURITY_ATTRIBUTES;
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
    time: u64,
) -> core::result::Result<M, PipeError> {
    Ok(read::<M, _>(pipe, time).await?)
}

pub async fn read<M: DeserializeOwned, R: AsyncReadExt + std::marker::Unpin>(
    pipe: &mut R,
    time: u64,
) -> std::io::Result<M> {
    let message_length = timeout(Duration::from_millis(time), pipe.read_u64()).await??;
    let mut buffer = vec![0u8; message_length as usize];
    pipe.read_exact(&mut buffer).await?;
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

    let input =
        CString::new("D:(D;OICI;GA;;;BG)(D;OICI;GA;;;AN)(A;OICI;GRGWGX;;;AU)(A;OICI;GA;;;BA)")?;

    let mut attributes: SECURITY_ATTRIBUTES = unsafe { zeroed() };

    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorA(
            PCSTR::from_raw(input.as_ptr() as *const _),
            SDDL_REVISION_1,
            &mut attributes.lpSecurityDescriptor as *mut _ as _,
            None,
        )?;
    }

    unsafe {
        ServerOptions::new()
            .first_pipe_instance(first)
            .create_with_security_attributes_raw(pipe_name, &mut attributes as *mut _ as _)
    }
}
