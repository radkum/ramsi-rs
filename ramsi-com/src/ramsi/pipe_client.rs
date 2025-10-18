use macros::error;
use serde::Serialize;
use serde_json::to_vec;
use thiserror::Error;
use tokio::{
    io::AsyncWriteExt,
    net::windows::named_pipe::{ClientOptions, NamedPipeClient},
    time,
};

#[derive(Error, Debug)]
pub enum PipeClientError {
    #[error("Io error: {0}")]
    IoError(std::io::Error),

    #[error("Timeout")]
    Timeout,

    #[error("Pipe not active")]
    NotActive,
}

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

pub struct PipeClient {
    pub pipe: Option<NamedPipeClient>,
    pub pipe_name: String,
}

impl PipeClient {
    pub fn new(pipe_name: &str) -> Self {
        Self {
            pipe: None,
            pipe_name: pipe_name.to_string(),
        }
    }

    pub async fn connect(&mut self) -> bool {
        match ClientOptions::new().open(&self.pipe_name) {
            Ok(pipe) => {
                self.pipe = Some(pipe);
                true
            },
            Err(err) => {
                error!("Desktop-ui: Connecting pipe failed: {err}");
                false
            },
        }
    }

    pub fn active(&self) -> bool {
        self.pipe.is_some()
    }

    // pub fn disconnect(&mut self) {
    //     self.pipe = None;
    // }

    pub async fn send<M: Serialize + Clone + std::fmt::Debug>(
        &mut self,
        message: M,
    ) -> Result<(), PipeClientError> {
        if let Some(ref mut pipe) = self.pipe {
            Self::send_internal(pipe, message.clone()).await?;
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
