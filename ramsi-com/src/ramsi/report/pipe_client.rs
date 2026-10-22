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
    #[error("Failed to connect pipe \"{1}\": {0}")]
    FailedToConnect(std::io::Error, String),

    #[error("Io error: {0}")]
    IoError(std::io::Error),

    #[error("Timeout")]
    Timeout,

    #[error("Pipe not active")]
    NotActive,
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

const SEND_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(500);

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

    pub fn connect(&mut self) -> PipeClientResult<()> {
        self.pipe = Some(
            ClientOptions::new()
                .open(&self.pipe_name)
                .map_err(|err| PipeClientError::FailedToConnect(err, self.pipe_name.clone()))?,
        );
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
}
