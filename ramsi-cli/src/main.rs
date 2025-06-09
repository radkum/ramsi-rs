mod com_wrapper;
mod pipe_server;

use com_wrapper::{ComWrapper, RamsiComWrapper};

use shared::{RamsiMessage, constants::RAMSI_PIPE_NAME};
use tokio::runtime::Runtime;

use crate::pipe_server::PipeError;
use std::{
    sync::{
        LazyLock,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::time::timeout;

const RAMSI_COM_DLL: &str = "ramsi_com.dll";

static CONTROL_C: LazyLock<AtomicBool> = LazyLock::new(|| AtomicBool::new(false));

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::Builder::new()
        .filter_level(log::LevelFilter::max())
        .init();
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        log::error!("missing args");
        return Ok(());
    }

    log::debug!("main start");

    let command = args[1].as_str();
    match command {
        "-r" | "--register" => {
            let com_wrapper = ComWrapper::new(RAMSI_COM_DLL)?;
            com_wrapper.register()?;
        },
        "-u" | "--unregister" => {
            let com_wrapper = ComWrapper::new(RAMSI_COM_DLL)?;
            com_wrapper.unregister()?;
        },
        "-a" | "--all" => {
            let _ramsi_wrapper = RamsiComWrapper::new(RAMSI_COM_DLL)?;
            let rt = Runtime::new()?;
            rt.block_on(trace_amsi_events())?;
        },
        "-t" | "--trace" => {
            let rt = Runtime::new()?;
            rt.block_on(trace_amsi_events())?;
        },
        _ => {},
    }

    log::debug!("main finish");
    Ok(())
}

async fn trace_amsi_events() -> Result<(), Box<dyn std::error::Error>> {
    tokio::spawn(async move {
        ctrlc::set_handler(move || {
            println!("received Ctrl+C!");
            CONTROL_C.store(true, Ordering::Release);
        })
        .expect("Error setting Ctrl-C handler");
    });

    let mut server = pipe_server::create_first_server(RAMSI_PIPE_NAME)?;

    loop {
        {
            let control_c = CONTROL_C.load(Ordering::Acquire);
            if control_c {
                break;
            }
        }

        // Wait for a client to connect.
        if let Err(_) = timeout(Duration::from_millis(1000), server.connect()).await {
            //timeout
            continue;
        }

        let mut connected_client = server;

        // Construct the next server to be connected before sending the one
        // we already have of onto a task. This ensures that the server
        // isn't closed (after it's done in the task) before a new one is
        // available. Otherwise the client might error with
        // `io::ErrorKind::NotFound`.
        server = pipe_server::create_server(RAMSI_PIPE_NAME)?;

        let _client = tokio::spawn(async move {
            loop {
                {
                    let control_c = CONTROL_C.load(Ordering::Acquire);
                    if control_c {
                        break;
                    }
                }

                match pipe_server::message::<RamsiMessage>(&mut connected_client, 1000).await {
                    Ok(input_message) => {
                        println!("{:?}", input_message);
                    },
                    Err(err) => match err {
                        PipeError::Timeout => { /* to noisy */ },
                        PipeError::UnexpectedEof => break,
                        PipeError::IoError(err) => log::trace!("IoErrorrr: {err}"),
                    },
                }
            }
        });
    }

    Ok(())
}
