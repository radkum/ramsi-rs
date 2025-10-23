mod com_wrapper;
mod pipe_server;

use std::{
    sync::{
        LazyLock,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use com_wrapper::{ComWrapper, RamsiComWrapper};
use shared::{FfiString, PipeName, RamsiMessage, constants::RAMSI_PIPE_SUFFIX};
use tokio::{runtime::Runtime, time::timeout};

use crate::pipe_server::PipeError;

const RAMSI_COM_DLL: &str = "ramsi_com.dll";

static CONTROL_C: LazyLock<AtomicBool> = LazyLock::new(|| AtomicBool::new(false));

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::Builder::new()
        .filter_level(log::LevelFilter::max())
        .init();
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        println!("No arguments provided.");
        print_help();
        return Ok(());
    }

    let ramsi_path = if args.len() > 2 {
        args[2].as_str()
    } else {
        RAMSI_COM_DLL
    };

    let pipe_suffix = if args.len() > 3 {
        args[3].as_str()
    } else {
        RAMSI_PIPE_SUFFIX
    };
    let pipe_name = PipeName::from_suffix(pipe_suffix);
    pipe_name.verify()?;
    let pipe_suffix_ffi = FfiString::new(pipe_suffix);

    log::trace!("Main start");

    let command = args[1].as_str();
    match command {
        "-r" | "--register" => {
            let com_wrapper = ComWrapper::new(ramsi_path)?;
            com_wrapper.register(pipe_suffix_ffi)?;
        },
        "-u" | "--unregister" => {
            let com_wrapper = ComWrapper::new(ramsi_path)?;
            com_wrapper.unregister()?;
        },
        "-a" | "--all" => {
            let _ramsi_wrapper = RamsiComWrapper::new(ramsi_path, pipe_suffix_ffi)?;
            let rt = Runtime::new()?;
            rt.block_on(trace_amsi_events(pipe_name.as_str()))?;
        },
        "-t" | "--trace" => {
            let rt = Runtime::new()?;
            rt.block_on(trace_amsi_events(pipe_name.as_str()))?;
        },
        "-h" | "--help" => {
            print_help();
        },
        _ => {
            println!("Unknown command: {}", command);
            print_help();
        },
    }

    log::debug!("Main finished");
    Ok(())
}

async fn trace_amsi_events(pipe_name: &str) -> Result<(), Box<dyn std::error::Error>> {
    tokio::spawn(async move {
        ctrlc::set_handler(move || {
            println!("received Ctrl+C!");
            CONTROL_C.store(true, Ordering::Release);
        })
        .expect("Error setting Ctrl-C handler");
    });

    let mut server = pipe_server::create_first_server(pipe_name)?;

    loop {
        {
            let control_c = CONTROL_C.load(Ordering::Acquire);
            if control_c {
                break;
            }
        }

        // Wait for a client to connect.
        if let Err(_err) = timeout(Duration::from_millis(1000), server.connect()).await {
            //timeout
            continue;
        }

        let mut connected_client = server;

        // Construct the next server to be connected before sending the one
        // we already have of onto a task. This ensures that the server
        // isn't closed (after it's done in the task) before a new one is
        // available. Otherwise the client might error with
        // `io::ErrorKind::NotFound`.
        server = pipe_server::create_server(pipe_name)?;

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
                        println!("{}", input_message);
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

fn print_help() {
    println!("Usage: ramsi-cli [OPTION]");
    println!("Options:");
    println!("  -r, --register       Register the COM component");
    println!("  -u, --unregister     Unregister the COM component");
    println!("  -a, --all            Register the COM component and trace AMSI events");
    println!("  -t, --trace          Trace AMSI events");
}
