mod com_wrapper;
mod config;
mod pipe_server;

use std::{
    sync::{
        LazyLock,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use clap::{Parser, Subcommand};
use com_wrapper::{ComWrapper, RamsiComWrapper};
use shared::{PipeName, ScanEvent};
use tokio::{runtime::Runtime, time::timeout};

use crate::pipe_server::PipeError;

const RAMSI_COM_DLL: &str = "ramsi_com.dll";

static CONTROL_C: LazyLock<AtomicBool> = LazyLock::new(|| AtomicBool::new(false));

#[derive(Parser)]
#[command(about = "Manage the Ramsi AMSI provider and trace its events")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Register the provider DLL as an AMSI provider
    Register {
        #[arg(long, default_value = RAMSI_COM_DLL)]
        dll: String,
        /// Pipe name suffix (\\.\pipe\<SUFFIX>) the provider reports to
        #[arg(long, value_name = "SUFFIX")]
        pipe: Option<String>,
    },
    /// Unregister the provider DLL
    Unregister {
        #[arg(long, default_value = RAMSI_COM_DLL)]
        dll: String,
    },
    /// Print events reported by the provider until Ctrl+C
    Trace {
        /// Pipe name suffix, the configured one by default
        #[arg(long, value_name = "SUFFIX")]
        pipe: Option<String>,
        /// Register the DLL for the time of tracing
        #[arg(long)]
        register: bool,
        #[arg(long, default_value = RAMSI_COM_DLL)]
        dll: String,
        /// Print events as JSON lines
        #[arg(long)]
        json: bool,
        /// Print only events containing TEXT (case-insensitive)
        #[arg(long, value_name = "TEXT")]
        filter: Option<String>,
    },
    /// Show registration and configuration
    Status,
    /// Show or change the configuration in HKLM\SOFTWARE\Ramsi
    #[command(subcommand)]
    Config(ConfigCommand),
}

#[derive(Subcommand)]
enum ConfigCommand {
    Show,
    Set { name: String, value: String },
    Unset { name: String },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    match Cli::parse().command {
        Command::Register { dll, pipe } => {
            let pipe = pipe_suffix(pipe)?;
            ComWrapper::new(&dll)?.register(&pipe)?;
            println!("Log dir: {}", config::secure_log_dir()?.display());
        },
        Command::Unregister { dll } => {
            ComWrapper::new(&dll)?.unregister()?;
        },
        Command::Trace {
            pipe,
            register,
            dll,
            json,
            filter,
        } => {
            let pipe = pipe_suffix(pipe)?;
            let _ramsi_wrapper = if register {
                let wrapper = RamsiComWrapper::new(&dll, &pipe)?;
                config::secure_log_dir()?;
                Some(wrapper)
            } else {
                None
            };
            let output = Output {
                json,
                filter: filter.map(|f| f.to_lowercase()),
            };
            let rt = Runtime::new()?;
            rt.block_on(trace_amsi_events(
                PipeName::from_suffix(&pipe).as_str(),
                output,
            ))?;
        },
        Command::Status => config::status()?,
        Command::Config(ConfigCommand::Show) => config::show()?,
        Command::Config(ConfigCommand::Set { name, value }) => config::set(&name, &value)?,
        Command::Config(ConfigCommand::Unset { name }) => config::unset(&name)?,
    }

    log::debug!("Main finished");
    Ok(())
}

// an explicit suffix wins over the configured one
fn pipe_suffix(pipe: Option<String>) -> Result<String, Box<dyn std::error::Error>> {
    let pipe = pipe.unwrap_or_else(config::pipe_suffix);
    PipeName::from_suffix(&pipe).verify()?;
    Ok(pipe)
}

#[derive(Clone)]
struct Output {
    json: bool,
    filter: Option<String>,
}

impl Output {
    fn print(&self, event: &ScanEvent) {
        let line = event.to_string();
        if let Some(filter) = &self.filter
            && !line.to_lowercase().contains(filter)
            && !event.content.to_lowercase().contains(filter)
        {
            return;
        }
        if self.json {
            match serde_json::to_string(event) {
                Ok(json) => println!("{json}"),
                Err(err) => log::error!("{err}"),
            }
        } else {
            println!("{line}");
        }
    }
}

async fn trace_amsi_events(
    pipe_name: &str,
    output: Output,
) -> Result<(), Box<dyn std::error::Error>> {
    tokio::spawn(async move {
        ctrlc::set_handler(move || {
            eprintln!("received Ctrl+C!");
            CONTROL_C.store(true, Ordering::Release);
        })
        .expect("Error setting Ctrl-C handler");
    });

    let mut server = pipe_server::create_first_server(pipe_name)?;
    log::info!("Tracing events on {pipe_name}");

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

        let output = output.clone();
        // ends with the runtime on Ctrl+C
        let _client = tokio::spawn(async move {
            loop {
                match pipe_server::message::<ScanEvent>(&mut connected_client).await {
                    Ok(event) => output.print(&event),
                    Err(PipeError::UnexpectedEof) => break,
                    // the stream is stalled or out of sync, drop the client
                    Err(err) => {
                        log::warn!("Dropping client: {err}");
                        break;
                    },
                }
            }
        });
    }

    Ok(())
}
